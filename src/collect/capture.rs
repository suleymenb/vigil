//! Packet capture to a file Wireshark opens directly.
//!
//! Linux and macOS run `tcpdump -w FILE.pcap`; Windows 10 2004+ runs the
//! built-in `pktmon` and converts its trace to `FILE.pcapng`. One engine
//! serves three front ends:
//!
//! * `C` in Sockets: the selected connection, for `capture_seconds`;
//! * `C` in Network and `t` in Troubleshoot: any interface and BPF filter;
//! * `vigil capture`: the same from the shell, including `-w -` to stream a
//!   live pcap into Wireshark (`… | wireshark -k -i -`), also over SSH.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::tools::Tone;

#[derive(Default)]
pub struct CaptureState {
    pub running: Option<(PathBuf, Instant, Duration)>,
    /// Last finished capture: Ok(path, size) or Err(message).
    pub last: Option<Result<(PathBuf, u64), String>>,
    pub version: u64,
}

/// What to capture.
#[derive(Clone, Debug, PartialEq)]
pub struct Spec {
    /// Interface name, or "any".
    pub iface: String,
    /// BPF expression ("" = everything).
    pub filter: String,
    pub secs: Option<u64>,
    pub count: Option<u64>,
}

/// Where the packets go.
#[derive(Clone, Debug, PartialEq)]
pub enum Out {
    File(PathBuf),
    /// pcap on stdout, for `| wireshark -k -i -`.
    Stdout,
}

/// A finished capture.
#[derive(Clone, Debug)]
pub struct Done {
    pub path: Option<PathBuf>,
    pub bytes: u64,
    pub packets: Option<u64>,
}

/// tcpdump filter for a socket's endpoints: the remote side when connected,
/// otherwise the local port.
pub fn bpf_filter(local: &str, remote: &str) -> Option<String> {
    let host_port = |ep: &str| -> Option<(Option<String>, u16)> {
        let (h, p) = ep.rsplit_once(':')?;
        let h = h.trim_matches(['[', ']']);
        let port = p.parse().ok()?;
        let host = (h != "*" && !h.is_empty()).then(|| h.to_string());
        Some((host, port))
    };
    if !remote.is_empty() {
        let (h, p) = host_port(remote)?;
        return Some(match h {
            Some(h) => format!("host {h} and port {p}"),
            None => format!("port {p}"),
        });
    }
    let (_, p) = host_port(local)?;
    Some(format!("port {p}"))
}

/// Parse the prompt / CLI form `[IFACE] [30s] [500p] [BPF filter…]`.
/// `ifaces` are the known interface names (the first word is an interface
/// only if it is one of them, or `any`).
pub fn parse_spec(input: &str, ifaces: &[String], default_secs: u64) -> Result<Spec, String> {
    let mut words: Vec<&str> = input.split_whitespace().collect();
    let mut spec = Spec { iface: "any".into(), filter: String::new(), secs: None, count: None };
    if let Some(first) = words.first() {
        if *first == "any" || ifaces.iter().any(|i| i == first) {
            spec.iface = first.to_string();
            words.remove(0);
        }
    }
    let mut rest = Vec::new();
    for w in words {
        let digits = |suffix: &[&str]| suffix.iter().find_map(|s| w.strip_suffix(s)).and_then(|n| n.parse::<u64>().ok());
        if let (Some(n), true) = (digits(&["s", "sec"]), spec.secs.is_none() && rest.is_empty()) {
            spec.secs = Some(n.clamp(1, 24 * 3600));
        } else if let (Some(n), true) = (digits(&["p", "pkts", "packets"]), spec.count.is_none() && rest.is_empty()) {
            spec.count = Some(n.max(1));
        } else {
            rest.push(w);
        }
    }
    spec.filter = rest.join(" ");
    if spec.secs.is_none() && spec.count.is_none() {
        spec.secs = Some(default_secs.max(1));
    }
    Ok(spec)
}

/// `vigil-capture-<unix time>.<ext>` in the current directory if writable,
/// else the home directory, else the temp directory.
pub fn default_path(ext: &str) -> PathBuf {
    let stamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let dir = std::env::current_dir().ok().filter(|d| std::fs::metadata(d).map(|m| !m.permissions().readonly()).unwrap_or(false));
    dir.or_else(crate::util::home_dir).unwrap_or_else(std::env::temp_dir).join(format!("vigil-capture-{stamp}.{ext}"))
}

/// File extension this OS's capture writes.
pub fn ext() -> &'static str {
    if cfg!(windows) {
        "pcapng"
    } else {
        "pcap"
    }
}

/// Count packets in a pcap or pcapng file.
pub fn count_pcap(path: &Path) -> Option<u64> {
    let b = std::fs::read(path).ok()?;
    let magic = u32::from_le_bytes(b.get(0..4)?.try_into().ok()?);
    if magic == 0x0a0d0d0a {
        return count_pcapng(&b);
    }
    let le = match magic {
        0xa1b2c3d4 | 0xa1b23c4d => true,
        0xd4c3b2a1 | 0x4d3cb2a1 => false,
        _ => return None,
    };
    let rd = |o: usize| -> Option<u32> {
        let a: [u8; 4] = b.get(o..o + 4)?.try_into().ok()?;
        Some(if le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) })
    };
    let (mut off, mut n) = (24usize, 0u64);
    while off + 16 <= b.len() {
        let incl = rd(off + 8)? as usize;
        off += 16 + incl;
        if off > b.len() {
            break; // last record cut short by the stop
        }
        n += 1;
    }
    Some(n)
}

/// pcapng: count Enhanced (6) and Simple (3) Packet Blocks.
fn count_pcapng(b: &[u8]) -> Option<u64> {
    let le = u32::from_le_bytes(b.get(8..12)?.try_into().ok()?) == 0x1a2b3c4d;
    let rd = |o: usize| -> Option<u32> {
        let a: [u8; 4] = b.get(o..o + 4)?.try_into().ok()?;
        Some(if le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) })
    };
    let (mut off, mut n) = (0usize, 0u64);
    while off + 12 <= b.len() {
        let (ty, len) = (rd(off)?, rd(off + 4)? as usize);
        if len < 12 {
            break;
        }
        if ty == 6 || ty == 3 {
            n += 1;
        }
        off += len;
    }
    Some(n)
}

/// Map a simple BPF filter to pktmon arguments (Windows): `port N`,
/// `host A`, `tcp` / `udp` / `icmp`, joined with `and`.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn pktmon_filter(filter: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut it = filter.split_whitespace();
    while let Some(w) = it.next() {
        match w.to_ascii_lowercase().as_str() {
            "and" | "&&" => {}
            "port" => args.extend(["-p".to_string(), it.next().ok_or("port needs a number")?.to_string()]),
            "host" => args.extend(["-i".to_string(), it.next().ok_or("host needs an address")?.to_string()]),
            p @ ("tcp" | "udp" | "icmp") => args.extend(["-t".to_string(), p.to_ascii_uppercase()]),
            other => return Err(format!("pktmon understands port N, host ADDR, tcp/udp/icmp and `and`; not \"{other}\"")),
        }
    }
    Ok(args)
}

fn friendly(err: &str) -> String {
    let l = err.to_ascii_lowercase();
    if l.contains("permission") || l.contains("not permitted") || l.contains("access is denied") || l.contains("operation not permitted") {
        if cfg!(windows) {
            "packet capture needs an elevated (administrator) terminal".into()
        } else if cfg!(target_os = "macos") {
            "packet capture needs root: run sudo vigil (or install Wireshark's ChmodBPF to capture without sudo)".into()
        } else {
            "packet capture needs root: run sudo vigil (or give tcpdump CAP_NET_RAW)".into()
        }
    } else if l.contains("no such device") || l.contains("doesn't exist") {
        format!("{} (list interfaces with tcpdump -D)", err.trim())
    } else if l.contains("syntax error") || l.contains("parse error") || l.contains("illegal") {
        format!("{} (BPF filter syntax: port 443 · host 10.0.0.5 · tcp and not port 22)", err.trim())
    } else {
        err.trim().to_string()
    }
}

/// A capture in progress.
pub struct Running {
    child: Option<Child>,
    out: Out,
    started: Instant,
    deadline: Option<Instant>,
    #[cfg_attr(windows, allow(dead_code))]
    stderr: Arc<Mutex<Vec<String>>>,
    #[cfg_attr(not(windows), allow(dead_code))]
    etl: Option<PathBuf>,
}

impl Running {
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

/// Start capturing.
pub fn spawn(spec: &Spec, out: Out) -> Result<Running, String> {
    let deadline = spec.secs.map(|s| Instant::now() + Duration::from_secs(s));
    #[cfg(windows)]
    {
        let Out::File(file) = &out else { return Err("streaming to stdout needs tcpdump (Linux/macOS)".into()) };
        if spec.count.is_some() {
            return Err("pktmon stops by time only: use seconds (30s)".into());
        }
        let fargs = pktmon_filter(&spec.filter)?;
        let run = |args: &[String]| -> Result<String, String> {
            let o = Command::new("pktmon").args(args).output().map_err(|e| format!("pktmon: {e} (Windows 10 2004 or newer)"))?;
            let text = String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr);
            if o.status.success() {
                Ok(text)
            } else {
                Err(friendly(text.lines().find(|l| !l.trim().is_empty()).unwrap_or("pktmon failed")))
            }
        };
        let _ = run(&["filter".into(), "remove".into()]);
        if !fargs.is_empty() {
            let mut a = vec!["filter".to_string(), "add".into(), "vigil".into()];
            a.extend(fargs);
            run(&a)?;
        }
        let etl = file.with_extension("etl");
        run(&["start".into(), "--capture".into(), "--comp".into(), "nics".into(), "--pkt-size".into(), "0".into(), "--file-name".into(), etl.display().to_string()])?;
        Ok(Running { child: None, out, started: Instant::now(), deadline, stderr: Arc::default(), etl: Some(etl) })
    }
    #[cfg(not(windows))]
    {
        if !crate::platform::get().tools.tcpdump {
            return Err("tcpdump not found: install it (apt install tcpdump · dnf install tcpdump)".into());
        }
        let mut c = Command::new("tcpdump");
        c.args(["-i", &spec.iface, "-nn", "-U", "-s", "0", "-w"]);
        match &out {
            Out::File(p) => {
                c.arg(p).stdout(Stdio::null());
            }
            Out::Stdout => {
                c.arg("-").stdout(Stdio::inherit());
            }
        }
        if let Some(n) = spec.count {
            c.arg("-c").arg(n.to_string());
        }
        if !spec.filter.trim().is_empty() {
            c.arg(spec.filter.trim());
        }
        let mut child = c.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().map_err(|e| format!("tcpdump: {e}"))?;
        let stderr: Arc<Mutex<Vec<String>>> = Arc::default();
        if let Some(err) = child.stderr.take() {
            let st = stderr.clone();
            thread::spawn(move || {
                use std::io::BufRead;
                for l in std::io::BufReader::new(err).lines().map_while(Result::ok) {
                    if let Ok(mut v) = st.lock() {
                        v.push(l);
                    }
                }
            });
        }
        Ok(Running { child: Some(child), out, started: Instant::now(), deadline, stderr, etl: None })
    }
}

/// Has the capture ended on its own (count reached, error) or hit its time?
pub fn poll(r: &mut Running) -> bool {
    if r.deadline.is_some_and(|d| Instant::now() >= d) {
        return true;
    }
    match r.child.as_mut() {
        Some(c) => matches!(c.try_wait(), Ok(Some(_))),
        None => false,
    }
}

/// Stop (if still running), wait, convert on Windows, and summarise.
pub fn finish(mut r: Running) -> Result<Done, String> {
    #[cfg(windows)]
    {
        let Out::File(file) = &r.out else { unreachable!() };
        let o = Command::new("pktmon").arg("stop").output().map_err(|e| e.to_string())?;
        let etl = r.etl.take().unwrap_or_default();
        let conv = Command::new("pktmon").arg("etl2pcap").arg(&etl).arg("--out").arg(file).output().map_err(|e| e.to_string())?;
        let _ = Command::new("pktmon").args(["filter", "remove"]).output();
        let _ = std::fs::remove_file(&etl);
        if !file.exists() {
            let t = String::from_utf8_lossy(&conv.stdout).to_string() + &String::from_utf8_lossy(&o.stdout);
            return Err(friendly(t.lines().find(|l| !l.trim().is_empty()).unwrap_or("pktmon produced no capture")));
        }
        let _ = &r.child;
        Ok(Done { path: Some(file.clone()), bytes: std::fs::metadata(file).map(|m| m.len()).unwrap_or(0), packets: count_pcap(file) })
    }
    #[cfg(not(windows))]
    {
        let mut child = r.child.take().ok_or("no capture running")?;
        if matches!(child.try_wait(), Ok(None)) {
            // SIGINT lets tcpdump flush and close the pcap cleanly.
            unsafe {
                libc::kill(child.id() as i32, libc::SIGINT);
            }
        }
        let status = child.wait().map_err(|e| e.to_string())?;
        thread::sleep(Duration::from_millis(50)); // let the stderr reader drain
        let lines = r.stderr.lock().map(|v| v.clone()).unwrap_or_default();
        let packets = lines.iter().find_map(|l| l.strip_suffix(" packets captured").or_else(|| l.strip_suffix(" packet captured")).and_then(|n| n.trim().parse().ok()));
        match &r.out {
            Out::File(p) if p.exists() => Ok(Done {
                path: Some(p.clone()),
                bytes: std::fs::metadata(p).map(|m| m.len()).unwrap_or(0),
                packets: packets.or_else(|| count_pcap(p)),
            }),
            Out::Stdout if status.success() || packets.is_some() => Ok(Done { path: None, bytes: 0, packets }),
            _ => Err(friendly(lines.iter().rev().find(|l| !l.trim().is_empty() && !l.contains("listening on")).map(String::as_str).unwrap_or("tcpdump failed"))),
        }
    }
}

/// Run a whole capture, reporting progress through `emit` every 5 s.
pub fn run(spec: &Spec, out: Out, stop: Option<&std::sync::atomic::AtomicBool>, emit: &dyn Fn(Tone, String)) -> Result<Done, String> {
    let target = match &out {
        Out::File(p) => p.display().to_string(),
        Out::Stdout => "stdout".into(),
    };
    let limit = match (spec.secs, spec.count) {
        (Some(s), Some(c)) => format!("{s} s or {c} packets"),
        (Some(s), None) => format!("{s} s"),
        (None, Some(c)) => format!("{c} packets"),
        (None, None) => "until stopped".into(),
    };
    emit(Tone::Head, format!("capturing on {} · {limit} · {} → {target}", spec.iface, if spec.filter.is_empty() { "all traffic".to_string() } else { format!("filter: {}", spec.filter) }));
    let mut r = spawn(spec, out.clone())?;
    let mut last = Instant::now();
    while !poll(&mut r) && !stop.is_some_and(|s| s.load(std::sync::atomic::Ordering::Relaxed)) {
        thread::sleep(Duration::from_millis(200));
        if last.elapsed() >= Duration::from_secs(5) {
            last = Instant::now();
            let size = match &out {
                Out::File(p) => std::fs::metadata(p).map(|m| crate::util::fmt_bytes(m.len())).unwrap_or_default(),
                Out::Stdout => String::new(),
            };
            emit(Tone::Dim, format!("  {:>4} s  {size}", r.elapsed().as_secs()));
        }
    }
    let d = finish(r)?;
    let what = match (d.packets, d.bytes) {
        (Some(p), b) if b > 0 => format!("{p} packets · {}", crate::util::fmt_bytes(b)),
        (Some(p), _) => format!("{p} packets"),
        (None, b) => crate::util::fmt_bytes(b),
    };
    match &d.path {
        Some(p) => {
            emit(Tone::Good, format!("→ {what} saved to {}", p.display()));
            emit(Tone::Normal, format!("→ open it in Wireshark: {}", open_hint(p)));
            if d.packets == Some(0) {
                emit(Tone::Warn, "→ no packets matched: check the interface and the filter (tcpdump -D lists interfaces)".into());
            }
        }
        None => emit(Tone::Good, format!("→ {what}")),
    }
    Ok(d)
}

/// The command that opens a capture in Wireshark on this OS.
pub fn open_hint(p: &Path) -> String {
    if cfg!(target_os = "macos") {
        format!("open -a Wireshark {}", p.display())
    } else if cfg!(windows) {
        format!("start {}", p.display())
    } else {
        format!("wireshark {}", p.display())
    }
}

/// Open a capture in Wireshark (or the default app for .pcap).
pub fn open_in_wireshark(p: &Path) -> Result<(), String> {
    let r = if cfg!(target_os = "macos") {
        Command::new("open").arg("-a").arg("Wireshark").arg(p).status().or_else(|_| Command::new("open").arg(p).status())
    } else if cfg!(windows) {
        Command::new("cmd").args(["/C", "start", ""]).arg(p).status()
    } else {
        Command::new("wireshark").arg(p).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(|_| std::process::ExitStatus::default())
    };
    match r {
        Ok(s) if s.success() => Ok(()),
        Ok(_) => Err("could not open Wireshark (is it installed?)".into()),
        Err(e) => Err(format!("could not open Wireshark: {e}")),
    }
}

/// One-key capture of a connection (Sockets `C`): runs in the background
/// and reports through `CaptureState`.
pub fn start(state: Arc<Mutex<CaptureState>>, filter: String, secs: u64) -> Result<PathBuf, String> {
    if state.lock().map(|s| s.running.is_some()).unwrap_or(false) {
        return Err("a capture is already running".into());
    }
    let spec = Spec { iface: "any".into(), filter, secs: Some(secs.max(1)), count: None };
    let file = default_path(ext());
    let mut r = spawn(&spec, Out::File(file.clone()))?;
    if let Ok(mut s) = state.lock() {
        s.running = Some((file.clone(), Instant::now(), Duration::from_secs(secs.max(1))));
        s.version += 1;
    }
    thread::spawn(move || {
        while !poll(&mut r) {
            thread::sleep(Duration::from_millis(200));
        }
        let res = finish(r).and_then(|d| d.path.map(|p| (p, d.bytes)).ok_or_else(|| "no file written".to_string()));
        if let Ok(mut s) = state.lock() {
            s.running = None;
            s.last = Some(res);
            s.version += 1;
        }
    });
    Ok(file)
}

/// Interface names known to the OS (for parsing `[IFACE] …`).
pub fn interfaces() -> Vec<String> {
    sysinfo::Networks::new_with_refreshed_list().keys().cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters() {
        assert_eq!(bpf_filter("10.0.0.5:51000", "93.184.216.34:443").as_deref(), Some("host 93.184.216.34 and port 443"));
        assert_eq!(bpf_filter("[::1]:5432", "[::1]:40000").as_deref(), Some("host ::1 and port 40000"));
        assert_eq!(bpf_filter("*:22", "").as_deref(), Some("port 22"));
    }

    #[test]
    fn specs() {
        let ifs = vec!["en0".to_string(), "eth0".to_string()];
        assert_eq!(parse_spec("", &ifs, 20).unwrap(), Spec { iface: "any".into(), filter: String::new(), secs: Some(20), count: None });
        assert_eq!(parse_spec("eth0 30s port 443", &ifs, 20).unwrap(), Spec { iface: "eth0".into(), filter: "port 443".into(), secs: Some(30), count: None });
        assert_eq!(parse_spec("500p host 10.0.0.5 and port 53", &ifs, 20).unwrap(), Spec { iface: "any".into(), filter: "host 10.0.0.5 and port 53".into(), secs: None, count: Some(500) });
        // "port 22s" style words inside the filter stay part of the filter.
        assert_eq!(parse_spec("tcp port 80", &ifs, 5).unwrap().filter, "tcp port 80");
        assert_eq!(pktmon_filter("host 10.0.0.5 and port 443 and tcp").unwrap(), vec!["-i", "10.0.0.5", "-p", "443", "-t", "TCP"]);
        assert!(pktmon_filter("not port 22").is_err());
    }

    #[test]
    fn counts_pcap_records() {
        let dir = std::env::temp_dir().join(format!("vigil-pcap-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.pcap");
        let mut b = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        b.extend([0u8; 16]);
        for len in [60u32, 42] {
            b.extend([0u8; 8]);
            b.extend(len.to_le_bytes());
            b.extend(len.to_le_bytes());
            b.extend(vec![0u8; len as usize]);
        }
        std::fs::write(&p, &b).unwrap();
        assert_eq!(count_pcap(&p), Some(2));
        // pcapng: section header (28 bytes), interface block (20), two enhanced packet blocks (32 each).
        let mut g = Vec::new();
        g.extend(0x0a0d0d0au32.to_le_bytes());
        g.extend(28u32.to_le_bytes());
        g.extend(0x1a2b3c4du32.to_le_bytes());
        g.extend([1, 0, 0, 0]);
        g.extend([0xff; 8]);
        g.extend(28u32.to_le_bytes());
        g.extend(1u32.to_le_bytes());
        g.extend(20u32.to_le_bytes());
        g.extend([1, 0, 0, 0, 0, 0, 0, 0]);
        g.extend(20u32.to_le_bytes());
        for _ in 0..2 {
            g.extend(6u32.to_le_bytes());
            g.extend(32u32.to_le_bytes());
            g.extend([0u8; 20]);
            g.extend(32u32.to_le_bytes());
        }
        let q = dir.join("t.pcapng");
        std::fs::write(&q, &g).unwrap();
        assert_eq!(count_pcap(&q), Some(2));
        std::fs::remove_dir_all(&dir).ok();
    }
}
