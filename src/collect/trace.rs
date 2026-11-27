//! Path analysis for a probe target: latency and loss per hop.
//!
//! Uses `mtr --json` when installed (loss per hop over several cycles),
//! otherwise `traceroute -n`. ICMP by default; TCP (to a port) or UDP get
//! through firewalls that drop ICMP and show where a service's traffic
//! really stops. Runs on demand (`t` in the Probes view, `vigil trace`).

use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;

/// Which packets probe the path.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum Mode {
    #[default]
    Icmp,
    Udp,
    Tcp(u16),
}

impl Mode {
    pub fn label(self) -> String {
        match self {
            Mode::Icmp => "icmp".into(),
            Mode::Udp => "udp".into(),
            Mode::Tcp(p) => format!("tcp/{p}"),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Hop {
    pub n: u32,
    /// "???" / "*" when the hop didn't answer.
    pub host: String,
    pub loss_pct: f64,
    pub sent: u32,
    pub last: f64,
    pub avg: f64,
    pub best: f64,
    pub worst: f64,
}

#[derive(Clone, Debug, Default)]
pub struct TraceResult {
    pub target: String,
    pub mode: Mode,
    pub tool: &'static str,
    pub hops: Vec<Hop>,
    pub error: Option<String>,
    pub running: bool,
}

#[derive(Default)]
pub struct TraceStore {
    pub current: Option<TraceResult>,
    pub version: u64,
}

pub fn parse_mtr_json(text: &str) -> Vec<Hop> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else { return Vec::new() };
    let hubs = v.pointer("/report/hubs").and_then(|h| h.as_array()).cloned().unwrap_or_default();
    let f = |h: &serde_json::Value, k: &str| h.get(k).and_then(|x| x.as_f64()).unwrap_or(0.0);
    hubs.iter()
        .map(|h| Hop {
            n: h.get("count").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
            host: h.get("host").and_then(|x| x.as_str()).unwrap_or("???").to_string(),
            loss_pct: f(h, "Loss%"),
            sent: f(h, "Snt") as u32,
            last: f(h, "Last"),
            avg: f(h, "Avg"),
            best: f(h, "Best"),
            worst: f(h, "Wrst"),
        })
        .collect()
}

/// `traceroute -n -q 3` output: ` 3  10.1.1.1  1.2 ms  1.1 ms *`.
pub fn parse_traceroute(text: &str) -> Vec<Hop> {
    let mut hops = Vec::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        let Some(n) = f.first().and_then(|x| x.parse::<u32>().ok()) else { continue };
        let mut host = String::from("*");
        let mut times = Vec::new();
        let mut stars = 0u32;
        let mut i = 1;
        while i < f.len() {
            match f[i] {
                "*" => stars += 1,
                "ms" => {}
                t => {
                    if let Ok(ms) = t.parse::<f64>() {
                        times.push(ms);
                    } else if host == "*" && !t.starts_with('!') && !t.starts_with('(') {
                        host = t.to_string();
                    }
                }
            }
            i += 1;
        }
        let sent = times.len() as u32 + stars;
        let avg = if times.is_empty() { 0.0 } else { times.iter().sum::<f64>() / times.len() as f64 };
        hops.push(Hop {
            n,
            host,
            loss_pct: if sent == 0 { 100.0 } else { stars as f64 / sent as f64 * 100.0 },
            sent,
            last: times.last().copied().unwrap_or(0.0),
            avg,
            best: times.iter().copied().fold(f64::INFINITY, f64::min).min(if times.is_empty() { 0.0 } else { f64::INFINITY }),
            worst: times.iter().copied().fold(0.0, f64::max),
        });
    }
    hops
}

/// mtr / traceroute arguments for a mode (Linux and macOS spell TCP differently).
pub fn args(tool: &str, mode: Mode, target: &str) -> Vec<String> {
    let mut a: Vec<String> = match tool {
        "mtr" => vec!["-n".into(), "--json".into(), "-c".into(), "5".into(), "-r".into()],
        _ => vec!["-n".into(), "-q".into(), "3".into(), "-w".into(), "1".into(), "-m".into(), "30".into()],
    };
    match (tool, mode) {
        ("mtr", Mode::Tcp(p)) => a.extend(["--tcp".into(), "-P".into(), p.to_string()]),
        ("mtr", Mode::Udp) => a.push("--udp".into()),
        (_, Mode::Tcp(p)) if cfg!(target_os = "macos") => a.extend(["-P".into(), "tcp".into(), "-p".into(), p.to_string()]),
        (_, Mode::Tcp(p)) => a.extend(["-T".into(), "-p".into(), p.to_string()]),
        // traceroute's own default (UDP) works without root; mtr's default is ICMP.
        _ => {}
    }
    a.push(target.to_string());
    a
}

fn run(target: &str, mode: Mode) -> (&'static str, Result<Vec<Hop>, String>) {
    if cfg!(windows) && mode != Mode::Icmp {
        return ("tracert", Err("Windows tracert traces with ICMP only; for TCP use WSL or pathping".into()));
    }
    if cfg!(windows) {
        return match Command::new("tracert").args(["-d", "-h", "30", "-w", "1000", target]).output() {
            Ok(o) => {
                let hops = super::windows::parse_tracert(&String::from_utf8_lossy(&o.stdout));
                if hops.is_empty() {
                    ("tracert", Err(String::from_utf8_lossy(&o.stdout).lines().find(|l| !l.trim().is_empty()).unwrap_or("tracert failed").trim().to_string()))
                } else {
                    ("tracert", Ok(hops))
                }
            }
            Err(e) => ("tracert", Err(format!("tracert: {e}"))),
        };
    }
    let tools = &crate::platform::get().tools;
    if !tools.mtr && !tools.traceroute {
        return ("-", Err("install mtr or traceroute to trace the path".into()));
    }
    let mtr = if tools.mtr { Command::new("mtr").args(args("mtr", mode, target)).output().ok() } else { None };
    if let Some(o) = mtr {
        if o.status.success() {
            let hops = parse_mtr_json(&String::from_utf8_lossy(&o.stdout));
            if !hops.is_empty() {
                return ("mtr", Ok(hops));
            }
        }
    }
    match Command::new("traceroute").args(args("traceroute", mode, target)).output() {
        Ok(o) => {
            let hops = parse_traceroute(&String::from_utf8_lossy(&o.stdout));
            if hops.is_empty() {
                let e = String::from_utf8_lossy(&o.stderr);
                let last = e.lines().last().unwrap_or("traceroute failed").to_string();
                let needs_root = mode != Mode::Udp && (last.contains("permission") || last.contains("Operation not permitted") || last.contains("root"));
                ("traceroute", Err(if needs_root { format!("{last} ({} traceroute needs root: run with sudo)", mode.label()) } else { last }))
            } else {
                ("traceroute", Ok(hops))
            }
        }
        Err(_) => ("-", Err("install mtr or traceroute to trace the path".into())),
    }
}

/// Trace and print (for `vigil trace`).
pub fn report(target: &str, mode: Mode, emit: &dyn Fn(crate::tools::Tone, String)) -> bool {
    use crate::tools::Tone;
    emit(Tone::Head, format!("path to {target} · {}", mode.label()));
    let (tool, res) = run(target, mode);
    match res {
        Ok(hops) => {
            emit(Tone::Dim, format!("  {:>3}  {:<40} {:>6} {:>5} {:>8} {:>8} {:>8}   ({tool})", "HOP", "HOST", "LOSS%", "SENT", "AVG ms", "BEST", "WORST"));
            let last = hops.len();
            for (i, h) in hops.iter().enumerate() {
                let tone = if h.loss_pct >= 100.0 { Tone::Dim } else if h.loss_pct > 0.0 && i + 1 < last && hops[i + 1..].iter().all(|x| x.loss_pct > 0.0) { Tone::Bad } else { Tone::Normal };
                emit(tone, format!("  {:>3}  {:<40} {:>5.0}% {:>5} {:>8.1} {:>8.1} {:>8.1}", h.n, crate::util::truncate(&h.host, 40), h.loss_pct, h.sent, h.avg, h.best, h.worst));
            }
            if let Some(stop) = hops.iter().rposition(|h| h.loss_pct < 100.0) {
                if stop + 1 < hops.len() {
                    emit(Tone::Warn, format!("→ no answers after hop {} ({}): {}", hops[stop].n, hops[stop].host, if mode == Mode::Icmp { "ICMP filtered from there on; try --tcp 443" } else { "the path or a firewall stops this traffic there" }));
                }
            }
            true
        }
        Err(e) => {
            emit(Tone::Bad, e);
            false
        }
    }
}

pub fn start(store: Arc<Mutex<TraceStore>>, target: String, mode: Mode) {
    if let Ok(mut s) = store.lock() {
        if s.current.as_ref().is_some_and(|c| c.running) {
            return;
        }
        s.current = Some(TraceResult { target: target.clone(), mode, running: true, ..Default::default() });
        s.version += 1;
    }
    thread::spawn(move || {
        let (tool, res) = run(&target, mode);
        if let Ok(mut s) = store.lock() {
            let (hops, error) = match res {
                Ok(h) => (h, None),
                Err(e) => (Vec::new(), Some(e)),
            };
            s.current = Some(TraceResult { target, mode, tool, hops, error, running: false });
            s.version += 1;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtr_json() {
        let t = r#"{"report":{"mtr":{"dst":"1.1.1.1"},"hubs":[{"count":1,"host":"10.0.0.1","Loss%":0.0,"Snt":5,"Last":0.5,"Avg":0.6,"Best":0.4,"Wrst":0.9,"StDev":0.1},{"count":2,"host":"???","Loss%":100.0,"Snt":5,"Last":0.0,"Avg":0.0,"Best":0.0,"Wrst":0.0,"StDev":0.0}]}}"#;
        let h = parse_mtr_json(t);
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].host, "10.0.0.1");
        assert_eq!(h[1].loss_pct, 100.0);
    }

    #[test]
    fn mode_arguments() {
        assert!(args("mtr", Mode::Tcp(443), "1.1.1.1").windows(3).any(|w| w == ["--tcp", "-P", "443"]));
        let t = args("traceroute", Mode::Tcp(443), "1.1.1.1");
        if cfg!(target_os = "macos") {
            assert!(t.windows(2).any(|w| w == ["-P", "tcp"]));
        } else {
            assert!(t.contains(&"-T".to_string()));
        }
        assert_eq!(args("traceroute", Mode::Udp, "h").last().unwrap(), "h");
    }

    #[test]
    fn traceroute_text() {
        let t = "traceroute to 1.1.1.1 (1.1.1.1), 30 hops max, 60 byte packets\n 1  10.0.0.1  0.512 ms  0.401 ms  0.389 ms\n 2  * * *\n 3  100.64.0.1  4.1 ms *  4.3 ms\n";
        let h = parse_traceroute(t);
        assert_eq!(h.len(), 3);
        assert_eq!(h[0].host, "10.0.0.1");
        assert!((h[0].avg - 0.434).abs() < 0.01);
        assert_eq!(h[1].loss_pct, 100.0);
        assert_eq!(h[1].host, "*");
        assert!((h[2].loss_pct - 33.3).abs() < 0.1);
        assert_eq!(h[2].best, 4.1);
    }
}
