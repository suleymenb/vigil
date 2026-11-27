//! Per-tick process and interface numbers on Linux, straight from /proc.
//!
//! sysinfo's Linux backend walks `/proc/<pid>/task` of every process on every
//! refresh and reads `stat`, `statm` and `io` for each *thread*; vigil lists
//! processes only and threw all of that away. A server with 300 processes and
//! 5 000 threads paid for 5 300 of everything, four times a second.
//!
//! This reads one file per process: `/proc/<pid>/stat` has the parent, state,
//! CPU time, start time, resident and virtual size. `/proc/<pid>/io` is read
//! with it where permitted, and the command line, executable and owner once
//! per new process. Interface counters come from the single `/proc/net/dev`.
//!
//! The parsers are plain functions over bytes, so they are tested on every
//! OS; the readers themselves only compile on Linux.

use super::system::{NetRaw, Raw};

/// PF_KTHREAD from <linux/sched.h>: the task is a kernel thread.
const PF_KTHREAD: u64 = 0x0020_0000;

fn status_str(state: u8) -> &'static str {
    match state {
        b'R' => "Running",
        b'S' => "Sleeping",
        b'I' => "Idle",
        b'T' => "Stopped",
        b'Z' => "Zombie",
        b't' => "Tracing",
        b'X' | b'x' => "Dead",
        b'K' => "Wakekill",
        b'W' => "Waking",
        b'P' => "Parked",
        b'D' => "Disk sleep",
        _ => "Unknown",
    }
}

/// One `/proc/<pid>/stat` line. `ns_per_tick` and `page` convert the kernel's
/// clock ticks and pages.
pub fn parse_stat(pid: u32, data: &[u8], ns_per_tick: u64, page: u64) -> Option<Raw> {
    // "pid (comm) S ppid …": the name may itself hold spaces and brackets, so
    // it ends at the last ')'.
    let open = data.iter().position(|b| *b == b'(')?;
    let close = data.iter().rposition(|b| *b == b')')?;
    let comm = data.get(open + 1..close)?;
    let mut it = data.get(close + 2..)?.split(|b| *b == b' ' || *b == b'\n');
    let state = *it.next()?.first()?;
    fn num(f: Option<&[u8]>) -> Option<u64> {
        std::str::from_utf8(f?).ok()?.parse::<i64>().ok().map(|v| v.max(0) as u64)
    }
    // Fields after the state, counted from 1: ppid 1, flags 6, utime 11,
    // stime 12, starttime 19, vsize 20, rss 21.
    let ppid = num(it.next())?;
    let flags = num(it.nth(4))?;
    let utime = num(it.nth(4))?;
    let stime = num(it.next())?;
    let start = num(it.nth(6))?;
    let virt = num(it.next())?;
    let rss = num(it.next())?;
    let mut r = Raw {
        pid,
        ppid: ppid as u32,
        uid: None,
        start,
        status: status_str(state),
        task: true,
        kernel: flags & PF_KTHREAD != 0,
        cpu_ns: (utime + stime).saturating_mul(ns_per_tick),
        rss: rss.saturating_mul(page),
        virt,
        ..Default::default()
    };
    r.set_name(comm);
    Some(r)
}

/// `read_bytes` and `write_bytes` of a `/proc/<pid>/io`: what actually went
/// to and came from storage.
pub fn parse_io(text: &[u8]) -> Option<(u64, u64)> {
    let (mut r, mut w) = (None, None);
    for l in text.split(|b| *b == b'\n') {
        let val = |p: &[u8]| l.strip_prefix(p).and_then(|v| std::str::from_utf8(v).ok()).and_then(|v| v.trim().parse::<u64>().ok());
        if let Some(v) = val(b"read_bytes:") {
            r = Some(v);
        } else if let Some(v) = val(b"write_bytes:") {
            w = Some(v);
        }
    }
    Some((r?, w?))
}

/// `/proc/net/dev`: one line per interface, sixteen counters each.
pub fn parse_net_dev(text: &str, out: &mut Vec<NetRaw>) {
    let mut n = 0;
    for l in text.lines().skip(2) {
        let Some((name, rest)) = l.split_once(':') else { continue };
        let mut f = rest.split_ascii_whitespace().map(|v| v.parse::<u64>().unwrap_or(0));
        // Receive: bytes packets errs drop fifo frame compressed multicast,
        // then transmit: bytes packets errs drop …
        let (Some(rx), _, Some(rx_errors), Some(rx_dropped)) = (f.next(), f.next(), f.next(), f.next()) else { continue };
        let (Some(tx), _, Some(tx_errors), Some(tx_dropped)) = (f.nth(4), f.next(), f.next(), f.next()) else { continue };
        let r = NetRaw::slot(out, n, name.trim());
        (r.rx, r.tx, r.rx_errors, r.tx_errors, r.rx_dropped, r.tx_dropped, r.mtu) = (rx, tx, rx_errors, tx_errors, rx_dropped, tx_dropped, 0);
        n += 1;
    }
    out.truncate(n);
}

/// Real uid from a `/proc/<pid>/status`.
pub fn parse_uid(status: &str) -> Option<u32> {
    status.lines().find_map(|l| l.strip_prefix("Uid:"))?.split_ascii_whitespace().next()?.parse().ok()
}

/// A `/proc/<pid>/cmdline` (arguments separated by NUL) as one line.
pub fn parse_cmdline(raw: &[u8]) -> String {
    let end = raw.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
    raw[..end].split(|b| *b == 0).map(String::from_utf8_lossy).collect::<Vec<_>>().join(" ")
}

#[cfg(target_os = "linux")]
pub use imp::*;

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use std::io::Read;
    use std::sync::OnceLock;

    /// (nanoseconds per clock tick, page size, clock ticks per second).
    fn units() -> (u64, u64, u64) {
        static U: OnceLock<(u64, u64, u64)> = OnceLock::new();
        *U.get_or_init(|| unsafe {
            let hz = libc::sysconf(libc::_SC_CLK_TCK).max(1) as u64;
            let page = libc::sysconf(libc::_SC_PAGESIZE).max(1) as u64;
            (1_000_000_000 / hz, page, hz)
        })
    }

    /// All pids, into a reused buffer.
    #[allow(clippy::unnecessary_cast)] // c_char is u8 on arm, i8 on x86
    pub fn list_pids(buf: &mut Vec<libc::pid_t>) {
        buf.clear();
        unsafe {
            let d = libc::opendir(c"/proc".as_ptr());
            if d.is_null() {
                return;
            }
            loop {
                let e = libc::readdir(d);
                if e.is_null() {
                    break;
                }
                // Process directories are all digits.
                let mut pid: i64 = 0;
                for c in (*e).d_name.iter() {
                    let c = *c as u8;
                    if c == 0 {
                        break;
                    }
                    if !c.is_ascii_digit() || pid > i32::MAX as i64 {
                        pid = -1;
                        break;
                    }
                    pid = pid * 10 + (c - b'0') as i64;
                }
                if pid > 0 && pid <= i32::MAX as i64 {
                    buf.push(pid as libc::pid_t);
                }
            }
            libc::closedir(d);
        }
    }

    /// "/proc/<pid>/<file>\0" without allocating.
    fn path(pid: u32, file: &[u8], out: &mut [u8; 48]) {
        let mut n = 0;
        let mut put = |b: &[u8]| {
            out[n..n + b.len()].copy_from_slice(b);
            n += b.len();
        };
        put(b"/proc/");
        let mut digits = [0u8; 10];
        let mut i = digits.len();
        let mut v = pid;
        loop {
            i -= 1;
            digits[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        put(&digits[i..]);
        put(b"/");
        put(&file[..file.len().min(24)]);
        put(&[0]);
    }

    /// One `read` of a small /proc file: these are generated whole on the
    /// first read, so a buffer that fits them needs no second call.
    fn read_small(pid: u32, file: &[u8], buf: &mut [u8]) -> Option<usize> {
        let mut p = [0u8; 48];
        path(pid, file, &mut p);
        unsafe {
            let fd = libc::open(p.as_ptr() as *const libc::c_char, libc::O_RDONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return None;
            }
            let n = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
            libc::close(fd);
            (n > 0).then_some(n as usize)
        }
    }

    /// One process, from its `stat`.
    pub fn read(pid: libc::pid_t) -> Option<Raw> {
        let mut buf = [0u8; 1024];
        let n = read_small(pid as u32, b"stat", &mut buf)?;
        let (ns_per_tick, page, _) = units();
        parse_stat(pid as u32, &buf[..n], ns_per_tick, page)
    }

    /// Cumulative disk bytes (read, written). Other users' processes refuse
    /// this without root.
    pub fn disk(pid: u32) -> Option<(u64, u64)> {
        let mut buf = [0u8; 512];
        let n = read_small(pid, b"io", &mut buf)?;
        parse_io(&buf[..n])
    }

    /// How long the process has run, from its start time and the uptime.
    pub fn run_time(start: u64, _now_s: u64, uptime_s: u64) -> u64 {
        uptime_s.saturating_sub(start / units().2)
    }

    pub struct Identity {
        pub uid: Option<u32>,
        pub cmd: String,
        pub exe: String,
    }

    /// Owner, command line and executable: read once per new process.
    pub fn identity(pid: u32) -> Identity {
        let base = format!("/proc/{pid}");
        let uid = std::fs::read_to_string(format!("{base}/status")).ok().and_then(|s| parse_uid(&s));
        let mut raw = Vec::new();
        if let Ok(f) = std::fs::File::open(format!("{base}/cmdline")) {
            // Command lines can be megabytes (xargs); the first 16 kB are plenty.
            let _ = f.take(16 * 1024).read_to_end(&mut raw);
        }
        let exe = std::fs::read_link(format!("{base}/exe")).map(|p| p.display().to_string()).unwrap_or_default();
        Identity { uid, cmd: parse_cmdline(&raw), exe }
    }

    /// What the interface reader keeps between ticks.
    #[derive(Default)]
    pub struct NetState {
        buf: Vec<u8>,
    }

    /// Counters of every interface: one read of `/proc/net/dev` instead of
    /// six files per interface under /sys.
    pub fn net(st: &mut NetState, _relist: bool, out: &mut Vec<NetRaw>) {
        st.buf.clear();
        let ok = std::fs::File::open("/proc/net/dev").and_then(|mut f| f.read_to_end(&mut st.buf)).is_ok();
        match std::str::from_utf8(&st.buf) {
            Ok(text) if ok => parse_net_dev(text, out),
            _ => out.clear(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn reads_own_process() {
            let mut pids = Vec::new();
            list_pids(&mut pids);
            let me = std::process::id();
            assert!(pids.contains(&(me as libc::pid_t)) && pids.contains(&1), "{} pids", pids.len());
            let r = read(me as libc::pid_t).expect("own process");
            assert!(r.task && !r.kernel && r.rss > 0 && r.virt >= r.rss, "rss {} virt {}", r.rss, r.virt);
            assert_eq!(r.ppid, unsafe { libc::getppid() } as u32);
            assert!(matches!(r.status, "Running" | "Sleeping"), "{}", r.status);
            // The test binary's name, cut at 15 bytes like every Linux comm.
            assert!(!r.name().is_empty() && r.name().len() <= 15);
            let id = identity(me);
            assert_eq!(id.uid, Some(unsafe { libc::getuid() }));
            assert!(id.exe.starts_with('/') && !id.cmd.is_empty(), "{} / {}", id.exe, id.cmd);
            assert!(disk(me).is_some());
            assert!(run_time(r.start, 0, sysinfo::System::uptime()) < 3600);
            // Burn a little CPU: the counter moves, in whole clock ticks.
            let t = std::time::Instant::now();
            let mut x = 0u64;
            while t.elapsed().as_millis() < 60 {
                x = x.wrapping_mul(31).wrapping_add(7);
            }
            std::hint::black_box(x);
            assert!(read(me as libc::pid_t).unwrap().cpu_ns > r.cpu_ns);
        }

        #[test]
        fn reads_interfaces() {
            let (mut st, mut out) = (NetState::default(), Vec::new());
            net(&mut st, false, &mut out);
            assert!(out.iter().any(|r| r.name == "lo"), "{out:?}");
            // Same list as /sys/class/net.
            let mut names: Vec<String> = out.iter().map(|r| r.name.clone()).collect();
            let mut sys: Vec<String> = std::fs::read_dir("/sys/class/net").map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
            if !sys.is_empty() {
                names.sort();
                sys.sort();
                assert_eq!(names, sys);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HZ_NS: u64 = 10_000_000;

    #[test]
    fn parses_stat() {
        let line = b"4242 (nginx) S 1 4242 4242 0 -1 4194560 1234 0 2 0 150 50 0 0 20 0 5 0 987654 123456789 2500 18446744073709551615 1 1 0 0 0 0 0 4096 0 0 0 0 17 3 0 0 0 0 0\n";
        let r = parse_stat(4242, line, HZ_NS, 4096).unwrap();
        assert_eq!((r.pid, r.ppid, r.start, r.virt, r.rss), (4242, 1, 987654, 123456789, 2500 * 4096));
        assert_eq!(r.cpu_ns, 200 * HZ_NS);
        assert_eq!((r.name(), r.status, r.kernel, r.task), (&b"nginx"[..], "Sleeping", false, true));
    }

    #[test]
    fn name_may_hold_spaces_and_brackets() {
        let line = b"77 (tmux: server (1) x) R 1 77 77 0 -1 0 0 0 0 0 1 2 0 0 20 0 1 0 5 10 20 0\n";
        let r = parse_stat(77, line, HZ_NS, 4096).unwrap();
        assert_eq!(std::str::from_utf8(r.name()).unwrap(), "tmux: server (1) x");
        assert_eq!((r.status, r.ppid, r.cpu_ns, r.start), ("Running", 1, 3 * HZ_NS, 5));
    }

    #[test]
    fn recognises_kernel_threads_and_zombies() {
        let k = parse_stat(2, b"2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 3 0 0 20 0 1 0 2 0 0 18446744073709551615\n", HZ_NS, 4096).unwrap();
        assert!(k.kernel && k.rss == 0);
        let z = parse_stat(9, b"9 (sh) Z 5 9 9 0 -1 4228100 0 0 0 0 0 0 0 0 20 0 1 0 77 0 0 0\n", HZ_NS, 4096).unwrap();
        assert_eq!((z.status, z.kernel), ("Zombie", false));
        assert!(parse_stat(1, b"garbage", HZ_NS, 4096).is_none());
        assert!(parse_stat(1, b"1 (x) S 1 2", HZ_NS, 4096).is_none());
    }

    #[test]
    fn parses_io_and_identity() {
        let io = b"rchar: 100\nwchar: 200\nsyscr: 1\nsyscw: 2\nread_bytes: 4096\nwrite_bytes: 8192\ncancelled_write_bytes: 0\n";
        assert_eq!(parse_io(io), Some((4096, 8192)));
        assert_eq!(parse_io(b"rchar: 1\n"), None);
        assert_eq!(parse_uid("Name:\tsshd\nUid:\t1000\t0\t0\t0\nGid:\t100\t100\n"), Some(1000));
        assert_eq!(parse_cmdline(b"nginx\0-g\0daemon off;\0"), "nginx -g daemon off;");
        assert_eq!(parse_cmdline(b""), "");
        assert_eq!(parse_cmdline(b"sshd: user@pts/0\0\0\0"), "sshd: user@pts/0");
    }

    #[test]
    fn parses_net_dev() {
        let text = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo: 1000      10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0\n  eth0:98765432  5000    3    7    0     0          0        12 12345678    4000    1    2    0     0       0          0\nveth1a2b3c: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16\n";
        let mut out = vec![NetRaw { name: "stale".into(), ..Default::default() }; 5];
        parse_net_dev(text, &mut out);
        assert_eq!(out.len(), 3);
        assert_eq!((out[0].name.as_str(), out[0].rx, out[0].tx), ("lo", 1000, 1000));
        let e = &out[1];
        assert_eq!((e.name.as_str(), e.rx, e.rx_errors, e.rx_dropped, e.tx, e.tx_errors, e.tx_dropped), ("eth0", 98765432, 3, 7, 12345678, 1, 2));
        assert_eq!((out[2].rx, out[2].rx_errors, out[2].rx_dropped, out[2].tx, out[2].tx_errors, out[2].tx_dropped), (1, 3, 4, 9, 11, 12));
    }
}
