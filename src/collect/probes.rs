//! Latency probes: a tiny SmokePing inside vigil.
//!
//! Targets (config `[network] probes = [...]`, or `a` in the Probes view):
//!   `icmp:1.1.1.1` / `1.1.1.1`   ICMP echo (unprivileged ping socket, raw as root)
//!   `tcp:db.internal:5432`       TCP connect time (a RST still proves reachability)
//!   `dns:github.com`             system resolver lookup time
//! Auto probes ping the default gateway(s) and DNS servers, so nothing leaves
//! your own network unless you add targets yourself.
//!
//! All probes of a round run in parallel threads; one round every interval.

use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::util::History;

const TIMEOUT: Duration = Duration::from_millis(1500);
const WINDOW: usize = 100;

#[derive(Clone, Debug, PartialEq)]
pub enum Target {
    Icmp(IpAddr),
    Tcp(String, u16),
    Dns(String),
}

impl Target {
    pub fn parse(s: &str) -> Option<Target> {
        let s = s.trim();
        if let Some(r) = s.strip_prefix("icmp:") {
            return r.parse().ok().map(Target::Icmp);
        }
        if let Some(r) = s.strip_prefix("dns:") {
            return (!r.is_empty()).then(|| Target::Dns(r.to_string()));
        }
        if let Some(r) = s.strip_prefix("tcp:") {
            let (h, p) = r.rsplit_once(':')?;
            return Some(Target::Tcp(h.trim_matches(['[', ']']).to_string(), p.parse().ok()?));
        }
        s.parse().ok().map(Target::Icmp)
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Target::Icmp(_) => "icmp",
            Target::Tcp(..) => "tcp",
            Target::Dns(_) => "dns",
        }
    }

    pub fn label(&self) -> String {
        match self {
            Target::Icmp(ip) => ip.to_string(),
            Target::Tcp(h, p) => format!("{h}:{p}"),
            Target::Dns(n) => n.clone(),
        }
    }

    pub fn spec(&self) -> String {
        format!("{}:{}", self.kind(), self.label())
    }
}

#[derive(Clone)]
pub struct Probe {
    pub name: String,
    pub target: Target,
    pub auto: bool,
    /// RTT in ms; NaN = lost.
    pub hist: History,
    recent: Vec<bool>,
    pub last_ms: Option<f64>,
    pub last_err: Option<String>,
}

impl Probe {
    fn new(name: String, target: Target, auto: bool) -> Self {
        Self {
            name,
            target,
            auto,
            hist: History::new(crate::collect::system::HISTORY),
            recent: Vec::new(),
            last_ms: None,
            last_err: None,
        }
    }

    pub fn loss_pct(&self) -> f64 {
        if self.recent.is_empty() {
            return 0.0;
        }
        self.recent.iter().filter(|ok| !**ok).count() as f64 / self.recent.len() as f64 * 100.0
    }

    pub fn sent(&self) -> usize {
        self.recent.len()
    }

    /// (min, avg, max, jitter) over the recent window, in ms.
    pub fn stats(&self) -> Option<(f64, f64, f64, f64)> {
        let v: Vec<f64> = self.hist.tail(WINDOW).into_iter().filter(|x| x.is_finite()).collect();
        if v.is_empty() {
            return None;
        }
        let min = v.iter().copied().fold(f64::INFINITY, f64::min);
        let max = v.iter().copied().fold(0.0, f64::max);
        let avg = v.iter().sum::<f64>() / v.len() as f64;
        let jitter = if v.len() > 1 {
            v.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (v.len() - 1) as f64
        } else {
            0.0
        };
        Some((min, avg, max, jitter))
    }

    fn record(&mut self, r: Result<f64, String>) {
        match r {
            Ok(ms) => {
                self.hist.push(ms);
                self.last_ms = Some(ms);
                self.last_err = None;
                self.recent.push(true);
            }
            Err(e) => {
                self.hist.push(f64::NAN);
                self.last_ms = None;
                self.last_err = Some(e);
                self.recent.push(false);
            }
        }
        if self.recent.len() > WINDOW {
            self.recent.remove(0);
        }
    }
}

#[derive(Default)]
pub struct ProbeStore {
    pub probes: Vec<Probe>,
    pub version: u64,
}

impl ProbeStore {
    pub fn add(&mut self, spec: &str) -> Result<(), String> {
        let t = Target::parse(spec).ok_or_else(|| format!("can't parse probe \"{spec}\": use icmp:IP, tcp:HOST:PORT or dns:NAME"))?;
        if self.probes.iter().any(|p| p.target == t) {
            return Err("probe already exists".into());
        }
        self.probes.push(Probe::new(t.label(), t, false));
        self.version += 1;
        Ok(())
    }

    pub fn remove(&mut self, i: usize) {
        if i < self.probes.len() {
            self.probes.remove(i);
            self.version += 1;
        }
    }

    /// Replace the auto probes (gateway / DNS servers) without touching user ones.
    pub fn set_auto(&mut self, targets: Vec<(String, Target)>) {
        let wanted: Vec<&Target> = targets.iter().map(|(_, t)| t).collect();
        self.probes.retain(|p| !p.auto || wanted.contains(&&p.target));
        for (name, t) in targets {
            if !self.probes.iter().any(|p| p.target == t) {
                self.probes.insert(0, Probe::new(name, t, true));
                self.version += 1;
            }
        }
    }

    pub fn user_specs(&self) -> Vec<String> {
        self.probes.iter().filter(|p| !p.auto).map(|p| p.target.spec()).collect()
    }
}

pub fn run_once(t: &Target) -> Result<f64, String> {
    let start = Instant::now();
    match t {
        Target::Tcp(host, port) => {
            let addr: SocketAddr = (host.as_str(), *port)
                .to_socket_addrs()
                .map_err(|e| format!("resolve: {e}"))?
                .next()
                .ok_or("no address")?;
            let t0 = Instant::now();
            match TcpStream::connect_timeout(&addr, TIMEOUT) {
                Ok(_) => Ok(t0.elapsed().as_secs_f64() * 1000.0),
                // A RST means the host answered: reachable, port closed.
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => Ok(t0.elapsed().as_secs_f64() * 1000.0),
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Err("timeout".into()),
                Err(e) => Err(e.to_string()),
            }
        }
        Target::Dns(name) => {
            (name.as_str(), 0).to_socket_addrs().map_err(|e| e.to_string())?;
            Ok(start.elapsed().as_secs_f64() * 1000.0)
        }
        Target::Icmp(ip) => icmp::ping(*ip, TIMEOUT),
    }
}

pub fn spawn_worker(
    store: Arc<Mutex<ProbeStore>>,
    netinfo: Arc<Mutex<super::netinfo::NetInfo>>,
    interval: Duration,
    auto: bool,
) {
    thread::spawn(move || {
        let mut seen_netinfo = u64::MAX;
        loop {
            let round = Instant::now();
            if auto {
                if let Ok(ni) = netinfo.lock() {
                    if ni.version != seen_netinfo {
                        seen_netinfo = ni.version;
                        let mut t: Vec<(String, Target)> = Vec::new();
                        for g in ni.default_gateways() {
                            if let Ok(ip) = g.split('%').next().unwrap_or(&g).parse::<IpAddr>() {
                                if !ip.is_loopback() && !(matches!(ip, IpAddr::V6(v) if v.segments()[0] & 0xffc0 == 0xfe80)) {
                                    t.push((format!("gateway {g}"), Target::Icmp(ip)));
                                }
                            }
                        }
                        for d in &ni.dns.servers {
                            if let Ok(ip) = d.split('%').next().unwrap_or(d).parse::<IpAddr>() {
                                if !ip.is_loopback() {
                                    t.push((format!("dns {d}"), Target::Icmp(ip)));
                                }
                            }
                        }
                        drop(ni);
                        if let Ok(mut s) = store.lock() {
                            s.set_auto(t);
                        }
                    }
                }
            }
            let targets: Vec<Target> = store.lock().map(|s| s.probes.iter().map(|p| p.target.clone()).collect()).unwrap_or_default();
            let handles: Vec<_> = targets
                .into_iter()
                .map(|t| thread::spawn(move || (run_once(&t), t)))
                .collect();
            let results: Vec<_> = handles.into_iter().filter_map(|h| h.join().ok()).collect();
            if let Ok(mut s) = store.lock() {
                for (r, t) in results {
                    if let Some(p) = s.probes.iter_mut().find(|p| p.target == t) {
                        p.record(r);
                    }
                }
                s.version += 1;
            }
            thread::sleep(interval.saturating_sub(round.elapsed()));
        }
    });
}

#[cfg(unix)]
mod icmp {
    use std::io;
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::time::{Duration, Instant};

    static SEQ: AtomicU16 = AtomicU16::new(1);

    fn checksum(b: &[u8]) -> u16 {
        let mut sum = 0u32;
        for c in b.chunks(2) {
            let w = if c.len() == 2 { u16::from_be_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], 0]) };
            sum += w as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    struct Fd(i32);
    impl Drop for Fd {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }

    fn open(v6: bool) -> io::Result<(Fd, bool)> {
        let (dom, proto) = if v6 { (libc::AF_INET6, libc::IPPROTO_ICMPV6) } else { (libc::AF_INET, libc::IPPROTO_ICMP) };
        // Unprivileged "ping socket" first, raw socket (root) second.
        for (ty, raw) in [(libc::SOCK_DGRAM, false), (libc::SOCK_RAW, true)] {
            let fd = unsafe { libc::socket(dom, ty, proto) };
            if fd >= 0 {
                return Ok((Fd(fd), raw));
            }
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ICMP not permitted: run as root or widen net.ipv4.ping_group_range (use tcp: probes otherwise)",
        ))
    }

    pub fn ping(ip: IpAddr, timeout: Duration) -> Result<f64, String> {
        let v6 = ip.is_ipv6();
        let (fd, raw) = open(v6).map_err(|e| e.to_string())?;
        let id = (std::process::id() & 0xffff) as u16;
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let mut pkt = vec![if v6 { 128 } else { 8 }, 0, 0, 0];
        pkt.extend_from_slice(&id.to_be_bytes());
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(b"vigil-probe-0123");
        if !v6 {
            let c = checksum(&pkt);
            pkt[2..4].copy_from_slice(&c.to_be_bytes());
        }

        let tv = libc::timeval { tv_sec: 0, tv_usec: 200_000 };
        unsafe {
            libc::setsockopt(fd.0, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as _);
        }

        let sent = unsafe {
            match ip {
                IpAddr::V4(a) => {
                    let mut sa: libc::sockaddr_in = std::mem::zeroed();
                    sa.sin_family = libc::AF_INET as _;
                    sa.sin_addr = libc::in_addr { s_addr: u32::from_ne_bytes(a.octets()) };
                    #[cfg(target_os = "macos")]
                    {
                        sa.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
                    }
                    libc::sendto(fd.0, pkt.as_ptr() as *const _, pkt.len(), 0, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as _)
                }
                IpAddr::V6(a) => {
                    let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
                    sa.sin6_family = libc::AF_INET6 as _;
                    sa.sin6_addr = libc::in6_addr { s6_addr: a.octets() };
                    #[cfg(target_os = "macos")]
                    {
                        sa.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
                    }
                    libc::sendto(fd.0, pkt.as_ptr() as *const _, pkt.len(), 0, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in6>() as _)
                }
            }
        };
        let t0 = Instant::now();
        if sent < 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        let mut buf = [0u8; 1500];
        while t0.elapsed() < timeout {
            let n = unsafe { libc::recv(fd.0, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
            if n <= 0 {
                continue; // 200 ms tick, try again until the deadline
            }
            let mut b = &buf[..n as usize];
            // IPv4 replies may carry the IP header (raw sockets, macOS ping sockets).
            if !v6 && b.len() >= 20 && b[0] >> 4 == 4 {
                let ihl = (b[0] & 0x0f) as usize * 4;
                if b.len() < ihl + 8 {
                    continue;
                }
                b = &b[ihl..];
            }
            if b.len() < 8 {
                continue;
            }
            let reply = if v6 { 129 } else { 0 };
            let rseq = u16::from_be_bytes([b[6], b[7]]);
            let rid = u16::from_be_bytes([b[4], b[5]]);
            // Ping sockets rewrite the id; raw sockets see everyone's replies.
            if b[0] == reply && rseq == seq && (!raw || rid == id) {
                return Ok(t0.elapsed().as_secs_f64() * 1000.0);
            }
        }
        Err("timeout".into())
    }
}

#[cfg(not(unix))]
mod icmp {
    pub fn ping(_ip: std::net::IpAddr, _t: std::time::Duration) -> Result<f64, String> {
        Err("ICMP not supported on this OS".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_targets() {
        assert_eq!(Target::parse("1.1.1.1"), Some(Target::Icmp("1.1.1.1".parse().unwrap())));
        assert_eq!(Target::parse("icmp:2606:4700::1111"), Some(Target::Icmp("2606:4700::1111".parse().unwrap())));
        assert_eq!(Target::parse("tcp:db.internal:5432"), Some(Target::Tcp("db.internal".into(), 5432)));
        assert_eq!(Target::parse("tcp:[::1]:22"), Some(Target::Tcp("::1".into(), 22)));
        assert_eq!(Target::parse("dns:github.com"), Some(Target::Dns("github.com".into())));
        assert_eq!(Target::parse("nonsense"), None);
    }

    #[test]
    fn tcp_probe_local() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let r = run_once(&Target::Tcp("127.0.0.1".into(), port));
        assert!(r.is_ok(), "{r:?}");
    }

    #[test]
    fn stats_and_loss() {
        let mut p = Probe::new("x".into(), Target::Dns("x".into()), false);
        p.record(Ok(10.0));
        p.record(Ok(20.0));
        p.record(Err("timeout".into()));
        assert!((p.loss_pct() - 33.33).abs() < 0.1);
        let (min, avg, max, jit) = p.stats().unwrap();
        assert_eq!((min, avg, max, jit), (10.0, 15.0, 20.0, 10.0));
    }

    #[test]
    fn icmp_loopback_or_permission_error() {
        // Either works, or fails with a clear message: never hangs or panics.
        match run_once(&Target::Icmp("127.0.0.1".parse().unwrap())) {
            Ok(ms) => assert!(ms < 1500.0),
            Err(e) => assert!(!e.is_empty()),
        }
    }
}
