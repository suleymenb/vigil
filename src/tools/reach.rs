//! `vigil reach HOST PORTS`: is a TCP port open, refused or filtered from here?
//!
//! The question behind half of all firewall tickets. A TCP connect tells the
//! three apart: *open* (handshake completed), *refused* (a RST came back:
//! the host is reachable, nothing listens or a firewall REJECTs) and
//! *filtered* (no answer at all: a firewall DROPs it, or the host is down).
//! Only the host and ports you name are tried, at most 1024 per run.

use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use super::Tone;

pub const MAX_PORTS: usize = 1024;

/// Connect timeout. Windows retries a refused SYN for about 2 s before it
/// reports "refused", so a shorter timeout would call closed ports filtered.
pub fn default_timeout() -> Duration {
    Duration::from_millis(if cfg!(windows) { 3000 } else { 1500 })
}

#[derive(Clone, Debug, PartialEq)]
pub enum State {
    Open(f64),
    Refused(f64),
    Filtered,
    Error(String),
}

/// Well-known names, so you can type `ssh,https,rdp`.
const NAMES: [(&str, u16); 26] = [
    ("ftp", 21), ("ssh", 22), ("telnet", 23), ("smtp", 25), ("dns", 53), ("http", 80), ("kerberos", 88), ("pop3", 110), ("ntp", 123),
    ("netbios", 139), ("imap", 143), ("snmp", 161), ("ldap", 389), ("https", 443), ("smb", 445), ("submission", 587), ("ldaps", 636),
    ("imaps", 993), ("mssql", 1433), ("oracle", 1521), ("mysql", 3306), ("rdp", 3389), ("postgres", 5432), ("winrm", 5985), ("redis", 6379),
    ("netconf", 830),
];

/// `22,80,443,8000-8010,https,rdp` → ports (deduplicated, in order).
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut out: Vec<u16> = Vec::new();
    for part in spec.split([',', ' ']).map(str::trim).filter(|p| !p.is_empty()) {
        let p = part.trim_start_matches("tcp/").to_ascii_lowercase();
        if let Some((a, b)) = p.split_once('-') {
            let (a, b): (u16, u16) = (a.parse().map_err(|_| format!("bad port: {a}"))?, b.parse().map_err(|_| format!("bad port: {b}"))?);
            if a == 0 || b < a {
                return Err(format!("bad range: {part}"));
            }
            if (b - a) as usize + 1 + out.len() > MAX_PORTS {
                return Err(format!("at most {MAX_PORTS} ports per run"));
            }
            out.extend(a..=b);
        } else if let Ok(n) = p.parse::<u16>() {
            if n == 0 {
                return Err("port 0 is not valid".into());
            }
            out.push(n);
        } else if let Some((_, n)) = NAMES.iter().find(|(name, _)| *name == p) {
            out.push(*n);
        } else {
            return Err(format!("unknown port or service: {part}"));
        }
    }
    let mut seen = std::collections::HashSet::new();
    out.retain(|p| seen.insert(*p));
    if out.is_empty() {
        return Err("give ports, e.g. 22,443,3389 or 8000-8010 or ssh,https".into());
    }
    if out.len() > MAX_PORTS {
        return Err(format!("at most {MAX_PORTS} ports per run"));
    }
    Ok(out)
}

fn try_port(addr: SocketAddr, timeout: Duration) -> State {
    let t0 = Instant::now();
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => State::Open(t0.elapsed().as_secs_f64() * 1000.0),
        Err(e) => match e.kind() {
            std::io::ErrorKind::ConnectionRefused => State::Refused(t0.elapsed().as_secs_f64() * 1000.0),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => State::Filtered,
            _ => {
                let s = e.to_string();
                if s.to_ascii_lowercase().contains("timed out") {
                    State::Filtered
                } else {
                    State::Error(s)
                }
            }
        },
    }
}

fn name_of(port: u16) -> String {
    crate::collect::ipinfo::service(port, false)
        .map(String::from)
        .or_else(|| NAMES.iter().find(|(_, p)| *p == port).map(|(n, _)| n.to_string()))
        .unwrap_or_default()
}

/// Check `ports` on `host` in parallel and report each one.
pub fn run(host: &str, ports: &[u16], timeout: Duration, emit: &dyn Fn(Tone, String)) -> Result<Vec<(u16, State)>, String> {
    let ip: IpAddr = match host.parse() {
        Ok(ip) => ip,
        Err(_) => (host, 0).to_socket_addrs().map_err(|e| format!("{host}: {e}"))?.next().ok_or_else(|| format!("{host}: no address"))?.ip(),
    };
    emit(Tone::Head, format!("TCP reachability of {host}{} · {} port(s) · timeout {} ms", if host != ip.to_string() { format!(" ({ip})") } else { String::new() }, ports.len(), timeout.as_millis()));
    let (tx, rx) = mpsc::channel();
    let workers = ports.len().min(64);
    let chunks: Vec<Vec<u16>> = (0..workers).map(|w| ports.iter().copied().skip(w).step_by(workers).collect()).collect();
    for chunk in chunks {
        let tx = tx.clone();
        thread::spawn(move || {
            for p in chunk {
                let _ = tx.send((p, try_port(SocketAddr::new(ip, p), timeout)));
            }
        });
    }
    drop(tx);
    let mut results: Vec<(u16, State)> = rx.into_iter().collect();
    results.sort_by_key(|(p, s)| (!matches!(s, State::Open(_)), *p));
    let quiet = ports.len() > 20; // long lists: show open ports and a summary only
    for (p, st) in &results {
        let name = name_of(*p);
        let label = format!("  {:>5}/tcp {:<12}", p, if name.is_empty() { String::new() } else { format!("({name})") });
        match st {
            State::Open(ms) => emit(Tone::Good, format!("{label} open      {ms:.1} ms")),
            State::Refused(ms) if !quiet => emit(Tone::Warn, format!("{label} refused   {ms:.1} ms: the host answers; nothing listens, or a firewall REJECTs")),
            State::Filtered if !quiet => emit(Tone::Bad, format!("{label} filtered  no answer: a firewall DROPs it, or the host is down")),
            State::Error(e) if !quiet => emit(Tone::Bad, format!("{label} {e}")),
            _ => {}
        }
    }
    let count = |f: fn(&State) -> bool| results.iter().filter(|(_, s)| f(s)).count();
    let (open, refused, filtered) = (count(|s| matches!(s, State::Open(_))), count(|s| matches!(s, State::Refused(_))), count(|s| matches!(s, State::Filtered)));
    emit(Tone::Head, format!("{open} open · {refused} refused · {filtered} filtered"));
    if open == 0 && refused == 0 && filtered == results.len() {
        emit(Tone::Warn, "→ nothing answered at all: the host is down or unreachable, or a firewall drops everything from here (check with W, d or vigil doctor)".into());
    } else if filtered > 0 && (open > 0 || refused > 0) {
        emit(Tone::Normal, "→ the host is reachable, so the filtered ports are blocked by a firewall on the way or on the host (Junos: show security policies hit-count · Cisco: show access-lists)".into());
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports() {
        assert_eq!(parse_ports("22,443, 8000-8002,https,rdp").unwrap(), vec![22, 443, 8000, 8001, 8002, 3389]);
        assert!(parse_ports("1-2000").is_err());
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("gopher").is_err());
        assert!(parse_ports("").is_err());
    }

    #[test]
    fn open_and_refused_on_loopback() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = l.local_addr().unwrap().port();
        // A port that was free a moment ago is almost certainly closed now.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let res = run("127.0.0.1", &[open, closed], default_timeout(), &|_, _| {}).unwrap();
        assert!(matches!(res[0], (p, State::Open(_)) if p == open), "{res:?}");
        assert!(matches!(res[1], (p, State::Refused(_)) if p == closed), "{res:?}");
    }
}
