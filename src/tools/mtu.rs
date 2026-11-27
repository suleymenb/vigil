//! Path MTU discovery: binary search with "don't fragment" pings.
//!
//! Uses the system `ping` because setting DF on unprivileged ICMP sockets is
//! not portable: Linux `ping -M do -s N`, macOS `ping -D -s N`, Windows
//! `ping -f -l N`. About ten probes; a "fragmentation needed" reply with an
//! MTU in it short-cuts the search.

use std::net::{IpAddr, ToSocketAddrs};
use std::process::Command;

use super::Tone;

#[derive(Clone, Debug, PartialEq)]
pub enum Probe {
    Ok,
    /// "Frag needed and DF set", optionally with the next-hop MTU.
    FragNeeded(Option<u32>),
    /// The local interface refused (message too long).
    TooBigLocal(Option<u32>),
    Lost,
}

fn digits_after(s: &str, key: &str) -> Option<u32> {
    let i = s.find(key)? + key.len();
    let rest: String = s[i..].chars().skip_while(|c| !c.is_ascii_digit()).take_while(|c| c.is_ascii_digit()).collect();
    rest.parse().ok()
}

/// Interpret one `ping` run (any OS, any language where it matters).
pub fn classify(out: &str) -> Probe {
    let low = out.to_ascii_lowercase();
    if low.contains("frag needed") || low.contains("fragmentation needed") || low.contains("needs to be fragmented") {
        return Probe::FragNeeded(digits_after(&low, "mtu"));
    }
    if low.contains("message too long") || low.contains("local error") {
        return Probe::TooBigLocal(digits_after(&low, "mtu"));
    }
    if cfg!(windows) {
        // Reply lines carry "TTL=" in every language; error lines don't.
        if out.lines().any(|l| l.contains("TTL=") && super::super::collect::windows::parse_ping_ms(l).is_some()) {
            return Probe::Ok;
        }
        return Probe::Lost;
    }
    if low.contains("bytes from") && !low.contains(" 0 received") && !low.contains(" 0 packets received") {
        Probe::Ok
    } else {
        Probe::Lost
    }
}

fn ping_df(ip: IpAddr, payload: u32) -> Probe {
    let size = payload.to_string();
    let target = ip.to_string();
    let mut c = Command::new("ping");
    if cfg!(windows) {
        c.args(["-f", "-l", &size, "-n", "1", "-w", "1000", &target]);
    } else if cfg!(target_os = "macos") {
        c.args(["-D", "-s", &size, "-c", "1", "-t", "1", &target]);
    } else if ip.is_ipv6() {
        c.args(["-6", "-M", "do", "-s", &size, "-c", "1", "-W", "1", "-n", &target]);
    } else {
        c.args(["-M", "do", "-s", &size, "-c", "1", "-W", "1", "-n", &target]);
    }
    match c.output() {
        Ok(o) => {
            let mut t = String::from_utf8_lossy(&o.stdout).into_owned();
            t.push_str(&String::from_utf8_lossy(&o.stderr));
            classify(&t)
        }
        Err(_) => Probe::Lost,
    }
}

/// MTU of the interface the route to `ip` leaves through (upper bound).
fn local_mtu(ip: IpAddr) -> Option<u32> {
    let out = |cmd: &str, args: &[&str]| Command::new(cmd).args(args).output().ok().map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
    if cfg!(target_os = "linux") {
        let r = out("ip", &["-o", "route", "get", &ip.to_string()])?;
        let dev = r.split_whitespace().skip_while(|w| *w != "dev").nth(1)?;
        std::fs::read_to_string(format!("/sys/class/net/{dev}/mtu")).ok()?.trim().parse().ok()
    } else if cfg!(target_os = "macos") {
        let r = out("route", &["-n", "get", &ip.to_string()])?;
        let mut lines = r.lines().rev();
        let vals = lines.next()?;
        let head = lines.next()?;
        let idx = head.split_whitespace().position(|w| w == "mtu")?;
        vals.split_whitespace().nth(idx)?.parse().ok()
    } else {
        None
    }
}

/// What a given path MTU usually means.
pub fn explain(mtu: u32) -> &'static str {
    match mtu {
        9000.. => "jumbo frames end to end",
        1500 => "standard Ethernet: no tunnel or encapsulation on the path",
        1492 => "PPPoE (DSL/fibre access): 8 bytes of PPPoE header",
        1480 => "IP-in-IP / 6in4 tunnel (20 bytes)",
        1476 => "GRE tunnel (24 bytes)",
        1450 => "VXLAN overlay (50 bytes), e.g. Kubernetes or cloud networks",
        1420 => "WireGuard (60/80 bytes)",
        1360..=1440 => "IPsec / VPN tunnel overhead",
        1280 => "IPv6 minimum MTU: something on the path clamps hard",
        _ if mtu < 1280 => "very small: a misconfigured tunnel or a broken middlebox",
        _ => "reduced by encapsulation somewhere on the path",
    }
}

pub struct Result {
    pub path_mtu: Option<u32>,
    pub local_mtu: Option<u32>,
    pub black_hole: bool,
}

/// Discover the path MTU to `target` (host name or IP).
pub fn discover(target: &str, emit: &dyn Fn(Tone, String)) -> Result {
    let ip: IpAddr = match target.parse() {
        Ok(ip) => ip,
        Err(_) => match (target, 0).to_socket_addrs().ok().and_then(|mut a| a.find(|x| x.is_ipv4()).or_else(|| (target, 0).to_socket_addrs().ok()?.next())) {
            Some(a) => a.ip(),
            None => {
                emit(Tone::Bad, format!("cannot resolve {target}"));
                return Result { path_mtu: None, local_mtu: None, black_hole: false };
            }
        },
    };
    let overhead = if ip.is_ipv6() { 48 } else { 28 };
    if ip.is_ipv6() && !cfg!(target_os = "linux") {
        emit(Tone::Warn, "IPv6 path MTU discovery needs Linux ping (-M do); routers never fragment IPv6, so a Packet Too Big filter is the usual culprit".into());
        return Result { path_mtu: None, local_mtu: None, black_hole: false };
    }
    let local = local_mtu(ip);
    emit(Tone::Head, format!("path MTU to {ip}{}", local.map(|m| format!(" · interface MTU {m}")).unwrap_or_default()));
    if ping_df(ip, 56) != Probe::Ok && ping_df(ip, 56) != Probe::Ok {
        emit(Tone::Bad, format!("{ip} does not answer ping: ICMP is filtered or the host is down (try another target)"));
        return Result { path_mtu: None, local_mtu: local, black_hole: false };
    }
    let mut lo = 56u32; // known good payload
    let mut hi = local.unwrap_or(1500).saturating_sub(overhead) + 1; // first known (or assumed) bad
    let mut frag_seen = false;
    // Try the full size first: most paths are clean.
    let probe = |size: u32, emit: &dyn Fn(Tone, String)| -> Probe {
        let mut r = ping_df(ip, size);
        if r == Probe::Lost {
            r = ping_df(ip, size); // a single loss is not proof of "too big"
        }
        let tone = if r == Probe::Ok { Tone::Good } else { Tone::Dim };
        let what = match &r {
            Probe::Ok => "passes".to_string(),
            Probe::FragNeeded(Some(m)) => format!("too big: a router reports next-hop MTU {m}"),
            Probe::FragNeeded(None) => "too big: fragmentation needed".to_string(),
            Probe::TooBigLocal(_) => "too big for the local interface".to_string(),
            Probe::Lost => "no reply".to_string(),
        };
        emit(tone, format!("  {:>5} bytes  {what}", size + overhead));
        r
    };
    while hi - lo > 1 {
        let mid = if lo == 56 && hi > 1000 { hi - 1 } else { (lo + hi) / 2 };
        match probe(mid, emit) {
            Probe::Ok => lo = mid,
            Probe::FragNeeded(Some(m)) if m > overhead && m - overhead < hi => {
                frag_seen = true;
                hi = mid;
                let cand = m - overhead;
                if cand > lo && probe(cand, emit) == Probe::Ok {
                    lo = cand;
                    hi = hi.min(cand + 1);
                }
            }
            Probe::FragNeeded(_) | Probe::TooBigLocal(_) => {
                frag_seen = true;
                hi = mid;
            }
            Probe::Lost => hi = mid,
        }
    }
    let mtu = lo + overhead;
    let black_hole = !frag_seen && mtu < local.unwrap_or(1500);
    let mss = mtu.saturating_sub(if ip.is_ipv6() { 60 } else { 40 });
    emit(Tone::Head, format!("path MTU {mtu} · TCP MSS {mss} · {}", explain(mtu)));
    if black_hole {
        emit(
            Tone::Warn,
            "→ larger packets vanish without an ICMP \"fragmentation needed\" reply: a PMTU black hole. Symptoms: SSH or TLS hangs after connecting, big downloads stall. Fix: clamp TCP MSS on the router (Junos: set security flow tcp-mss all-tcp mss 1360 · Cisco: ip tcp adjust-mss 1360) or allow ICMP type 3 code 4".into(),
        );
    } else if mtu < local.unwrap_or(1500) {
        emit(Tone::Normal, "→ the path is smaller than your interface; routers report it correctly, so TCP adapts on its own".into());
    } else {
        emit(Tone::Good, "→ full-size packets pass".into());
    }
    Result { path_mtu: Some(mtu), local_mtu: local, black_hole }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_ping_output() {
        assert_eq!(classify("PING 1.1.1.1 (1.1.1.1): 1472 data bytes\n1480 bytes from 1.1.1.1: icmp_seq=0 ttl=54 time=7.2 ms\n\n1 packets transmitted, 1 packets received, 0.0% packet loss"), if cfg!(windows) { Probe::Lost } else { Probe::Ok });
        assert_eq!(classify("From 10.0.0.1 icmp_seq=1 Frag needed and DF set (mtu = 1400)\n1 packets transmitted, 0 received, +1 errors"), Probe::FragNeeded(Some(1400)));
        assert_eq!(classify("ping: local error: message too long, mtu=1500"), Probe::TooBigLocal(Some(1500)));
        assert_eq!(classify("ping: sendto: Message too long"), Probe::TooBigLocal(None));
        assert_eq!(classify("Packet needs to be fragmented but DF set."), Probe::FragNeeded(None));
        assert_eq!(classify("1 packets transmitted, 0 packets received, 100.0% packet loss"), Probe::Lost);
        assert_eq!(explain(1492), "PPPoE (DSL/fibre access): 8 bytes of PPPoE header");
        assert_eq!(explain(1400), "IPsec / VPN tunnel overhead");
    }
}
