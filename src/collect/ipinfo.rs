//! IP context: address scope (private, CGNAT, link-local …), well-known
//! service names from /etc/services, and asynchronous reverse DNS.
//!
//! Reverse DNS runs on one background thread with a bounded cache, so the UI
//! never waits on a resolver. It only starts when you turn names on (`n`).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

/// Pull the IP out of `1.2.3.4:443`, `[2001:db8::1]:443` or `*:80`.
pub fn endpoint_ip(ep: &str) -> Option<IpAddr> {
    let host = ep.rsplit_once(':').map(|(h, _)| h).unwrap_or(ep);
    host.trim_start_matches('[').trim_end_matches(']').parse().ok()
}

pub fn endpoint_port(ep: &str) -> Option<u16> {
    ep.rsplit_once(':')?.1.parse().ok()
}

/// Short scope label for an address.
pub fn scope(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(a) => scope_v4(a),
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return scope_v4(&v4);
            }
            let s = a.segments();
            if a.is_loopback() {
                "loopback"
            } else if a.is_unspecified() {
                "any"
            } else if a.is_multicast() {
                "multicast"
            } else if s[0] & 0xffc0 == 0xfe80 {
                "link-local"
            } else if s[0] & 0xfe00 == 0xfc00 {
                "private" // ULA fc00::/7
            } else if s[0] == 0x2001 && s[1] == 0x0db8 {
                "doc"
            } else {
                "public"
            }
        }
    }
}

fn scope_v4(a: &Ipv4Addr) -> &'static str {
    let o = a.octets();
    if a.is_loopback() {
        "loopback"
    } else if a.is_unspecified() {
        "any"
    } else if a.is_private() {
        "private"
    } else if o[0] == 100 && (o[1] & 0xc0) == 64 {
        "cgnat" // 100.64.0.0/10
    } else if a.is_link_local() {
        "link-local"
    } else if a.is_multicast() {
        "multicast"
    } else if a.is_broadcast() {
        "broadcast"
    } else if a.is_documentation() {
        "doc"
    } else {
        "public"
    }
}

// ───────────────────────────── /etc/services ─────────────────────────────

pub fn parse_services(text: &str) -> HashMap<(u16, bool), String> {
    let mut m = HashMap::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        let mut it = line.split_whitespace();
        let (Some(name), Some(pp)) = (it.next(), it.next()) else { continue };
        let Some((port, proto)) = pp.split_once('/') else { continue };
        let Ok(port) = port.parse::<u16>() else { continue };
        m.entry((port, proto.eq_ignore_ascii_case("udp"))).or_insert_with(|| name.to_string());
    }
    m
}

/// Service name for a port (`443` → `https`). Loaded once, lazily.
pub fn service(port: u16, udp: bool) -> Option<&'static str> {
    static MAP: OnceLock<HashMap<(u16, bool), String>> = OnceLock::new();
    MAP.get_or_init(|| parse_services(&std::fs::read_to_string("/etc/services").unwrap_or_default()))
        .get(&(port, udp))
        .map(String::as_str)
}

// ───────────────────────────── reverse DNS ─────────────────────────────

const CACHE_MAX: usize = 20_000;

pub struct Resolver {
    tx: Sender<IpAddr>,
    cache: Arc<Mutex<HashMap<IpAddr, Option<String>>>>,
    pending: Mutex<HashSet<IpAddr>>,
}

impl Resolver {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel::<IpAddr>();
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let c = cache.clone();
        thread::spawn(move || worker(rx, c));
        Self { tx, cache, pending: Mutex::new(HashSet::new()) }
    }

    /// Cached name, or None while it is being resolved / has no PTR record.
    /// Unknown addresses are queued; the UI shows the IP meanwhile.
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        if let Ok(c) = self.cache.lock() {
            if let Some(v) = c.get(&ip) {
                return v.clone();
            }
        }
        if let Ok(mut p) = self.pending.lock() {
            if p.len() < 4096 && p.insert(ip) {
                let _ = self.tx.send(ip);
            }
        }
        None
    }
}

fn worker(rx: Receiver<IpAddr>, cache: Arc<Mutex<HashMap<IpAddr, Option<String>>>>) {
    while let Ok(ip) = rx.recv() {
        let name = reverse(ip);
        if let Ok(mut c) = cache.lock() {
            if c.len() >= CACHE_MAX {
                c.clear();
            }
            c.insert(ip, name);
        }
    }
}

#[cfg(unix)]
fn reverse(ip: IpAddr) -> Option<String> {
    use std::mem;
    let mut host = [0 as libc::c_char; 256];
    let rc = unsafe {
        match ip {
            IpAddr::V4(a) => {
                let mut sa: libc::sockaddr_in = mem::zeroed();
                sa.sin_family = libc::AF_INET as _;
                sa.sin_addr = libc::in_addr { s_addr: u32::from_ne_bytes(a.octets()) };
                #[cfg(any(target_os = "macos", target_os = "freebsd"))]
                {
                    sa.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
                }
                libc::getnameinfo(
                    &sa as *const _ as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in>() as _,
                    host.as_mut_ptr(),
                    host.len() as _,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
            IpAddr::V6(a) => {
                let mut sa: libc::sockaddr_in6 = mem::zeroed();
                sa.sin6_family = libc::AF_INET6 as _;
                sa.sin6_addr = libc::in6_addr { s6_addr: a.octets() };
                #[cfg(any(target_os = "macos", target_os = "freebsd"))]
                {
                    sa.sin6_len = mem::size_of::<libc::sockaddr_in6>() as u8;
                }
                libc::getnameinfo(
                    &sa as *const _ as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in6>() as _,
                    host.as_mut_ptr(),
                    host.len() as _,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };
    if rc != 0 {
        return None;
    }
    let s = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) }.to_string_lossy().into_owned();
    (!s.is_empty()).then_some(s)
}

#[cfg(not(unix))]
fn reverse(_ip: IpAddr) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes() {
        let s = |x: &str| scope(&x.parse().unwrap());
        assert_eq!(s("10.1.2.3"), "private");
        assert_eq!(s("100.72.0.1"), "cgnat");
        assert_eq!(s("169.254.1.1"), "link-local");
        assert_eq!(s("8.8.8.8"), "public");
        assert_eq!(s("127.0.0.1"), "loopback");
        assert_eq!(s("fe80::1"), "link-local");
        assert_eq!(s("fd00::1"), "private");
        assert_eq!(s("::ffff:192.168.1.1"), "private");
        assert_eq!(s("2606:4700::1111"), "public");
    }

    #[test]
    fn endpoints() {
        assert_eq!(endpoint_ip("[2001:db8::1]:443"), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(endpoint_ip("1.2.3.4:80"), Some("1.2.3.4".parse().unwrap()));
        assert_eq!(endpoint_ip("*:22"), None);
        assert_eq!(endpoint_port("[::1]:8080"), Some(8080));
    }

    #[test]
    fn services_file() {
        let m = parse_services("ssh 22/tcp # comment\nhttps 443/tcp\ndomain 53/udp\n# x\n");
        assert_eq!(m[&(22, false)], "ssh");
        assert_eq!(m[&(53, true)], "domain");
    }

    #[test]
    fn reverse_localhost_does_not_hang() {
        let r = Resolver::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let _ = r.lookup(ip);
        for _ in 0..50 {
            if r.lookup(ip).is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}
