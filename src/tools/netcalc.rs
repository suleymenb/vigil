//! Subnet calculator for IPv4 and IPv6.
//!
//! Accepts `10.0.0.0/22`, `10.0.0.5 255.255.252.0`, `10.0.0.5/255.255.252.0`,
//! `10.0.0.5 0.0.3.255` (wildcard, as in ACLs and OSPF network statements) and
//! `2001:db8::/48`. Optional second argument: a prefix to split into
//! (`/24`) or an address to test for membership.

use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, PartialEq)]
pub struct V4 {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl V4 {
    pub fn mask(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix as u32)
        }
    }
    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) & self.mask())
    }
    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) | !self.mask())
    }
    pub fn size(&self) -> u64 {
        1u64 << (32 - self.prefix as u32)
    }
    /// Usable hosts: /31 point-to-point links have 2 (RFC 3021), /32 has 1.
    pub fn hosts(&self) -> u64 {
        match self.prefix {
            32 => 1,
            31 => 2,
            _ => self.size() - 2,
        }
    }
    pub fn first_last(&self) -> (Ipv4Addr, Ipv4Addr) {
        let (n, b) = (u32::from(self.network()), u32::from(self.broadcast()));
        if self.prefix >= 31 {
            (Ipv4Addr::from(n), Ipv4Addr::from(b))
        } else {
            (Ipv4Addr::from(n + 1), Ipv4Addr::from(b - 1))
        }
    }
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask() == u32::from(self.network())
    }
}

pub fn scope_v4(ip: Ipv4Addr) -> &'static str {
    let o = ip.octets();
    match o {
        [10, ..] => "private (RFC 1918)",
        [172, b, ..] if (16..32).contains(&b) => "private (RFC 1918)",
        [192, 168, ..] => "private (RFC 1918)",
        [100, b, ..] if (64..128).contains(&b) => "carrier-grade NAT (RFC 6598)",
        [127, ..] => "loopback",
        [169, 254, ..] => "link-local / APIPA (no DHCP answer)",
        [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _] => "documentation (RFC 5737)",
        [198, b, ..] if b == 18 || b == 19 => "benchmarking (RFC 2544)",
        [0, ..] => "this network",
        [a, ..] if (224..240).contains(&a) => "multicast",
        [255, 255, 255, 255] => "limited broadcast",
        [a, ..] if a >= 240 => "reserved",
        _ => "public",
    }
}

pub fn class_v4(ip: Ipv4Addr) -> char {
    match ip.octets()[0] {
        0..=127 => 'A',
        128..=191 => 'B',
        192..=223 => 'C',
        224..=239 => 'D',
        _ => 'E',
    }
}

/// Contiguous netmask → prefix length; None for masks like 255.0.255.0.
pub fn mask_to_prefix(m: Ipv4Addr) -> Option<u8> {
    let v = u32::from(m);
    let p = v.leading_ones();
    (v.checked_shl(p).unwrap_or(0) == 0).then_some(p as u8)
}

fn parse_v4_prefix(s: &str) -> Option<u8> {
    if let Ok(p) = s.parse::<u8>() {
        return (p <= 32).then_some(p);
    }
    let m: Ipv4Addr = s.parse().ok()?;
    // A wildcard mask (0.0.3.255) is the inverse of a netmask.
    mask_to_prefix(m).or_else(|| mask_to_prefix(Ipv4Addr::from(!u32::from(m))))
}

#[derive(Clone, Debug, PartialEq)]
pub enum Net {
    V4(V4),
    V6(Ipv6Addr, u8),
}

/// Parse `addr/prefix`, `addr mask`, `addr/mask` or a bare address (/32, /128).
pub fn parse(input: &str) -> Result<Net, String> {
    let s = input.trim();
    let (a, p) = match s.split_once('/') {
        Some((a, p)) => (a.trim(), Some(p.trim())),
        None => match s.split_once(char::is_whitespace) {
            Some((a, p)) => (a.trim(), Some(p.trim())),
            None => (s, None),
        },
    };
    match a.parse::<IpAddr>().map_err(|_| format!("not an IP address: {a}"))? {
        IpAddr::V4(addr) => {
            let prefix = match p {
                Some(p) => parse_v4_prefix(p).ok_or_else(|| format!("bad prefix or mask: {p}"))?,
                None => 32,
            };
            Ok(Net::V4(V4 { addr, prefix }))
        }
        IpAddr::V6(addr) => {
            let prefix = match p {
                Some(p) => p.parse::<u8>().ok().filter(|p| *p <= 128).ok_or_else(|| format!("bad IPv6 prefix: {p}"))?,
                None => 128,
            };
            Ok(Net::V6(addr, prefix))
        }
    }
}

fn mask6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix as u32)
    }
}

pub fn scope_v6(ip: Ipv6Addr) -> &'static str {
    let s = ip.segments();
    if ip.is_loopback() {
        "loopback"
    } else if ip.is_unspecified() {
        "unspecified"
    } else if s[0] & 0xffc0 == 0xfe80 {
        "link-local"
    } else if s[0] & 0xfe00 == 0xfc00 {
        "unique local (ULA, private)"
    } else if s[0] & 0xff00 == 0xff00 {
        "multicast"
    } else if s[0] == 0x2001 && s[1] == 0x0db8 {
        "documentation (RFC 3849)"
    } else if s[0] == 0x2002 {
        "6to4"
    } else if s[0] == 0x0064 && s[1] == 0xff9b {
        "NAT64 well-known prefix"
    } else if s[0] & 0xe000 == 0x2000 {
        "global unicast"
    } else {
        "reserved"
    }
}

fn dotted_bin(v: u32) -> String {
    v.to_be_bytes().iter().map(|b| format!("{b:08b}")).collect::<Vec<_>>().join(".")
}

fn group(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Rows of (label, value) for display in the TUI and on the command line.
pub fn describe(net: &Net) -> Vec<(String, String)> {
    let mut r: Vec<(String, String)> = Vec::new();
    let mut add = |k: &str, v: String| r.push((k.to_string(), v));
    match net {
        Net::V4(n) => {
            let (first, last) = n.first_last();
            add("Address", format!("{} ({}, class {})", n.addr, scope_v4(n.addr), class_v4(n.addr)));
            add("Network", format!("{}/{}", n.network(), n.prefix));
            add("Netmask", format!("{}  = /{}", Ipv4Addr::from(n.mask()), n.prefix));
            add("Wildcard", format!("{}  (ACL / OSPF form)", Ipv4Addr::from(!n.mask())));
            add("Broadcast", n.broadcast().to_string());
            add("Host range", format!("{first} – {last}"));
            add("Usable hosts", format!("{}{}", group(n.hosts()), if n.prefix == 31 { "  (point-to-point, RFC 3021)" } else { "" }));
            add("Addresses", group(n.size()));
            add("Mask bits", dotted_bin(n.mask()));
            add("Address bits", dotted_bin(u32::from(n.addr)));
            if n.prefix > 0 {
                let size = n.size() as u32;
                let net = u32::from(n.network());
                if let Some(prev) = net.checked_sub(size) {
                    add("Previous", format!("{}/{}", Ipv4Addr::from(prev), n.prefix));
                }
                if let Some(next) = net.checked_add(size) {
                    add("Next", format!("{}/{}", Ipv4Addr::from(next), n.prefix));
                }
                let sup = V4 { addr: n.addr, prefix: n.prefix - 1 };
                add("Supernet", format!("{}/{}", sup.network(), sup.prefix));
            }
            add("PTR zone", {
                let o = n.network().octets();
                match n.prefix {
                    0..=8 => format!("{}.in-addr.arpa", o[0]),
                    9..=16 => format!("{}.{}.in-addr.arpa", o[1], o[0]),
                    _ => format!("{}.{}.{}.in-addr.arpa", o[2], o[1], o[0]),
                }
            });
        }
        Net::V6(a, p) => {
            let m = mask6(*p);
            let netw = Ipv6Addr::from(u128::from(*a) & m);
            let last = Ipv6Addr::from(u128::from(*a) | !m);
            add("Address", format!("{a} ({})", scope_v6(*a)));
            add("Network", format!("{netw}/{p}"));
            add("Range", format!("{netw} – {last}"));
            add("Expanded", a.segments().iter().map(|s| format!("{s:04x}")).collect::<Vec<_>>().join(":"));
            if *p <= 64 {
                let n64 = 1u128 << (64 - *p as u32);
                add("/64 subnets", if n64 > u64::MAX as u128 { format!("2^{}", 64 - p) } else { group(n64 as u64) });
            } else {
                let bits = 128 - *p as u32;
                add("Addresses", if bits >= 64 { format!("2^{bits}") } else { group(1u64 << bits) });
            }
            if *p == 64 {
                add("Note", "standard LAN size: SLAAC needs exactly /64".into());
            } else if *p == 127 {
                add("Note", "point-to-point link (RFC 6164)".into());
            } else if *p == 48 || *p == 56 {
                add("Note", format!("typical site allocation: {} /64 LANs", group(1 << (64 - *p as u32))));
            }
        }
    }
    r
}

/// Split a network into subnets of `new_prefix` (at most `limit` listed).
pub fn split(net: &Net, new_prefix: u8, limit: usize) -> Result<(u128, Vec<String>), String> {
    match net {
        Net::V4(n) => {
            if new_prefix < n.prefix || new_prefix > 32 {
                return Err(format!("/{new_prefix} must be between /{} and /32", n.prefix));
            }
            let count = 1u128 << (new_prefix - n.prefix);
            let step = 1u64 << (32 - new_prefix as u32);
            let base = u32::from(n.network()) as u64;
            let v = (0..count.min(limit as u128) as u64)
                .map(|i| {
                    let s = V4 { addr: Ipv4Addr::from((base + i * step) as u32), prefix: new_prefix };
                    let (f, l) = s.first_last();
                    format!("{}/{new_prefix}  {f} – {l}  bc {}", s.network(), s.broadcast())
                })
                .collect();
            Ok((count, v))
        }
        Net::V6(a, p) => {
            if new_prefix < *p || new_prefix > 128 {
                return Err(format!("/{new_prefix} must be between /{p} and /128"));
            }
            let diff = (new_prefix - p) as u32;
            let count = if diff >= 127 { u128::MAX } else { 1u128 << diff };
            let base = u128::from(*a) & mask6(*p);
            let step = if new_prefix == 0 { 0 } else { 1u128 << (128 - new_prefix as u32) };
            let v = (0..count.min(limit as u128)).map(|i| format!("{}/{new_prefix}", Ipv6Addr::from(base + i * step))).collect();
            Ok((count, v))
        }
    }
}

/// Is `ip` inside `net`?
pub fn contains(net: &Net, ip: IpAddr) -> Option<bool> {
    match (net, ip) {
        (Net::V4(n), IpAddr::V4(i)) => Some(n.contains(i)),
        (Net::V6(a, p), IpAddr::V6(i)) => Some(u128::from(i) & mask6(*p) == u128::from(*a) & mask6(*p)),
        _ => None,
    }
}

/// Full calculator output for a query line: `NET [ /NEW | ADDR ]`.
pub fn run(query: &str) -> Result<String, String> {
    let q = query.trim();
    // A trailing "/24" or an address after the network is the second argument.
    let mut parts: Vec<&str> = q.split_whitespace().collect();
    let mut extra: Option<String> = None;
    if parts.len() >= 2 {
        let last = parts[parts.len() - 1];
        let is_split = last.starts_with('/') && last[1..].parse::<u8>().is_ok();
        let is_addr = last.parse::<IpAddr>().is_ok() && parts[0].contains('/');
        if is_split || is_addr {
            extra = Some(last.to_string());
            parts.pop();
        }
    }
    let net = parse(&parts.join(" "))?;
    let mut out = String::new();
    let rows = describe(&net);
    let w = rows.iter().map(|r| r.0.len()).max().unwrap_or(0);
    for (k, v) in &rows {
        let _ = writeln!(out, "{k:<w$}  {v}");
    }
    if let Some(x) = extra {
        out.push('\n');
        if let Some(p) = x.strip_prefix('/') {
            let p: u8 = p.parse().map_err(|_| format!("bad prefix {x}"))?;
            let (count, list) = split(&net, p, 64)?;
            let _ = writeln!(out, "{} subnets of /{p}{}", if count == u128::MAX { "2^127+".to_string() } else { count.to_string() }, if count > list.len() as u128 { format!(" (first {})", list.len()) } else { String::new() });
            for l in list {
                let _ = writeln!(out, "  {l}");
            }
        } else if let Ok(ip) = x.parse::<IpAddr>() {
            match contains(&net, ip) {
                Some(true) => {
                    let _ = writeln!(out, "{ip} is inside this network");
                }
                Some(false) => {
                    let _ = writeln!(out, "{ip} is NOT inside this network (different subnet: traffic goes via the gateway)");
                }
                None => {
                    let _ = writeln!(out, "{ip} is a different address family");
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> V4 {
        match parse(s).unwrap() {
            Net::V4(v) => v,
            _ => panic!(),
        }
    }

    #[test]
    fn ipv4_math() {
        let n = v4("10.0.1.77/22");
        assert_eq!(n.network(), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(n.broadcast(), Ipv4Addr::new(10, 0, 3, 255));
        assert_eq!(n.hosts(), 1022);
        assert_eq!(n.first_last(), (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 3, 254)));
        assert_eq!(v4("10.0.1.77 255.255.252.0"), V4 { addr: Ipv4Addr::new(10, 0, 1, 77), prefix: 22 });
        assert_eq!(v4("10.0.1.77 0.0.3.255").prefix, 22);
        assert_eq!(v4("10.0.1.77/255.255.255.0").prefix, 24);
        assert_eq!(v4("192.168.1.0/31").hosts(), 2);
        assert_eq!(v4("192.168.1.9").hosts(), 1);
        assert_eq!(v4("0.0.0.0/0").size(), 1 << 32);
        assert!(parse("10.0.0.0 255.0.255.0").is_err());
        assert!(parse("10.0.0.0/33").is_err());
        assert_eq!(scope_v4(Ipv4Addr::new(172, 20, 1, 1)), "private (RFC 1918)");
        assert_eq!(scope_v4(Ipv4Addr::new(100, 100, 1, 1)), "carrier-grade NAT (RFC 6598)");
        assert_eq!(scope_v4(Ipv4Addr::new(169, 254, 3, 3)), "link-local / APIPA (no DHCP answer)");
    }

    #[test]
    fn split_and_contains() {
        let n = parse("10.0.0.0/22").unwrap();
        let (count, l) = split(&n, 24, 10).unwrap();
        assert_eq!(count, 4);
        assert_eq!(l[3], "10.0.3.0/24  10.0.3.1 – 10.0.3.254  bc 10.0.3.255");
        assert!(split(&n, 20, 10).is_err());
        assert_eq!(contains(&n, "10.0.3.7".parse().unwrap()), Some(true));
        assert_eq!(contains(&n, "10.0.4.1".parse().unwrap()), Some(false));
        let out = run("10.0.0.0/22 /24").unwrap();
        assert!(out.contains("4 subnets of /24"));
        assert!(out.contains("Wildcard"));
        assert!(run("10.0.0.0/22 10.0.4.1").unwrap().contains("NOT inside"));
    }

    #[test]
    fn ipv6_math() {
        let n = parse("2001:db8:abcd:12::1/48").unwrap();
        let d = describe(&n);
        assert!(d.iter().any(|(k, v)| k == "Network" && v == "2001:db8:abcd::/48"));
        assert!(d.iter().any(|(k, v)| k == "/64 subnets" && v == "65,536"));
        let (count, l) = split(&n, 52, 3).unwrap();
        assert_eq!(count, 16);
        assert_eq!(l[1], "2001:db8:abcd:1000::/52");
        assert_eq!(scope_v6("fe80::1".parse().unwrap()), "link-local");
        assert_eq!(scope_v6("fd00::1".parse().unwrap()), "unique local (ULA, private)");
        assert_eq!(contains(&n, "2001:db8:abcd:ffff::9".parse().unwrap()), Some(true));
    }
}
