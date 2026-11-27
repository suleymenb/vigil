//! A small DNS client (RFC 1035 + EDNS0) so vigil can ask *each* resolver
//! directly instead of going through the system's stub resolver.
//!
//! That is what you need when DNS "sometimes" fails: one resolver times out,
//! one answers NXDOMAIN, one returns an internal (split-horizon) address, or
//! DNSSEC validation fails with SERVFAIL on just one of them.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use super::Tone;

pub const TYPES: [(&str, u16); 11] = [
    ("A", 1),
    ("NS", 2),
    ("CNAME", 5),
    ("SOA", 6),
    ("PTR", 12),
    ("MX", 15),
    ("TXT", 16),
    ("AAAA", 28),
    ("SRV", 33),
    ("CAA", 257),
    ("ANY", 255),
];

pub fn type_code(name: &str) -> Option<u16> {
    TYPES.iter().find(|t| t.0.eq_ignore_ascii_case(name)).map(|t| t.1).or_else(|| name.strip_prefix("TYPE")?.parse().ok())
}

pub fn type_name(code: u16) -> String {
    TYPES.iter().find(|t| t.1 == code).map(|t| t.0.to_string()).unwrap_or_else(|| format!("TYPE{code}"))
}

pub fn rcode_name(r: u8) -> &'static str {
    match r {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "RCODE?",
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: String,
}

#[derive(Clone, Debug, Default)]
pub struct Response {
    pub rcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_available: bool,
    pub authenticated: bool,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub ms: f64,
    pub tcp: bool,
}

impl Response {
    /// Answer values of the asked type, sorted (for comparing resolvers).
    pub fn values(&self, qtype: u16) -> Vec<String> {
        let mut v: Vec<String> = self.answers.iter().filter(|r| r.rtype == qtype || qtype == 255).map(|r| r.data.clone()).collect();
        v.sort();
        v
    }
}

/// `1.2.3.4` → `4.3.2.1.in-addr.arpa`, IPv6 → nibble format under ip6.arpa.
pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(a) => {
            let mut s = String::new();
            for b in a.octets().iter().rev() {
                let _ = write!(s, "{:x}.{:x}.", b & 0xf, b >> 4);
            }
            s + "ip6.arpa"
        }
    }
}

pub fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let mut q = Vec::with_capacity(64);
    q.extend(id.to_be_bytes());
    q.extend([0x01, 0x20]); // RD + AD (ask for DNSSEC status)
    q.extend([0, 1, 0, 0, 0, 0, 0, 1]); // 1 question, 1 additional (OPT)
    for label in name.trim_end_matches('.').split('.').filter(|l| !l.is_empty()) {
        if label.len() > 63 {
            return Err(format!("label too long: {label}"));
        }
        q.push(label.len() as u8);
        q.extend(label.as_bytes());
    }
    q.push(0);
    q.extend(qtype.to_be_bytes());
    q.extend([0, 1]); // class IN
    // EDNS0 OPT: root name, type 41, UDP payload 1232, no flags, no options.
    q.extend([0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
    Ok(q)
}

fn read_name(b: &[u8], mut pos: usize) -> Result<(String, usize), String> {
    let mut out = String::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *b.get(pos).ok_or("truncated name")? as usize;
        if len & 0xc0 == 0xc0 {
            let ptr = ((len & 0x3f) << 8) | *b.get(pos + 1).ok_or("truncated pointer")? as usize;
            end.get_or_insert(pos + 2);
            jumps += 1;
            if jumps > 32 {
                return Err("compression loop".into());
            }
            pos = ptr;
            continue;
        }
        if len == 0 {
            let next = end.unwrap_or(pos + 1);
            if out.is_empty() {
                out.push('.');
            }
            return Ok((out, next));
        }
        let label = b.get(pos + 1..pos + 1 + len).ok_or("truncated label")?;
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(label));
        pos += 1 + len;
    }
}

fn u16_at(b: &[u8], p: usize) -> Result<u16, String> {
    Ok(u16::from_be_bytes([*b.get(p).ok_or("short")?, *b.get(p + 1).ok_or("short")?]))
}

fn u32_at(b: &[u8], p: usize) -> Result<u32, String> {
    Ok(((u16_at(b, p)? as u32) << 16) | u16_at(b, p + 2)? as u32)
}

fn rdata(b: &[u8], rtype: u16, start: usize, len: usize) -> Result<String, String> {
    let d = b.get(start..start + len).ok_or("truncated rdata")?;
    Ok(match rtype {
        1 if len == 4 => IpAddr::from([d[0], d[1], d[2], d[3]]).to_string(),
        28 if len == 16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(d);
            IpAddr::from(a).to_string()
        }
        2 | 5 | 12 => read_name(b, start)?.0,
        15 => format!("{} {}", u16_at(b, start)?, read_name(b, start + 2)?.0),
        16 => {
            let mut parts = Vec::new();
            let mut i = 0;
            while i < d.len() {
                let l = d[i] as usize;
                parts.push(format!("\"{}\"", String::from_utf8_lossy(d.get(i + 1..i + 1 + l).unwrap_or_default())));
                i += 1 + l;
            }
            parts.join(" ")
        }
        6 => {
            let (mname, p) = read_name(b, start)?;
            let (rname, p) = read_name(b, p)?;
            format!("{mname} {rname} serial {} refresh {} retry {} expire {} min {}", u32_at(b, p)?, u32_at(b, p + 4)?, u32_at(b, p + 8)?, u32_at(b, p + 12)?, u32_at(b, p + 16)?)
        }
        33 => format!("{} {} {} {}", u16_at(b, start)?, u16_at(b, start + 2)?, u16_at(b, start + 4)?, read_name(b, start + 6)?.0),
        257 if len >= 2 => {
            let tl = d[1] as usize;
            format!("{} {} \"{}\"", d[0], String::from_utf8_lossy(d.get(2..2 + tl).unwrap_or_default()), String::from_utf8_lossy(d.get(2 + tl..).unwrap_or_default()))
        }
        _ => d.iter().map(|x| format!("{x:02x}")).collect(),
    })
}

pub fn parse_response(b: &[u8], id: u16) -> Result<Response, String> {
    if b.len() < 12 {
        return Err("short response".into());
    }
    if u16_at(b, 0)? != id {
        return Err("response id mismatch".into());
    }
    let (f1, f2) = (b[2], b[3]);
    let (qd, an, ns) = (u16_at(b, 4)?, u16_at(b, 6)?, u16_at(b, 8)?);
    let mut pos = 12;
    for _ in 0..qd {
        pos = read_name(b, pos)?.1 + 4;
    }
    let mut r = Response {
        rcode: f2 & 0x0f,
        authoritative: f1 & 0x04 != 0,
        truncated: f1 & 0x02 != 0,
        recursion_available: f2 & 0x80 != 0,
        authenticated: f2 & 0x20 != 0,
        ..Default::default()
    };
    for i in 0..(an as usize + ns as usize) {
        let (name, p) = read_name(b, pos)?;
        let rtype = u16_at(b, p)?;
        let ttl = u32_at(b, p + 4)?;
        let len = u16_at(b, p + 8)? as usize;
        let data = rdata(b, rtype, p + 10, len)?;
        let rec = Record { name, rtype, ttl, data };
        if i < an as usize {
            r.answers.push(rec);
        } else {
            r.authority.push(rec);
        }
        pos = p + 10 + len;
    }
    Ok(r)
}

fn query_id() -> u16 {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(7);
    (t ^ (std::process::id() << 3)) as u16
}

/// Ask one server; retries over TCP when the UDP answer is truncated.
pub fn query(server: IpAddr, name: &str, qtype: u16, timeout: Duration) -> Result<Response, String> {
    let id = query_id();
    let pkt = build_query(id, name, qtype)?;
    let addr = SocketAddr::new(server, 53);
    let bind: SocketAddr = if server.is_ipv6() { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
    let sock = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    let t0 = Instant::now();
    sock.send_to(&pkt, addr).map_err(|e| format!("send: {e}"))?;
    let mut buf = [0u8; 4096];
    loop {
        let (n, from) = sock.recv_from(&mut buf).map_err(|e| match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => "timeout (no answer on UDP 53)".to_string(),
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused => "refused (ICMP port unreachable: nothing listens on 53)".to_string(),
            _ => e.to_string(),
        })?;
        if from.ip() != server {
            continue;
        }
        let mut r = parse_response(&buf[..n], id)?;
        r.ms = t0.elapsed().as_secs_f64() * 1000.0;
        if r.truncated {
            return query_tcp(server, &pkt, id, timeout);
        }
        return Ok(r);
    }
}

fn query_tcp(server: IpAddr, pkt: &[u8], id: u16, timeout: Duration) -> Result<Response, String> {
    let t0 = Instant::now();
    let mut s = TcpStream::connect_timeout(&SocketAddr::new(server, 53), timeout).map_err(|e| format!("tcp: {e}"))?;
    s.set_read_timeout(Some(timeout)).ok();
    let mut msg = (pkt.len() as u16).to_be_bytes().to_vec();
    msg.extend(pkt);
    s.write_all(&msg).map_err(|e| e.to_string())?;
    let mut len = [0u8; 2];
    s.read_exact(&mut len).map_err(|e| e.to_string())?;
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut body).map_err(|e| e.to_string())?;
    let mut r = parse_response(&body, id)?;
    r.ms = t0.elapsed().as_secs_f64() * 1000.0;
    r.tcp = true;
    Ok(r)
}

/// Parse `NAME [TYPE] [@server …]`; a bare IP means a PTR lookup.
pub fn parse_args(input: &str) -> Result<(String, u16, Vec<IpAddr>), String> {
    let mut name = None;
    let mut qtype = None;
    let mut servers = Vec::new();
    for t in input.split_whitespace() {
        if let Some(s) = t.strip_prefix('@') {
            servers.push(s.parse::<IpAddr>().map_err(|_| format!("@{s}: resolver must be an IP address"))?);
        } else if name.is_some() && type_code(t).is_some() {
            qtype = type_code(t);
        } else if name.is_none() {
            name = Some(t.to_string());
        } else {
            return Err(format!("unexpected argument: {t}"));
        }
    }
    let name = name.ok_or("usage: NAME [A|AAAA|MX|TXT|NS|SOA|CNAME|PTR|SRV|CAA] [@server]")?;
    if let Ok(ip) = name.parse::<IpAddr>() {
        return Ok((reverse_name(ip), qtype.unwrap_or(12), servers));
    }
    Ok((name, qtype.unwrap_or(1), servers))
}

/// Query every resolver in parallel and explain where they disagree.
/// `system` are the machine's configured resolvers, `public` the comparison set.
pub fn compare(name: &str, qtype: u16, system: &[String], public: &[String], extra: &[IpAddr], emit: &dyn Fn(Tone, String)) -> bool {
    let mut targets: Vec<(IpAddr, &'static str)> = Vec::new();
    for s in system {
        if let Ok(ip) = s.parse() {
            targets.push((ip, "system"));
        }
    }
    for ip in extra {
        targets.push((*ip, "asked"));
    }
    for s in public {
        if let Ok(ip) = s.parse::<IpAddr>() {
            if !targets.iter().any(|t| t.0 == ip) {
                targets.push((ip, "public"));
            }
        }
    }
    if extra.is_empty() && targets.is_empty() {
        emit(Tone::Bad, "no resolvers configured and no public resolvers set".into());
        return false;
    }
    if !extra.is_empty() {
        targets.retain(|t| t.1 == "asked");
    }
    emit(Tone::Head, format!("{name} {} · {} resolvers", type_name(qtype), targets.len()));

    // The system resolver first (what applications actually see).
    let t0 = Instant::now();
    match system_lookup(name) {
        Ok(v) if qtype == 1 || qtype == 28 => emit(Tone::Normal, format!("  {:<20} {:>7.1} ms  {}", "getaddrinfo (system)", t0.elapsed().as_secs_f64() * 1000.0, v.join(" "))),
        Ok(_) => {}
        Err(e) if qtype == 1 || qtype == 28 => emit(Tone::Warn, format!("  {:<20} {:>7.1} ms  {e}", "getaddrinfo (system)", t0.elapsed().as_secs_f64() * 1000.0)),
        Err(_) => {}
    }

    let handles: Vec<_> = targets
        .iter()
        .map(|(ip, kind)| {
            let (ip, kind, name) = (*ip, *kind, name.to_string());
            std::thread::spawn(move || (ip, kind, query(ip, &name, qtype, Duration::from_secs(2))))
        })
        .collect();
    let results: Vec<(IpAddr, &str, Result<Response, String>)> = handles.into_iter().filter_map(|h| h.join().ok()).collect();

    let mut answers: Vec<(Vec<String>, u8)> = Vec::new();
    let mut ok = true;
    let w = results.iter().map(|(ip, kind, _)| format!("{ip} ({kind})").len()).max().unwrap_or(20).max(20);
    for (ip, kind, res) in &results {
        let label = format!("{ip} ({kind})");
        match res {
            Ok(r) => {
                let vals = r.values(qtype);
                let flags = [(r.authoritative, "aa"), (r.authenticated, "ad"), (r.tcp, "tcp"), (!r.recursion_available, "no-recursion")]
                    .iter()
                    .filter(|f| f.0)
                    .map(|f| f.1)
                    .collect::<Vec<_>>()
                    .join(",");
                let ttl = r.answers.iter().map(|a| a.ttl).min();
                let tone = match r.rcode {
                    0 if !vals.is_empty() => Tone::Good,
                    0 | 3 => Tone::Warn,
                    _ => Tone::Bad,
                };
                if r.rcode != 0 {
                    ok = false;
                }
                let body = if vals.is_empty() {
                    let cname = r.answers.iter().find(|a| a.rtype == 5).map(|a| format!(" (CNAME {})", a.data)).unwrap_or_default();
                    format!("{}{cname}", rcode_name(r.rcode))
                } else {
                    vals.join("  ")
                };
                emit(
                    tone,
                    format!(
                        "  {label:<w$} {:>7.1} ms  {body}{}{}",
                        r.ms,
                        ttl.map(|t| format!("  ttl {t}")).unwrap_or_default(),
                        if flags.is_empty() { String::new() } else { format!("  [{flags}]") }
                    ),
                );
                answers.push((vals, r.rcode));
            }
            Err(e) => {
                ok = false;
                emit(Tone::Bad, format!("  {label:<w$} {:>10}  {e}", "-"));
            }
        }
    }

    // Verdict.
    let distinct: std::collections::BTreeSet<_> = answers.iter().collect();
    let failed = results.iter().filter(|r| r.2.is_err()).count();
    if failed == results.len() && !results.is_empty() {
        emit(Tone::Bad, "→ no resolver answered: UDP/TCP 53 is blocked, or there is no route to any of them".into());
    } else if failed > 0 {
        emit(Tone::Warn, format!("→ {failed} resolver(s) did not answer: applications stall for the resolver timeout (often 5 s) before trying the next one"));
    }
    if answers.iter().any(|a| a.1 == 2) {
        emit(Tone::Warn, "→ SERVFAIL: upstream unreachable or DNSSEC validation failed on that resolver (compare with one that answers)".into());
    }
    if distinct.len() > 1 {
        if answers.iter().any(|a| a.1 == 3) && answers.iter().any(|a| a.1 == 0 && !a.0.is_empty()) {
            emit(Tone::Warn, "→ NXDOMAIN on some resolvers only: an internal zone (split-horizon) or a filtering resolver".into());
        } else {
            emit(Tone::Warn, "→ resolvers disagree: split-horizon DNS, geo/CDN load balancing (normal for big sites) or a stale cache".into());
        }
    } else if failed == 0 && !answers.is_empty() && answers.iter().all(|a| a.1 == 3) {
        emit(Tone::Warn, "→ the name does not exist (NXDOMAIN from every resolver): a typo, or the record was never created".into());
    } else if failed == 0 && !answers.is_empty() && answers.iter().all(|a| a.1 == 0 && a.0.is_empty()) {
        emit(Tone::Warn, format!("→ the name exists but has no {} record (NODATA)", type_name(qtype)));
    } else if failed == 0 && !answers.is_empty() {
        emit(Tone::Good, "→ all resolvers agree".into());
    }
    let slow: Vec<String> = results.iter().filter_map(|(ip, _, r)| r.as_ref().ok().filter(|r| r.ms > 200.0).map(|r| format!("{ip} ({:.0} ms)", r.ms))).collect();
    if !slow.is_empty() {
        emit(Tone::Warn, format!("→ slow: {} (cache miss, an overloaded resolver, or a long path to it)", slow.join(", ")));
    }
    ok
}

/// The system resolver (getaddrinfo), which is what applications use.
pub fn system_lookup(name: &str) -> Result<Vec<String>, String> {
    use std::net::ToSocketAddrs;
    let mut v: Vec<String> = (name, 0).to_socket_addrs().map_err(|e| e.to_string())?.map(|a| a.ip().to_string()).collect();
    v.sort();
    v.dedup();
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_packet_and_parse() {
        let q = build_query(0xbeef, "example.com", 1).unwrap();
        assert_eq!(&q[..2], &[0xbe, 0xef]);
        assert_eq!(&q[12..25], b"\x07example\x03com\x00");
        // Response: same header with QR, 1 answer: example.com A 93.184.215.14 via a pointer to the question name.
        let mut r = q[..12].to_vec();
        r[2] = 0x81;
        r[3] = 0xa0; // RA + AD
        r[6..8].copy_from_slice(&1u16.to_be_bytes());
        r[10..12].copy_from_slice(&0u16.to_be_bytes());
        r.extend(&q[12..29]); // question
        r.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 93, 184, 215, 14]);
        let p = parse_response(&r, 0xbeef).unwrap();
        assert_eq!(p.rcode, 0);
        assert!(p.recursion_available && p.authenticated);
        assert_eq!(p.answers[0], Record { name: "example.com".into(), rtype: 1, ttl: 3600, data: "93.184.215.14".into() });
        assert!(parse_response(&r, 1).is_err());
    }

    #[test]
    fn mx_txt_and_args() {
        // MX 10 mail.<ptr to example.com>
        let mut b = vec![0u8; 12];
        b.extend(b"\x07example\x03com\x00");
        let start = b.len();
        b.extend([0, 10, 4, b'm', b'a', b'i', b'l', 0xc0, 12]);
        assert_eq!(rdata(&b, 15, start, 9).unwrap(), "10 mail.example.com");
        let t = [5, b'h', b'e', b'l', b'l', b'o', 2, b'h', b'i'];
        let mut b2 = vec![0u8; 3];
        b2.extend(t);
        assert_eq!(rdata(&b2, 16, 3, t.len()).unwrap(), "\"hello\" \"hi\"");
        assert_eq!(parse_args("github.com MX @1.1.1.1").unwrap(), ("github.com".into(), 15, vec!["1.1.1.1".parse().unwrap()]));
        assert_eq!(parse_args("8.8.4.4").unwrap().0, "4.4.8.8.in-addr.arpa");
        assert_eq!(reverse_name("2001:db8::1".parse().unwrap()), "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa");
        assert!(parse_args("x.com @resolver").is_err());
    }
}
