//! Windows collectors (Windows 7 and newer).
//!
//! Sockets and TCP/UDP counters come straight from the IP Helper API
//! (`GetExtendedTcpTable`, `GetTcpStatisticsEx`), which is fast and does not
//! depend on the display language. Routes, neighbours, DNS servers, services,
//! sessions, ping, traceroute and the event log come from the standard tools
//! (`route print`, `arp -a`, `ipconfig /all`, `sc queryex`, `quser`, `ping`,
//! `tracert`, `wevtutil`). Their parsers key on numbers and addresses rather
//! than on (translated) labels, and are unit-tested on every OS.

#![cfg_attr(not(windows), allow(dead_code))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::kmsg::{classify, KEvent};
use super::netinfo::{Neighbor, Route};
use super::services::Unit;
use super::sessions::Session;
use super::trace::Hop;

// ───────────────────────────── IP Helper tables ─────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct WinSock {
    pub proto: &'static str,
    pub v6: bool,
    pub local: String,
    pub remote: String,
    pub state: &'static str,
    pub pid: u32,
}

pub fn tcp_state(n: u32) -> &'static str {
    match n {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RECV",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

/// Ports are stored in network byte order in the low 16 bits of a DWORD.
fn port_at(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

fn ep(ip: IpAddr, port: u16, v6: bool) -> String {
    if ip.is_unspecified() {
        format!("*:{port}")
    } else if v6 {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

fn remote_ep(ip: IpAddr, port: u16, v6: bool) -> String {
    if ip.is_unspecified() && port == 0 {
        String::new()
    } else {
        ep(ip, port, v6)
    }
}

fn v4(b: &[u8], o: usize) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(b[o], b[o + 1], b[o + 2], b[o + 3]))
}

fn v6(b: &[u8], o: usize) -> IpAddr {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[o..o + 16]);
    IpAddr::V6(Ipv6Addr::from(a))
}

/// MIB_TCPTABLE_OWNER_PID: count, then rows of {state, laddr, lport, raddr, rport, pid}.
pub fn parse_tcp4(b: &[u8]) -> Vec<WinSock> {
    let n = u32_at(b, 0).unwrap_or(0) as usize;
    (0..n)
        .filter_map(|i| {
            let o = 4 + i * 24;
            b.get(o..o + 24)?;
            Some(WinSock {
                proto: "TCP",
                v6: false,
                state: tcp_state(u32_at(b, o)?),
                local: ep(v4(b, o + 4), port_at(b, o + 8), false),
                remote: remote_ep(v4(b, o + 12), port_at(b, o + 16), false),
                pid: u32_at(b, o + 20)?,
            })
        })
        .collect()
}

/// MIB_TCP6TABLE_OWNER_PID rows: laddr[16], lscope, lport, raddr[16], rscope, rport, state, pid.
pub fn parse_tcp6(b: &[u8]) -> Vec<WinSock> {
    let n = u32_at(b, 0).unwrap_or(0) as usize;
    (0..n)
        .filter_map(|i| {
            let o = 4 + i * 56;
            b.get(o..o + 56)?;
            Some(WinSock {
                proto: "TCP",
                v6: true,
                local: ep(v6(b, o), port_at(b, o + 20), true),
                remote: remote_ep(v6(b, o + 24), port_at(b, o + 44), true),
                state: tcp_state(u32_at(b, o + 48)?),
                pid: u32_at(b, o + 52)?,
            })
        })
        .collect()
}

/// MIB_UDPTABLE_OWNER_PID rows: laddr, lport, pid.
pub fn parse_udp4(b: &[u8]) -> Vec<WinSock> {
    let n = u32_at(b, 0).unwrap_or(0) as usize;
    (0..n)
        .filter_map(|i| {
            let o = 4 + i * 12;
            b.get(o..o + 12)?;
            Some(WinSock { proto: "UDP", v6: false, local: ep(v4(b, o), port_at(b, o + 4), false), remote: String::new(), state: "", pid: u32_at(b, o + 8)? })
        })
        .collect()
}

/// MIB_UDP6TABLE_OWNER_PID rows: laddr[16], lscope, lport, pid.
pub fn parse_udp6(b: &[u8]) -> Vec<WinSock> {
    let n = u32_at(b, 0).unwrap_or(0) as usize;
    (0..n)
        .filter_map(|i| {
            let o = 4 + i * 28;
            b.get(o..o + 28)?;
            Some(WinSock { proto: "UDP", v6: true, local: ep(v6(b, o), port_at(b, o + 20), true), remote: String::new(), state: "", pid: u32_at(b, o + 24)? })
        })
        .collect()
}

#[cfg(windows)]
mod api {
    use std::ffi::c_void;

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetExtendedTcpTable(table: *mut c_void, size: *mut u32, order: i32, af: u32, class: u32, reserved: u32) -> u32;
        fn GetExtendedUdpTable(table: *mut c_void, size: *mut u32, order: i32, af: u32, class: u32, reserved: u32) -> u32;
        fn GetTcpStatisticsEx(stats: *mut u32, family: u32) -> u32;
        fn GetUdpStatisticsEx(stats: *mut u32, family: u32) -> u32;
    }

    pub const AF_INET: u32 = 2;
    pub const AF_INET6: u32 = 23;
    const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
    const UDP_TABLE_OWNER_PID: u32 = 1;

    fn table(tcp: bool, af: u32) -> Vec<u8> {
        let mut size: u32 = 0;
        let class = if tcp { TCP_TABLE_OWNER_PID_ALL } else { UDP_TABLE_OWNER_PID };
        let call = |p: *mut c_void, s: *mut u32| unsafe {
            if tcp {
                GetExtendedTcpTable(p, s, 0, af, class, 0)
            } else {
                GetExtendedUdpTable(p, s, 0, af, class, 0)
            }
        };
        call(std::ptr::null_mut(), &mut size);
        // The table can grow between the two calls: retry a few times.
        for _ in 0..4 {
            let mut buf = vec![0u8; size as usize + 4096];
            let mut s = buf.len() as u32;
            if call(buf.as_mut_ptr() as *mut c_void, &mut s) == 0 {
                return buf;
            }
            size = s;
        }
        Vec::new()
    }

    pub fn tcp(af: u32) -> Vec<u8> {
        table(true, af)
    }

    pub fn udp(af: u32) -> Vec<u8> {
        table(false, af)
    }

    /// MIB_TCPSTATS (15 DWORDs) and MIB_UDPSTATS (5 DWORDs), IPv4 + IPv6 summed.
    pub fn stats() -> ([u64; 15], [u64; 5]) {
        let mut tcp = [0u64; 15];
        let mut udp = [0u64; 5];
        for af in [AF_INET, AF_INET6] {
            let mut t = [0u32; 15];
            if unsafe { GetTcpStatisticsEx(t.as_mut_ptr(), af) } == 0 {
                for (a, b) in tcp.iter_mut().zip(t) {
                    *a += b as u64;
                }
            }
            let mut u = [0u32; 5];
            if unsafe { GetUdpStatisticsEx(u.as_mut_ptr(), af) } == 0 {
                for (a, b) in udp.iter_mut().zip(u) {
                    *a += b as u64;
                }
            }
        }
        (tcp, udp)
    }
}

/// pid → executable name, from a Toolhelp snapshot (one syscall-ish walk, ~1 ms).
#[cfg(windows)]
pub fn process_names() -> std::collections::HashMap<u32, String> {
    #[repr(C)]
    struct ProcessEntry32W {
        size: u32,
        usage: u32,
        pid: u32,
        heap: usize,
        module: u32,
        threads: u32,
        ppid: u32,
        pri: i32,
        flags: u32,
        exe: [u16; 260],
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> isize;
        fn Process32FirstW(h: isize, e: *mut ProcessEntry32W) -> i32;
        fn Process32NextW(h: isize, e: *mut ProcessEntry32W) -> i32;
        fn CloseHandle(h: isize) -> i32;
    }
    let mut out = std::collections::HashMap::new();
    let h = unsafe { CreateToolhelp32Snapshot(0x2, 0) };
    if h == -1 {
        return out;
    }
    let mut e = ProcessEntry32W { size: std::mem::size_of::<ProcessEntry32W>() as u32, usage: 0, pid: 0, heap: 0, module: 0, threads: 0, ppid: 0, pri: 0, flags: 0, exe: [0; 260] };
    let mut ok = unsafe { Process32FirstW(h, &mut e) } != 0;
    while ok {
        let n = e.exe.iter().position(|&c| c == 0).unwrap_or(260);
        out.insert(e.pid, String::from_utf16_lossy(&e.exe[..n]));
        ok = unsafe { Process32NextW(h, &mut e) } != 0;
    }
    unsafe { CloseHandle(h) };
    out.insert(0, "System Idle".into());
    out.insert(4, "System".into());
    out
}

/// Socket rows in the same shape as the Linux scanner and lsof produce.
pub fn to_open_files(socks: Vec<WinSock>, names: &std::collections::HashMap<u32, String>) -> Vec<super::lsof::OpenFile> {
    socks
        .into_iter()
        .map(|s| super::lsof::OpenFile {
            pid: s.pid,
            command: names.get(&s.pid).cloned().unwrap_or_else(|| if s.pid == 0 { "-".into() } else { format!("pid {}", s.pid) }),
            fd: "-".into(),
            ftype: if s.v6 { "IPv6".into() } else { "IPv4".into() },
            name: if s.remote.is_empty() { s.local } else { format!("{}->{}", s.local, s.remote) },
            proto: s.proto.into(),
            state: s.state.into(),
            ..Default::default()
        })
        .collect()
}

/// All TCP and UDP sockets with their owning pid.
#[cfg(windows)]
pub fn sockets() -> Vec<WinSock> {
    let mut v = parse_tcp4(&api::tcp(api::AF_INET));
    v.extend(parse_tcp6(&api::tcp(api::AF_INET6)));
    v.extend(parse_udp4(&api::udp(api::AF_INET)));
    v.extend(parse_udp6(&api::udp(api::AF_INET6)));
    v
}

/// TCP/UDP counters under the same names as Linux /proc/net/snmp, so the
/// rate logic and the health badges are shared.
#[cfg(windows)]
pub fn counters(out: &mut std::collections::HashMap<String, u64>) {
    let (t, u) = api::stats();
    for (k, i) in [("ActiveOpens", 4), ("PassiveOpens", 5), ("AttemptFails", 6), ("EstabResets", 7), ("CurrEstab", 8), ("InSegs", 9), ("OutSegs", 10), ("RetransSegs", 11), ("InErrs", 12), ("OutRsts", 13)] {
        out.insert(format!("Tcp.{k}"), t[i]);
    }
    for (k, i) in [("InDatagrams", 0), ("NoPorts", 1), ("InErrors", 2), ("OutDatagrams", 3)] {
        out.insert(format!("Udp.{k}"), u[i]);
    }
}

// ───────────────────────────── text parsers ─────────────────────────────

fn mask_len(mask: &str) -> Option<u32> {
    mask.parse::<Ipv4Addr>().ok().map(|m| u32::from(m).count_ones())
}

/// `route print`: IPv4 rows `dest mask gateway iface metric`, IPv6 rows
/// `if metric dest gateway` (the gateway may wrap to the next line). Labels
/// such as "On-link" are translated, so anything that isn't an address means on-link.
pub fn parse_route_print(text: &str) -> Vec<Route> {
    let mut out = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let f: Vec<&str> = lines[i].split_whitespace().collect();
        if f.len() == 5 && f[0].parse::<Ipv4Addr>().is_ok() && f[1].parse::<Ipv4Addr>().is_ok() && f[3].parse::<Ipv4Addr>().is_ok() && f[4].parse::<u32>().is_ok() {
            let len = mask_len(f[1]).unwrap_or(32);
            out.push(Route {
                family: "inet",
                dst: if f[0] == "0.0.0.0" && len == 0 { "default".into() } else { format!("{}/{len}", f[0]) },
                gateway: if f[2].parse::<Ipv4Addr>().is_ok() { f[2].into() } else { String::new() },
                dev: f[3].into(),
                metric: f[4].into(),
                ..Default::default()
            });
        } else if (f.len() == 3 || f.len() == 4) && f[0].parse::<u32>().is_ok() && f[1].parse::<u32>().is_ok() && f[2].contains(':') && f[2].contains('/') {
            let gw_text = if f.len() == 4 { f[3].to_string() } else { lines.get(i + 1).map(|l| l.trim().to_string()).unwrap_or_default() };
            if f.len() == 3 {
                i += 1;
            }
            out.push(Route {
                family: "inet6",
                dst: if f[2] == "::/0" { "default".into() } else { f[2].into() },
                gateway: if gw_text.parse::<Ipv6Addr>().is_ok() { gw_text } else { String::new() },
                dev: format!("if{}", f[0]),
                metric: f[1].into(),
                ..Default::default()
            });
        }
        i += 1;
    }
    out
}

/// `arp -a`: "Interface: 10.0.0.5 --- 0x5" then rows `ip  aa-bb-cc-dd-ee-ff  dynamic`.
pub fn parse_arp_a(text: &str) -> Vec<Neighbor> {
    let mut dev = String::new();
    let mut out = Vec::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() >= 2 && f[0].ends_with(':') && f[1].parse::<Ipv4Addr>().is_ok() {
            dev = f[1].to_string();
            continue;
        }
        if f.len() >= 3 && f[0].parse::<Ipv4Addr>().is_ok() && f[1].len() == 17 && f[1].matches('-').count() == 5 {
            let ip: Ipv4Addr = f[0].parse().unwrap();
            if ip.is_multicast() || ip.is_broadcast() || f[1].eq_ignore_ascii_case("ff-ff-ff-ff-ff-ff") {
                continue;
            }
            out.push(Neighbor {
                ip: f[0].into(),
                mac: f[1].replace('-', ":"),
                dev: dev.clone(),
                // "dynamic"/"static" are translated; dynamic entries come first in every language's sort.
                state: if f[2].eq_ignore_ascii_case("static") || f[2].eq_ignore_ascii_case("statisch") { "PERMANENT".into() } else { "REACHABLE".into() },
            });
        }
    }
    out
}

/// DNS servers from `ipconfig /all`: lines mentioning DNS whose value is an
/// address, plus indented continuation lines with one more address.
pub fn parse_ipconfig_dns(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut in_dns = false;
    for l in text.lines() {
        let trimmed = l.trim();
        if let Some((key, val)) = l.split_once(" : ") {
            in_dns = key.to_ascii_uppercase().contains("DNS") && val.trim().parse::<IpAddr>().is_ok();
            if in_dns {
                let v = val.trim().split('%').next().unwrap_or("").to_string();
                if !out.contains(&v) {
                    out.push(v);
                }
            }
        } else if in_dns && trimmed.parse::<IpAddr>().is_ok() && l.starts_with(' ') {
            let v = trimmed.split('%').next().unwrap_or("").to_string();
            if !out.contains(&v) {
                out.push(v);
            }
        } else {
            in_dns = false;
        }
    }
    out
}

/// `sc queryex type= service state= all`.
pub fn parse_sc_query(text: &str) -> Vec<Unit> {
    let mut out = Vec::new();
    let mut cur: Option<Unit> = None;
    let mut exit: i64 = 0;
    let mut state = String::new();
    let flush = |cur: &mut Option<Unit>, state: &str, exit: i64, out: &mut Vec<Unit>| {
        if let Some(mut u) = cur.take() {
            let st = state.to_ascii_lowercase();
            u.sub = st.clone();
            // 1077 = ERROR_SERVICE_NEVER_STARTED: a stopped manual service is not a failure.
            let failed = st == "stopped" && exit != 0 && exit != 1077;
            u.active = if failed { "failed".into() } else if st == "running" { "active".into() } else { "inactive".into() };
            out.push(u);
        }
    };
    for l in text.lines() {
        let t = l.trim();
        let Some((k, v)) = t.split_once(':') else { continue };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "SERVICE_NAME" => {
                flush(&mut cur, &state, exit, &mut out);
                cur = Some(Unit { name: v.to_string(), ..Default::default() });
                exit = 0;
                state.clear();
            }
            "DISPLAY_NAME" => {
                if let Some(u) = cur.as_mut() {
                    u.description = v.to_string();
                }
            }
            "STATE" => state = v.split_whitespace().nth(1).unwrap_or("").to_string(),
            "WIN32_EXIT_CODE" => exit = v.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0),
            "PID" => {
                if let Some(u) = cur.as_mut() {
                    u.main_pid = v.parse().unwrap_or(0);
                }
            }
            _ => {}
        }
    }
    flush(&mut cur, &state, exit, &mut out);
    out
}

/// `quser`: "user  session  id  state  idle  logon-time". The session name is
/// empty for disconnected sessions, so columns are found by the numeric ID.
pub fn parse_quser(text: &str) -> Vec<Session> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.trim_start_matches([' ', '>']).split_whitespace().collect();
            let id_at = f.iter().position(|t| t.parse::<u32>().is_ok())?;
            if id_at == 0 || f.len() < id_at + 3 {
                return None;
            }
            let idle = f[id_at + 2];
            Some(Session {
                user: f[0].to_string(),
                tty: if id_at >= 2 { f[1].to_string() } else { String::new() },
                from: String::new(),
                login: f[id_at + 3..].join(" "),
                idle: if idle == "none" || idle == "." { String::new() } else { idle.to_string() },
                what: f[id_at + 1].to_string(),
            })
        })
        .collect()
}

/// Round-trip time from one line of Windows `ping` output, any language:
/// "time=12ms", "Zeit=12ms", "temps=12 ms", "time<1ms".
pub fn parse_ping_ms(text: &str) -> Option<f64> {
    let b = text.as_bytes();
    for (i, w) in b.windows(2).enumerate() {
        if w == b"ms" {
            let mut j = i;
            while j > 0 && b[j - 1] == b' ' {
                j -= 1;
            }
            let end = j;
            while j > 0 && b[j - 1].is_ascii_digit() {
                j -= 1;
            }
            if j < end && j > 0 && (b[j - 1] == b'=' || b[j - 1] == b'<') {
                let v: f64 = text[j..end].parse().ok()?;
                return Some(if b[j - 1] == b'<' { v / 2.0 } else { v });
            }
        }
    }
    None
}

/// `tracert -d`: "  3    12 ms    11 ms    *     10.0.0.1".
pub fn parse_tracert(text: &str) -> Vec<Hop> {
    let mut out = Vec::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        let Some(n) = f.first().and_then(|x| x.parse::<u32>().ok()) else { continue };
        let (mut times, mut stars, mut host) = (Vec::new(), 0u32, String::from("*"));
        let mut i = 1;
        while i < f.len() {
            let t = f[i];
            if t == "*" {
                stars += 1;
            } else if f.get(i + 1) == Some(&"ms") {
                let v = t.trim_start_matches('<').parse::<f64>().unwrap_or(0.0);
                times.push(if t.starts_with('<') { v / 2.0 } else { v });
                i += 1;
            } else if t.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
                host = t.trim_matches(['[', ']']).to_string();
            }
            i += 1;
        }
        if times.is_empty() && stars == 0 {
            continue; // header lines like "Tracing route to … over a maximum of 30 hops"
        }
        let sent = times.len() as u32 + stars;
        out.push(Hop {
            n,
            host,
            loss_pct: stars as f64 / sent.max(1) as f64 * 100.0,
            sent,
            last: times.last().copied().unwrap_or(0.0),
            avg: if times.is_empty() { 0.0 } else { times.iter().sum::<f64>() / times.len() as f64 },
            best: times.iter().copied().fold(f64::INFINITY, f64::min).min(if times.is_empty() { 0.0 } else { f64::INFINITY }),
            worst: times.iter().copied().fold(0.0, f64::max),
        });
    }
    out
}

fn between<'a>(s: &'a str, a: &str, b: &str) -> Option<&'a str> {
    let i = s.find(a)? + a.len();
    let j = s[i..].find(b)? + i;
    Some(&s[i..j])
}

/// `2026-11-25T08:00:00.1234567Z` → SystemTime.
fn parse_iso(s: &str) -> Option<std::time::SystemTime> {
    let (d, t) = s.split_once('T')?;
    let mut dp = d.split('-').map(|x| x.parse::<i64>().ok());
    let (y, m, dd) = (dp.next()??, dp.next()??, dp.next()??);
    let mut tp = t.trim_end_matches('Z').split(':');
    let h: i64 = tp.next()?.parse().ok()?;
    let mi: i64 = tp.next()?.parse().ok()?;
    let sec: f64 = tp.next()?.parse().ok()?;
    let secs = crate::util::days_from_civil(y, m as u32, dd as u32) * 86_400 + h * 3600 + mi * 60 + sec as i64;
    Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs.max(0) as u64))
}

/// `wevtutil qe System /f:RenderedXml` → classified events, newest first.
pub fn parse_events(xml: &str) -> Vec<KEvent> {
    let mut out = Vec::new();
    for ev in xml.split("<Event ").skip(1) {
        let provider = between(ev, "<Provider Name='", "'").or_else(|| between(ev, "<Provider Name=\"", "\"")).unwrap_or("");
        let id: u32 = between(ev, "<EventID", "</EventID>").and_then(|x| x.rsplit('>').next()).and_then(|x| x.trim().parse().ok()).unwrap_or(0);
        let level: u8 = between(ev, "<Level>", "</Level>").and_then(|x| x.trim().parse().ok()).unwrap_or(4);
        let at = between(ev, "SystemTime='", "'").or_else(|| between(ev, "SystemTime=\"", "\"")).and_then(parse_iso).unwrap_or(std::time::UNIX_EPOCH);
        let msg = between(ev, "<Message>", "</Message>").unwrap_or("").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">");
        let msg = msg.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" ");
        // Windows levels: 1 critical, 2 error, 3 warning → syslog 2, 3, 4.
        let sys_level = match level {
            1 => 2,
            2 => 3,
            3 => 4,
            _ => 6,
        };
        let kind = match (provider, id) {
            ("Microsoft-Windows-Kernel-Power", 41) => Some("POWER"),
            ("Microsoft-Windows-Resource-Exhaustion-Detector", _) => Some("OOM"),
            ("disk", _) | ("Disk", _) => Some("IO"),
            ("Ntfs", _) | ("Microsoft-Windows-Ntfs", _) => Some("FS"),
            ("Microsoft-Windows-WHEA-Logger", _) => Some("HW"),
            ("BugCheck", _) | ("Microsoft-Windows-WER-SystemErrorReporting", _) => Some("CRASH"),
            _ => classify(&msg, sys_level),
        };
        if let Some(kind) = kind {
            let text = if msg.is_empty() { format!("{provider} event {id}") } else { format!("{provider}: {msg}") };
            out.push(KEvent { at, kind, level: sys_level, text });
        }
    }
    out
}

/// Run a console tool and return stdout (lossy: the OEM code page differs per locale,
/// but the parsers only look at ASCII numbers and addresses).
pub fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let o = std::process::Command::new(cmd).args(args).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Recent System-log events (newest first), XML rendered in the user's language.
pub fn system_events(count: u32, query: Option<&str>) -> Option<String> {
    let c = format!("/c:{count}");
    let mut args = vec!["qe", "System", "/rd:true", "/f:RenderedXml", c.as_str()];
    let q;
    if let Some(query) = query {
        q = format!("/q:{query}");
        args.push(&q);
    }
    run("wevtutil", &args)
}

/// Service Control Manager events that mention a service (crashes, restarts,
/// start/stop), as display lines for the service journal pane.
pub fn service_events(service: &str) -> Vec<String> {
    let Some(xml) = system_events(400, Some("*[System[Provider[@Name='Service Control Manager']]]")) else {
        return vec!["wevtutil failed: run from an elevated prompt to read the System log".into()];
    };
    let display = run("sc", &["getdisplayname", service]).and_then(|t| t.lines().find_map(|l| l.split_once('=').map(|(_, v)| v.trim().to_string()))).unwrap_or_default();
    let needle = |m: &str| m.contains(service) || (!display.is_empty() && m.contains(&display));
    let mut out = Vec::new();
    for ev in xml.split("<Event ").skip(1) {
        let msg = between(ev, "<Message>", "</Message>").unwrap_or("");
        if !needle(msg) {
            continue;
        }
        let at = between(ev, "SystemTime='", "'").or_else(|| between(ev, "SystemTime=\"", "\"")).unwrap_or("");
        let at = at.get(..19).unwrap_or(at).replace('T', " ");
        out.push(format!("{at}  {}", msg.split_whitespace().collect::<Vec<_>>().join(" ")));
    }
    if out.is_empty() {
        out.push(format!("no Service Control Manager events for {service} in the last 400 System events"));
    }
    out
}

/// Classified System-log events (link changes, disk and NTFS errors, unexpected
/// reboots, crashes, resource exhaustion), oldest first.
pub fn read_events() -> Result<Vec<KEvent>, String> {
    let xml = system_events(300, Some("*[System[(Level=1 or Level=2 or Level=3)]]")).ok_or("wevtutil qe System failed (needs Event Log access)")?;
    let mut v = parse_events(&xml);
    v.reverse();
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_table_buffers() {
        // One IPv4 row: LISTEN on 0.0.0.0:135, pid 1012; one ESTABLISHED 10.0.0.5:51000 -> 1.1.1.1:443, pid 42.
        let mut b = 2u32.to_ne_bytes().to_vec();
        b.extend(2u32.to_ne_bytes());
        b.extend([0, 0, 0, 0]);
        b.extend([0, 135, 0, 0]);
        b.extend([0, 0, 0, 0]);
        b.extend([0, 0, 0, 0]);
        b.extend(1012u32.to_ne_bytes());
        b.extend(5u32.to_ne_bytes());
        b.extend([10, 0, 0, 5]);
        b.extend(51000u16.to_be_bytes());
        b.extend([0, 0]);
        b.extend([1, 1, 1, 1]);
        b.extend(443u16.to_be_bytes());
        b.extend([0, 0]);
        b.extend(42u32.to_ne_bytes());
        let v = parse_tcp4(&b);
        assert_eq!(v[0], WinSock { proto: "TCP", v6: false, local: "*:135".into(), remote: String::new(), state: "LISTEN", pid: 1012 });
        assert_eq!(v[1].remote, "1.1.1.1:443");
        assert_eq!(v[1].local, "10.0.0.5:51000");
        assert_eq!(v[1].state, "ESTABLISHED");
    }

    /// Runs on the windows-latest CI runner: real IP Helper tables and counters.
    #[cfg(windows)]
    #[test]
    fn real_windows_apis() {
        let socks = sockets();
        assert!(socks.iter().any(|s| s.state == "LISTEN"), "no listening sockets: {socks:?}");
        let names = process_names();
        assert!(names.len() > 5);
        let mut c = std::collections::HashMap::new();
        counters(&mut c);
        assert!(c["Tcp.OutSegs"] > 0);
        assert!(!parse_route_print(&run("route", &["print"]).unwrap()).is_empty());
        assert!(!parse_sc_query(&run("sc", &["queryex", "type=", "service", "state=", "all"]).unwrap()).is_empty());
        assert!(super::super::probes::run_once(&super::super::probes::Target::Icmp("127.0.0.1".parse().unwrap())).is_ok());
    }

    #[test]
    fn rows_match_lsof_shape() {
        let names = std::collections::HashMap::from([(42u32, "chrome.exe".to_string())]);
        let v = to_open_files(vec![WinSock { proto: "TCP", v6: false, local: "10.0.0.5:51000".into(), remote: "1.1.1.1:443".into(), state: "ESTABLISHED", pid: 42 }], &names);
        assert_eq!(v[0].command, "chrome.exe");
        assert_eq!(v[0].endpoints(), ("10.0.0.5:51000", "1.1.1.1:443"));
        assert_eq!(v[0].local_port(), Some(51000));
        assert!(v[0].is_network());
    }

    #[test]
    fn udp6_buffer() {
        let mut b = 1u32.to_ne_bytes().to_vec();
        let mut lo = [0u8; 16];
        lo[15] = 1;
        b.extend(lo);
        b.extend(0u32.to_ne_bytes());
        b.extend(53u16.to_be_bytes());
        b.extend([0, 0]);
        b.extend(7u32.to_ne_bytes());
        let v = parse_udp6(&b);
        assert_eq!(v[0].local, "[::1]:53");
        assert_eq!(v[0].pid, 7);
    }

    #[test]
    fn route_print() {
        let t = "IPv4 Route Table\n===\nActive Routes:\nNetwork Destination        Netmask          Gateway       Interface  Metric\n          0.0.0.0          0.0.0.0      172.20.48.1    172.20.52.94     15\n      172.20.48.0    255.255.240.0         On-link      172.20.52.94    271\nPersistent Routes:\n  Network Address          Netmask  Gateway Address  Metric\n          0.0.0.0          0.0.0.0     10.0.0.1  Default\n\nIPv6 Route Table\nActive Routes:\n If Metric Network Destination      Gateway\n  1    331 ::1/128                  On-link\n  5    271 fe80::c5e3:2f45:1d1c:1d2c/128\n                                    On-link\n  5    281 ::/0                     fe80::1\n";
        let r = parse_route_print(t);
        assert_eq!(r[0].dst, "default");
        assert_eq!(r[0].gateway, "172.20.48.1");
        assert_eq!(r[1].dst, "172.20.48.0/20");
        assert_eq!(r[1].gateway, "");
        assert_eq!(r.iter().filter(|x| x.family == "inet6").count(), 3);
        assert_eq!(r.last().unwrap().gateway, "fe80::1");
        assert_eq!(r.last().unwrap().dst, "default");
    }

    #[test]
    fn arp_ipconfig_sc_quser() {
        let a = parse_arp_a("\nInterface: 172.20.52.94 --- 0x5\n  Internet Address      Physical Address      Type\n  172.20.48.1           00-15-5d-a8-b2-c1     dynamic\n  224.0.0.22            01-00-5e-00-00-16     static\n");
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].mac, "00:15:5d:a8:b2:c1");
        assert_eq!(a[0].dev, "172.20.52.94");
        let d = parse_ipconfig_dns("   DNS-Server  . . . . . . . . . . . : 172.20.48.1\n                                       8.8.8.8\n   NetBIOS over Tcpip. . . . . . . . : Enabled\n   Connection-specific DNS Suffix  . : corp.example\n");
        assert_eq!(d, vec!["172.20.48.1", "8.8.8.8"]);
        let s = parse_sc_query("SERVICE_NAME: Spooler\nDISPLAY_NAME: Print Spooler\n        TYPE               : 110  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING\n        WIN32_EXIT_CODE    : 0  (0x0)\n        PID                : 2212\n\nSERVICE_NAME: Broken\nDISPLAY_NAME: Broken Service\n        STATE              : 1  STOPPED\n        WIN32_EXIT_CODE    : 1067  (0x42b)\n        PID                : 0\n\nSERVICE_NAME: Manual\nDISPLAY_NAME: Manual one\n        STATE              : 1  STOPPED\n        WIN32_EXIT_CODE    : 1077  (0x435)\n");
        assert_eq!(s.len(), 3);
        assert_eq!((s[0].active.as_str(), s[0].main_pid), ("active", 2212));
        assert!(s[1].failed());
        assert!(!s[2].failed());
        let q = parse_quser(" USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME\n>administrator         console             1  Active      none   11/25/2026 9:05 AM\n bob                   rdp-tcp#0           2  Active          5  11/25/2026 10:00 AM\n");
        assert_eq!(q.len(), 2);
        assert_eq!(q[0].user, "administrator");
        assert_eq!(q[1].tty, "rdp-tcp#0");
        assert_eq!(q[1].idle, "5");
        assert_eq!(q[1].login, "11/25/2026 10:00 AM");
    }

    #[test]
    fn ping_and_tracert() {
        assert_eq!(parse_ping_ms("Reply from 1.1.1.1: bytes=32 time=12ms TTL=57"), Some(12.0));
        assert_eq!(parse_ping_ms("Antwort von 1.1.1.1: Bytes=32 Zeit=7ms TTL=57"), Some(7.0));
        assert_eq!(parse_ping_ms("Réponse de 1.1.1.1 : octets=32 temps=15 ms TTL=57"), Some(15.0));
        assert_eq!(parse_ping_ms("Reply from 192.168.1.1: bytes=32 time<1ms TTL=64"), Some(0.5));
        assert_eq!(parse_ping_ms("Request timed out."), None);
        assert_eq!(parse_ping_ms("Reply from 10.0.0.1: Destination host unreachable."), None);
        let h = parse_tracert("Tracing route to 1.1.1.1 over a maximum of 30 hops\n\n  1    <1 ms    <1 ms    <1 ms  192.168.1.1\n  2     *        *        *     Request timed out.\n  3    12 ms    11 ms     *     10.0.0.1\n\nTrace complete.\n");
        assert_eq!(h.len(), 3);
        assert_eq!(h[0].host, "192.168.1.1");
        assert_eq!(h[1].loss_pct, 100.0);
        assert!((h[2].loss_pct - 33.3).abs() < 0.1);
        assert_eq!(h[2].best, 11.0);
    }

    #[test]
    fn event_log_xml() {
        let x = "<Events><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Kernel-Power' Guid='{x}'/><EventID>41</EventID><Level>1</Level><TimeCreated SystemTime='2026-11-25T08:00:00.1234567Z'/></System><RenderingInfo Culture='en-US'><Message>The system has rebooted without cleanly shutting down first.</Message></RenderingInfo></Event><Event xmlns='x'><System><Provider Name='e1dexpress'/><EventID Qualifiers='16384'>27</EventID><Level>3</Level><TimeCreated SystemTime='2026-11-25T09:00:00Z'/></System><RenderingInfo><Message>Intel(R) Ethernet Connection: Network link is disconnected.</Message></RenderingInfo></Event></Events>";
        let e = parse_events(x);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].kind, "POWER");
        assert_eq!(e[1].kind, "LINK");
        assert_eq!(crate::report::utc_timestamp(e[0].at), "2026-11-25 08:00:00 UTC");
    }
}
