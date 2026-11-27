//! `vigil syslog`: a syslog receiver for the moment you're working on the
//! network. Point a switch, router or firewall at this machine and watch link
//! flaps, OSPF/BGP neighbour changes, spanning tree, logins and commits live,
//! classified and coloured.
//!
//! UDP and TCP on the same port (514 by default; ports below 1024 need root,
//! so `-p 5514` works unprivileged). RFC 3164 and RFC 5424 messages; Junos,
//! Cisco IOS / NX-OS, Arista, HPE Aruba and Linux are recognised.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use super::Tone;

pub const SEVERITY: [&str; 8] = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"];

#[derive(Clone, Debug, PartialEq)]
pub struct Msg {
    pub severity: u8,
    pub facility: u8,
    pub host: String,
    pub app: String,
    /// RFC 5424 MSGID (Junos puts the event name here).
    pub msgid: String,
    pub text: String,
}

/// Parse one syslog message (RFC 5424, RFC 3164, or Cisco's sequence-number form).
pub fn parse(raw: &str) -> Msg {
    let raw = raw.trim_end_matches(['\n', '\r', '\0']);
    let (pri, rest) = match raw.strip_prefix('<').and_then(|r| r.split_once('>')) {
        Some((p, r)) if p.len() <= 3 => (p.parse::<u16>().unwrap_or(13), r),
        _ => (13, raw), // user.notice
    };
    let (facility, severity) = ((pri / 8) as u8, (pri % 8) as u8);
    let words: Vec<&str> = rest.split(' ').collect();
    // RFC 5424: "1 2026-11-27T14:00:01Z host app procid msgid [sd] msg"
    if words.first() == Some(&"1") && words.len() >= 7 {
        let host = words[2].to_string();
        let app = words[3].to_string();
        let msgid = nil(words[5].to_string());
        let mut msg = words[6..].join(" ");
        if msg.starts_with('[') {
            // skip structured data blocks
            let mut depth = 0i32;
            let mut cut = 0;
            for (i, c) in msg.char_indices() {
                match c {
                    '[' => depth += 1,
                    ']' => {
                        depth -= 1;
                        if depth == 0 && !msg[i + 1..].starts_with('[') {
                            cut = i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            msg = msg[cut..].trim_start().to_string();
        } else if let Some(m) = msg.strip_prefix("- ") {
            msg = m.to_string();
        }
        return Msg { severity, facility, host: nil(host), app: nil(app), msgid, text: msg.trim_start_matches('\u{feff}').to_string() };
    }
    // RFC 3164: "Nov 27 14:00:01 host tag[pid]: msg" (Cisco: "34: *Mar  1 00:12:34.567: %LINK-3-UPDOWN: …")
    let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let r = rest.trim_start();
    let after_time = |s: &str| -> Option<String> {
        // "Mmm dd hh:mm:ss" with an optional leading '*' and fraction
        let s = s.trim_start_matches(['*', '.']);
        let mon = s.get(..3)?;
        if !months.contains(&mon) {
            return None;
        }
        let tail = s[3..].trim_start();
        let day_end = tail.find(' ')?;
        let tail = tail[day_end..].trim_start();
        let t_end = tail.find(' ').unwrap_or(tail.len());
        Some(tail[t_end..].trim_start().to_string())
    };
    if let Some(after) = after_time(r) {
        // Cisco sends "…: %FAC-SEV-MNEMONIC: text" without a host field
        let after = after.trim_start_matches(':').trim_start().to_string();
        if after.starts_with('%') {
            return Msg { severity, facility, host: String::new(), app: String::new(), msgid: String::new(), text: after };
        }
        let (host, rest) = after.split_once(' ').unwrap_or(("", after.as_str()));
        let (tag, msg) = match rest.split_once(": ") {
            Some((t, m)) if !t.contains(' ') => (t, m),
            _ => ("", rest),
        };
        let app = tag.split('[').next().unwrap_or("").to_string();
        return Msg { severity, facility, host: host.to_string(), app, msgid: String::new(), text: msg.to_string() };
    }
    // "34: *Mar  1 00:12:34.567: %LINK-…" (sequence number first)
    if let Some((seq, tail)) = r.split_once(": ") {
        if seq.chars().all(|c| c.is_ascii_digit()) {
            if let Some(after) = after_time(tail.trim_start()) {
                return Msg { severity, facility, host: String::new(), app: String::new(), msgid: String::new(), text: after.trim_start_matches(':').trim_start().to_string() };
            }
        }
    }
    Msg { severity, facility, host: String::new(), app: String::new(), msgid: String::new(), text: r.to_string() }
}

fn nil(s: String) -> String {
    if s == "-" {
        String::new()
    } else {
        s
    }
}

/// What a message is about: (kind, tone).
pub fn classify(m: &Msg) -> (&'static str, Tone) {
    let full = format!("{} {} {}", m.app, m.msgid, m.text);
    let t = full.to_ascii_lowercase();
    let u = &full;
    let has = |s: &str| t.contains(s);
    // Whole words: Cisco's "%LINK-3-UPDOWN … changed state to up" is not a down event.
    let words: Vec<&str> = t.split(|c: char| !c.is_ascii_alphanumeric()).collect();
    let down = words.iter().any(|w| matches!(*w, "down" | "disconnected" | "idle" | "lost"));
    if u.contains("SNMP_TRAP_LINK_DOWN") || u.contains("SNMP_TRAP_LINK_UP") || u.contains("%LINK-") || u.contains("%LINEPROTO-") || u.contains("%ETHPORT-") || has("link down") || has("link up") || has("link is down") || has("link is up") {
        return ("LINK", if down || u.contains("LINK_DOWN") { Tone::Bad } else { Tone::Good });
    }
    if u.contains("RPD_OSPF_NBR") || u.contains("RPD_BGP_NEIGHBOR_STATE_CHANGED") || u.contains("BGP_") || u.contains("%OSPF-") || u.contains("%BGP-") || u.contains("RPD_ISIS_ADJ") || u.contains("%ISIS-") || u.contains("%OSPFV3-") || has("adjacency") || has("bgp peer") || has("neighbor") && (has("ospf") || has("bgp") || has("isis")) {
        let bad = down || has("notification") || has("holdtime") || has("hold time") || has("to active");
        return ("ROUTING", if bad { Tone::Bad } else { Tone::Good });
    }
    if u.contains("%PM-4-ERR_DISABLE") || has("err-disable") || has("errdisable") || has("err_disable") {
        return ("ERRDISABLE", Tone::Bad);
    }
    if u.contains("DUPLEX_MISMATCH") || has("duplex mismatch") {
        return ("DUPLEX", Tone::Warn);
    }
    if has("spanning") || u.contains("%SPANTREE") || u.contains("STP") || has("topology change") || u.contains("%STP-") {
        return ("STP", Tone::Warn);
    }
    if u.contains("LOGIN_FAILED") || u.contains("SSHD_LOGIN_FAILED") || has("authentication failure") || has("failed password") || u.contains("%PORT_SECURITY") || u.contains("PORT_SECURITY") || u.contains("%SW_DAI") || u.contains("%DHCP_SNOOPING") || u.contains("RT_SCREEN") || u.contains("RT_IDP") || has("invalid user") {
        return ("SECURITY", Tone::Warn);
    }
    if u.contains("UI_COMMIT") || u.contains("UI_CFG_AUDIT") || u.contains("%SYS-5-CONFIG") || has("configured from") || has("commit complete") || u.contains("%PARSER-5-CFGLOG") {
        return ("CONFIG", Tone::Normal);
    }
    if u.contains("CHASSISD") || u.contains("%ENVMON") || u.contains("%PLATFORM") || has("power supply") || has("fan ") || has("temperature") || has("psu") {
        return ("HW", if m.severity <= 3 { Tone::Bad } else { Tone::Warn });
    }
    if u.contains("UI_LOGIN_EVENT") || has("accepted password") || has("accepted publickey") || u.contains("%SEC_LOGIN-5-LOGIN_SUCCESS") {
        return ("LOGIN", Tone::Normal);
    }
    match m.severity {
        0..=3 => ("ERROR", Tone::Bad),
        4 => ("WARN", Tone::Warn),
        5 => ("NOTICE", Tone::Normal),
        _ => ("INFO", Tone::Dim),
    }
}

/// One display line.
pub fn line(from: &str, m: &Msg) -> (Tone, String) {
    let (kind, tone) = classify(m);
    let now = time_hms();
    let host = if m.host.is_empty() { from.to_string() } else { m.host.clone() };
    let app = match (m.app.is_empty(), m.msgid.is_empty()) {
        (true, _) => String::new(),
        (false, true) => format!("{}: ", m.app),
        (false, false) => format!("{} {}: ", m.app, m.msgid),
    };
    (tone, format!("{now} {host:<16} {:<7} {kind:<10} {app}{}", SEVERITY[m.severity as usize & 7], m.text.trim()))
}

fn time_hms() -> String {
    let s = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let local = s as i64 + crate::util::utc_offset_secs();
    let d = local.rem_euclid(86_400);
    format!("{:02}:{:02}:{:02}", d / 3600, d % 3600 / 60, d % 60)
}

/// Listen until `stop` is set. `filter` keeps lines containing that text
/// (case-insensitive); `save` appends every raw message to a file.
pub fn listen(port: u16, filter: Option<&str>, save: Option<&std::path::Path>, stop: Arc<AtomicBool>, emit: &(dyn Fn(Tone, String) + Sync)) -> Result<(), String> {
    let udp = crate::util::bind_udp_any(port).map_err(|e| bind_error(port, &e))?;
    udp.set_read_timeout(Some(Duration::from_millis(300))).ok();
    let tcp: Option<TcpListener> = crate::util::bind_tcp_any(port).ok();
    if let Some(t) = &tcp {
        t.set_nonblocking(true).ok();
    }
    // Addresses to point devices at, the default-route interface first.
    let main_if = crate::collect::netinfo::default_iface();
    let mut ips: Vec<(bool, String)> = sysinfo::Networks::new_with_refreshed_list()
        .iter()
        .flat_map(|(name, d)| d.ip_networks().iter().map(|n| (Some(name) == main_if.as_ref(), n.addr)).collect::<Vec<_>>())
        .filter(|(_, a)| a.is_ipv4() && !a.is_loopback() && !a.to_string().starts_with("169.254."))
        .map(|(m, a)| (m, a.to_string()))
        .collect();
    ips.sort_by_key(|(main, _)| !main);
    let ips: Vec<String> = ips.into_iter().map(|(_, a)| a).collect();
    let me = ips.first().cloned().unwrap_or_else(|| "THIS-HOST".into());
    emit(Tone::Head, format!("syslog receiver on UDP{} {port} · {} · x or ctrl-c stops", if tcp.is_some() { "/TCP" } else { "" }, if ips.is_empty() { "no IPv4 address".into() } else { ips.join(", ") }));
    let port_part = if port == 514 { String::new() } else { format!(" port {port}") };
    emit(Tone::Dim, format!("  Junos: set system syslog host {me} any any{port_part} · Cisco: logging host {me}{} · Aruba: logging {me}", if port == 514 { String::new() } else { format!(" transport udp port {port}") }));
    let filter = filter.map(|f| f.to_ascii_lowercase()).filter(|f| !f.is_empty());
    let file = save.map(|p| std::fs::OpenOptions::new().create(true).append(true).open(p)).transpose().map_err(|e| format!("save file: {e}"))?;
    let file = Arc::new(Mutex::new(file));
    let count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let handle = |from: String, raw: &str| {
        if let Ok(mut f) = file.lock() {
            if let Some(f) = f.as_mut() {
                let _ = writeln!(f, "{from} {}", raw.trim_end());
            }
        }
        let m = parse(raw);
        let (tone, text) = line(&from, &m);
        if filter.as_ref().is_none_or(|f| text.to_ascii_lowercase().contains(f.as_str())) {
            count.fetch_add(1, Ordering::Relaxed);
            emit(tone, text);
        }
    };
    thread::scope(|s| {
        if let Some(tcp) = &tcp {
            s.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    match tcp.accept() {
                        Ok((conn, peer)) => {
                            let from = peer.ip().to_canonical().to_string();
                            conn.set_nonblocking(false).ok();
                            conn.set_read_timeout(Some(Duration::from_millis(500))).ok();
                            let stop = stop.clone();
                            let handle = &handle;
                            s.spawn(move || {
                                let mut r = BufReader::new(conn);
                                let mut buf = String::new();
                                while !stop.load(Ordering::Relaxed) {
                                    buf.clear();
                                    match r.read_line(&mut buf) {
                                        Ok(0) => break,
                                        Ok(_) => {
                                            // RFC 6587 octet counting: "123 <34>…"
                                            let msg = match buf.split_once(' ') {
                                                Some((n, rest)) if n.chars().all(|c| c.is_ascii_digit()) && rest.starts_with('<') => rest,
                                                _ => buf.as_str(),
                                            };
                                            handle(from.clone(), msg);
                                        }
                                        Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
                                        Err(_) => break,
                                    }
                                }
                            });
                        }
                        Err(_) => thread::sleep(Duration::from_millis(200)),
                    }
                }
            });
        }
        let mut buf = vec![0u8; 8192];
        while !stop.load(Ordering::Relaxed) {
            if let Ok((n, from)) = udp.recv_from(&mut buf) {
                let from = from_ip(from);
                handle(from, &String::from_utf8_lossy(&buf[..n]));
            }
        }
    });
    emit(Tone::Head, format!("stopped · {} message(s)", count.load(Ordering::Relaxed)));
    Ok(())
}

fn from_ip(a: SocketAddr) -> String {
    a.ip().to_canonical().to_string()
}

fn bind_error(port: u16, e: &std::io::Error) -> String {
    if port < 1024 && e.kind() == std::io::ErrorKind::PermissionDenied {
        format!("port {port} needs root: run sudo vigil, or use -p 5514 and point the device at that port")
    } else if e.kind() == std::io::ErrorKind::AddrInUse {
        format!("port {port} is already in use (rsyslog or syslog-ng?): use -p 5514")
    } else {
        format!("listen on {port}: {e}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    #[test]
    fn parses_vendor_messages() {
        let j = parse("<28>Nov 27 14:00:01 vsrx1 mib2d[1234]: SNMP_TRAP_LINK_DOWN: ifIndex 526, ifAdminStatus up(1), ifOperStatus down(2), ifName ge-0/0/1");
        assert_eq!((j.severity, j.host.as_str(), j.app.as_str()), (4, "vsrx1", "mib2d"));
        assert_eq!(classify(&j), ("LINK", Tone::Bad));
        let c = parse("<187>34: *Mar  1 00:12:34.567: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up");
        assert_eq!(c.severity, 3);
        assert!(c.text.starts_with("%LINK-3-UPDOWN"), "{c:?}");
        assert_eq!(classify(&c), ("LINK", Tone::Good));
        let b = parse("<30>1 2026-11-27T14:00:01.123Z mx1 rpd 2111 RPD_BGP_NEIGHBOR_STATE_CHANGED [junos@2636.1.1.1.2.21 peer-name=\"10.0.0.2\"] BGP peer 10.0.0.2 (External AS 65001) changed state from Established to Idle (event HoldTime)");
        assert_eq!((b.host.as_str(), b.app.as_str()), ("mx1", "rpd"));
        assert!(b.text.starts_with("BGP peer 10.0.0.2"), "{b:?}");
        assert_eq!(classify(&b), ("ROUTING", Tone::Bad));
        let o = parse("<189>Nov 27 14:00:02 r1 %OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.9 on Gi0/0 from LOADING to FULL, Loading Done");
        assert_eq!(classify(&o).0, "ROUTING");
        assert_eq!(classify(&parse("<14>Nov 27 14:00:03 ex4300 mgd[99]: UI_COMMIT: User 'admin' requested 'commit' operation")).0, "CONFIG");
        assert_eq!(classify(&parse("<36>Nov 27 14:00:04 sw1 %PM-4-ERR_DISABLE: bpduguard error detected on Gi1/0/5")).0, "ERRDISABLE");
        assert_eq!(classify(&parse("<38>Nov 27 14:00:05 srv sshd[1]: Failed password for root from 203.0.113.7 port 50122 ssh2")).0, "SECURITY");
        assert_eq!(parse("no priority at all").severity, 5);
    }

    #[test]
    fn receives_udp_messages() {
        let port = UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let got = Arc::new(Mutex::new(Vec::new()));
        let (g, st) = (got.clone(), stop.clone());
        let h = thread::spawn(move || listen(port, None, None, st, &move |_, l| g.lock().unwrap().push(l)));
        thread::sleep(Duration::from_millis(300));
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..5 {
            s.send_to(b"<28>Nov 27 14:00:01 vsrx1 mib2d[1]: SNMP_TRAP_LINK_DOWN: ifName ge-0/0/1", ("127.0.0.1", port)).unwrap();
            thread::sleep(Duration::from_millis(50));
            if got.lock().unwrap().iter().any(|l| l.contains("LINK")) {
                break;
            }
        }
        stop.store(true, Ordering::Relaxed);
        h.join().unwrap().unwrap();
        let lines = got.lock().unwrap();
        assert!(lines.iter().any(|l| l.contains("vsrx1") && l.contains("LINK") && l.contains("ge-0/0/1")), "{lines:?}");
    }
}
