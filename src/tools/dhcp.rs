//! `vigil dhcp`: which DHCP servers answer on this network?
//!
//! Broadcasts one DHCPDISCOVER (from a random, locally administered MAC so
//! your real lease is untouched) and lists every OFFER that comes back in a
//! few seconds. Two different servers on one VLAN is the classic "rogue
//! DHCP" problem (a home router plugged into a wall port); none at all means
//! no server, a missing relay (ip helper-address / forwarding-options
//! dhcp-relay) or DHCP snooping dropping it. Needs root (UDP port 68).

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use super::Tone;

#[derive(Clone, Debug, PartialEq)]
pub struct Offer {
    pub from: String,
    pub server_id: Option<Ipv4Addr>,
    pub your_ip: Ipv4Addr,
    pub mask: Option<Ipv4Addr>,
    pub routers: Vec<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub domain: String,
    pub lease_s: Option<u32>,
    pub relay: Option<Ipv4Addr>,
}

pub fn discover_packet(xid: u32, mac: [u8; 6]) -> Vec<u8> {
    let mut p = vec![0u8; 236];
    p[0] = 1; // BOOTREQUEST
    p[1] = 1; // Ethernet
    p[2] = 6;
    p[4..8].copy_from_slice(&xid.to_be_bytes());
    p[10] = 0x80; // broadcast flag: answer to 255.255.255.255
    p[28..34].copy_from_slice(&mac);
    p.extend([99, 130, 83, 99]); // magic cookie
    p.extend([53, 1, 1]); // DHCPDISCOVER
    p.extend([61, 7, 1]);
    p.extend(mac);
    p.extend([55, 8, 1, 3, 6, 15, 28, 42, 51, 54]);
    p.extend([57, 2, 0x05, 0xdc]);
    p.push(255);
    while p.len() < 300 {
        p.push(0);
    }
    p
}

fn ip4(b: &[u8]) -> Option<Ipv4Addr> {
    (b.len() >= 4).then(|| Ipv4Addr::new(b[0], b[1], b[2], b[3]))
}

/// Parse a DHCPOFFER for `xid`.
pub fn parse_offer(b: &[u8], xid: u32, from: &str) -> Option<Offer> {
    if b.len() < 240 || b[0] != 2 || b[4..8] != xid.to_be_bytes() || b[236..240] != [99, 130, 83, 99] {
        return None;
    }
    let mut o = Offer { from: from.to_string(), server_id: None, your_ip: ip4(&b[16..20])?, mask: None, routers: Vec::new(), dns: Vec::new(), domain: String::new(), lease_s: None, relay: None };
    let giaddr = ip4(&b[24..28])?;
    if !giaddr.is_unspecified() {
        o.relay = Some(giaddr);
    }
    let mut i = 240;
    let mut msg_type = 0;
    while i < b.len() {
        let code = b[i];
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        let len = *b.get(i + 1)? as usize;
        let v = b.get(i + 2..i + 2 + len)?;
        match code {
            53 => msg_type = *v.first()?,
            54 => o.server_id = ip4(v),
            1 => o.mask = ip4(v),
            3 => o.routers = v.chunks(4).filter_map(ip4).collect(),
            6 => o.dns = v.chunks(4).filter_map(ip4).collect(),
            15 => o.domain = String::from_utf8_lossy(v).trim_end_matches('\0').to_string(),
            51 if len == 4 => o.lease_s = Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]])),
            _ => {}
        }
        i += 2 + len;
    }
    (msg_type == 2).then_some(o)
}

#[cfg(unix)]
fn open_socket(iface: Option<&str>) -> Result<UdpSocket, String> {
    use std::os::fd::FromRawFd;
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP);
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let sock = UdpSocket::from_raw_fd(fd);
        let one: libc::c_int = 1;
        let opt = |level, name| libc::setsockopt(fd, level, name, &one as *const _ as *const libc::c_void, std::mem::size_of::<libc::c_int>() as libc::socklen_t);
        opt(libc::SOL_SOCKET, libc::SO_REUSEADDR);
        opt(libc::SOL_SOCKET, libc::SO_REUSEPORT);
        opt(libc::SOL_SOCKET, libc::SO_BROADCAST);
        if let Some(name) = iface {
            let cname = std::ffi::CString::new(name).map_err(|_| "bad interface name")?;
            #[cfg(target_os = "linux")]
            let r = libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, cname.as_ptr() as *const libc::c_void, name.len() as libc::socklen_t);
            #[cfg(target_os = "macos")]
            let r = {
                let idx = libc::if_nametoindex(cname.as_ptr());
                if idx == 0 {
                    return Err(format!("no interface {name}"));
                }
                libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_BOUND_IF, &idx as *const _ as *const libc::c_void, std::mem::size_of::<u32>() as libc::socklen_t)
            };
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            let r = 0;
            if r != 0 {
                return Err(format!("bind to {name}: {}", std::io::Error::last_os_error()));
            }
        }
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        sa.sin_family = libc::AF_INET as _;
        sa.sin_port = 68u16.to_be();
        #[cfg(target_os = "macos")]
        {
            sa.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        }
        if libc::bind(fd, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t) != 0 {
            let e = std::io::Error::last_os_error();
            return Err(if e.kind() == std::io::ErrorKind::PermissionDenied { "DHCP uses UDP port 68, which needs root: run sudo vigil dhcp".into() } else { format!("bind UDP 68: {e}") });
        }
        Ok(sock)
    }
}

#[cfg(not(unix))]
fn open_socket(_iface: Option<&str>) -> Result<UdpSocket, String> {
    let s = UdpSocket::bind("0.0.0.0:68").map_err(|e| format!("bind UDP 68: {e} (the Windows DHCP client may hold the port; run as administrator)"))?;
    s.set_broadcast(true).map_err(|e| e.to_string())?;
    Ok(s)
}

/// Broadcast a DISCOVER and collect offers for `wait`.
pub fn run(iface: Option<&str>, wait: Duration, emit: &dyn Fn(Tone, String)) -> Result<Vec<Offer>, String> {
    // Without -i, use the interface of the IPv4 default route: a broadcast on a
    // multi-homed host otherwise leaves through whichever interface the OS picks.
    let default_if = if iface.is_none() && !cfg!(windows) { crate::collect::netinfo::default_iface() } else { None };
    let iface = iface.or(default_if.as_deref());
    let sock = open_socket(iface)?;
    sock.set_read_timeout(Some(Duration::from_millis(250))).ok();
    let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(7);
    let xid = (seed as u32) ^ std::process::id().rotate_left(13);
    let mut mac = [0x02, 0, 0, 0, 0, 0]; // locally administered, unicast
    mac[1..].copy_from_slice(&(seed >> 8).to_be_bytes()[3..8]);
    emit(Tone::Head, format!("DHCP discover{} · test MAC {} · waiting {} s for offers", iface.map(|i| format!(" on {i}")).unwrap_or_default(), mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"), wait.as_secs()));
    let dst: SocketAddr = "255.255.255.255:67".parse().unwrap();
    let pkt = discover_packet(xid, mac);
    sock.send_to(&pkt, dst).map_err(|e| format!("send: {e} (pick the interface with -i)"))?;
    let mut offers: Vec<Offer> = Vec::new();
    let mut buf = [0u8; 1500];
    let start = Instant::now();
    let mut resent = false;
    while start.elapsed() < wait {
        if !resent && start.elapsed() > wait / 2 && offers.is_empty() {
            let _ = sock.send_to(&pkt, dst); // one retry, like real clients
            resent = true;
        }
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            if let Some(o) = parse_offer(&buf[..n], xid, &from.ip().to_string()) {
                if !offers.iter().any(|x| x.server_id == o.server_id && x.from == o.from) {
                    let lease = o.lease_s.map(|l| crate::util::fmt_duration(l as u64)).unwrap_or_else(|| "?".into());
                    emit(
                        Tone::Normal,
                        format!(
                            "  offer from {} (server id {}){}: {} /{} · router {} · DNS {} · lease {lease}{}",
                            o.from,
                            o.server_id.map(|s| s.to_string()).unwrap_or_else(|| "?".into()),
                            o.relay.map(|r| format!(" via relay {r}")).unwrap_or_default(),
                            o.your_ip,
                            o.mask.map(|m| u32::from(m).count_ones().to_string()).unwrap_or_else(|| "?".into()),
                            o.routers.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(", "),
                            o.dns.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(", "),
                            if o.domain.is_empty() { String::new() } else { format!(" · domain {}", o.domain) },
                        ),
                    );
                    offers.push(o);
                }
            }
        }
    }
    let servers: std::collections::BTreeSet<String> = offers.iter().map(|o| o.server_id.map(|s| s.to_string()).unwrap_or_else(|| o.from.clone())).collect();
    match servers.len() {
        0 => emit(Tone::Bad, "→ no DHCP server answered: no server on this VLAN, a missing relay (Cisco: ip helper-address · Junos: forwarding-options dhcp-relay), or DHCP snooping drops it".into()),
        1 => emit(Tone::Good, format!("→ one DHCP server: {}", servers.iter().next().unwrap())),
        n => emit(Tone::Bad, format!("→ {n} different DHCP servers answer: {}. One is probably rogue (a home router on a wall port?). Find its MAC in the switch's MAC table and enable DHCP snooping (Junos: dhcp-security · Cisco: ip dhcp snooping)", servers.into_iter().collect::<Vec<_>>().join(", "))),
    }
    Ok(offers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_and_offer() {
        let mac = [0x02, 1, 2, 3, 4, 5];
        let d = discover_packet(0xdeadbeef, mac);
        assert_eq!(d[0], 1);
        assert_eq!(&d[4..8], &0xdeadbeefu32.to_be_bytes());
        assert_eq!(&d[28..34], &mac);
        assert_eq!(&d[236..243], &[99, 130, 83, 99, 53, 1, 1]);
        // Build an OFFER the way a server would.
        let mut o = d.clone();
        o.truncate(240);
        o[0] = 2;
        o[16..20].copy_from_slice(&[10, 0, 0, 77]);
        o.extend([53, 1, 2, 54, 4, 10, 0, 0, 1, 1, 4, 255, 255, 255, 0, 3, 4, 10, 0, 0, 1, 6, 8, 10, 0, 0, 53, 1, 1, 1, 1, 15, 4, b'c', b'o', b'r', b'p', 51, 4, 0, 1, 81, 128, 255]);
        let off = parse_offer(&o, 0xdeadbeef, "10.0.0.1").unwrap();
        assert_eq!(off.your_ip, Ipv4Addr::new(10, 0, 0, 77));
        assert_eq!(off.server_id, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(off.mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(off.dns, vec![Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(1, 1, 1, 1)]);
        assert_eq!((off.domain.as_str(), off.lease_s), ("corp", Some(86_400)));
        assert!(parse_offer(&o, 1, "x").is_none(), "other transaction");
        let mut ack = o.clone();
        ack[242] = 5; // DHCPACK, not an offer
        assert!(parse_offer(&ack, 0xdeadbeef, "x").is_none());
    }
}
