//! Linux `NETLINK_SOCK_DIAG` client: the same interface `ss -ti` uses.
//!
//! One dump returns every TCP socket in the current network namespace with its
//! `struct tcp_info` (RTT, retransmits, cwnd, byte counters …), the receive /
//! send queues, owner uid and inode. It also implements `SOCK_DESTROY` to close
//! a single connection (needs CAP_NET_ADMIN and CONFIG_INET_DIAG_DESTROY).
//!
//! Message layouts follow include/uapi/linux/{netlink,inet_diag,sock_diag,tcp}.h.
//! Parsing is done on plain byte slices so it is unit-tested on every OS.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

pub const SOCK_DIAG_BY_FAMILY: u16 = 20;
pub const SOCK_DESTROY: u16 = 21;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_DUMP: u16 = 0x300;
const INET_DIAG_INFO: u16 = 2;
const NLMSG_HDRLEN: usize = 16;
const DIAG_MSG_LEN: usize = 72;

/// Socket identity exactly as the kernel reported it; sent back for SOCK_DESTROY.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagId {
    pub family: u8,
    /// `inet_diag_sockid` as raw bytes (ports + addresses in network order).
    pub raw: [u8; 48],
}

impl Default for DiagId {
    fn default() -> Self {
        Self { family: 0, raw: [0; 48] }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TcpStats {
    pub rtt_us: u32,
    pub rttvar_us: u32,
    pub min_rtt_us: u32,
    pub retransmits: u8,
    pub total_retrans: u32,
    pub lost: u32,
    pub unacked: u32,
    pub snd_cwnd: u32,
    pub snd_mss: u32,
    pub pmtu: u32,
    pub bytes_acked: u64,
    pub bytes_received: u64,
    pub delivery_rate: u64,
}

#[derive(Clone, Debug)]
pub struct DiagEntry {
    pub id: DiagId,
    pub inode: u64,
    pub tcp: Option<TcpStats>,
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

/// Parse `struct tcp_info`. Older kernels send a shorter struct; missing
/// fields stay zero.
pub fn parse_tcp_info(b: &[u8]) -> TcpStats {
    let g32 = |o| u32_at(b, o).unwrap_or(0);
    let g64 = |o| u64_at(b, o).unwrap_or(0);
    TcpStats {
        retransmits: b.get(2).copied().unwrap_or(0),
        snd_mss: g32(16),
        unacked: g32(24),
        lost: g32(32),
        pmtu: g32(60),
        rtt_us: g32(68),
        rttvar_us: g32(72),
        snd_cwnd: g32(80),
        total_retrans: g32(100),
        bytes_acked: g64(120),
        bytes_received: g64(128),
        min_rtt_us: g32(148),
        delivery_rate: g64(160),
    }
}

/// Parse a buffer of netlink messages. Returns the entries and whether the
/// dump is finished (NLMSG_DONE or an error was seen).
pub fn parse_messages(buf: &[u8], out: &mut Vec<DiagEntry>) -> Result<bool, i32> {
    let mut off = 0;
    while off + NLMSG_HDRLEN <= buf.len() {
        let len = u32_at(buf, off).unwrap_or(0) as usize;
        let ty = u16_at(buf, off + 4).unwrap_or(0);
        if len < NLMSG_HDRLEN || off + len > buf.len() {
            break;
        }
        let payload = &buf[off + NLMSG_HDRLEN..off + len];
        match ty {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => {
                let err = u32_at(payload, 0).map(|e| e as i32).unwrap_or(-1);
                if err != 0 {
                    return Err(-err);
                }
                return Ok(true); // ACK
            }
            SOCK_DIAG_BY_FAMILY if payload.len() >= DIAG_MSG_LEN => {
                let mut raw = [0u8; 48];
                raw.copy_from_slice(&payload[4..52]);
                let mut tcp = None;
                let mut a = DIAG_MSG_LEN;
                while a + 4 <= payload.len() {
                    let alen = u16_at(payload, a).unwrap_or(0) as usize;
                    let aty = u16_at(payload, a + 2).unwrap_or(0);
                    if alen < 4 || a + alen > payload.len() {
                        break;
                    }
                    if aty == INET_DIAG_INFO {
                        tcp = Some(parse_tcp_info(&payload[a + 4..a + alen]));
                    }
                    a += (alen + 3) & !3;
                }
                out.push(DiagEntry {
                    id: DiagId { family: payload[0], raw },
                    inode: u32_at(payload, 68).unwrap_or(0) as u64,
                    tcp,
                });
            }
            _ => {}
        }
        off += (len + 3) & !3;
    }
    Ok(false)
}

/// Build an `nlmsghdr + inet_diag_req_v2` request.
pub fn build_request(ty: u16, flags: u16, family: u8, protocol: u8, id: Option<&[u8; 48]>) -> Vec<u8> {
    let total = NLMSG_HDRLEN + 56;
    let mut v = Vec::with_capacity(total);
    v.extend_from_slice(&(total as u32).to_ne_bytes());
    v.extend_from_slice(&ty.to_ne_bytes());
    v.extend_from_slice(&flags.to_ne_bytes());
    v.extend_from_slice(&1u32.to_ne_bytes()); // seq
    v.extend_from_slice(&0u32.to_ne_bytes()); // pid: kernel
    v.push(family);
    v.push(protocol);
    v.push(1 << (INET_DIAG_INFO - 1)); // ext: ask for tcp_info
    v.push(0);
    v.extend_from_slice(&u32::MAX.to_ne_bytes()); // all states
    match id {
        Some(r) => v.extend_from_slice(r),
        None => v.extend_from_slice(&[0u8; 48]),
    }
    v
}

#[cfg(target_os = "linux")]
mod sys {
    use super::*;
    use std::io;

    struct Fd(i32);
    impl Drop for Fd {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }

    fn open() -> io::Result<Fd> {
        let fd = unsafe {
            libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, libc::NETLINK_SOCK_DIAG)
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = Fd(fd);
        // Never block the collector thread for long.
        let tv = libc::timeval { tv_sec: 2, tv_usec: 0 };
        unsafe {
            libc::setsockopt(
                fd.0,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            );
        }
        Ok(fd)
    }

    fn send(fd: &Fd, req: &[u8]) -> io::Result<()> {
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        let r = unsafe {
            libc::sendto(
                fd.0,
                req.as_ptr() as *const libc::c_void,
                req.len(),
                0,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if r < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn recv_all(fd: &Fd, out: &mut Vec<DiagEntry>) -> io::Result<()> {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = unsafe { libc::recv(fd.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            if n == 0 {
                return Ok(());
            }
            match parse_messages(&buf[..n as usize], out) {
                Ok(true) => return Ok(()),
                Ok(false) => continue,
                Err(errno) => return Err(io::Error::from_raw_os_error(errno)),
            }
        }
    }

    /// Dump every TCP socket (IPv4 + IPv6) of this network namespace.
    pub fn dump_tcp() -> io::Result<Vec<DiagEntry>> {
        let fd = open()?;
        let mut out = Vec::new();
        for fam in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
            let req = build_request(SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST | NLM_F_DUMP, fam, libc::IPPROTO_TCP as u8, None);
            send(&fd, &req)?;
            recv_all(&fd, &mut out)?;
        }
        Ok(out)
    }

    /// Close one TCP connection (like `ss -K`).
    pub fn destroy(id: &DiagId) -> io::Result<()> {
        let fd = open()?;
        let req = build_request(SOCK_DESTROY, NLM_F_REQUEST | NLM_F_ACK, id.family, libc::IPPROTO_TCP as u8, Some(&id.raw));
        send(&fd, &req)?;
        let mut sink = Vec::new();
        recv_all(&fd, &mut sink)
    }
}

#[cfg(target_os = "linux")]
pub use sys::{destroy, dump_tcp};

#[cfg(not(target_os = "linux"))]
pub fn destroy(_id: &DiagId) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "closing single connections needs Linux sock_diag",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_dump(inode: u32, rtt: u32, acked: u64) -> Vec<u8> {
        let mut tcp = vec![0u8; 168];
        tcp[68..72].copy_from_slice(&rtt.to_ne_bytes());
        tcp[100..104].copy_from_slice(&7u32.to_ne_bytes());
        tcp[120..128].copy_from_slice(&acked.to_ne_bytes());
        let mut payload = vec![0u8; DIAG_MSG_LEN];
        payload[0] = 2; // AF_INET
        payload[1] = 1; // ESTABLISHED
        payload[56..60].copy_from_slice(&5u32.to_ne_bytes()); // rqueue
        payload[68..72].copy_from_slice(&inode.to_ne_bytes());
        let alen = (4 + tcp.len()) as u16;
        payload.extend_from_slice(&alen.to_ne_bytes());
        payload.extend_from_slice(&INET_DIAG_INFO.to_ne_bytes());
        payload.extend_from_slice(&tcp);
        let len = (NLMSG_HDRLEN + payload.len()) as u32;
        let mut m = Vec::new();
        m.extend_from_slice(&len.to_ne_bytes());
        m.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        m.extend_from_slice(&[0u8; 10]);
        m.extend_from_slice(&payload);
        // NLMSG_DONE
        m.extend_from_slice(&(NLMSG_HDRLEN as u32 + 4).to_ne_bytes());
        m.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
        m.extend_from_slice(&[0u8; 14]);
        m
    }

    #[test]
    fn parses_dump_messages() {
        let buf = fake_dump(4242, 1500, 1 << 20);
        let mut out = Vec::new();
        assert_eq!(parse_messages(&buf, &mut out), Ok(true));
        assert_eq!(out.len(), 1);
        let e = &out[0];
        assert_eq!(e.inode, 4242);
        let t = e.tcp.unwrap();
        assert_eq!(t.rtt_us, 1500);
        assert_eq!(t.total_retrans, 7);
        assert_eq!(t.bytes_acked, 1 << 20);
    }

    #[test]
    fn request_layout() {
        let r = build_request(SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST | NLM_F_DUMP, 2, 6, None);
        assert_eq!(r.len(), 72);
        assert_eq!(u32_at(&r, 0), Some(72));
        assert_eq!(r[16], 2);
        assert_eq!(r[17], 6);
        assert_eq!(r[18], 2);
    }

    /// On Linux CI: open a real connection and find it, with tcp_info, in the dump.
    #[cfg(target_os = "linux")]
    #[test]
    fn real_dump_sees_own_connection() {
        use std::io::Write;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (_s, _) = l.accept().unwrap();
        c.write_all(&[0u8; 4096]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let all = dump_tcp().expect("sock_diag dump");
        let port_be = port.to_be_bytes();
        let mine: Vec<_> = all.iter().filter(|e| e.id.raw[2..4] == port_be).collect();
        assert!(!mine.is_empty(), "client socket not found among {}", all.len());
        let t = mine[0].tcp.expect("tcp_info attached");
        assert!(t.bytes_acked >= 4096 || t.snd_mss > 0);
    }
}
