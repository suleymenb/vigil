#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

//! Native Linux socket collector.
//!
//! * `/proc/net/{tcp,tcp6,udp,udp6}` for every socket, including TIME_WAIT
//!   (which lsof can't show because it has no owner) and the rx/tx queues.
//! * `/proc/<pid>/net/*` for every other network namespace (containers), each
//!   socket tagged with a container / namespace label.
//! * `sock_diag` netlink for TCP internals of the host namespace: RTT,
//!   retransmits, cwnd and byte counters, which give per-connection bandwidth.
//! * inode → pid map from `/proc/<pid>/fd`, cached and only rebuilt when an
//!   unknown inode shows up or every 30 s.
//!
//! The parsers are platform independent and unit-tested everywhere.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::lsof::OpenFile;

pub fn tcp_state(hex: &str) -> &'static str {
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSED",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        "0C" => "NEW_SYN_RECV",
        _ => "UNKNOWN",
    }
}

/// Parse `0100007F:0050` (v4) or 32-hex-char v6 addresses into lsof notation.
/// The kernel prints each 32-bit word in host byte order, hence `to_ne_bytes`.
pub fn parse_addr(s: &str, v6: bool) -> Option<(String, u16)> {
    let (ip, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let host = if v6 {
        if ip.len() != 32 {
            return None;
        }
        let mut b = [0u8; 16];
        for w in 0..4 {
            let word = u32::from_str_radix(&ip[w * 8..w * 8 + 8], 16).ok()?;
            b[w * 4..w * 4 + 4].copy_from_slice(&word.to_ne_bytes());
        }
        let a = Ipv6Addr::from(b);
        if a.is_unspecified() {
            "*".to_string()
        } else {
            format!("[{a}]")
        }
    } else {
        let a = Ipv4Addr::from(u32::from_str_radix(ip, 16).ok()?.to_ne_bytes());
        if a.is_unspecified() {
            "*".to_string()
        } else {
            a.to_string()
        }
    };
    Some((host, port))
}

/// One parsed line of /proc/net/{tcp,udp}[6].
#[derive(Debug, Clone)]
pub struct RawSock {
    pub proto: &'static str,
    pub v6: bool,
    pub local: String,
    pub remote: String,
    pub state: &'static str,
    pub tx_queue: u32,
    pub rx_queue: u32,
    pub uid: u32,
    pub inode: u64,
}

pub fn parse_table(text: &str, proto: &'static str, v6: bool) -> Vec<RawSock> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let (Some((lh, lp)), Some((rh, rp))) = (parse_addr(f[1], v6), parse_addr(f[2], v6)) else {
            continue;
        };
        let state = if proto == "UDP" {
            if f[3] == "01" { "ESTABLISHED" } else { "" }
        } else {
            tcp_state(f[3])
        };
        let (tx_queue, rx_queue) = f[4]
            .split_once(':')
            .map(|(t, r)| (u32::from_str_radix(t, 16).unwrap_or(0), u32::from_str_radix(r, 16).unwrap_or(0)))
            .unwrap_or((0, 0));
        let remote = if rp == 0 && rh == "*" { String::new() } else { format!("{rh}:{rp}") };
        out.push(RawSock {
            proto,
            v6,
            local: format!("{lh}:{lp}"),
            remote,
            state,
            tx_queue,
            rx_queue,
            uid: f[7].parse().unwrap_or(0),
            inode: f[9].parse().unwrap_or(0),
        });
    }
    out
}

/// The inode in a `/proc/<pid>/fd/N` link target of the form "socket:[12345]".
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_socket_link(link: &[u8]) -> Option<u64> {
    let digits = link.strip_prefix(b"socket:[")?;
    let end = digits.iter().position(|b| *b == b']')?;
    std::str::from_utf8(&digits[..end]).ok()?.parse().ok()
}

pub fn parse_passwd(text: &str) -> std::collections::HashMap<u32, String> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split(':');
            let name = it.next()?;
            let uid = it.nth(1)?.parse().ok()?;
            Some((uid, name.to_string()))
        })
        .collect()
}

/// Short container label from `/proc/<pid>/cgroup`, e.g. `ctr:3f2a9c81d0e4`
/// for Docker / containerd / CRI-O / Podman, `pod:<uid>` for other kubepods.
pub fn container_label(cgroup: &str) -> Option<String> {
    for marker in ["docker-", "/docker/", "cri-containerd-", "crio-", "libpod-", "containerd/"] {
        if let Some(i) = cgroup.find(marker) {
            let id: String = cgroup[i + marker.len()..]
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .take(12)
                .collect();
            if id.len() == 12 {
                return Some(format!("ctr:{id}"));
            }
        }
    }
    if let Some(i) = cgroup.find("pod") {
        let uid: String = cgroup[i + 3..]
            .chars()
            .skip_while(|c| !c.is_ascii_hexdigit())
            .take_while(|c| c.is_ascii_hexdigit() || *c == '_' || *c == '-')
            .take(8)
            .collect();
        if cgroup.contains("kubepods") && uid.len() == 8 {
            return Some(format!("pod:{uid}"));
        }
    }
    None
}

#[cfg(target_os = "linux")]
pub use linux::Scanner;

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::collect::lsof::NetExtra;
    use crate::collect::sockdiag::{self, DiagEntry};

    fn ns_inode(pid: &str) -> Option<u64> {
        let l = fs::read_link(format!("/proc/{pid}/ns/net")).ok()?;
        l.to_str()?.strip_prefix("net:[")?.strip_suffix(']')?.parse().ok()
    }

    /// Socket inodes among a process's open files, as (inode, fd). False when
    /// its fd directory is not readable (another user's process, without root).
    ///
    /// One `readlinkat` per fd into a stack buffer: only "socket:[N]" matters,
    /// so nothing is allocated for the thousands of files and pipes.
    #[allow(clippy::unnecessary_cast)] // c_char is u8 on arm, i8 on x86
    fn socket_fds(pid: u32, mut found: impl FnMut(u64, u32)) -> bool {
        let Ok(path) = std::ffi::CString::new(format!("/proc/{pid}/fd")) else { return false };
        unsafe {
            let dir = libc::opendir(path.as_ptr());
            if dir.is_null() {
                return false;
            }
            let dfd = libc::dirfd(dir);
            loop {
                let e = libc::readdir(dir);
                if e.is_null() {
                    break;
                }
                let name = &(*e).d_name;
                let mut fd: u32 = 0;
                let mut digits = 0;
                for c in name.iter().map(|c| *c as u8).take_while(|c| *c != 0) {
                    if !c.is_ascii_digit() {
                        digits = 0;
                        break;
                    }
                    fd = fd.wrapping_mul(10).wrapping_add((c - b'0') as u32);
                    digits += 1;
                }
                if digits == 0 {
                    continue; // "." and ".."
                }
                let mut buf = [0u8; 48];
                let n = libc::readlinkat(dfd, name.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char, buf.len());
                if n <= 0 {
                    continue;
                }
                if let Some(ino) = parse_socket_link(&buf[..n as usize]) {
                    found(ino, fd);
                }
            }
            libc::closedir(dir);
        }
        true
    }

    pub struct Scanner {
        /// socket inode → (pid, fd)
        owners: HashMap<u64, (u32, u32)>,
        /// Sockets no readable process owns (other users' without root, or
        /// kernel-held): looking again every scan would walk all of /proc
        /// every three seconds for nothing.
        unowned: HashSet<u64>,
        comm: HashMap<u32, String>,
        users: HashMap<u32, String>,
        built: Option<Instant>,
        host_ns: Option<u64>,
        /// Other network namespaces: ns inode → (one pid inside it, label).
        other_ns: HashMap<u64, (u32, Arc<str>)>,
        /// Previous byte counters per socket inode, for bandwidth.
        prev_bytes: HashMap<u64, (u64, u64)>,
        last_scan: Option<Instant>,
        diag_ok: bool,
    }

    impl Scanner {
        /// Returns None when /proc/net is not readable (fall back to lsof).
        pub fn new() -> Option<Self> {
            fs::metadata("/proc/net/tcp").ok()?;
            Some(Self {
                owners: HashMap::new(),
                unowned: HashSet::new(),
                comm: HashMap::new(),
                users: parse_passwd(&fs::read_to_string("/etc/passwd").unwrap_or_default()),
                built: None,
                host_ns: ns_inode("self"),
                other_ns: HashMap::new(),
                prev_bytes: HashMap::new(),
                last_scan: None,
                diag_ok: true,
            })
        }

        fn rebuild_owners(&mut self) {
            self.owners.clear();
            self.comm.clear();
            self.other_ns.clear();
            let Ok(dir) = fs::read_dir("/proc") else { return };
            for e in dir.flatten() {
                let name = e.file_name();
                let Some(pid_s) = name.to_str() else { continue };
                let Ok(pid) = pid_s.parse::<u32>() else { continue };
                let mut has_sock = false;
                let owners = &mut self.owners;
                socket_fds(pid, |ino, fd| {
                    owners.insert(ino, (pid, fd));
                    has_sock = true;
                });
                if !has_sock {
                    continue;
                }
                let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
                let comm = comm.trim().to_string();
                if let Some(ns) = ns_inode(pid_s) {
                    if Some(ns) != self.host_ns && !self.other_ns.contains_key(&ns) {
                        let cg = fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
                        let label = container_label(&cg).unwrap_or_else(|| format!("ns:{comm}"));
                        self.other_ns.insert(ns, (pid, Arc::from(label)));
                    }
                }
                self.comm.insert(pid, comm);
            }
            self.built = Some(Instant::now());
        }

        fn read_tables(prefix: &str, out: &mut Vec<RawSock>) {
            for (file, proto, v6) in [("tcp", "TCP", false), ("tcp6", "TCP", true), ("udp", "UDP", false), ("udp6", "UDP", true)] {
                if let Ok(t) = fs::read_to_string(format!("{prefix}/{file}")) {
                    out.extend(parse_table(&t, proto, v6));
                }
            }
        }

        pub fn scan(&mut self) -> Vec<OpenFile> {
            let now = Instant::now();
            // Host namespace first, then one table set per other namespace.
            let mut groups: Vec<(Option<Arc<str>>, Vec<RawSock>)> = Vec::new();
            let mut host = Vec::new();
            Self::read_tables("/proc/net", &mut host);
            groups.push((None, host));
            for (pid, label) in self.other_ns.values() {
                let mut v = Vec::new();
                Self::read_tables(&format!("/proc/{pid}/net"), &mut v);
                if !v.is_empty() {
                    groups.push((Some(label.clone()), v));
                }
            }

            // Walk every process's files only for sockets not seen before
            // (and every 30 s, to notice a socket that changed hands).
            let stale = self.built.is_none_or(|b| b.elapsed() > Duration::from_secs(30));
            let unknown = groups
                .iter()
                .flat_map(|(_, v)| v.iter())
                .any(|s| s.inode != 0 && !self.owners.contains_key(&s.inode) && !self.unowned.contains(&s.inode));
            if stale || unknown {
                self.rebuild_owners();
                self.unowned = groups.iter().flat_map(|(_, v)| v.iter()).map(|s| s.inode).filter(|i| *i != 0 && !self.owners.contains_key(i)).collect();
            }

            // TCP internals for the host namespace.
            let diag: HashMap<u64, DiagEntry> = if self.diag_ok {
                match sockdiag::dump_tcp() {
                    Ok(v) => v.into_iter().filter(|e| e.inode != 0).map(|e| (e.inode, e)).collect(),
                    Err(_) => {
                        self.diag_ok = false; // e.g. seccomp / old kernel: stop trying
                        HashMap::new()
                    }
                }
            } else {
                HashMap::new()
            };
            let dt = self.last_scan.map(|t| now.duration_since(t).as_secs_f64()).unwrap_or(0.0);
            let mut next_bytes = HashMap::with_capacity(diag.len());

            let mut out = Vec::new();
            let mut live = HashSet::new();
            for (ns, raws) in groups {
                for s in raws {
                    live.insert(s.inode);
                    let (pid, fd) = self.owners.get(&s.inode).copied().unwrap_or((0, 0));
                    let command = if pid == 0 {
                        "(kernel)".to_string()
                    } else {
                        self.comm.get(&pid).cloned().unwrap_or_default()
                    };
                    let mut extra = NetExtra {
                        netns: ns.clone(),
                        rx_queue: s.rx_queue,
                        tx_queue: s.tx_queue,
                        ..Default::default()
                    };
                    if ns.is_none() && s.proto == "TCP" && s.inode != 0 {
                        if let Some(d) = diag.get(&s.inode) {
                            extra.diag = Some(d.id);
                            if let Some(t) = d.tcp {
                                next_bytes.insert(s.inode, (t.bytes_acked, t.bytes_received));
                                if let (Some(&(pa, pr)), true) = (self.prev_bytes.get(&s.inode), dt > 0.0) {
                                    extra.tx_rate = t.bytes_acked.saturating_sub(pa) as f64 / dt;
                                    extra.rx_rate = t.bytes_received.saturating_sub(pr) as f64 / dt;
                                }
                                extra.tcp = Some(t);
                            }
                        }
                    }
                    out.push(OpenFile {
                        pid,
                        command,
                        user: self.users.get(&s.uid).cloned().unwrap_or_else(|| s.uid.to_string()),
                        fd: if pid == 0 { "-".into() } else { fd.to_string() },
                        access: if pid == 0 { String::new() } else { "u".into() },
                        ftype: if s.v6 { "IPv6".into() } else { "IPv4".into() },
                        name: if s.remote.is_empty() {
                            s.local
                        } else {
                            format!("{}->{}", s.local, s.remote)
                        },
                        proto: s.proto.into(),
                        state: s.state.into(),
                        net: Some(Box::new(extra)),
                        ..Default::default()
                    });
                }
            }
            self.owners.retain(|ino, _| live.contains(ino));
            self.unowned.retain(|ino| live.contains(ino));
            self.prev_bytes = next_bytes;
            self.last_scan = Some(now);
            out
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Runs on Linux CI: our own listening socket must show up with its pid.
        #[test]
        fn real_scan_finds_own_listener() {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = l.local_addr().unwrap().port();
            let mut sc = Scanner::new().expect("/proc/net readable");
            let all = sc.scan();
            let me = std::process::id();
            let found = all
                .iter()
                .find(|e| e.state == "LISTEN" && e.local_port() == Some(port))
                .expect("own listener in scan");
            assert_eq!(found.pid, me);
            assert!(found.net.as_ref().unwrap().netns.is_none());
            // The fd it reports is one of ours and really is that socket.
            let mut mine = Vec::new();
            assert!(socket_fds(me, |ino, fd| mine.push((ino, fd))));
            let fd: u32 = found.fd.parse().expect("fd number");
            assert!(mine.iter().any(|(_, f)| *f == fd), "fd {fd} not among {mine:?}");
            assert!(!socket_fds(u32::MAX - 7, |_, _| {}), "a pid that doesn't exist has no files");
            // Sockets nobody readable owns are remembered, never left pending.
            let pending = all.iter().filter(|e| e.pid == 0).count();
            assert!(sc.unowned.len() <= pending, "{} unowned, {pending} without a process", sc.unowned.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixture lines from a little-endian (x86_64 / aarch64) kernel.
    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 0100007F:D431 01 00000010:00000020 00:00000000 00000000  1000        0 22222 1 0000000000000000 20 4 30 10 -1
   2: 0A00000F:01BB 08080808:C350 06 00000000:00000000 03:00000F8F 00000000     0        0 0 3 0000000000000000";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000    33        0 4444 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:1F90 00000000000000000000000001000000:9C40 01 00000000:00000000 00:00000000 00000000  1000        0 5555 1 0000000000000000 20 4 30 10 -1";

    #[cfg(target_endian = "little")]
    #[test]
    fn parses_tcp4() {
        let v = parse_table(TCP, "TCP", false);
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].local, "*:22");
        assert_eq!(v[0].state, "LISTEN");
        assert_eq!(v[0].remote, "");
        assert_eq!(v[1].local, "127.0.0.1:8080");
        assert_eq!(v[1].remote, "127.0.0.1:54321");
        assert_eq!(v[1].uid, 1000);
        assert_eq!((v[1].tx_queue, v[1].rx_queue), (16, 32));
        assert_eq!(v[2].local, "15.0.0.10:443");
        assert_eq!(v[2].remote, "8.8.8.8:50000");
        assert_eq!(v[2].state, "TIME_WAIT");
        assert_eq!(v[2].inode, 0);
    }

    #[test]
    fn socket_links() {
        assert_eq!(parse_socket_link(b"socket:[48213]"), Some(48213));
        assert_eq!(parse_socket_link(b"socket:[18446744073709551615]"), Some(u64::MAX));
        for other in [&b"/var/log/syslog"[..], b"pipe:[1234]", b"anon_inode:[eventpoll]", b"socket:[12", b"socket:[x]", b""] {
            assert_eq!(parse_socket_link(other), None, "{}", String::from_utf8_lossy(other));
        }
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn parses_tcp6() {
        let v = parse_table(TCP6, "TCP", true);
        assert_eq!(v[0].local, "*:80");
        assert_eq!(v[1].local, "[::1]:8080");
        assert_eq!(v[1].remote, "[::1]:40000");
    }

    #[test]
    fn parses_passwd() {
        let m = parse_passwd("root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n");
        assert_eq!(m[&0], "root");
        assert_eq!(m[&33], "www-data");
    }

    #[test]
    fn container_labels() {
        assert_eq!(
            container_label("0::/system.slice/docker-3f2a9c81d0e4aa11bb22cc33dd44ee55ff66.scope").as_deref(),
            Some("ctr:3f2a9c81d0e4")
        );
        assert_eq!(
            container_label("0::/kubepods/burstable/pod1a2b3c4d-1111/cri-containerd-abcdef012345678.scope").as_deref(),
            Some("ctr:abcdef012345")
        );
        assert_eq!(container_label("0::/user.slice/user-1000.slice"), None);
    }
}
