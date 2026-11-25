#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

//! Native Linux socket collector: reads /proc/net/{tcp,tcp6,udp,udp6} directly
//! and maps socket inodes to processes via /proc/<pid>/fd.
//!
//! Why: `lsof -i` stats every open fd of every process. On a busy server
//! (thousands of fds, containers) that takes seconds per scan. Reading
//! /proc/net is O(sockets), and the inode→pid map is cached and rebuilt only
//! when an unknown inode appears (or every 30 s), so a steady-state scan
//! costs a few milliseconds.
//!
//! It also shows TIME_WAIT sockets, which have no owning process and are
//! therefore invisible in lsof — exactly what a network engineer wants to see.
//!
//! The parsers are platform independent (and unit-tested everywhere); only the
//! filesystem scanning is Linux-specific.

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
        let remote = if rp == 0 && rh == "*" { String::new() } else { format!("{rh}:{rp}") };
        out.push(RawSock {
            proto,
            v6,
            local: format!("{lh}:{lp}"),
            remote,
            state,
            uid: f[7].parse().unwrap_or(0),
            inode: f[9].parse().unwrap_or(0),
        });
    }
    out
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

#[cfg(target_os = "linux")]
pub use linux::Scanner;

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::time::{Duration, Instant};

    use super::*;

    pub struct Scanner {
        /// socket inode → (pid, fd)
        owners: HashMap<u64, (u32, u32)>,
        comm: HashMap<u32, String>,
        users: HashMap<u32, String>,
        built: Option<Instant>,
    }

    impl Scanner {
        /// Returns None when /proc/net is not readable (fall back to lsof).
        pub fn new() -> Option<Self> {
            fs::metadata("/proc/net/tcp").ok()?;
            Some(Self {
                owners: HashMap::new(),
                comm: HashMap::new(),
                users: parse_passwd(&fs::read_to_string("/etc/passwd").unwrap_or_default()),
                built: None,
            })
        }

        fn rebuild_owners(&mut self) {
            self.owners.clear();
            self.comm.clear();
            let Ok(dir) = fs::read_dir("/proc") else { return };
            for e in dir.flatten() {
                let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                    continue;
                };
                let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
                let mut has_sock = false;
                for fd in fds.flatten() {
                    let Ok(link) = fs::read_link(fd.path()) else { continue };
                    let link = link.to_string_lossy();
                    if let Some(ino) = link.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                        if let (Ok(ino), Some(fdn)) =
                            (ino.parse::<u64>(), fd.file_name().to_str().and_then(|s| s.parse().ok()))
                        {
                            self.owners.insert(ino, (pid, fdn));
                            has_sock = true;
                        }
                    }
                }
                if has_sock {
                    let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
                    self.comm.insert(pid, comm.trim().to_string());
                }
            }
            self.built = Some(Instant::now());
        }

        pub fn scan(&mut self) -> Vec<OpenFile> {
            let mut raw = Vec::new();
            for (file, proto, v6) in [
                ("/proc/net/tcp", "TCP", false),
                ("/proc/net/tcp6", "TCP", true),
                ("/proc/net/udp", "UDP", false),
                ("/proc/net/udp6", "UDP", true),
            ] {
                if let Ok(t) = fs::read_to_string(file) {
                    raw.extend(parse_table(&t, proto, v6));
                }
            }
            // Rebuild the inode map only when we see sockets we can't attribute.
            let stale = self.built.is_none_or(|b| b.elapsed() > Duration::from_secs(30));
            let unknown = raw.iter().any(|s| s.inode != 0 && !self.owners.contains_key(&s.inode));
            if stale || unknown {
                self.rebuild_owners();
            }
            let live: HashSet<u64> = raw.iter().map(|s| s.inode).collect();
            self.owners.retain(|ino, _| live.contains(ino));

            raw.into_iter()
                .map(|s| {
                    let (pid, fd) = self.owners.get(&s.inode).copied().unwrap_or((0, 0));
                    let command = if pid == 0 {
                        "(kernel)".to_string()
                    } else {
                        self.comm.get(&pid).cloned().unwrap_or_default()
                    };
                    OpenFile {
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
                        ..Default::default()
                    }
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixture lines from a little-endian (x86_64 / aarch64) kernel.
    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0000000000000000 20 4 30 10 -1
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
        assert_eq!(v[2].local, "15.0.0.10:443");
        assert_eq!(v[2].remote, "8.8.8.8:50000");
        assert_eq!(v[2].state, "TIME_WAIT");
        assert_eq!(v[2].inode, 0);
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
}
