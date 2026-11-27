//! Resource exhaustion before it bites: open file descriptors per process
//! against its limit, the system-wide file table, and the ephemeral port range.
//!
//! Runs on its own thread every 5 s (counting fds for every process is a
//! readdir per pid). Per-process limits are cached and re-read once a minute.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::util::MiniHist;

#[derive(Default, Clone)]
pub struct Limits {
    /// pid → (open fds, soft limit if known)
    pub fds: HashMap<u32, (u32, Option<u64>)>,
    /// System-wide (allocated, max) file handles.
    pub files: Option<(u64, u64)>,
    /// Local ports the kernel hands out for outgoing connections.
    pub ephemeral: Option<(u16, u16)>,
    /// pid → open fds over the last ~10 minutes (one sample per 5 s).
    pub fd_hist: HashMap<u32, MiniHist>,
    /// Processes still running replaced binaries or libraries (Linux):
    /// pid → what was replaced.
    pub needs_restart: Vec<(u32, String)>,
    pub version: u64,
}

impl Limits {
    /// Highest fd usage as (pid, open, limit, pct).
    pub fn worst(&self) -> Option<(u32, u32, u64, f64)> {
        self.fds
            .iter()
            .filter_map(|(p, (n, l))| l.filter(|l| *l > 0).map(|l| (*p, *n, l, *n as f64 / l as f64 * 100.0)))
            .max_by(|a, b| a.3.total_cmp(&b.3))
    }
}

/// `Max open files  1024  524288  files` → soft limit.
pub fn parse_limits(text: &str) -> Option<u64> {
    let l = text.lines().find(|l| l.starts_with("Max open files"))?;
    l.split_whitespace().nth(3)?.parse().ok()
}

pub fn parse_file_nr(text: &str) -> Option<(u64, u64)> {
    let f: Vec<u64> = text.split_whitespace().filter_map(|x| x.parse().ok()).collect();
    (f.len() >= 3).then(|| (f[0], f[2]))
}

/// Replaced libraries in a /proc/<pid>/maps listing: shared objects marked
/// "(deleted)". Anonymous shared memory, tmpfs and memfd mappings are normal
/// and ignored.
pub fn deleted_libs(maps: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for l in maps.lines() {
        let Some(path) = l.strip_suffix(" (deleted)") else { continue };
        let Some(path) = path.split_whitespace().nth(5) else { continue };
        if path.starts_with("/dev/") || path.starts_with("/tmp/") || path.starts_with("/run/") || path.starts_with("/memfd:") || path.starts_with("/SYSV") {
            continue;
        }
        if !(path.contains(".so") || path.starts_with("/usr/") || path.starts_with("/lib") || path.starts_with("/bin") || path.starts_with("/sbin")) {
            continue;
        }
        let name = path.rsplit('/').next().unwrap_or(path).to_string();
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// Scan every process for a replaced executable or replaced libraries.
#[cfg(target_os = "linux")]
pub fn scan_needs_restart() -> Vec<(u32, String)> {
    use std::fs;
    let mut out = Vec::new();
    let Ok(dir) = fs::read_dir("/proc") else { return out };
    for e in dir.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let exe = fs::read_link(format!("/proc/{pid}/exe")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        if let Some(bin) = exe.strip_suffix(" (deleted)") {
            out.push((pid, format!("binary replaced: {bin}")));
            continue;
        }
        if let Ok(maps) = fs::read_to_string(format!("/proc/{pid}/maps")) {
            let libs = deleted_libs(&maps);
            if !libs.is_empty() {
                out.push((pid, format!("libraries replaced: {}", libs.join(", "))));
            }
        }
    }
    out
}

#[cfg(not(target_os = "linux"))]
pub fn scan_needs_restart() -> Vec<(u32, String)> {
    Vec::new()
}

pub fn parse_port_range(text: &str) -> Option<(u16, u16)> {
    let mut it = text.split_whitespace().filter_map(|x| x.parse().ok());
    Some((it.next()?, it.next()?))
}

#[cfg(target_os = "linux")]
fn collect(limit_cache: &mut HashMap<u32, (Option<u64>, Instant)>) -> Limits {
    use std::fs;
    let mut fds = HashMap::new();
    if let Ok(dir) = fs::read_dir("/proc") {
        for e in dir.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
            // Linux 6.2+ reports the number of open files as the size of the
            // fd directory: one stat instead of listing it. Older kernels say 0.
            let dir = format!("/proc/{pid}/fd");
            let n = match fs::metadata(&dir).map(|m| m.len()) {
                Ok(n) if n > 0 => n as u32,
                Ok(_) => match fs::read_dir(&dir) {
                    Ok(rd) => rd.count() as u32,
                    Err(_) => continue,
                },
                Err(_) => continue,
            };
            let lim = match limit_cache.get(&pid) {
                Some((l, at)) if at.elapsed() < Duration::from_secs(60) => *l,
                _ => {
                    let l = fs::read_to_string(format!("/proc/{pid}/limits")).ok().and_then(|t| parse_limits(&t));
                    limit_cache.insert(pid, (l, Instant::now()));
                    l
                }
            };
            fds.insert(pid, (n, lim));
        }
    }
    limit_cache.retain(|p, _| fds.contains_key(p));
    Limits {
        fds,
        files: fs::read_to_string("/proc/sys/fs/file-nr").ok().and_then(|t| parse_file_nr(&t)),
        ephemeral: fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").ok().and_then(|t| parse_port_range(&t)),
        ..Default::default()
    }
}

#[cfg(target_os = "macos")]
fn sysctl_u64(name: &str) -> Option<u64> {
    let c = std::ffi::CString::new(name).ok()?;
    let mut v: i64 = 0;
    let mut len = std::mem::size_of::<i64>();
    let r = unsafe { libc::sysctlbyname(c.as_ptr(), &mut v as *mut _ as *mut libc::c_void, &mut len, std::ptr::null_mut(), 0) };
    if r != 0 {
        return None;
    }
    // Values may be 32-bit; the low bytes are valid either way on little-endian.
    Some(if len == 4 { v as u32 as u64 } else { v as u64 })
}

#[cfg(target_os = "macos")]
fn collect(_cache: &mut HashMap<u32, (Option<u64>, Instant)>) -> Limits {
    // macOS doesn't expose other processes' rlimits; fd counts via proc_pidinfo.
    const PROC_PIDLISTFDS: i32 = 1;
    const FDINFO_SIZE: i32 = 8;
    let mut fds = HashMap::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut pids = vec![0i32; 8192];
    let n = unsafe { libc::proc_listallpids(pids.as_mut_ptr() as *mut libc::c_void, (pids.len() * 4) as i32) };
    for &pid in pids.iter().take(n.max(0) as usize) {
        if pid <= 0 {
            continue;
        }
        // The first call only returns the size of the fd *table*; the second
        // fills a buffer and returns the bytes actually used by open fds.
        let cap = unsafe { libc::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
        if cap <= 0 {
            continue;
        }
        buf.resize(cap as usize + 64 * FDINFO_SIZE as usize, 0);
        let used = unsafe {
            libc::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as i32)
        };
        if used > 0 {
            fds.insert(pid as u32, ((used / FDINFO_SIZE) as u32, None));
        }
    }
    Limits {
        fds,
        files: sysctl_u64("kern.num_files").zip(sysctl_u64("kern.maxfiles")),
        ephemeral: sysctl_u64("net.inet.ip.portrange.first")
            .zip(sysctl_u64("net.inet.ip.portrange.last"))
            .map(|(a, b)| (a as u16, b as u16)),
        ..Default::default()
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn collect(_cache: &mut HashMap<u32, (Option<u64>, Instant)>) -> Limits {
    Limits::default()
}

/// One synchronous collection (used by `vigil report`).
pub fn collect_once() -> Limits {
    collect(&mut HashMap::new())
}

pub fn spawn_worker(store: Arc<Mutex<Limits>>) {
    crate::util::spawn_named("limits", move || {
        let mut cache = HashMap::new();
        let mut hist: HashMap<u32, MiniHist> = HashMap::new();
        let mut restart: Vec<(u32, String)> = Vec::new();
        let mut last_restart_scan: Option<Instant> = None;
        loop {
            let mut l = collect(&mut cache);
            for (pid, (n, _)) in &l.fds {
                hist.entry(*pid).or_default().push(*n as f32);
            }
            hist.retain(|p, _| l.fds.contains_key(p));
            // Reading every process's memory map is the expensive part: every 2 minutes.
            if last_restart_scan.is_none_or(|t| t.elapsed() >= Duration::from_secs(120)) {
                restart = scan_needs_restart();
                last_restart_scan = Some(Instant::now());
            }
            restart.retain(|(p, _)| l.fds.contains_key(p));
            l.fd_hist = hist.clone();
            l.needs_restart = restart.clone();
            if let Ok(mut s) = store.lock() {
                let v = s.version + 1;
                *s = l;
                s.version = v;
            }
            thread::sleep(Duration::from_secs(5));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsers() {
        let limits = "Limit                     Soft Limit           Hard Limit           Units\nMax cpu time              unlimited            unlimited            seconds\nMax open files            1024                 524288               files\n";
        assert_eq!(parse_limits(limits), Some(1024));
        assert_eq!(parse_file_nr("3264\t0\t9223372036854775807\n"), Some((3264, 9223372036854775807)));
        assert_eq!(parse_port_range("32768\t60999\n"), Some((32768, 60999)));
    }

    #[test]
    fn deleted_libraries() {
        let maps = "7f00-7f01 r-xp 00000000 08:01 1234 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)\n\
7f02-7f03 r-xp 00000000 08:01 1235 /usr/lib/x86_64-linux-gnu/libc.so.6\n\
7f04-7f05 rw-s 00000000 00:05 99 /dev/shm/pulse-shm-1 (deleted)\n\
7f06-7f07 rw-s 00000000 00:01 98 /memfd:wayland (deleted)\n\
7f08-7f09 r-xp 00000000 08:01 1234 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)\n";
        assert_eq!(deleted_libs(maps), vec!["libssl.so.3".to_string()]);
    }

    #[test]
    fn real_collection_sees_own_process() {
        let mut cache = HashMap::new();
        let l = collect(&mut cache);
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            let me = std::process::id();
            let (n, _) = l.fds.get(&me).copied().expect("own process in fd table");
            assert!(n >= 3, "stdin/out/err at least, got {n}");
            assert!(l.ephemeral.is_some());
        }
    }
}
