//! Kernel events that explain incidents in one line: OOM kills, link flaps,
//! NIC resets, segfaults, I/O and filesystem errors, SYN floods, conntrack
//! overflows, hung tasks.
//!
//! Linux: a thread reads `/dev/kmsg` (the existing ring buffer first, then new
//! records as they arrive). Needs root when `kernel.dmesg_restrict = 1`.
//! Windows: warnings and errors from the System event log (`wevtutil`).

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

const KEEP: usize = 500;

#[derive(Clone, Debug)]
pub struct KEvent {
    /// Wall-clock time of the event.
    pub at: SystemTime,
    pub kind: &'static str,
    /// 0 = emergency … 7 = debug (syslog levels).
    pub level: u8,
    pub text: String,
}

#[derive(Default)]
pub struct KmsgStore {
    pub events: VecDeque<KEvent>,
    pub error: Option<String>,
    pub version: u64,
}

impl KmsgStore {
    /// Events of a kind newer than `within`.
    pub fn recent(&self, kind: &str, within: Duration) -> usize {
        let now = SystemTime::now();
        self.events
            .iter()
            .filter(|e| e.kind == kind && now.duration_since(e.at).map(|d| d < within).unwrap_or(true))
            .count()
    }
}

/// Classify a kernel message; None for routine noise.
pub fn classify(msg: &str, level: u8) -> Option<&'static str> {
    let m = msg.to_ascii_lowercase();
    let has = |s: &str| m.contains(s);
    Some(if has("out of memory") || has("oom-kill") || has("oom_kill_process") || has("killed process") {
        "OOM"
    } else if has("link is down") || has("link is up") || has("nic link is") || has("carrier lost") || has("link down") || has("link is disconnected") || has("link has been established") {
        "LINK"
    } else if has("netdev watchdog") || has("transmit queue") && has("timed out") || has("reset adapter") || has("tx hang") {
        "NIC"
    } else if has("segfault") || has("general protection") || has("trap invalid opcode") {
        "SEGV"
    } else if has("i/o error") || has("blk_update_request") || has("medium error") || has("critical medium error") {
        "IO"
    } else if has("ext4-fs error") || has("xfs") && has("error") || has("btrfs") && has("error") || has("remounting filesystem read-only") {
        "FS"
    } else if has("syn flooding") {
        "SYNFLOOD"
    } else if has("nf_conntrack: table full") || has("nf_conntrack: nf_conntrack: table full") {
        "CONNTRACK"
    } else if has("blocked for more than") || has("soft lockup") || has("hard lockup") || has("rcu_sched self-detected stall") {
        "HUNG"
    } else if has("mce:") || has("machine check") || has("hardware error") || has("edac") {
        "HW"
    } else if level <= 3 {
        "ERROR"
    } else {
        return None;
    })
}

/// Parse one `/dev/kmsg` record: `prio,seq,usec,flags;message`.
/// Returns (level, microseconds since boot, message).
pub fn parse_record(rec: &str) -> Option<(u8, u64, String)> {
    let (head, msg) = rec.split_once(';')?;
    let mut f = head.split(',');
    let prio: u32 = f.next()?.parse().ok()?;
    let _seq = f.next()?;
    let usec: u64 = f.next()?.parse().ok()?;
    let msg = msg.lines().next().unwrap_or("").trim().to_string();
    Some(((prio & 7) as u8, usec, msg))
}

/// Read the classified events currently in the kernel ring buffer, without
/// waiting for new ones (used by `vigil report`). Empty when not permitted.
pub fn read_existing() -> Vec<KEvent> {
    #[cfg(target_os = "linux")]
    {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let Ok(mut f) = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open("/dev/kmsg") else {
            return Vec::new();
        };
        let boot = SystemTime::now() - Duration::from_secs_f64(sysinfo::System::uptime() as f64);
        let mut out = Vec::new();
        let mut buf = vec![0u8; 8192];
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Some((level, usec, msg)) = parse_record(&String::from_utf8_lossy(&buf[..n])) {
                        if let Some(kind) = classify(&msg, level) {
                            out.push(KEvent { at: boot + Duration::from_micros(usec), kind, level, text: msg });
                        }
                    }
                }
                Err(e) if e.raw_os_error() == Some(libc::EPIPE) => continue,
                Err(_) => break, // EAGAIN: buffer drained
            }
        }
        out
    }
    #[cfg(windows)]
    return super::windows::read_events().unwrap_or_default();
    #[cfg(not(any(target_os = "linux", windows)))]
    Vec::new()
}

pub fn spawn_worker(store: Arc<Mutex<KmsgStore>>) {
    #[cfg(target_os = "linux")]
    crate::util::spawn_named("kernel-log", move || {
        use std::io::Read;
        let mut f = match std::fs::File::open("/dev/kmsg") {
            Ok(f) => f,
            Err(e) => {
                if let Ok(mut s) = store.lock() {
                    s.error = Some(format!("/dev/kmsg: {e} (run as root, or sysctl kernel.dmesg_restrict=0)"));
                    s.version += 1;
                }
                return;
            }
        };
        let boot = SystemTime::now() - Duration::from_secs_f64(sysinfo::System::uptime() as f64);
        let mut buf = vec![0u8; 8192];
        loop {
            // One read = one record. EPIPE means records were overwritten; keep going.
            match f.read(&mut buf) {
                Ok(0) => std::thread::sleep(Duration::from_millis(500)),
                Ok(n) => {
                    let rec = String::from_utf8_lossy(&buf[..n]);
                    if let Some((level, usec, msg)) = parse_record(&rec) {
                        if let Some(kind) = classify(&msg, level) {
                            if let Ok(mut s) = store.lock() {
                                s.events.push_back(KEvent { at: boot + Duration::from_micros(usec), kind, level, text: msg });
                                if s.events.len() > KEEP {
                                    s.events.pop_front();
                                }
                                s.version += 1;
                            }
                        }
                    }
                }
                Err(e) if e.raw_os_error() == Some(libc::EPIPE) => continue,
                Err(_) => std::thread::sleep(Duration::from_secs(1)),
            }
        }
    });
    // Windows: the System event log, re-read every 30 s (wevtutil is cheap with /c:300).
    #[cfg(windows)]
    crate::util::spawn_named("kernel-log", move || loop {
        let res = super::windows::read_events();
        if let Ok(mut s) = store.lock() {
            match res {
                Ok(v) => {
                    let changed = s.events.back().map(|e| (e.at, e.text.len())) != v.last().map(|e| (e.at, e.text.len()));
                    if changed {
                        s.events = v.into_iter().rev().take(KEEP).rev().collect();
                        s.version += 1;
                    }
                    s.error = None;
                }
                Err(e) => {
                    s.error = Some(e);
                    s.version += 1;
                }
            }
        }
        std::thread::sleep(Duration::from_secs(30));
    });
    #[cfg(not(any(target_os = "linux", windows)))]
    if let Ok(mut s) = store.lock() {
        s.error = Some("kernel events: Linux and Windows only".into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_classifies() {
        let (lvl, us, msg) = parse_record("3,1234,987654321,-;Out of memory: Killed process 4242 (java) total-vm:...\n SUBSYSTEM=x").unwrap();
        assert_eq!((lvl, us), (3, 987654321));
        assert_eq!(classify(&msg, lvl), Some("OOM"));
        assert_eq!(classify("e1000e 0000:00:1f.6 eth0: NIC Link is Down", 6), Some("LINK"));
        assert_eq!(classify("NETDEV WATCHDOG: eth0 (ixgbe): transmit queue 3 timed out", 4), Some("NIC"));
        assert_eq!(classify("python3[311]: segfault at 0 ip 000 sp 000 error 4", 6), Some("SEGV"));
        assert_eq!(classify("TCP: request_sock_TCP: Possible SYN flooding on port 443. Sending cookies.", 6), Some("SYNFLOOD"));
        assert_eq!(classify("nf_conntrack: nf_conntrack: table full, dropping packet", 4), Some("CONNTRACK"));
        assert_eq!(classify("INFO: task kworker:12 blocked for more than 120 seconds.", 3), Some("HUNG"));
        assert_eq!(classify("usb 1-1: new high-speed USB device", 6), None);
    }
}
