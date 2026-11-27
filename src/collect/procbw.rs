//! Per-process network bandwidth on macOS, from `nettop`.
//!
//! Linux gets this from tcp_info deltas in the socket scanner; macOS has no
//! such interface for unprivileged users, but `nettop -P -L 1 -x` prints the
//! cumulative bytes in/out of every process. Two samples 2 s apart give the
//! rate. One nettop run takes ~0.5 s, so it runs on its own thread and only
//! while a view that shows bandwidth (Network, Processes) is open.

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// pid → cumulative (bytes in, bytes out).
type Totals = HashMap<u32, (u64, u64)>;

#[derive(Default)]
pub struct ProcBw {
    /// pid → (tx bytes/s, rx bytes/s)
    pub rates: HashMap<u32, (f64, f64)>,
    pub version: u64,
}

/// `nettop -P -L 1 -J bytes_in,bytes_out -x`: "name.pid,in,out," per line.
pub fn parse_nettop(text: &str) -> Totals {
    let mut out = HashMap::new();
    for l in text.lines().skip(1) {
        let mut f = l.split(',');
        let (Some(name), Some(i), Some(o)) = (f.next(), f.next(), f.next()) else { continue };
        let Some(pid) = name.rsplit_once('.').and_then(|(_, p)| p.parse::<u32>().ok()) else { continue };
        let (Ok(i), Ok(o)) = (i.trim().parse::<u64>(), o.trim().parse::<u64>()) else { continue };
        out.insert(pid, (i, o));
    }
    out
}

pub fn spawn_worker(store: Arc<Mutex<ProcBw>>, active: Arc<AtomicBool>) {
    if !cfg!(target_os = "macos") || !crate::platform::get().tools.nettop {
        return;
    }
    crate::util::spawn_named("proc-bandwidth", move || {
        let mut prev: Option<(Instant, Totals)> = None;
        loop {
            if !active.load(Ordering::Relaxed) {
                prev = None;
                std::thread::sleep(Duration::from_millis(300));
                continue;
            }
            let t0 = Instant::now();
            let Ok(o) = std::process::Command::new("nettop").args(["-P", "-L", "1", "-J", "bytes_in,bytes_out", "-x"]).output() else {
                return;
            };
            let now = parse_nettop(&String::from_utf8_lossy(&o.stdout));
            if let Some((t, old)) = &prev {
                let dt = t.elapsed().as_secs_f64().max(0.2);
                let rates = now
                    .iter()
                    .filter_map(|(pid, (i, o))| {
                        let (pi, po) = old.get(pid).copied().unwrap_or((*i, *o));
                        let (rx, tx) = (i.saturating_sub(pi) as f64 / dt, o.saturating_sub(po) as f64 / dt);
                        (rx > 0.0 || tx > 0.0).then_some((*pid, (tx, rx)))
                    })
                    .collect();
                if let Ok(mut s) = store.lock() {
                    s.rates = rates;
                    s.version += 1;
                }
            }
            prev = Some((Instant::now(), now));
            std::thread::sleep(Duration::from_secs(2).saturating_sub(t0.elapsed()));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nettop_csv() {
        let m = parse_nettop(",bytes_in,bytes_out,\nsyslogd.574,0,26303,\nGoogle Chrome H.1234,5698,9697,\nbad line\n");
        assert_eq!(m[&574], (0, 26303));
        assert_eq!(m[&1234], (5698, 9697));
        assert_eq!(m.len(), 2);
    }
}
