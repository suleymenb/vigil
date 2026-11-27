//! Per-device disk latency, like `iostat -x`: IOPS, throughput, await,
//! utilisation and queue depth from `/proc/diskstats` (Linux, one read per
//! tick) or IOKit block-driver statistics via `ioreg` (macOS, every 2 s).

#![allow(dead_code)] // parsers for other platforms are unit-tested on every OS

use std::collections::HashMap;
use std::time::Instant;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Raw {
    pub reads: u64,
    pub read_sectors: u64,
    pub read_ms: u64,
    pub writes: u64,
    pub write_sectors: u64,
    pub write_ms: u64,
    pub io_ms: u64,
    pub weighted_ms: u64,
}

#[derive(Clone, Debug, Default)]
pub struct DevStats {
    pub name: String,
    pub r_iops: f64,
    pub w_iops: f64,
    pub r_bps: f64,
    pub w_bps: f64,
    /// Average time per completed request, ms (queue + service).
    pub await_ms: f64,
    /// Share of time the device had I/O in flight.
    pub util_pct: f64,
    /// Average number of requests in flight.
    pub queue: f64,
}

/// Whole devices only: partitions, loop and ram devices are skipped.
pub fn interesting(name: &str) -> bool {
    if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("zram") || name.starts_with("fd") {
        return false;
    }
    if name.starts_with("nvme") || name.starts_with("mmcblk") {
        return !name.contains('p') || !name.rsplit('p').next().is_some_and(|t| t.chars().all(|c| c.is_ascii_digit()));
    }
    if name.starts_with("sd") || name.starts_with("vd") || name.starts_with("xvd") || name.starts_with("hd") {
        return !name.ends_with(|c: char| c.is_ascii_digit());
    }
    true // dm-*, md*, rbd*, …
}

pub fn parse(text: &str) -> HashMap<String, Raw> {
    let mut m = HashMap::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 14 || !interesting(f[2]) {
            continue;
        }
        let n = |i: usize| f[i].parse::<u64>().unwrap_or(0);
        m.insert(
            f[2].to_string(),
            Raw {
                reads: n(3),
                read_sectors: n(5),
                read_ms: n(6),
                writes: n(7),
                write_sectors: n(9),
                write_ms: n(10),
                io_ms: n(12),
                weighted_ms: n(13),
            },
        );
    }
    m
}

pub fn rates(prev: &Raw, cur: &Raw, dt: f64, name: &str) -> DevStats {
    let d = |a: u64, b: u64| a.saturating_sub(b) as f64;
    let reads = d(cur.reads, prev.reads);
    let writes = d(cur.writes, prev.writes);
    let ios = reads + writes;
    let dt_ms = dt * 1000.0;
    DevStats {
        name: name.to_string(),
        r_iops: reads / dt,
        w_iops: writes / dt,
        r_bps: d(cur.read_sectors, prev.read_sectors) * 512.0 / dt,
        w_bps: d(cur.write_sectors, prev.write_sectors) * 512.0 / dt,
        await_ms: if ios > 0.0 { (d(cur.read_ms, prev.read_ms) + d(cur.write_ms, prev.write_ms)) / ios } else { 0.0 },
        util_pct: (d(cur.io_ms, prev.io_ms) / dt_ms * 100.0).min(100.0),
        queue: d(cur.weighted_ms, prev.weighted_ms) / dt_ms,
    }
}

/// macOS: `ioreg -c IOBlockStorageDriver -r -w0 -l`. Each driver's "Statistics"
/// dictionary (operations, bytes, total time in ns per direction) belongs to
/// the first whole-disk "BSD Name" below it. IOKit has no busy-time counter,
/// so utilisation and queue are estimated from the summed service time.
pub fn parse_ioreg(text: &str) -> HashMap<String, Raw> {
    let mut m = HashMap::new();
    let mut pending: Option<Raw> = None;
    for l in text.lines() {
        if let Some(i) = l.find("\"Statistics\" = {").filter(|_| l.contains("Total Time (Read)")) {
            let body = &l[i + 16..];
            let get = |k: &str| -> u64 {
                body.find(&format!("\"{k}\"=")).and_then(|p| body[p + k.len() + 3..].split([',', '}']).next()).and_then(|v| v.trim().parse().ok()).unwrap_or(0)
            };
            let (rt, wt) = (get("Total Time (Read)") / 1_000_000, get("Total Time (Write)") / 1_000_000);
            pending = Some(Raw {
                reads: get("Operations (Read)"),
                read_sectors: get("Bytes (Read)") / 512,
                read_ms: rt,
                writes: get("Operations (Write)"),
                write_sectors: get("Bytes (Write)") / 512,
                write_ms: wt,
                io_ms: rt + wt,
                weighted_ms: rt + wt,
            });
        } else if let Some(i) = l.find("\"BSD Name\" = \"") {
            if let Some(raw) = pending.take() {
                let name = l[i + 14..].trim_end_matches('"').to_string();
                if raw.reads + raw.writes > 0 {
                    m.insert(name, raw);
                }
            }
        }
    }
    m
}

#[derive(Default)]
pub struct DiskIo {
    prev: HashMap<String, Raw>,
    last: Option<Instant>,
    pub devices: Vec<DevStats>,
    /// macOS: ioreg runs on a poller thread (~15 ms per call).
    #[cfg(target_os = "macos")]
    poller: Option<(crate::util::Poller<HashMap<String, Raw>>, u64)>,
}

impl DiskIo {
    pub fn refresh(&mut self) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            #[cfg(target_os = "linux")]
            let cur = {
                let Ok(t) = std::fs::read_to_string("/proc/diskstats") else { return };
                parse(&t)
            };
            #[cfg(target_os = "macos")]
            let (cur, now) = {
                let (poller, seen) = self.poller.get_or_insert_with(|| {
                    let p = crate::util::Poller::spawn(std::time::Duration::from_secs(2), || {
                        let o = std::process::Command::new("ioreg").args(["-c", "IOBlockStorageDriver", "-r", "-w0", "-l"]).output().ok()?;
                        Some(parse_ioreg(&String::from_utf8_lossy(&o.stdout)))
                    });
                    (p, 0)
                });
                let Some((at, seq, cur)) = poller.latest(*seen) else { return };
                *seen = seq;
                (cur, at)
            };
            #[cfg(target_os = "linux")]
            let now = Instant::now();
            if let Some(last) = self.last {
                let dt = now.duration_since(last).as_secs_f64().max(0.05);
                let mut v: Vec<DevStats> = cur
                    .iter()
                    .filter_map(|(n, c)| self.prev.get(n).map(|p| rates(p, c, dt, n)))
                    .collect();
                v.sort_by(|a, b| a.name.cmp(&b.name));
                self.devices = v;
            }
            self.prev = cur;
            self.last = Some(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_partitions() {
        for (n, ok) in [("sda", true), ("sda1", false), ("nvme0n1", true), ("nvme0n1p2", false), ("loop3", false), ("dm-0", true), ("vdb", true), ("mmcblk0p1", false)] {
            assert_eq!(interesting(n), ok, "{n}");
        }
    }

    #[test]
    fn computes_iostat_numbers() {
        let a = parse("   8       0 sda 100 0 2000 50 200 0 4000 150 0 100 200 0 0 0 0\n   8       1 sda1 1 0 1 1 1 0 1 1 0 1 1\n");
        let b = parse("   8       0 sda 200 0 4048 150 300 0 6048 350 2 600 1200 0 0 0 0\n");
        assert!(a.contains_key("sda") && !a.contains_key("sda1"));
        let s = rates(&a["sda"], &b["sda"], 1.0, "sda");
        assert_eq!(s.r_iops, 100.0);
        assert_eq!(s.w_iops, 100.0);
        assert_eq!(s.r_bps, 2048.0 * 512.0);
        assert_eq!(s.await_ms, (100.0 + 200.0) / 200.0);
        assert_eq!(s.util_pct, 50.0);
        assert_eq!(s.queue, 1.0);
    }

    #[test]
    fn macos_ioreg() {
        let t = "+-o IOBlockStorageDriver  <class IOBlockStorageDriver>\n      \"Statistics\" = {\"Operations (Write)\"=0,\"Bytes (Read)\"=0,\"Total Time (Read)\"=0,\"Total Time (Write)\"=0,\"Bytes (Write)\"=0,\"Operations (Read)\"=0}\n    +-o Media\n          \"BSD Name\" = \"disk9\"\n+-o IOBlockStorageDriver\n  |   \"Statistics\" = {\"Operations (Write)\"=1216244,\"Bytes (Read)\"=61797339136,\"Total Time (Read)\"=348113085960,\"Total Time (Write)\"=68432797349,\"Bytes (Write)\"=69153046528,\"Operations (Read)\"=1385454}\n  | +-o APPLE SSD Media\n  |       \"BSD Name\" = \"disk0\"\n  |   +-o disk0s1\n  |         \"BSD Name\" = \"disk0s1\"\n";
        let m = parse_ioreg(t);
        assert_eq!(m.len(), 1);
        let d = m["disk0"];
        assert_eq!((d.reads, d.writes, d.read_ms), (1385454, 1216244, 348113));
        assert_eq!(d.read_sectors, 61797339136 / 512);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn reads_real_ioreg() {
        let o = std::process::Command::new("ioreg").args(["-c", "IOBlockStorageDriver", "-r", "-w0", "-l"]).output().unwrap();
        assert!(!parse_ioreg(&String::from_utf8_lossy(&o.stdout)).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_real_diskstats() {
        let t = std::fs::read_to_string("/proc/diskstats").unwrap();
        assert!(!parse(&t).is_empty(), "no whole devices in /proc/diskstats");
    }
}
