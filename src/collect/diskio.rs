//! Per-device disk latency, like `iostat -x`: IOPS, throughput, await,
//! utilisation and queue depth from `/proc/diskstats` (Linux, one read per tick).

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

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

#[derive(Default)]
pub struct DiskIo {
    prev: HashMap<String, Raw>,
    last: Option<Instant>,
    pub devices: Vec<DevStats>,
}

impl DiskIo {
    pub fn refresh(&mut self) {
        #[cfg(target_os = "linux")]
        {
            let Ok(t) = std::fs::read_to_string("/proc/diskstats") else { return };
            let cur = parse(&t);
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

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_real_diskstats() {
        let t = std::fs::read_to_string("/proc/diskstats").unwrap();
        assert!(!parse(&t).is_empty(), "no whole devices in /proc/diskstats");
    }
}
