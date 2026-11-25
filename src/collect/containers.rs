//! Containers from cgroup v2: CPU, CPU throttling, memory against its limit,
//! OOM kills, block I/O, pids and network per container.
//!
//! Works for Docker, containerd / Kubernetes, CRI-O and Podman without
//! talking to any daemon: everything comes from /sys/fs/cgroup, plus
//! /proc/<pid>/net/dev for traffic inside the container's network namespace.
//! Docker names are read from /var/lib/docker/containers/<id>/config.v2.json.
//!
//! Polled every 2 s while the Containers view is open, every 10 s otherwise
//! (throttling and OOM badges need it).

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub runtime: &'static str,
    pub cpu_pct: f64,
    /// CPU limit in cores (cpu.max), None = unlimited.
    pub cpu_limit: Option<f64>,
    /// Share of scheduler periods in which the container was throttled.
    pub throttled_pct: f64,
    pub mem: u64,
    pub mem_max: Option<u64>,
    pub oom_kills: u64,
    /// OOM kills seen since vigil started.
    pub new_ooms: u64,
    pub io_read_bps: f64,
    pub io_write_bps: f64,
    pub pids: u64,
    pub net_rx_bps: f64,
    pub net_tx_bps: f64,
    pub path: String,
}

impl Container {
    pub fn mem_pct(&self) -> Option<f64> {
        self.mem_max.filter(|m| *m > 0).map(|m| self.mem as f64 / m as f64 * 100.0)
    }
}

#[derive(Default)]
pub struct ContainerStore {
    pub containers: Vec<Container>,
    pub error: Option<String>,
    pub version: u64,
}

/// Recognise a container cgroup directory name: returns (runtime, 64-hex id).
pub fn match_container(dir: &str) -> Option<(&'static str, String)> {
    for (prefix, rt) in [("docker-", "docker"), ("cri-containerd-", "containerd"), ("crio-", "cri-o"), ("libpod-", "podman")] {
        if let Some(rest) = dir.strip_prefix(prefix) {
            let id: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            if id.len() >= 12 {
                return Some((rt, id));
            }
        }
    }
    // cgroupfs driver: /docker/<id>
    if dir.len() == 64 && dir.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(("docker", dir.to_string()));
    }
    None
}

pub fn kv(text: &str) -> HashMap<&str, u64> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            Some((it.next()?, it.next()?.parse().ok()?))
        })
        .collect()
}

/// `cpu.max`: "200000 100000" → 2.0 cores; "max 100000" → None.
pub fn parse_cpu_max(text: &str) -> Option<f64> {
    let mut it = text.split_whitespace();
    let quota: f64 = it.next()?.parse().ok()?;
    let period: f64 = it.next()?.parse().ok()?;
    (period > 0.0).then(|| quota / period)
}

/// Sum rbytes/wbytes over all devices in io.stat.
pub fn parse_io_stat(text: &str) -> (u64, u64) {
    let (mut r, mut w) = (0, 0);
    for tok in text.split_whitespace() {
        if let Some(v) = tok.strip_prefix("rbytes=") {
            r += v.parse::<u64>().unwrap_or(0);
        } else if let Some(v) = tok.strip_prefix("wbytes=") {
            w += v.parse::<u64>().unwrap_or(0);
        }
    }
    (r, w)
}

/// Sum rx/tx bytes over non-loopback interfaces in /proc/<pid>/net/dev.
pub fn parse_net_dev(text: &str) -> (u64, u64) {
    let (mut rx, mut tx) = (0, 0);
    for l in text.lines().skip(2) {
        let Some((name, rest)) = l.split_once(':') else { continue };
        if name.trim() == "lo" {
            continue;
        }
        let f: Vec<u64> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        if f.len() >= 9 {
            rx += f[0];
            tx += f[8];
        }
    }
    (rx, tx)
}

#[derive(Clone, Copy, Default)]
struct Raw {
    usage_usec: u64,
    periods: u64,
    throttled: u64,
    rbytes: u64,
    wbytes: u64,
    net_rx: u64,
    net_tx: u64,
}

fn read(p: &Path, f: &str) -> String {
    std::fs::read_to_string(p.join(f)).unwrap_or_default()
}

fn docker_name(id: &str) -> Option<String> {
    let t = std::fs::read_to_string(format!("/var/lib/docker/containers/{id}/config.v2.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&t).ok()?;
    v.get("Name")?.as_str().map(|s| s.trim_start_matches('/').to_string())
}

fn find(dir: &Path, depth: usize, out: &mut Vec<(PathBuf, &'static str, String)>) {
    if depth > 6 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        if !e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = e.file_name();
        let name = name.to_string_lossy();
        if let Some((rt, id)) = match_container(name.trim_end_matches(".scope")) {
            out.push((e.path(), rt, id));
        } else {
            find(&e.path(), depth + 1, out);
        }
    }
}

pub struct Collector {
    prev: HashMap<String, (Raw, Instant)>,
    names: HashMap<String, String>,
    base_ooms: HashMap<String, u64>,
}

impl Collector {
    pub fn new() -> Self {
        Self { prev: HashMap::new(), names: HashMap::new(), base_ooms: HashMap::new() }
    }

    pub fn collect(&mut self) -> Result<Vec<Container>, String> {
        let root = Path::new("/sys/fs/cgroup");
        if !root.join("cgroup.controllers").exists() {
            return Err(if cfg!(target_os = "linux") {
                "cgroup v2 not mounted at /sys/fs/cgroup (cgroup v1 hosts are not supported)".into()
            } else {
                "containers: Linux only (Docker Desktop runs containers inside a VM)".into()
            });
        }
        let mut found = Vec::new();
        find(root, 0, &mut found);
        let now = Instant::now();
        let mut out = Vec::new();
        let mut next = HashMap::new();
        for (path, runtime, id) in found {
            let cpu = read(&path, "cpu.stat");
            let cpu = kv(&cpu);
            let events = read(&path, "memory.events");
            let ooms = kv(&events).get("oom_kill").copied().unwrap_or(0);
            let (rbytes, wbytes) = parse_io_stat(&read(&path, "io.stat"));
            let pid = read(&path, "cgroup.procs").lines().next().and_then(|l| l.trim().parse::<u32>().ok());
            let (net_rx, net_tx) = pid
                .map(|p| parse_net_dev(&std::fs::read_to_string(format!("/proc/{p}/net/dev")).unwrap_or_default()))
                .unwrap_or((0, 0));
            let raw = Raw {
                usage_usec: cpu.get("usage_usec").copied().unwrap_or(0),
                periods: cpu.get("nr_periods").copied().unwrap_or(0),
                throttled: cpu.get("nr_throttled").copied().unwrap_or(0),
                rbytes,
                wbytes,
                net_rx,
                net_tx,
            };
            let name = self
                .names
                .entry(id.clone())
                .or_insert_with(|| {
                    docker_name(&id).unwrap_or_else(|| {
                        let comm = pid
                            .and_then(|p| std::fs::read_to_string(format!("/proc/{p}/comm")).ok())
                            .map(|c| c.trim().to_string())
                            .unwrap_or_default();
                        if comm.is_empty() { id[..12].to_string() } else { format!("{comm} ({})", &id[..12]) }
                    })
                })
                .clone();
            let base = *self.base_ooms.entry(id.clone()).or_insert(ooms);
            let mut c = Container {
                name,
                runtime,
                cpu_limit: parse_cpu_max(&read(&path, "cpu.max")),
                mem: read(&path, "memory.current").trim().parse().unwrap_or(0),
                mem_max: read(&path, "memory.max").trim().parse().ok(),
                oom_kills: ooms,
                new_ooms: ooms.saturating_sub(base),
                pids: read(&path, "pids.current").trim().parse().unwrap_or(0),
                path: path.strip_prefix(root).map(|p| p.display().to_string()).unwrap_or_default(),
                id: id.clone(),
                ..Default::default()
            };
            if let Some((p, t)) = self.prev.get(&id) {
                let dt = now.duration_since(*t).as_secs_f64().max(0.1);
                let d = |a: u64, b: u64| a.saturating_sub(b) as f64;
                c.cpu_pct = d(raw.usage_usec, p.usage_usec) / 1e6 / dt * 100.0;
                let periods = d(raw.periods, p.periods);
                c.throttled_pct = if periods > 0.0 { d(raw.throttled, p.throttled) / periods * 100.0 } else { 0.0 };
                c.io_read_bps = d(raw.rbytes, p.rbytes) / dt;
                c.io_write_bps = d(raw.wbytes, p.wbytes) / dt;
                c.net_rx_bps = d(raw.net_rx, p.net_rx) / dt;
                c.net_tx_bps = d(raw.net_tx, p.net_tx) / dt;
            }
            next.insert(id, (raw, now));
            out.push(c);
        }
        self.prev = next;
        out.sort_by(|a, b| b.cpu_pct.total_cmp(&a.cpu_pct).then(a.name.cmp(&b.name)));
        Ok(out)
    }
}

pub fn spawn_worker(store: Arc<Mutex<ContainerStore>>, active: Arc<AtomicBool>) {
    thread::spawn(move || {
        let mut col = Collector::new();
        let mut last: Option<Instant> = None;
        loop {
            let iv = if active.load(Ordering::Relaxed) { 2 } else { 10 };
            if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(iv)) {
                let res = col.collect();
                if let Ok(mut s) = store.lock() {
                    match res {
                        Ok(c) => {
                            s.containers = c;
                            s.error = None;
                        }
                        Err(e) => s.error = Some(e),
                    }
                    s.version += 1;
                }
                last = Some(Instant::now());
                if store.lock().map(|s| s.error.is_some() && s.containers.is_empty()).unwrap_or(false) && !cfg!(target_os = "linux") {
                    return; // nothing will ever appear on this OS
                }
            }
            thread::sleep(Duration::from_millis(250));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_runtimes() {
        let id = "3f2a9c81d0e4aa11bb22cc33dd44ee55ff6677889900aabbccddeeff00112233";
        assert_eq!(match_container(&format!("docker-{id}")), Some(("docker", id.to_string())));
        assert_eq!(match_container(&format!("cri-containerd-{id}")).map(|x| x.0), Some("containerd"));
        assert_eq!(match_container(id).map(|x| x.0), Some("docker"));
        assert_eq!(match_container("user.slice"), None);
        assert_eq!(match_container("system.slice"), None);
    }

    #[test]
    fn parsers() {
        assert_eq!(parse_cpu_max("200000 100000\n"), Some(2.0));
        assert_eq!(parse_cpu_max("max 100000\n"), None);
        assert_eq!(parse_io_stat("8:0 rbytes=100 wbytes=50 rios=1 wios=1\n259:0 rbytes=10 wbytes=5\n"), (110, 55));
        let nd = "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets\n    lo: 500 5 0 0 0 0 0 0 500 5 0 0 0 0 0 0\n  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n";
        assert_eq!(parse_net_dev(nd), (1000, 2000));
        let k = kv("usage_usec 1500\nnr_periods 10\nnr_throttled 4\n");
        assert_eq!(k["nr_throttled"], 4);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_cgroup_walk_does_not_fail() {
        // CI runners have cgroup v2; containers may or may not be running.
        let mut c = Collector::new();
        assert!(c.collect().is_ok() || !Path::new("/sys/fs/cgroup/cgroup.controllers").exists());
    }
}
