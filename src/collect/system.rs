//! System sampler built on sysinfo: CPU, memory, processes, network.
//!
//! Performance notes (measured on macOS / M4, ~860 processes):
//!   process refresh ≈ 2 ms, networks ≈ 0.7 ms, disks ≈ 12 ms, sensors ≈ 108 ms.
//! Disks and sensors therefore live on a separate low-frequency thread so they
//! never stall the UI tick, and per-process strings (name/cmd/exe/user) are
//! cached per pid as `Arc<str>` so a steady-state tick allocates almost nothing.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use sysinfo::{
    Components, Disks, Networks, Pid, ProcessRefreshKind, ProcessesToUpdate, Signal, System,
    UpdateKind, Users,
};

use crate::util::{History, MiniHist};

pub const HISTORY: usize = 600;

#[derive(Clone, Debug)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: Arc<str>,
    pub cmd: Arc<str>,
    pub exe: Arc<str>,
    pub user: Arc<str>,
    pub cpu: f32,
    pub mem: u64,
    pub virt: u64,
    pub status: &'static str,
    pub read_rate: f64,
    pub write_rate: f64,
    pub read_total: u64,
    pub write_total: u64,
    pub run_time: u64,
}

#[derive(Clone, Debug)]
pub struct IfaceInfo {
    pub name: String,
    pub rx_rate: f64,
    pub tx_rate: f64,
    pub rx_total: u64,
    pub tx_total: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub mac: String,
    pub addrs: Vec<String>,
    pub mtu: u64,
    /// Linux /sys/class/net details (None elsewhere or when not exposed).
    pub speed_mbps: Option<u32>,
    pub duplex: Option<String>,
    pub oper: Option<String>,
    /// DEVTYPE from uevent: vlan, bridge, bond, wireguard, wlan, veth …
    pub kind: Option<String>,
    pub master: Option<String>,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub drop_rate: f64,
}

impl IfaceInfo {
    /// Busiest direction as a share of the negotiated link speed.
    pub fn util_pct(&self) -> Option<f64> {
        let sp = self.speed_mbps.filter(|s| *s > 0)? as f64 * 1e6 / 8.0;
        Some(self.rx_rate.max(self.tx_rate) / sp * 100.0)
    }
}

#[derive(Default, Clone)]
struct SysNet {
    speed: Option<u32>,
    duplex: Option<String>,
    oper: Option<String>,
    kind: Option<String>,
    master: Option<String>,
    rx_dropped: u64,
    tx_dropped: u64,
}

#[cfg(target_os = "linux")]
fn read_sysnet(name: &str) -> SysNet {
    let base = format!("/sys/class/net/{name}");
    let rd = |f: &str| std::fs::read_to_string(format!("{base}/{f}")).ok().map(|s| s.trim().to_string());
    let num = |f: &str| rd(f).and_then(|s| s.parse::<i64>().ok());
    let kind = rd("uevent").and_then(|u| {
        u.lines().find_map(|l| l.strip_prefix("DEVTYPE=").map(str::to_string))
    }).or_else(|| name.starts_with("veth").then(|| "veth".to_string()));
    let master = std::fs::read_link(format!("{base}/master"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
    SysNet {
        speed: num("speed").filter(|s| *s > 0).map(|s| s as u32),
        duplex: rd("duplex").filter(|d| d != "unknown"),
        oper: rd("operstate"),
        kind,
        master,
        rx_dropped: num("statistics/rx_dropped").unwrap_or(0).max(0) as u64,
        tx_dropped: num("statistics/tx_dropped").unwrap_or(0).max(0) as u64,
    }
}

#[cfg(not(target_os = "linux"))]
fn read_sysnet(_name: &str) -> SysNet {
    SysNet::default()
}

#[derive(Clone, Debug)]
pub struct DiskInfo {
    pub name: String,
    pub mount: String,
    pub fs: String,
    pub kind: String,
    pub total: u64,
    pub avail: u64,
    pub removable: bool,
    pub inodes_total: u64,
    pub inodes_free: u64,
}

impl DiskInfo {
    pub fn used(&self) -> u64 {
        self.total.saturating_sub(self.avail)
    }
    pub fn pct(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.used() as f64 / self.total as f64 * 100.0
        }
    }

    /// Inode usage; None for filesystems without a fixed inode table (btrfs, zfs, apfs report 0).
    pub fn inode_pct(&self) -> Option<f64> {
        (self.inodes_total > 0).then(|| {
            self.inodes_total.saturating_sub(self.inodes_free) as f64 / self.inodes_total as f64 * 100.0
        })
    }
}

/// (total, free) inodes for a mount point.
#[cfg(unix)]
fn inodes(mount: &str) -> (u64, u64) {
    let Ok(c) = std::ffi::CString::new(mount) else { return (0, 0) };
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return (0, 0);
    }
    #[allow(clippy::unnecessary_cast)]
    (st.f_files as u64, st.f_ffree as u64)
}

#[cfg(not(unix))]
fn inodes(_mount: &str) -> (u64, u64) {
    (0, 0)
}


#[derive(Clone, Debug)]
pub struct TempInfo {
    pub label: String,
    pub temp: f32,
    pub critical: Option<f32>,
}

/// Per-process detail for the inspector, collected on demand.
#[derive(Clone, Debug, Default)]
pub struct DeepInfo {
    pub cwd: String,
    pub root: String,
    pub environ: Vec<(String, String)>,
    pub threads: Option<u64>,
    pub cgroup: String,
    pub unit: Option<String>,
    pub container: Option<String>,
}

/// Environment variable names whose values are hidden in the inspector.
pub fn is_secret_env(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    ["KEY", "SECRET", "TOKEN", "PASS", "AUTH", "CREDENTIAL", "PRIVATE", "COOKIE", "SESSION", "DSN"]
        .iter()
        .any(|w| n.contains(w))
        || n.ends_with("_URL") && n.contains("DATABASE")
}

#[derive(Clone, Debug, Default)]
pub struct HostInfo {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub cpu_brand: String,
    pub physical_cores: usize,
}

// ───────────────────── slow collectors (disks + sensors) ─────────────────────

#[derive(Default)]
pub struct SlowData {
    pub disks: Vec<DiskInfo>,
    pub temps: Vec<TempInfo>,
    pub version: u64,
}

/// Disks every 10 s; sensors every 10 s, or every 2 s while `fast` is set
/// (the Storage view is open).
///
/// `Components::refresh(true)` re-enumerates every sensor through IOKit/hwmon
/// (≈108 ms on macOS); refreshing the existing sensors one by one costs
/// ≈1 ms each. So we re-enumerate only every 5 minutes.
fn spawn_slow_worker(store: Arc<Mutex<SlowData>>, fast: Arc<AtomicBool>) {
    thread::spawn(move || {
        let mut disks = Disks::new_with_refreshed_list();
        let mut comps = Components::new_with_refreshed_list();
        let mut last_disks = Instant::now();
        let mut last_comps = Instant::now();
        let mut last_enum = Instant::now();
        let mut first = true;
        loop {
            let is_fast = fast.load(Ordering::Relaxed);
            let mut changed = first;
            if !first && last_disks.elapsed() >= Duration::from_secs(10) {
                disks.refresh(true);
                last_disks = Instant::now();
                changed = true;
            }
            let comp_iv = Duration::from_secs(if is_fast { 2 } else { 10 });
            if !first && last_comps.elapsed() >= comp_iv {
                if last_enum.elapsed() >= Duration::from_secs(300) {
                    comps.refresh(true);
                    last_enum = Instant::now();
                } else {
                    for c in comps.list_mut() {
                        c.refresh();
                    }
                }
                last_comps = Instant::now();
                changed = true;
            }
            first = false;
            if changed {
                let mut d: Vec<DiskInfo> = disks
                    .iter()
                    .map(|d| {
                        let mount = d.mount_point().display().to_string();
                        let (inodes_total, inodes_free) = inodes(&mount);
                        DiskInfo {
                            name: d.name().to_string_lossy().into_owned(),
                            fs: d.file_system().to_string_lossy().into_owned(),
                            kind: d.kind().to_string(),
                            total: d.total_space(),
                            avail: d.available_space(),
                            removable: d.is_removable(),
                            inodes_total,
                            inodes_free,
                            mount,
                        }
                    })
                    .collect();
                d.sort_by(|a, b| a.mount.cmp(&b.mount));
                d.dedup_by(|a, b| a.mount == b.mount);
                let mut t: Vec<TempInfo> = comps
                    .iter()
                    .filter_map(|c| {
                        let temp = c.temperature()?;
                        (temp.is_finite() && temp > 0.0).then(|| TempInfo {
                            label: c.label().to_string(),
                            temp,
                            critical: c.critical(),
                        })
                    })
                    .collect();
                t.sort_by(|a, b| b.temp.total_cmp(&a.temp));
                if let Ok(mut s) = store.lock() {
                    s.disks = d;
                    s.temps = t;
                    s.version += 1;
                }
            }
            thread::sleep(Duration::from_millis(500));
        }
    });
}

// ─────────────────────────────── sampler ───────────────────────────────

struct ProcMeta {
    start: u64,
    seen: u64,
    name: Arc<str>,
    cmd: Arc<str>,
    exe: Arc<str>,
    user: Arc<str>,
}

pub struct Sampler {
    sys: System,
    networks: Networks,
    users: Users,
    meta: HashMap<u32, ProcMeta>,
    user_names: HashMap<String, Arc<str>>,
    slow: Arc<Mutex<SlowData>>,
    slow_seen: u64,
    pub sensors_fast: Arc<AtomicBool>,
    last: Instant,
    tick: u64,
    pub host: HostInfo,
    pub elapsed: f64,

    pub cpu_total: History,
    pub cpu_cores: Vec<History>,
    pub cpu_freq: u64,
    pub mem_hist: History,
    pub swap_hist: History,
    pub rx_hist: History,
    pub tx_hist: History,
    pub iface_hist: HashMap<String, (History, History)>,
    /// pid → (cpu %, memory bytes) over the last two minutes.
    pub proc_hist: HashMap<u32, (MiniHist, MiniHist)>,
    prev_drops: HashMap<String, u64>,
    pub knet: super::kernelnet::KernelNet,
    pub diskio: super::diskio::DiskIo,

    pub procs: Vec<ProcInfo>,
    pub ifaces: Vec<IfaceInfo>,
    pub disks_info: Vec<DiskInfo>,
    pub temps: Vec<TempInfo>,

    pub mem_total: u64,
    pub mem_used: u64,
    pub mem_avail: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub rx_rate: f64,
    pub tx_rate: f64,
    pub io_read_rate: f64,
    pub io_write_rate: f64,
    pub load: (f64, f64, f64),
    pub uptime: u64,
    /// Linux pressure stall info, `some avg10` % for [cpu, memory, io].
    pub psi: Option<[f64; 3]>,
}

/// Parse `some avg10=1.23 avg60=… total=…` from /proc/pressure/*.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_psi_some_avg10(text: &str) -> Option<f64> {
    text.lines()
        .find(|l| l.starts_with("some"))?
        .split_whitespace()
        .find_map(|f| f.strip_prefix("avg10="))?
        .parse()
        .ok()
}

#[cfg(target_os = "linux")]
fn read_psi() -> Option<[f64; 3]> {
    let r = |n: &str| {
        std::fs::read_to_string(format!("/proc/pressure/{n}"))
            .ok()
            .and_then(|t| parse_psi_some_avg10(&t))
    };
    Some([r("cpu")?, r("memory").unwrap_or(0.0), r("io").unwrap_or(0.0)])
}

#[cfg(not(target_os = "linux"))]
fn read_psi() -> Option<[f64; 3]> {
    None
}

fn proc_kind() -> ProcessRefreshKind {
    ProcessRefreshKind::nothing()
        .with_cpu()
        .with_memory()
        .with_disk_usage()
        .with_user(UpdateKind::OnlyIfNotSet)
        .with_cmd(UpdateKind::OnlyIfNotSet)
        .with_exe(UpdateKind::OnlyIfNotSet)
}

fn status_str(s: sysinfo::ProcessStatus) -> &'static str {
    use sysinfo::ProcessStatus::*;
    match s {
        Run => "Running",
        Sleep => "Sleeping",
        Idle => "Idle",
        Stop => "Stopped",
        Zombie => "Zombie",
        Tracing => "Tracing",
        Dead => "Dead",
        Wakekill => "Wakekill",
        Waking => "Waking",
        Parked => "Parked",
        LockBlocked => "LockBlocked",
        UninterruptibleDiskSleep => "Disk sleep",
        Unknown(_) => "Unknown",
    }
}

impl Sampler {
    pub fn new() -> Self {
        let mut sys = System::new();
        sys.refresh_cpu_all();
        sys.refresh_memory();
        sys.refresh_processes_specifics(ProcessesToUpdate::All, true, proc_kind());

        let host = HostInfo {
            hostname: System::host_name().unwrap_or_else(|| "unknown".into()),
            os: System::long_os_version().unwrap_or_else(|| System::name().unwrap_or_default()),
            kernel: System::kernel_version().unwrap_or_default(),
            arch: System::cpu_arch(),
            cpu_brand: sys
                .cpus()
                .first()
                .map(|c| c.brand().trim().to_string())
                .unwrap_or_default(),
            physical_cores: sys.physical_core_count().unwrap_or(0),
        };
        let ncores = sys.cpus().len();

        let slow = Arc::new(Mutex::new(SlowData::default()));
        let sensors_fast = Arc::new(AtomicBool::new(false));
        spawn_slow_worker(slow.clone(), sensors_fast.clone());

        let mut s = Self {
            sys,
            networks: Networks::new_with_refreshed_list(),
            users: Users::new_with_refreshed_list(),
            meta: HashMap::new(),
            user_names: HashMap::new(),
            slow,
            slow_seen: 0,
            sensors_fast,
            last: Instant::now(),
            tick: 0,
            host,
            elapsed: 1.0,
            cpu_total: History::new(HISTORY),
            cpu_cores: (0..ncores).map(|_| History::new(HISTORY)).collect(),
            cpu_freq: 0,
            mem_hist: History::new(HISTORY),
            swap_hist: History::new(HISTORY),
            rx_hist: History::new(HISTORY),
            tx_hist: History::new(HISTORY),
            iface_hist: HashMap::new(),
            proc_hist: HashMap::new(),
            prev_drops: HashMap::new(),
            knet: super::kernelnet::KernelNet::new(),
            diskio: super::diskio::DiskIo::default(),
            procs: Vec::new(),
            ifaces: Vec::new(),
            disks_info: Vec::new(),
            temps: Vec::new(),
            mem_total: 0,
            mem_used: 0,
            mem_avail: 0,
            swap_total: 0,
            swap_used: 0,
            rx_rate: 0.0,
            tx_rate: 0.0,
            io_read_rate: 0.0,
            io_write_rate: 0.0,
            load: (0.0, 0.0, 0.0),
            uptime: 0,
            psi: None,
        };
        // CPU usage needs two samples with a gap between them.
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        s.refresh();
        s
    }

    pub fn refresh(&mut self) {
        let now = Instant::now();
        self.elapsed = now.duration_since(self.last).as_secs_f64().max(0.05);
        self.last = now;
        self.tick += 1;

        self.sys.refresh_cpu_all();
        self.sys.refresh_memory();
        self.sys
            .refresh_processes_specifics(ProcessesToUpdate::All, true, proc_kind());
        self.networks.refresh(true);
        if self.tick.is_multiple_of(120) {
            self.users.refresh();
            self.user_names.clear();
        }

        self.sample_cpu_mem();
        self.sample_procs();
        self.sample_net();
        self.knet.refresh();
        self.diskio.refresh();
        self.pull_slow();
    }

    /// Copy disks/sensors from the background thread only when they changed.
    fn pull_slow(&mut self) {
        if let Ok(s) = self.slow.try_lock() {
            if s.version != self.slow_seen {
                self.slow_seen = s.version;
                self.disks_info.clone_from(&s.disks);
                self.temps.clone_from(&s.temps);
            }
        }
    }

    pub fn slow_version(&self) -> u64 {
        self.slow.try_lock().map(|s| s.version).unwrap_or(self.slow_seen)
    }

    fn sample_cpu_mem(&mut self) {
        self.cpu_total.push(self.sys.global_cpu_usage() as f64);
        for (i, cpu) in self.sys.cpus().iter().enumerate() {
            if let Some(h) = self.cpu_cores.get_mut(i) {
                h.push(cpu.cpu_usage() as f64);
            }
        }
        self.cpu_freq = self.sys.cpus().first().map(|c| c.frequency()).unwrap_or(0);

        self.mem_total = self.sys.total_memory();
        self.mem_avail = self.sys.available_memory();
        self.mem_used = self.mem_total.saturating_sub(self.mem_avail);
        self.swap_total = self.sys.total_swap();
        self.swap_used = self.sys.used_swap();
        let pct = |u: u64, t: u64| if t == 0 { 0.0 } else { u as f64 / t as f64 * 100.0 };
        self.mem_hist.push(pct(self.mem_used, self.mem_total));
        self.swap_hist.push(pct(self.swap_used, self.swap_total));

        let l = System::load_average();
        self.load = (l.one, l.five, l.fifteen);
        self.uptime = System::uptime();
        self.psi = read_psi();
    }

    fn sample_procs(&mut self) {
        let dt = self.elapsed;
        let tick = self.tick;
        let (mut rd, mut wr) = (0.0, 0.0);
        // Reuse the existing allocation.
        let mut procs = std::mem::take(&mut self.procs);
        procs.clear();
        procs.reserve(self.sys.processes().len());

        for (pid, p) in self.sys.processes() {
            if p.thread_kind().is_some() {
                continue; // Linux threads: show processes only
            }
            let pid_u = pid.as_u32();
            let start = p.start_time();
            let users = &self.users;
            let user_names = &mut self.user_names;
            let m = self.meta.entry(pid_u).or_insert_with(|| ProcMeta {
                start: u64::MAX,
                seen: 0,
                name: Arc::from(""),
                cmd: Arc::from(""),
                exe: Arc::from(""),
                user: Arc::from(""),
            });
            // New pid (or pid reuse): build the strings once.
            if m.start != start || (m.cmd.is_empty() && !p.cmd().is_empty()) {
                m.start = start;
                m.name = Arc::from(p.name().to_string_lossy().as_ref());
                let cmd = p
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" ");
                m.cmd = Arc::from(cmd);
                m.exe = Arc::from(p.exe().map(|e| e.display().to_string()).unwrap_or_default());
                m.user = match p.user_id() {
                    Some(uid) => {
                        let key = uid.to_string();
                        user_names
                            .entry(key.clone())
                            .or_insert_with(|| {
                                Arc::from(
                                    users
                                        .get_user_by_id(uid)
                                        .map(|u| u.name().to_string())
                                        .unwrap_or(key),
                                )
                            })
                            .clone()
                    }
                    None => Arc::from(""),
                };
            }
            m.seen = tick;

            let du = p.disk_usage();
            let (r, w) = (du.read_bytes as f64 / dt, du.written_bytes as f64 / dt);
            rd += r;
            wr += w;
            procs.push(ProcInfo {
                pid: pid_u,
                ppid: p.parent().map(|p| p.as_u32()),
                name: m.name.clone(),
                cmd: m.cmd.clone(),
                exe: m.exe.clone(),
                user: m.user.clone(),
                cpu: p.cpu_usage(),
                mem: p.memory(),
                virt: p.virtual_memory(),
                status: status_str(p.status()),
                read_rate: r,
                write_rate: w,
                read_total: du.total_read_bytes,
                write_total: du.total_written_bytes,
                run_time: p.run_time(),
            });
        }
        self.meta.retain(|_, m| m.seen == tick);
        for p in &procs {
            let h = self.proc_hist.entry(p.pid).or_default();
            h.0.push(p.cpu);
            h.1.push(p.mem as f32);
        }
        let meta = &self.meta;
        self.proc_hist.retain(|pid, _| meta.contains_key(pid));
        self.io_read_rate = rd;
        self.io_write_rate = wr;
        self.procs = procs;
    }

    fn sample_net(&mut self) {
        let dt = self.elapsed;
        let (mut rx, mut tx) = (0.0, 0.0);
        let mut ifaces = std::mem::take(&mut self.ifaces);
        ifaces.clear();
        for (name, data) in self.networks.iter() {
            let r = data.received() as f64 / dt;
            let t = data.transmitted() as f64 / dt;
            if !name.starts_with("lo") {
                rx += r;
                tx += t;
            }
            let h = match self.iface_hist.get_mut(name) {
                Some(h) => h,
                None => self
                    .iface_hist
                    .entry(name.clone())
                    .or_insert_with(|| (History::new(HISTORY), History::new(HISTORY))),
            };
            h.0.push(r);
            h.1.push(t);
            let sn = read_sysnet(name);
            let drops = sn.rx_dropped + sn.tx_dropped;
            let prev = self.prev_drops.insert(name.clone(), drops).unwrap_or(drops);
            ifaces.push(IfaceInfo {
                mtu: data.mtu(),
                speed_mbps: sn.speed,
                duplex: sn.duplex,
                oper: sn.oper,
                kind: sn.kind,
                master: sn.master,
                rx_dropped: sn.rx_dropped,
                tx_dropped: sn.tx_dropped,
                drop_rate: drops.saturating_sub(prev) as f64 / dt,
                name: name.clone(),
                rx_rate: r,
                tx_rate: t,
                rx_total: data.total_received(),
                tx_total: data.total_transmitted(),
                rx_errors: data.total_errors_on_received(),
                tx_errors: data.total_errors_on_transmitted(),
                mac: data.mac_address().to_string(),
                addrs: data
                    .ip_networks()
                    .iter()
                    .map(|n| format!("{}/{}", n.addr, n.prefix))
                    .collect(),
            });
        }
        ifaces.sort_by(|a, b| {
            (b.rx_total + b.tx_total)
                .cmp(&(a.rx_total + a.tx_total))
                .then_with(|| a.name.cmp(&b.name))
        });
        self.ifaces = ifaces;
        self.rx_rate = rx;
        self.tx_rate = tx;
        self.rx_hist.push(rx);
        self.tx_hist.push(tx);
    }

    pub fn ncores(&self) -> usize {
        self.cpu_cores.len()
    }

    pub fn proc_count(&self) -> usize {
        self.procs.len()
    }

    /// Everything the inspector shows that isn't sampled every tick:
    /// working directory, root, environment, threads, cgroup, unit, container.
    /// Refreshes just this one process.
    pub fn deep_info(&mut self, pid: u32) -> Option<DeepInfo> {
        let kind = ProcessRefreshKind::nothing()
            .with_cwd(UpdateKind::Always)
            .with_environ(UpdateKind::Always)
            .with_root(UpdateKind::Always);
        let id = Pid::from_u32(pid);
        self.sys.refresh_processes_specifics(ProcessesToUpdate::Some(&[id]), false, kind);
        let p = self.sys.process(id)?;
        let path = |o: Option<&std::path::Path>| o.map(|x| x.display().to_string()).unwrap_or_default();
        let mut environ: Vec<(String, String)> = p
            .environ()
            .iter()
            .filter_map(|e| {
                let e = e.to_string_lossy();
                let (k, v) = e.split_once('=')?;
                Some((k.to_string(), v.to_string()))
            })
            .collect();
        environ.sort();
        let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
        let cgroup_path = cgroup.lines().find_map(|l| l.strip_prefix("0::")).unwrap_or("").to_string();
        let unit = cgroup_path
            .split('/')
            .rev()
            .find(|seg| seg.ends_with(".service"))
            .map(str::to_string);
        let threads = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|t| t.lines().find_map(|l| l.strip_prefix("Threads:").and_then(|v| v.trim().parse().ok())))
            .or_else(|| p.tasks().map(|t| t.len() as u64));
        Some(DeepInfo {
            cwd: path(p.cwd()),
            root: path(p.root()),
            environ,
            threads,
            container: super::procnet::container_label(&cgroup),
            unit,
            cgroup: cgroup_path,
        })
    }

    pub fn send_signal(&self, pid: u32, sig: Signal) -> Result<(), String> {
        let proc = self
            .sys
            .process(Pid::from_u32(pid))
            .ok_or_else(|| format!("process {pid} no longer exists"))?;
        match proc.kill_with(sig) {
            Some(true) => Ok(()),
            Some(false) => Err(format!("failed to send {sig:?} to {pid} (permission denied?)")),
            None => Err(format!("signal {sig:?} not supported on this platform")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psi_parse() {
        let t = "some avg10=12.50 avg60=3.00 avg300=1.00 total=123\nfull avg10=2.00 avg60=0.00 avg300=0.00 total=1\n";
        assert_eq!(parse_psi_some_avg10(t), Some(12.5));
        assert_eq!(parse_psi_some_avg10("garbage"), None);
    }
}

#[cfg(test)]
mod deep_tests {
    use super::*;

    #[test]
    fn secrets_are_masked() {
        for k in ["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "DB_PASSWORD", "api_key", "DATABASE_URL"] {
            assert!(is_secret_env(k), "{k}");
        }
        for k in ["PATH", "HOME", "LANG", "TERM"] {
            assert!(!is_secret_env(k), "{k}");
        }
    }

    #[test]
    fn deep_info_of_self() {
        let mut s = Sampler::new();
        let d = s.deep_info(std::process::id()).expect("own process");
        assert!(!d.cwd.is_empty());
        // Windows spells it "Path"; environment names are case-insensitive there.
        assert!(d.environ.iter().any(|(k, _)| k.eq_ignore_ascii_case("PATH")));
    }
}
