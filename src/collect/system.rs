//! System sampler: CPU, memory, processes, network.
//!
//! What changes every tick is read straight from the OS on macOS (libproc,
//! sysctl) and Linux (/proc): one small read per process, one for all
//! interfaces. sysinfo's per-tick process refresh does far more than vigil
//! shows (every thread on Linux, every argument block on macOS) and is only
//! used that way on the other systems. Processes that are doing nothing are
//! looked at about once a second instead of every tick.
//!
//! Disks and sensors (12 ms and ~100 ms per read) live on a low-frequency
//! thread so they never stall the UI tick, and per-process strings
//! (name/cmd/exe/user) are cached per pid as `Arc<str>`, so a steady-state
//! tick allocates almost nothing.

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

/// One process as the OS reports it this tick (macOS libproc, Linux /proc).
#[cfg(any(target_os = "macos", target_os = "linux", test))]
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))] // only the parser tests use it there
#[derive(Clone, Copy, Default)]
pub struct Raw {
    pub pid: u32,
    pub ppid: u32,
    /// Owner, where the per-tick read includes it (macOS).
    pub uid: Option<u32>,
    /// Start time: tells a reused pid from the process we knew. Seconds since
    /// the epoch on macOS, clock ticks since boot on Linux.
    pub start: u64,
    /// Short name from the kernel.
    pub name: [u8; 32],
    pub name_len: u8,
    pub status: &'static str,
    /// CPU time and memory are readable (own processes, or everything as root).
    pub task: bool,
    /// Linux kernel thread: not listed.
    pub kernel: bool,
    /// User + system CPU time.
    pub cpu_ns: u64,
    pub rss: u64,
    pub virt: u64,
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
impl Raw {
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    pub fn set_name(&mut self, src: &[u8]) {
        let n = src.len().min(self.name.len());
        self.name[..n].copy_from_slice(&src[..n]);
        self.name_len = n as u8;
    }
}

/// Cumulative counters of one interface, as read this tick.
#[derive(Clone, Debug, Default)]
pub struct NetRaw {
    pub name: String,
    pub rx: u64,
    pub tx: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    /// 0 when the counters don't come with it.
    pub mtu: u64,
}

impl NetRaw {
    /// The entry at `i` of a reused list, with its name set (no allocation
    /// once the list has its size).
    pub fn slot<'a>(list: &'a mut Vec<NetRaw>, i: usize, name: &str) -> &'a mut NetRaw {
        if list.len() <= i {
            list.push(NetRaw::default());
        }
        let r = &mut list[i];
        r.name.clear();
        r.name.push_str(name);
        r
    }
}

#[derive(Clone, Debug, Default)]
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
    /// Tick of the last sample that listed this interface.
    seen: u64,
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
    crate::util::spawn_named("disks-sensors", move || {
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

#[derive(Default)]
struct ProcMeta {
    start: u64,
    seen: u64,
    name: Arc<str>,
    cmd: Arc<str>,
    exe: Arc<str>,
    user: Arc<str>,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    nat: NatMeta,
}

/// Per-process state of the native sampler (macOS, Linux).
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Default)]
struct NatMeta {
    /// The last read; shown again on the ticks an idle process is skipped.
    last: Raw,
    /// Sampler clock at that read.
    read_t: f64,
    /// Busy at the last read (`ACTIVE_PCT`): look again every tick.
    active: bool,
    /// Identity lookups done so far.
    id_tries: u8,
    read_total: u64,
    write_total: u64,
    read_rate: f64,
    write_rate: f64,
    disk_seen: bool,
    /// The OS refuses this process's I/O counters (another user's).
    disk_denied: bool,
}

/// Reused buffers of the native process sampler.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Default)]
struct NatScratch {
    pids: Vec<libc::pid_t>,
    /// (process, read this tick).
    raws: Vec<(Raw, bool)>,
}

#[cfg(target_os = "linux")]
use super::linproc as native;
#[cfg(target_os = "macos")]
use super::macproc as native;

/// A process using at least this much of a core is read every tick; the
/// rest take turns (their CPU figure is then the average over that second).
#[cfg(any(target_os = "macos", target_os = "linux"))]
const ACTIVE_PCT: f64 = 1.0;

/// Idle processes are looked at once in this many ticks: about once a
/// second, every tick when the interval is a second or more.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn idle_stride(interval_s: f64) -> u64 {
    ((1.0 / interval_s.max(0.01)).round() as u64).clamp(1, 8)
}

pub struct Sampler {
    sys: System,
    networks: Networks,
    users: Users,
    meta: HashMap<u32, ProcMeta>,
    user_names: HashMap<String, Arc<str>>,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    nat: NatScratch,
    /// Seconds of sampling so far (sum of the tick lengths).
    clock: f64,
    net_raw: Vec<NetRaw>,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    net_state: native::NetState,
    /// Clock of the last look at addresses, link state and CPU frequency.
    slow_t: f64,
    slow_due: bool,
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

/// What changes every tick: CPU, memory, disk I/O.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn proc_kind() -> ProcessRefreshKind {
    ProcessRefreshKind::nothing().with_cpu().with_memory().with_disk_usage()
}

/// Identity (user, command line, executable): fetched once per process.
///
/// With `OnlyIfNotSet` in the per-tick refresh, sysinfo asks again on every
/// tick for each process whose command line is empty or unreadable: other
/// users' processes without root (two sysctls each on macOS) and every kernel
/// thread on Linux (a /proc read and a failed readlink each). On a desktop
/// with ~900 processes that was two thirds of the cost of a tick.
#[cfg(not(target_os = "linux"))]
fn proc_identity_kind() -> ProcessRefreshKind {
    ProcessRefreshKind::nothing().with_user(UpdateKind::Always).with_cmd(UpdateKind::Always).with_exe(UpdateKind::Always)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
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
        // macOS and Linux sample processes natively (macproc.rs, linproc.rs).
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
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
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            nat: NatScratch::default(),
            clock: 0.0,
            net_raw: Vec::new(),
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            net_state: native::NetState::default(),
            slow_t: f64::MIN,
            slow_due: true,
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

        self.clock += self.elapsed;
        // Addresses, link state and the CPU frequency change rarely and cost
        // a file or a system call per interface or core: every two seconds.
        self.slow_due = self.clock - self.slow_t >= 2.0;
        if self.slow_due {
            self.slow_t = self.clock;
            self.sys.refresh_cpu_frequency();
        }
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            self.sys.refresh_processes_specifics(ProcessesToUpdate::All, true, proc_kind());
            self.refresh_new_identities();
        }
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

    /// Fetch user, command line and executable for processes we haven't seen
    /// yet, for reused pids, and for processes whose name changed (exec).
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn refresh_new_identities(&mut self) {
        let mut fresh: Vec<Pid> = Vec::new();
        for (pid, p) in self.sys.processes() {
            let known = self.meta.get(&pid.as_u32()).is_some_and(|m| m.start == p.start_time() && *m.name == *p.name().to_string_lossy());
            if !known {
                fresh.push(*pid);
            }
        }
        if !fresh.is_empty() {
            self.sys.refresh_processes_specifics(ProcessesToUpdate::Some(&fresh), false, proc_identity_kind());
        }
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

    /// macOS and Linux: per-tick numbers straight from the OS (one read per
    /// process), identity once per new process. See `macproc.rs` and
    /// `linproc.rs` for why.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn sample_procs(&mut self) {
        let tick = self.tick;
        let now_t = self.clock;
        let stride = idle_stride(self.elapsed);
        native::list_pids(&mut self.nat.pids);
        let mut raws = std::mem::take(&mut self.nat.raws);
        raws.clear();
        for &pid in &self.nat.pids {
            let key = pid as u32;
            // A process that was idle at its last read keeps its numbers
            // until its turn comes round (pids spread over the ticks).
            let rest = stride > 1 && !(tick + key as u64).is_multiple_of(stride);
            match self.meta.get(&key) {
                Some(m) if rest && !m.nat.active && m.start != u64::MAX => raws.push((m.nat.last, false)),
                _ => raws.extend(native::read(pid).map(|r| (r, true))),
            }
        }

        #[cfg(target_os = "macos")]
        {
            // Processes we may not inspect (other users', without root) carry
            // no start time: keep the one we know, or look it up once.
            for (r, _) in raws.iter_mut().filter(|(r, fresh)| *fresh && !r.task) {
                r.start = match self.meta.get(&r.pid) {
                    Some(m) if m.start != u64::MAX && m.nat.last.name() == r.name() => m.start,
                    _ => native::start_time(r.pid).unwrap_or(0),
                };
            }
            // New processes, reused pids and exec'd ones: sysinfo fetches the
            // command line and executable, once.
            let fresh: Vec<Pid> = raws
                .iter()
                .filter(|(r, fresh)| *fresh && !self.meta.get(&r.pid).is_some_and(|m| m.start == r.start && m.nat.last.name() == r.name()))
                .map(|(r, _)| Pid::from_u32(r.pid))
                .collect();
            if !fresh.is_empty() {
                self.sys.refresh_processes_specifics(ProcessesToUpdate::Some(&fresh), false, proc_identity_kind());
            }
            // sysinfo only hears about new processes here, so let it forget
            // the dead ones every few minutes (one full pass, ~15 ms).
            if tick.is_multiple_of(300) {
                self.sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
            }
        }

        let now_s = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let uptime = self.uptime;
        let (mut rd, mut wr) = (0.0, 0.0);
        let mut procs = std::mem::take(&mut self.procs);
        procs.clear();
        procs.reserve(raws.len());
        for (r, fresh) in &raws {
            let m = self.meta.entry(r.pid).or_insert_with(|| ProcMeta { start: u64::MAX, ..Default::default() });
            m.seen = tick;
            if r.kernel {
                // Kernel threads aren't listed. Remembering them keeps them
                // on the once-a-second round like any idle process.
                m.start = r.start;
                m.nat.last = *r;
                continue;
            }
            let mut cpu = 0.0;
            if *fresh {
                let new_proc = m.start != r.start;
                let changed = new_proc || m.nat.last.name() != r.name() || m.nat.last.uid != r.uid;
                // Linux: look once more at the next read. A daemon drops its
                // privileges and finishes exec just after fork, and a command
                // line can still be empty at the first look.
                let again = cfg!(target_os = "linux") && (m.nat.id_tries < 2 || (m.nat.id_tries < 4 && m.cmd.is_empty() && r.status != "Zombie"));
                if changed || again {
                    let id = identity(&self.sys, r);
                    m.name = Arc::from(id.name);
                    m.cmd = Arc::from(id.cmd);
                    m.exe = Arc::from(id.exe);
                    m.user = user_name(&self.users, &mut self.user_names, id.uid);
                    m.nat.id_tries = if changed { 1 } else { m.nat.id_tries + 1 };
                }
                let dt = (now_t - m.nat.read_t).max(0.05);
                let mut moved = true;
                if new_proc {
                    // First sample of a process: no deltas yet, so look again next tick.
                    m.nat.disk_seen = false;
                    m.nat.disk_denied = false;
                    m.nat.active = true;
                } else {
                    let used = r.cpu_ns.saturating_sub(m.nat.last.cpu_ns);
                    cpu = used as f64 / (dt * 1e9) * 100.0;
                    m.nat.active = cpu >= ACTIVE_PCT;
                    moved = used > 0;
                }
                // macOS counts CPU time to the nanosecond: a process that got
                // none did no I/O either, so skip the call. Linux counts in
                // 10 ms ticks, which a small write never shows up in.
                let io_due = cfg!(target_os = "linux") || moved || !m.nat.disk_seen;
                (m.nat.read_rate, m.nat.write_rate) = (0.0, 0.0);
                if r.task && io_due && !m.nat.disk_denied {
                    match native::disk(r.pid) {
                        Some((rb, wb)) => {
                            if m.nat.disk_seen {
                                m.nat.read_rate = rb.saturating_sub(m.nat.read_total) as f64 / dt;
                                m.nat.write_rate = wb.saturating_sub(m.nat.write_total) as f64 / dt;
                            }
                            (m.nat.read_total, m.nat.write_total, m.nat.disk_seen) = (rb, wb, true);
                        }
                        None => m.nat.disk_denied = !m.nat.disk_seen,
                    }
                }
                m.start = r.start;
                m.nat.last = *r;
                m.nat.read_t = now_t;
            }
            // (A process at rest used no CPU; its I/O rate stands until the next look.)
            rd += m.nat.read_rate;
            wr += m.nat.write_rate;
            procs.push(ProcInfo {
                pid: r.pid,
                ppid: (r.ppid != 0).then_some(r.ppid),
                name: m.name.clone(),
                cmd: m.cmd.clone(),
                exe: m.exe.clone(),
                user: m.user.clone(),
                cpu: cpu as f32,
                mem: r.rss,
                virt: r.virt,
                status: r.status,
                read_rate: m.nat.read_rate,
                write_rate: m.nat.write_rate,
                read_total: m.nat.read_total,
                write_total: m.nat.write_total,
                run_time: native::run_time(r.start, now_s, uptime),
            });
        }
        self.nat.raws = raws;
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

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
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
            let m = self.meta.entry(pid_u).or_insert_with(|| ProcMeta { start: u64::MAX, ..Default::default() });
            // New pid, pid reuse or exec: build the strings once.
            if m.start != start || *m.name != *p.name().to_string_lossy() || (m.cmd.is_empty() && !p.cmd().is_empty()) {
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

    /// Cumulative counters of every interface into `net_raw`.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn read_net(&mut self) {
        native::net(&mut self.net_state, self.slow_due, &mut self.net_raw);
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn read_net(&mut self) {
        self.networks.refresh(true);
        let mut n = 0;
        for (name, d) in self.networks.iter() {
            let r = NetRaw::slot(&mut self.net_raw, n, name);
            (r.rx, r.tx, r.rx_errors, r.tx_errors, r.rx_dropped, r.tx_dropped, r.mtu) = (d.total_received(), d.total_transmitted(), d.total_errors_on_received(), d.total_errors_on_transmitted(), 0, 0, d.mtu());
            n += 1;
        }
        self.net_raw.truncate(n);
    }

    fn sample_net(&mut self) {
        let dt = self.elapsed;
        let tick = self.tick;
        self.read_net();
        // Addresses, MAC and link state: when due, and at once for a new interface.
        let slow = self.slow_due || self.net_raw.iter().any(|r| !self.ifaces.iter().any(|i| i.name == r.name));
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if slow {
            self.networks.refresh(true);
        }
        let (mut rx, mut tx) = (0.0, 0.0);
        for r in &self.net_raw {
            let i = match self.ifaces.iter().position(|i| i.name == r.name) {
                Some(i) => i,
                None => {
                    // First sight: totals only, so the first rate is zero.
                    self.ifaces.push(IfaceInfo { name: r.name.clone(), rx_total: r.rx, tx_total: r.tx, rx_dropped: r.rx_dropped, tx_dropped: r.tx_dropped, ..Default::default() });
                    self.ifaces.len() - 1
                }
            };
            let info = &mut self.ifaces[i];
            info.rx_rate = r.rx.saturating_sub(info.rx_total) as f64 / dt;
            info.tx_rate = r.tx.saturating_sub(info.tx_total) as f64 / dt;
            info.drop_rate = (r.rx_dropped + r.tx_dropped).saturating_sub(info.rx_dropped + info.tx_dropped) as f64 / dt;
            (info.rx_total, info.tx_total, info.rx_errors, info.tx_errors) = (r.rx, r.tx, r.rx_errors, r.tx_errors);
            (info.rx_dropped, info.tx_dropped, info.seen) = (r.rx_dropped, r.tx_dropped, tick);
            if r.mtu > 0 {
                info.mtu = r.mtu;
            }
            if slow {
                let sn = read_sysnet(&r.name);
                (info.speed_mbps, info.duplex, info.oper, info.kind, info.master) = (sn.speed, sn.duplex, sn.oper, sn.kind, sn.master);
                if let Some(data) = self.networks.get(&r.name) {
                    info.mac = data.mac_address().to_string();
                    info.addrs = data.ip_networks().iter().map(|n| format!("{}/{}", n.addr, n.prefix)).collect();
                    if r.mtu == 0 {
                        info.mtu = data.mtu();
                    }
                }
            }
            if !r.name.starts_with("lo") {
                rx += info.rx_rate;
                tx += info.tx_rate;
            }
            let h = match self.iface_hist.get_mut(&r.name) {
                Some(h) => h,
                None => self.iface_hist.entry(r.name.clone()).or_insert_with(|| (History::new(HISTORY), History::new(HISTORY))),
            };
            h.0.push(info.rx_rate);
            h.1.push(info.tx_rate);
        }
        self.ifaces.retain(|i| i.seen == tick);
        if slow {
            // Interfaces come and go on container hosts (one veth per container).
            let ifaces = &self.ifaces;
            self.iface_hist.retain(|name, _| ifaces.iter().any(|i| i.name == *name));
        }
        self.ifaces.sort_by(|a, b| {
            (b.rx_total + b.tx_total)
                .cmp(&(a.rx_total + a.tx_total))
                .then_with(|| a.name.cmp(&b.name))
        });
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

    /// Unix: `kill(2)` directly, so it works for any pid on screen.
    #[cfg(unix)]
    pub fn send_signal(&self, pid: u32, sig: Signal) -> Result<(), String> {
        let num = match sig {
            Signal::Term => libc::SIGTERM,
            Signal::Kill => libc::SIGKILL,
            Signal::Hangup => libc::SIGHUP,
            Signal::Interrupt => libc::SIGINT,
            Signal::Quit => libc::SIGQUIT,
            Signal::Stop => libc::SIGSTOP,
            Signal::Continue => libc::SIGCONT,
            Signal::User1 => libc::SIGUSR1,
            Signal::User2 => libc::SIGUSR2,
            _ => return Err(format!("signal {sig:?} not supported on this platform")),
        };
        // 0 and negative numbers mean "a whole process group" to kill(2).
        let target = libc::pid_t::try_from(pid).ok().filter(|p| *p > 0).ok_or_else(|| format!("{pid} is not a process id"))?;
        if unsafe { libc::kill(target, num) } == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        Err(match e.raw_os_error() {
            Some(libc::ESRCH) => format!("process {pid} no longer exists"),
            Some(libc::EPERM) => format!("failed to send {sig:?} to {pid} (permission denied?)"),
            _ => format!("failed to send {sig:?} to {pid}: {e}"),
        })
    }

    #[cfg(not(unix))]
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

/// Name, command line, executable and owner of a new or exec'd process.
#[cfg(any(target_os = "macos", target_os = "linux"))]
struct Identity {
    name: String,
    cmd: String,
    exe: String,
    uid: Option<u32>,
}

#[cfg(target_os = "macos")]
fn identity(sys: &System, r: &Raw) -> Identity {
    let sp = sys.process(Pid::from_u32(r.pid));
    let exe = sp.and_then(|p| p.exe());
    // The executable's file name is the full name; the kernel's is cut at 32 bytes.
    let name = exe
        .and_then(|e| e.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .or_else(|| sp.map(|p| p.name().to_string_lossy().into_owned()).filter(|n| !n.is_empty()))
        .unwrap_or_else(|| String::from_utf8_lossy(r.name()).into_owned());
    Identity {
        name,
        cmd: sp.map(|p| p.cmd().iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>().join(" ")).unwrap_or_default(),
        exe: exe.map(|e| e.display().to_string()).unwrap_or_default(),
        uid: r.uid,
    }
}

#[cfg(target_os = "linux")]
fn identity(_sys: &System, r: &Raw) -> Identity {
    let id = native::identity(r.pid);
    let name = full_name(&String::from_utf8_lossy(r.name()), &id.exe);
    Identity { name, cmd: id.cmd, exe: id.exe, uid: id.uid }
}

/// Linux cuts a process name at 15 bytes ("systemd-journal"). When the
/// executable's file name starts with exactly that, it is the whole name
/// ("systemd-journald"); anything else is a name the process chose itself.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn full_name(comm: &str, exe: &str) -> String {
    let file = exe.trim_end_matches(" (deleted)").rsplit('/').next().unwrap_or("");
    if comm.len() == 15 && file.len() > 15 && file.starts_with(comm) {
        file.to_string()
    } else {
        comm.to_string()
    }
}

/// The user name of a uid, looked up once per uid.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn user_name(users: &Users, cache: &mut HashMap<String, Arc<str>>, uid: Option<u32>) -> Arc<str> {
    let Some(uid) = uid else { return Arc::from("") };
    cache
        .entry(uid.to_string())
        .or_insert_with(|| {
            let name = sysinfo::Uid::try_from(uid as usize).ok().and_then(|u| users.get_user_by_id(&u).map(|u| u.name().to_string()));
            Arc::from(name.unwrap_or_else(|| uid.to_string()))
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_processes_get_a_look_about_once_a_second() {
        for (interval, stride) in [(0.25, 4), (0.5, 2), (1.0, 1), (2.0, 1), (5.0, 1), (0.1, 8), (0.05, 8), (0.0, 8)] {
            assert_eq!(idle_stride(interval), stride, "{interval}");
        }
    }

    #[test]
    fn long_linux_names_are_completed_from_the_executable() {
        assert_eq!(full_name("systemd-journal", "/usr/lib/systemd/systemd-journald"), "systemd-journald");
        assert_eq!(full_name("systemd-journal", "/usr/lib/systemd/systemd-journald (deleted)"), "systemd-journald");
        // Exactly 15 bytes and nothing cut off.
        assert_eq!(full_name("NetworkManager1", "/usr/sbin/NetworkManager1"), "NetworkManager1");
        // A name the process gave itself, or a script run by an interpreter.
        assert_eq!(full_name("my-long-script-", "/usr/bin/bash"), "my-long-script-");
        assert_eq!(full_name("Web Content", "/usr/lib/firefox/firefox"), "Web Content");
        assert_eq!(full_name("kworker/0:1", ""), "kworker/0:1");
    }

    /// The whole sampler against the real system: our own process (busy on
    /// one thread), a sleeping child, and the interfaces.
    #[test]
    fn sampler_follows_real_processes() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let stop = Arc::new(AtomicBool::new(false));
        let busy = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut x = 1u64;
                while !stop.load(Ordering::Relaxed) {
                    x = std::hint::black_box(x.wrapping_mul(6364136223846793005).wrapping_add(1));
                }
            })
        };
        #[cfg(unix)]
        let mut child = std::process::Command::new("sleep").arg("30").spawn().expect("sleep");
        let me = std::process::id();
        let mut s = Sampler::new();
        let mut peak = 0.0f32;
        for _round in 0..8 {
            std::thread::sleep(Duration::from_millis(120));
            s.refresh();
            let mut pids: Vec<u32> = s.procs.iter().map(|p| p.pid).collect();
            pids.sort_unstable();
            pids.dedup();
            assert_eq!(pids.len(), s.procs.len(), "a pid is listed twice");
            let p = s.procs.iter().find(|p| p.pid == me).expect("own process is listed");
            assert!(p.name.starts_with("vigil"), "{}", p.name);
            assert!(p.mem > 1 << 20 && p.virt >= p.mem, "mem {} virt {}", p.mem, p.virt);
            assert!(!p.cmd.is_empty() && !p.exe.is_empty(), "cmd {:?} exe {:?}", p.cmd, p.exe);
            assert!(p.run_time < 3600, "{}", p.run_time);
            peak = peak.max(p.cpu);
            #[cfg(unix)]
            {
                assert!(!p.user.is_empty() && matches!(p.status, "Running" | "Sleeping"), "{:?} {}", p.user, p.status);
                // The child rests between its turns: its numbers stay on screen.
                let c = s.procs.iter().find(|p| p.pid == child.id()).unwrap_or_else(|| panic!("child missing in round {_round}"));
                assert_eq!((c.ppid, &*c.name, &*c.cmd), (Some(me), "sleep", "sleep 30"));
                assert!(c.mem > 0 && c.cpu < 50.0 && c.user == p.user, "mem {} cpu {}", c.mem, c.cpu);
            }
        }
        stop.store(true, Ordering::Relaxed);
        busy.join().unwrap();
        // One thread spinning is about 100 % of a core.
        assert!(peak > 25.0, "own cpu peaked at {peak}");
        #[cfg(unix)]
        {
            child.kill().unwrap();
            child.wait().unwrap();
            s.refresh();
            assert!(!s.procs.iter().any(|p| p.pid == child.id()), "a dead process is still listed");
        }
        #[cfg(unix)]
        {
            let lo = s.ifaces.iter().find(|i| i.name.starts_with("lo")).expect("loopback interface");
            assert!(lo.mtu > 0, "{lo:?}");
        }
        assert!(!s.ifaces.is_empty());
        assert!(s.ifaces.iter().all(|i| i.rx_rate >= 0.0 && i.rx_rate < 1e12), "{:?}", s.ifaces);
        assert!(s.mem_total > 0 && s.ncores() > 0);
    }

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
