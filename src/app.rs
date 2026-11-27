//! Application state and input handling.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use ratatui::style::Color;
use ratatui::widgets::TableState;
use sysinfo::Signal;

use std::sync::atomic::AtomicBool;

use crate::collect::capture::{self, CaptureState};
use crate::collect::containers::{self, ContainerStore};
use crate::collect::kmsg::{self, KmsgStore};
use crate::collect::l2::{self, L2Store};
use crate::collect::limits::{self, Limits};
use crate::collect::services::{self, ServiceStore};
use crate::collect::sessions::{self, SessionStore};
use crate::collect::system::DeepInfo;
use crate::collect::trace::{self, TraceStore};
use crate::collect::firewall::{self, FwRule, FwStore};
use crate::collect::ipinfo::{self, Resolver};
use crate::collect::lsof::{self, FilesStore, OpenFile, Query, SocketStore};
use crate::collect::netinfo::{self, NetInfo};
use crate::collect::probes::{self, ProbeStore};
use crate::collect::system::{ProcInfo, Sampler};
use crate::config::{Alerts, Config};
use crate::theme;
use crate::tools::{self, ToolStore};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Overview,
    Processes,
    Network,
    Sockets,
    Files,
    Storage,
    Routes,
    Probes,
    Firewall,
    Containers,
    System,
    Users,
    Troubleshoot,
}

impl Tab {
    pub const ALL: [Tab; 13] = [
        Tab::Overview,
        Tab::Processes,
        Tab::Network,
        Tab::Sockets,
        Tab::Files,
        Tab::Storage,
        Tab::Routes,
        Tab::Probes,
        Tab::Firewall,
        Tab::Containers,
        Tab::System,
        Tab::Users,
        Tab::Troubleshoot,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Processes => "Procs",
            Tab::Network => "Network",
            Tab::Sockets => "Sockets",
            Tab::Files => "Files",
            Tab::Storage => "Storage",
            Tab::Routes => "Routes",
            Tab::Probes => "Probes",
            Tab::Firewall => "Firewall",
            Tab::Containers => "Containers",
            Tab::System => "System",
            Tab::Users => "Users",
            Tab::Troubleshoot => "Troubleshoot",
        }
    }

    /// Key shown in the tab bar and used to jump to the view.
    pub fn key(self) -> char {
        match self {
            Tab::Containers => '0',
            Tab::System => 'S',
            Tab::Users => 'U',
            Tab::Troubleshoot => 'W',
            t => char::from(b'1' + t.index() as u8),
        }
    }

    pub fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    pub fn from_name(s: &str) -> Option<Tab> {
        let s = s.to_ascii_lowercase();
        let s = match s.as_str() {
            "processes" => "procs".to_string(),
            "open files" | "openfiles" => "files".to_string(),
            "tools" | "doctor" => "troubleshoot".to_string(),
            _ => s,
        };
        Tab::ALL
            .into_iter()
            .find(|t| t.title().to_ascii_lowercase().starts_with(&s))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProcSort {
    Cpu,
    Mem,
    Pid,
    Name,
    User,
    Io,
    Conn,
    Net,
    Fds,
}

impl ProcSort {
    pub fn as_str(self) -> &'static str {
        match self {
            ProcSort::Cpu => "cpu",
            ProcSort::Mem => "mem",
            ProcSort::Pid => "pid",
            ProcSort::Name => "name",
            ProcSort::User => "user",
            ProcSort::Io => "io",
            ProcSort::Conn => "conn",
            ProcSort::Net => "net",
            ProcSort::Fds => "fds",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "cpu" => ProcSort::Cpu,
            "mem" | "memory" => ProcSort::Mem,
            "pid" => ProcSort::Pid,
            "name" => ProcSort::Name,
            "user" => ProcSort::User,
            "io" => ProcSort::Io,
            "conn" | "connections" => ProcSort::Conn,
            "net" | "network" => ProcSort::Net,
            "fds" | "fd" => ProcSort::Fds,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SockSort {
    Process,
    Port,
    State,
    Proto,
    Remote,
    Rtt,
    Traffic,
}

impl SockSort {
    fn next(self) -> Self {
        match self {
            SockSort::Process => SockSort::Port,
            SockSort::Port => SockSort::State,
            SockSort::State => SockSort::Proto,
            SockSort::Proto => SockSort::Remote,
            SockSort::Remote => SockSort::Rtt,
            SockSort::Rtt => SockSort::Traffic,
            SockSort::Traffic => SockSort::Process,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            SockSort::Process => "process",
            SockSort::Port => "port",
            SockSort::State => "state",
            SockSort::Proto => "proto",
            SockSort::Remote => "remote",
            SockSort::Rtt => "rtt",
            SockSort::Traffic => "traffic",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Normal,
    Filter,
    Query,
    Signal,
    Theme,
    AddProbe,
    ConfirmClose,
    ToolInput,
    Search,
}

/// One result of the global search (F).
#[derive(Clone, Debug)]
pub struct SearchHit {
    pub tab: Tab,
    pub kind: &'static str,
    pub text: String,
    /// Row to select in that view (pid for processes).
    pub target: usize,
}

const SIGNALS: [(&str, &str, Signal); 9] = [
    ("SIGTERM", "15  graceful termination", Signal::Term),
    ("SIGKILL", " 9  force kill (cannot be caught)", Signal::Kill),
    ("SIGHUP", " 1  hangup / reload config", Signal::Hangup),
    ("SIGINT", " 2  interrupt (Ctrl-C)", Signal::Interrupt),
    ("SIGQUIT", " 3  quit + core dump", Signal::Quit),
    ("SIGSTOP", "    pause process", Signal::Stop),
    ("SIGCONT", "    resume process", Signal::Continue),
    ("SIGUSR1", "    user defined 1", Signal::User1),
    ("SIGUSR2", "    user defined 2", Signal::User2),
];

/// Windows has no signals: TerminateProcess is the only thing sysinfo can send.
const WIN_SIGNALS: [(&str, &str, Signal); 1] = [("TERMINATE", "end the process (TerminateProcess)", Signal::Kill)];

/// Parse a key name from `[keys]`: `q`, `F5`, `ctrl-k`, `alt-x`, `esc`,
/// `enter`, `tab`, `space`, `up`, `pgdn`, `del`, …
pub fn parse_key(spec: &str) -> Option<KeyEvent> {
    let mut mods = KeyModifiers::NONE;
    let mut rest = spec.trim();
    loop {
        let low = rest.to_ascii_lowercase();
        if let Some(r) = ["ctrl-", "ctrl+", "c-"].iter().find_map(|p| low.strip_prefix(p).map(|_| &rest[p.len()..])) {
            mods |= KeyModifiers::CONTROL;
            rest = r;
        } else if let Some(r) = ["alt-", "alt+", "m-", "meta-"].iter().find_map(|p| low.strip_prefix(p).map(|_| &rest[p.len()..])) {
            mods |= KeyModifiers::ALT;
            rest = r;
        } else {
            break;
        }
    }
    let code = match rest.to_ascii_lowercase().as_str() {
        "esc" | "escape" => KeyCode::Esc,
        "enter" | "return" => KeyCode::Enter,
        "tab" => KeyCode::Tab,
        "backtab" => KeyCode::BackTab,
        "space" => KeyCode::Char(' '),
        "up" => KeyCode::Up,
        "down" => KeyCode::Down,
        "left" => KeyCode::Left,
        "right" => KeyCode::Right,
        "home" => KeyCode::Home,
        "end" => KeyCode::End,
        "pgup" | "pageup" => KeyCode::PageUp,
        "pgdn" | "pagedown" => KeyCode::PageDown,
        "del" | "delete" => KeyCode::Delete,
        "backspace" => KeyCode::Backspace,
        "insert" | "ins" => KeyCode::Insert,
        f if f.len() >= 2 && f.starts_with('f') && f[1..].parse::<u8>().is_ok_and(|n| (1..=24).contains(&n)) => KeyCode::F(f[1..].parse().ok()?),
        _ => {
            let mut ch = rest.chars();
            let c = ch.next()?;
            if ch.next().is_some() {
                return None;
            }
            KeyCode::Char(if mods.contains(KeyModifiers::CONTROL) { c.to_ascii_lowercase() } else { c })
        }
    };
    Some(KeyEvent::new(code, mods))
}

/// Terminals report `K` as Char('K') + SHIFT; the char already says it.
fn normalize_key(k: KeyEvent) -> (KeyCode, KeyModifiers) {
    match k.code {
        KeyCode::Char(_) => (k.code, k.modifiers - KeyModifiers::SHIFT),
        _ => (k.code, k.modifiers),
    }
}

/// Build the `[keys]` map; returns warnings for entries that don't parse.
pub fn key_map(keys: &std::collections::BTreeMap<String, String>) -> (HashMap<(KeyCode, KeyModifiers), KeyEvent>, Vec<String>) {
    let mut m = HashMap::new();
    let mut w = Vec::new();
    for (from, to) in keys {
        match (parse_key(from), parse_key(to)) {
            (Some(f), Some(t)) => {
                m.insert(normalize_key(f), t);
            }
            _ => w.push(format!("[keys] {from} = {to}: unknown key name")),
        }
    }
    (m, w)
}

/// The explain-mode key for a health badge's text ("MEM 96%" → "MEM").
pub fn badge_key(text: &str) -> &'static str {
    const PREFIXES: [&str; 23] = [
        "GATEWAY MAC CHANGED", "EPHEMERAL PORTS", "NEEDS RESTART", "FAILED UNITS", "LISTEN DROPS", "UDP DROPS", "SSH FAILS", "CLOSE_WAIT",
        "TIME_WAIT", "CONNTRACK", "THROTTLED", "RETRANS", "INODES", "FILES", "SWAP", "DISK", "LOAD", "TEMP", "LOSS", "CERT", "HTTP", "MEM", "FDS",
    ];
    let mapped = |p: &str| -> &'static str {
        match p {
            "LISTEN DROPS" => "listen drops",
            "UDP DROPS" => "UDP buffer drops",
            "FAILED UNITS" => "failed",
            "THROTTLED" => "throttled",
            "FILES" => "FDS",
            "HTTP" => "HTTP error",
            _ => PREFIXES.iter().find(|x| **x == p).copied().unwrap_or("healthy"),
        }
    };
    if let Some(p) = PREFIXES.iter().find(|p| text.starts_with(**p)) {
        return mapped(p);
    }
    if text.starts_with("OOM") {
        "OOM"
    } else if text.starts_with("PSI") {
        "PSI"
    } else if text.contains(" AWAIT ") {
        "AWAIT"
    } else if text.contains(" BUSY ") {
        "BUSY"
    } else if text.contains(" ERR ") {
        "ERR"
    } else if text.contains(" DROPS ") {
        "drops"
    } else {
        "healthy"
    }
}

/// The signals this OS can deliver.
pub fn signals() -> &'static [(&'static str, &'static str, Signal)] {
    if cfg!(windows) {
        &WIN_SIGNALS
    } else {
        &SIGNALS
    }
}

/// Every `[alerts]` threshold that is exceeded. Shared by the header badges and `vigil report`.
/// Inputs for health badges that come from collectors outside the sampler.
#[derive(Default)]
pub struct ExtraHealth {
    pub probe_losses: Vec<(String, f64)>,
    pub certs: Vec<(String, i64)>,
    pub http_errors: Vec<(String, u16)>,
    /// (process name, pct of its fd limit)
    pub fd_worst: Option<(String, f64)>,
    pub files_pct: Option<f64>,
    pub ephemeral_pct: Option<f64>,
    pub throttled: Vec<(String, f64)>,
    pub container_ooms: Vec<String>,
    pub kernel_ooms: usize,
    pub failed_units: usize,
    pub needs_restart: usize,
    pub ssh_failures: u32,
    pub gateway_mac_changes: usize,
    /// (interface, errors per second)
    pub nic_errors: Vec<(String, f64)>,
}

impl ExtraHealth {
    pub fn fill_limits(&mut self, l: &Limits, s: &Sampler, sockets: Option<Arc<Vec<OpenFile>>>) {
        self.needs_restart = l.needs_restart.len();
        if let Some((pid, _, _, pct)) = l.worst() {
            let name = s.procs.iter().find(|p| p.pid == pid).map(|p| p.name.to_string()).unwrap_or_else(|| pid.to_string());
            self.fd_worst = Some((name, pct));
        }
        self.files_pct = l.files.filter(|(_, m)| *m > 0 && *m < u64::MAX / 4).map(|(n, m)| n as f64 / m as f64 * 100.0);
        if let (Some((lo, hi)), Some(socks)) = (l.ephemeral, sockets) {
            let size = (hi.saturating_sub(lo) as f64 + 1.0).max(1.0);
            let used = socks
                .iter()
                .filter(|e| e.proto == "TCP" && !e.is_listening() && e.local_port().is_some_and(|p| p >= lo && p <= hi))
                .count();
            self.ephemeral_pct = Some(used as f64 / size * 100.0);
        }
    }
}

pub fn compute_alerts(
    s: &Sampler,
    a: &Alerts,
    close_wait: usize,
    time_wait: usize,
    x: &ExtraHealth,
) -> Vec<(String, Color)> {
    let probe_losses = &x.probe_losses;
    let mut out = Vec::new();
    let pct = |u: u64, t: u64| if t == 0 { 0.0 } else { u as f64 / t as f64 * 100.0 };
    let mem = pct(s.mem_used, s.mem_total);
    if a.mem_pct > 0.0 && mem >= a.mem_pct {
        out.push((format!("MEM {mem:.0}%"), theme::red()));
    }
    let swap = pct(s.swap_used, s.swap_total);
    if a.swap_pct > 0.0 && s.swap_total > 0 && swap >= a.swap_pct {
        out.push((format!("SWAP {swap:.0}%"), theme::orange()));
    }
    if a.disk_pct > 0.0 {
        if let Some(d) = s
            .disks_info
            .iter()
            .filter(|d| d.total > 0 && d.pct() >= a.disk_pct)
            .max_by(|x, y| x.pct().total_cmp(&y.pct()))
        {
            out.push((format!("DISK {} {:.0}%", d.mount, d.pct()), theme::red()));
        }
    }
    let lpc = s.load.0 / s.ncores().max(1) as f64;
    if a.load_per_core > 0.0 && lpc >= a.load_per_core {
        out.push((format!("LOAD {:.1}/core", lpc), theme::orange()));
    }
    if a.close_wait > 0 && close_wait >= a.close_wait {
        out.push((format!("CLOSE_WAIT {}", close_wait), theme::orange()));
    }
    if a.time_wait > 0 && time_wait >= a.time_wait {
        out.push((format!("TIME_WAIT {}", time_wait), theme::yellow()));
    }
    if a.temp_c > 0.0 {
        if let Some(t) = s.temps.first().filter(|t| t.temp >= a.temp_c) {
            out.push((format!("TEMP {:.0}°C", t.temp), theme::red()));
        }
    }
    if let Some(c) = &s.knet.counters {
        if a.retrans_pct > 0.0 && c.out_segs_rate > 50.0 && c.retrans_pct >= a.retrans_pct {
            out.push((format!("RETRANS {:.1}%", c.retrans_pct), theme::orange()));
        }
        let ld = c.listen_overflow_rate.max(c.listen_drop_rate);
        if a.listen_drops_per_s > 0.0 && ld >= a.listen_drops_per_s {
            out.push((format!("LISTEN DROPS {ld:.0}/s"), theme::red()));
        }
        let ud = c.udp_rcvbuf_err_rate + c.udp_sndbuf_err_rate;
        if a.udp_drops_per_s > 0.0 && ud >= a.udp_drops_per_s {
            out.push((format!("UDP DROPS {ud:.0}/s"), theme::orange()));
        }
        if let (Some(p), true) = (c.conntrack_pct(), a.conntrack_pct > 0.0) {
            if p >= a.conntrack_pct {
                out.push((format!("CONNTRACK {p:.0}%"), theme::red()));
            }
        }
    }
    if a.iface_drops_per_s > 0.0 {
        if let Some(i) = s.ifaces.iter().filter(|i| i.drop_rate >= a.iface_drops_per_s).max_by(|x, y| x.drop_rate.total_cmp(&y.drop_rate)) {
            out.push((format!("{} DROPS {:.0}/s", i.name, i.drop_rate), theme::orange()));
        }
    }
    if a.probe_loss_pct > 0.0 {
        for (name, loss) in probe_losses {
            if *loss >= a.probe_loss_pct {
                out.push((format!("LOSS {name} {loss:.0}%"), theme::red()));
            }
        }
    }
    if a.fd_pct > 0.0 {
        if let Some((n, p)) = x.fd_worst.as_ref().filter(|(_, p)| *p >= a.fd_pct) {
            out.push((format!("FDS {n} {p:.0}%"), theme::red()));
        }
    }
    if let (Some(p), true) = (x.files_pct, a.files_pct > 0.0) {
        if p >= a.files_pct {
            out.push((format!("FILES {p:.0}%"), theme::red()));
        }
    }
    if let (Some(p), true) = (x.ephemeral_pct, a.ephemeral_pct > 0.0) {
        if p >= a.ephemeral_pct {
            out.push((format!("EPHEMERAL PORTS {p:.0}%"), theme::red()));
        }
    }
    if a.inode_pct > 0.0 {
        if let Some((d, p)) = s
            .disks_info
            .iter()
            .filter_map(|d| d.inode_pct().map(|p| (d, p)))
            .filter(|(_, p)| *p >= a.inode_pct)
            .max_by(|x, y| x.1.total_cmp(&y.1))
        {
            out.push((format!("INODES {} {p:.0}%", d.mount), theme::red()));
        }
    }
    for d in &s.diskio.devices {
        if a.disk_await_ms > 0.0 && d.await_ms >= a.disk_await_ms && d.r_iops + d.w_iops >= 1.0 {
            out.push((format!("{} AWAIT {:.0}ms", d.name, d.await_ms), theme::orange()));
        } else if a.disk_util_pct > 0.0 && d.util_pct >= a.disk_util_pct {
            out.push((format!("{} BUSY {:.0}%", d.name, d.util_pct), theme::orange()));
        }
    }
    if a.cert_days > 0.0 {
        for (n, d) in &x.certs {
            if (*d as f64) < a.cert_days {
                out.push((format!("CERT {n} {d}d"), if *d < 7 { theme::red() } else { theme::orange() }));
            }
        }
    }
    for (n, st) in &x.http_errors {
        out.push((format!("HTTP {n} {st}"), theme::red()));
    }
    if a.throttle_pct > 0.0 {
        if let Some((n, p)) = x.throttled.iter().filter(|(_, p)| *p >= a.throttle_pct).max_by(|a, b| a.1.total_cmp(&b.1)) {
            out.push((format!("THROTTLED {n} {p:.0}%"), theme::orange()));
        }
    }
    for n in &x.container_ooms {
        out.push((format!("OOM {n}"), theme::red()));
    }
    if x.kernel_ooms > 0 && x.container_ooms.is_empty() {
        out.push((format!("OOM KILLS {}", x.kernel_ooms), theme::red()));
    }
    if a.needs_restart && x.needs_restart > 0 {
        out.push((format!("NEEDS RESTART {}", x.needs_restart), theme::orange()));
    }
    if a.ssh_failures_per_hour > 0 && x.ssh_failures >= a.ssh_failures_per_hour {
        out.push((format!("SSH FAILS {}/h", x.ssh_failures), theme::orange()));
    }
    if a.failed_units && x.failed_units > 0 {
        out.push((format!("FAILED UNITS {}", x.failed_units), theme::red()));
    }
    if a.gateway_mac_change && x.gateway_mac_changes > 0 {
        out.push(("GATEWAY MAC CHANGED".to_string(), theme::red()));
    }
    if a.nic_errors_per_s > 0.0 {
        for (n, r) in &x.nic_errors {
            if *r >= a.nic_errors_per_s {
                out.push((format!("{n} ERR {r:.0}/s"), theme::red()));
            }
        }
    }
    if let (Some(p), true) = (s.psi, a.psi_pct > 0.0) {
        for (name, v) in ["cpu", "mem", "io"].iter().zip(p) {
            if v >= a.psi_pct {
                out.push((format!("PSI {name} {v:.0}%"), theme::purple()));
            }
        }
    }
    out
}

/// Case-insensitive substring test without allocating. `needle` must already
/// be lowercase ASCII.
pub fn icontains(hay: &str, needle: &str) -> bool {
    let (h, n) = (hay.as_bytes(), needle.as_bytes());
    n.is_empty() || (h.len() >= n.len() && h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n)))
}

fn lower_cmp(a: &str, b: &str) -> Ordering {
    a.bytes().map(|c| c.to_ascii_lowercase()).cmp(b.bytes().map(|c| c.to_ascii_lowercase()))
}

/// A filtered, sorted view onto a shared snapshot of rows.
#[derive(Default)]
pub struct RowView {
    snap: Arc<Vec<OpenFile>>,
    idx: Vec<u32>,
}

impl RowView {
    pub fn len(&self) -> usize {
        self.idx.len()
    }
    pub fn get(&self, i: usize) -> Option<&OpenFile> {
        self.idx.get(i).map(|&j| &self.snap[j as usize])
    }
    pub fn iter(&self) -> impl Iterator<Item = &OpenFile> {
        self.idx.iter().map(|&j| &self.snap[j as usize])
    }
    pub fn range(&self, from: usize, to: usize) -> impl Iterator<Item = &OpenFile> {
        let to = to.min(self.idx.len());
        self.idx[from.min(to)..to].iter().map(|&j| &self.snap[j as usize])
    }
}

pub struct ProcRow {
    pub idx: usize,
    pub prefix: String,
}

/// Shared stores of the network collectors (each fed by its own thread).
pub struct NetHandles {
    pub netinfo: Arc<Mutex<NetInfo>>,
    pub routes_active: Arc<AtomicBool>,
    pub probes: Arc<Mutex<ProbeStore>>,
    pub fw: Arc<Mutex<FwStore>>,
    pub fw_active: Arc<AtomicBool>,
    pub capture: Arc<Mutex<CaptureState>>,
    pub limits: Arc<Mutex<Limits>>,
    pub kmsg: Arc<Mutex<KmsgStore>>,
    pub containers: Arc<Mutex<ContainerStore>>,
    pub containers_active: Arc<AtomicBool>,
    pub services: Arc<Mutex<ServiceStore>>,
    pub services_active: Arc<AtomicBool>,
    pub trace: Arc<Mutex<TraceStore>>,
    pub sessions: Arc<Mutex<SessionStore>>,
    pub sessions_active: Arc<AtomicBool>,
    pub l2: Arc<Mutex<L2Store>>,
    pub l2_active: Arc<AtomicBool>,
    pub tools: Arc<Mutex<ToolStore>>,
    /// macOS per-process bandwidth (nettop).
    pub procbw: Arc<Mutex<crate::collect::procbw::ProcBw>>,
    pub procbw_active: Arc<AtomicBool>,
}

impl NetHandles {
    /// Stores without background threads (tests, reports).
    pub fn idle() -> Self {
        Self {
            netinfo: Arc::default(),
            routes_active: Arc::default(),
            probes: Arc::default(),
            fw: Arc::default(),
            fw_active: Arc::default(),
            capture: Arc::default(),
            limits: Arc::default(),
            kmsg: Arc::default(),
            containers: Arc::default(),
            containers_active: Arc::default(),
            services: Arc::default(),
            services_active: Arc::default(),
            trace: Arc::default(),
            sessions: Arc::default(),
            sessions_active: Arc::default(),
            l2: Arc::default(),
            l2_active: Arc::default(),
            tools: Arc::default(),
            procbw: Arc::default(),
            procbw_active: Arc::default(),
        }
    }

    pub fn start(cfg: &Config) -> (Self, Vec<String>) {
        let h = Self::idle();
        let mut warnings = Vec::new();
        if let Ok(mut p) = h.probes.lock() {
            for spec in &cfg.network.probes {
                if let Err(e) = p.add(spec) {
                    warnings.push(e);
                }
            }
        }
        netinfo::spawn_worker(h.netinfo.clone(), h.routes_active.clone());
        probes::spawn_worker(
            h.probes.clone(),
            h.netinfo.clone(),
            Duration::from_secs(cfg.network.probe_interval_s.clamp(1, 300)),
            cfg.network.auto_probes,
        );
        firewall::spawn_worker(h.fw.clone(), h.fw_active.clone());
        limits::spawn_worker(h.limits.clone());
        kmsg::spawn_worker(h.kmsg.clone());
        containers::spawn_worker(h.containers.clone(), h.containers_active.clone());
        services::spawn_worker(h.services.clone(), h.services_active.clone());
        sessions::spawn_worker(h.sessions.clone(), h.sessions_active.clone());
        l2::spawn_worker(h.l2.clone(), h.netinfo.clone(), h.l2_active.clone());
        crate::collect::procbw::spawn_worker(h.procbw.clone(), h.procbw_active.clone());
        (h, warnings)
    }
}

pub struct App {
    pub tab: Tab,
    pub sampler: Sampler,
    pub sockets: Arc<Mutex<SocketStore>>,
    pub files: Arc<Mutex<FilesStore>>,
    pub interval: Duration,
    pub paused: bool,
    pub show_help: bool,
    /// Help screen: first visible line, lines per page (set when drawn),
    /// search text and whether it is being typed.
    pub help_scroll: u16,
    pub help_page: u16,
    pub help_filter: String,
    pub help_typing: bool,
    /// Explain mode (h): a panel explaining the selected item.
    pub explain: bool,
    /// `[keys]` from the config: pressed key → key it acts as.
    key_map: HashMap<(KeyCode, KeyModifiers), KeyEvent>,
    pub search_hits: Vec<SearchHit>,
    pub search_sel: usize,
    pub quit: bool,
    pub mode: Mode,
    pub input: String,
    pub is_root: bool,

    pub proc_sort: ProcSort,
    pub proc_desc: bool,
    pub proc_tree: bool,
    pub proc_filter: String,
    pub proc_rows: Vec<ProcRow>,
    pub proc_state: TableState,
    selected_pid: Option<u32>,

    pub sock_filter: String,
    pub sock_listen_only: bool,
    pub sock_sort: SockSort,
    pub sock_state: TableState,

    pub files_filter: String,
    pub files_state: TableState,

    pub net_state: TableState,
    pub conn_counts: HashMap<u32, usize>,

    pub signal_target: Option<(u32, String)>,
    pub signal_idx: usize,
    pub status: Option<(String, Color, Instant)>,

    // Derived-data caches: rebuilt only when their inputs change.
    pub cfg: Config,
    /// Theme index before the picker opened (Esc restores it).
    theme_before: usize,
    /// Set once the user confirms a theme in the picker. Only then is the
    /// theme written to the config; otherwise "auto" stays "auto".
    theme_user_set: bool,
    pub close_wait: usize,
    pub time_wait: usize,
    sock_rows: RowView,
    sock_key: Option<(u64, String, bool, SockSort)>,
    files_rows: RowView,
    files_key: Option<(u64, String)>,
    conn_version: u64,

    pub net: NetHandles,
    pub resolver: Option<Resolver>,
    pub show_names: bool,
    /// pid → (tx bytes/s, rx bytes/s), summed over its TCP connections.
    pub proc_net: HashMap<u32, (f64, f64)>,
    procbw_version: u64,
    pub route_state: TableState,
    pub probe_state: TableState,
    pub fw_state: TableState,
    pub fw_filter: String,
    pub fw_hide_zero: bool,
    pub fw_by_rate: bool,
    pub close_target: Option<OpenFile>,
    pub ctr_state: TableState,
    pub svc_state: TableState,
    /// Which System-view pane has the cursor: false = services, true = kernel events.
    pub sys_events_focus: bool,
    pub ev_state: TableState,
    pub users_state: TableState,
    pub tool_state: TableState,
    pub tool_kind: tools::Kind,
    /// Process shown in the inspector (Enter on a process).
    pub inspect: Option<u32>,
    pub inspect_info: Option<DeepInfo>,
    pub inspect_files: Arc<Mutex<FilesStore>>,
    /// Inspector right-bottom pane: false = journal, true = environment.
    pub inspect_env: bool,
    /// Clickable regions recorded while drawing.
    pub hits: Hits,
}

/// (file name part, column headers, rows) for CSV export.
type ExportTable = (&'static str, Vec<&'static str>, Vec<Vec<String>>);

/// Screen regions from the last frame, for mouse clicks.
#[derive(Default)]
pub struct Hits {
    /// (x start, x end, y, tab)
    pub tabs: Vec<(u16, u16, u16, Tab)>,
    /// Main table of the current view: (area incl. border, first visible row).
    pub table: Option<(ratatui::layout::Rect, usize)>,
    /// Process table column headers: (x start, x end, sort).
    pub proc_headers: Vec<(u16, u16, ProcSort)>,
}

impl App {
    pub fn new(
        sampler: Sampler,
        sockets: Arc<Mutex<SocketStore>>,
        files: Arc<Mutex<FilesStore>>,
        interval: Duration,
        tab: Tab,
        cfg: Config,
        net: NetHandles,
    ) -> Self {
        let show_names = cfg.network.reverse_dns;
        let keys = key_map(&cfg.keys).0;
        let mut app = Self {
            tab,
            sampler,
            sockets,
            files,
            interval,
            paused: false,
            show_help: false,
            help_scroll: 0,
            help_page: 10,
            help_filter: String::new(),
            help_typing: false,
            quit: false,
            mode: Mode::Normal,
            input: String::new(),
            is_root: crate::util::is_root(),
            proc_sort: ProcSort::parse(&cfg.proc_sort).unwrap_or(ProcSort::Cpu),
            proc_desc: cfg.proc_desc,
            proc_tree: cfg.proc_tree,
            proc_filter: String::new(),
            proc_rows: Vec::new(),
            proc_state: TableState::default().with_selected(0),
            selected_pid: None,
            sock_filter: String::new(),
            sock_listen_only: false,
            sock_sort: SockSort::Process,
            sock_state: TableState::default().with_selected(0),
            files_filter: String::new(),
            files_state: TableState::default().with_selected(0),
            net_state: TableState::default().with_selected(0),
            conn_counts: HashMap::new(),
            signal_target: None,
            signal_idx: 0,
            status: None,
            cfg,
            theme_before: 0,
            theme_user_set: false,
            close_wait: 0,
            time_wait: 0,
            sock_rows: RowView::default(),
            sock_key: None,
            files_rows: RowView::default(),
            files_key: None,
            conn_version: u64::MAX,
            net,
            resolver: show_names.then(Resolver::new),
            show_names,
            proc_net: HashMap::new(),
            procbw_version: 0,
            route_state: TableState::default().with_selected(0),
            probe_state: TableState::default().with_selected(0),
            fw_state: TableState::default().with_selected(0),
            fw_filter: String::new(),
            fw_hide_zero: false,
            fw_by_rate: false,
            close_target: None,
            ctr_state: TableState::default().with_selected(0),
            svc_state: TableState::default().with_selected(0),
            sys_events_focus: false,
            ev_state: TableState::default().with_selected(0),
            users_state: TableState::default().with_selected(0),
            tool_state: TableState::default(),
            explain: false,
            key_map: keys,
            search_hits: Vec::new(),
            search_sel: 0,
            tool_kind: tools::Kind::Doctor,
            inspect: None,
            inspect_info: None,
            inspect_files: Arc::default(),
            inspect_env: false,
            hits: Hits::default(),
        };
        app.rebuild();
        app
    }

    pub fn tick(&mut self) {
        if !self.paused {
            self.sampler.refresh();
        }
        self.rebuild();
    }

    pub fn rebuild(&mut self) {
        // macOS: bandwidth per process comes from nettop, not from the sockets.
        if let Ok(b) = self.net.procbw.try_lock() {
            if b.version != self.procbw_version {
                self.procbw_version = b.version;
                self.proc_net = b.rates.clone();
            }
        }
        if let Ok(s) = self.sockets.lock() {
            if s.version != self.conn_version {
                self.conn_version = s.version;
                self.conn_counts.clear();
                if self.procbw_version == 0 {
                    self.proc_net.clear();
                }
                self.close_wait = 0;
                self.time_wait = 0;
                for e in s.entries.iter() {
                    if let (Some(n), true) = (&e.net, e.pid != 0 && self.procbw_version == 0) {
                        if n.tx_rate > 0.0 || n.rx_rate > 0.0 {
                            let v = self.proc_net.entry(e.pid).or_default();
                            v.0 += n.tx_rate;
                            v.1 += n.rx_rate;
                        }
                    }
                    match e.state.as_str() {
                        "CLOSE_WAIT" => self.close_wait += 1,
                        "TIME_WAIT" => self.time_wait += 1,
                        _ => {}
                    }
                    if e.pid != 0 {
                        *self.conn_counts.entry(e.pid).or_default() += 1;
                    }
                }
            }
        }
        self.sync_activity();
        self.rebuild_procs();
        self.update_caches();
    }

    /// Tell the lazy collectors which views are visible.
    fn sync_activity(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        self.sampler.sensors_fast.store(self.tab == Tab::Storage, Relaxed);
        self.net.routes_active.store(self.tab == Tab::Routes, Relaxed);
        self.net.fw_active.store(self.tab == Tab::Firewall, Relaxed);
        self.net.containers_active.store(self.tab == Tab::Containers, Relaxed);
        self.net.services_active.store(self.tab == Tab::System, Relaxed);
        self.net.sessions_active.store(self.tab == Tab::Users, Relaxed);
        self.net.l2_active.store(self.tab == Tab::Troubleshoot, Relaxed);
        self.net.procbw_active.store(matches!(self.tab, Tab::Network | Tab::Processes) || self.proc_sort == ProcSort::Net, Relaxed);
    }

    /// Health badges for the header: every threshold from `[alerts]` that is exceeded.
    pub fn alerts(&self) -> Vec<(String, Color)> {
        let mut x = ExtraHealth::default();
        if let Ok(p) = self.net.probes.try_lock() {
            for pr in &p.probes {
                // Automatic probes only alarm once their target has answered at
                // least once: many gateways and resolvers simply don't answer ping.
                if pr.sent() >= 5 && (!pr.auto || pr.ever_ok) {
                    x.probe_losses.push((pr.name.clone(), pr.loss_pct()));
                }
                if let Some(d) = pr.cert_days {
                    x.certs.push((pr.name.clone(), d));
                }
                if let Some(st) = pr.http_status.filter(|s| *s >= 500) {
                    x.http_errors.push((pr.name.clone(), st));
                }
            }
        }
        if let Ok(l) = self.net.limits.try_lock() {
            x.fill_limits(&l, &self.sampler, self.socket_snapshot());
        }
        if let Ok(c) = self.net.containers.try_lock() {
            for ct in &c.containers {
                x.throttled.push((ct.name.clone(), ct.throttled_pct));
                if ct.new_ooms > 0 {
                    x.container_ooms.push(ct.name.clone());
                }
            }
        }
        if let Ok(k) = self.net.kmsg.try_lock() {
            x.kernel_ooms = k.recent("OOM", Duration::from_secs(600));
        }
        if let Ok(sv) = self.net.services.try_lock() {
            x.failed_units = sv.units.iter().filter(|u| u.failed() && sv.manager == "systemd").count();
        }
        if let Ok(ss) = self.net.sessions.try_lock() {
            x.ssh_failures = ss.failed_total;
        }
        if let Ok(l) = self.net.l2.try_lock() {
            x.gateway_mac_changes = l.gateway_changes();
            x.nic_errors = l.err_rate.iter().filter(|(n, r)| **r > 0.0 && l2::is_physical(n)).map(|(n, r)| (n.clone(), *r)).collect();
            x.nic_errors.sort_by(|a, b| a.0.cmp(&b.0));
        }
        compute_alerts(&self.sampler, &self.cfg.alerts, self.close_wait, self.time_wait, &x)
    }

    pub fn socket_snapshot(&self) -> Option<Arc<Vec<OpenFile>>> {
        self.sockets.try_lock().ok().map(|s| s.entries.clone())
    }

    /// (open fds, limit) for a pid, from the limits collector.
    pub fn fd_info(&self, pid: u32) -> Option<(u32, Option<u64>)> {
        self.net.limits.try_lock().ok()?.fds.get(&pid).copied()
    }

    /// Display form of a socket endpoint: host name (if resolved and names are
    /// on) or IP, plus the well-known service name of the port.
    pub fn endpoint_label(&self, ep: &str, udp: bool) -> String {
        if ep.is_empty() {
            return String::new();
        }
        let port = ipinfo::endpoint_port(ep);
        let mut host = ep.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_else(|| ep.to_string());
        if let (true, Some(r), Some(ip)) = (self.show_names, &self.resolver, ipinfo::endpoint_ip(ep)) {
            if !ip.is_loopback() && !ip.is_unspecified() {
                if let Some(n) = r.lookup(ip) {
                    host = n;
                }
            }
        }
        match port {
            Some(p) => match ipinfo::service(p, udp) {
                Some(svc) if p < 49152 => format!("{host}:{p} {svc}"),
                _ => format!("{host}:{p}"),
            },
            None => host,
        }
    }

    pub fn fw_rows(&self) -> Vec<FwRule> {
        let Ok(st) = self.net.fw.try_lock() else { return Vec::new() };
        let f = self.fw_filter.to_ascii_lowercase();
        let mut v: Vec<FwRule> = st
            .rules
            .iter()
            .filter(|r| !self.fw_hide_zero || r.packets > 0)
            .filter(|r| {
                f.is_empty()
                    || icontains(&r.rule, &f)
                    || icontains(&r.chain, &f)
                    || icontains(&r.table, &f)
                    || icontains(&r.verdict, &f)
            })
            .cloned()
            .collect();
        if self.fw_by_rate {
            v.sort_by(|a, b| b.pps.total_cmp(&a.pps).then(b.packets.cmp(&a.packets)));
        }
        v
    }

    /// `R`: write a Markdown report of what's on screen right now.
    fn write_report(&mut self) {
        let (entries, backend) = match self.sockets.lock() {
            Ok(s) => (s.entries.clone(), s.backend),
            Err(_) => (Arc::new(Vec::new()), crate::collect::lsof::SocketBackend::Lsof),
        };
        let mut inputs = crate::report::Inputs::default();
        if let Ok(l) = self.net.limits.lock() {
            inputs.health.fill_limits(&l, &self.sampler, Some(entries.clone()));
            inputs.limits = Some(l.clone());
        }
        if let Ok(c) = self.net.containers.lock() {
            inputs.containers = c.containers.clone();
        }
        if let Ok(sv) = self.net.services.lock() {
            inputs.units = sv.units.clone();
        }
        if let Ok(k) = self.net.kmsg.lock() {
            inputs.events = k.events.iter().cloned().collect();
        }
        match crate::report::write_from_tui(&self.sampler, &entries, backend, &self.cfg.alerts, &inputs) {
            Ok(p) => self.set_status(format!("report written to {}", p.display()), theme::green()),
            Err(e) => self.set_status(format!("report failed: {e}"), theme::red()),
        }
    }

    /// Copy the current UI state back into the config (saved on quit).
    pub fn snapshot_config(&mut self) -> Config {
        let mut c = self.cfg.clone();
        if self.theme_user_set {
            c.theme = theme::pal().name.to_string();
        }
        c.interval_ms = self.interval.as_millis() as u64;
        c.proc_sort = self.proc_sort.as_str().to_string();
        c.proc_desc = self.proc_desc;
        c.proc_tree = self.proc_tree;
        c.network.reverse_dns = self.show_names;
        if let Ok(p) = self.net.probes.lock() {
            c.network.probes = p.user_specs();
        }
        c
    }

    /// Everything that can change the screen without user input.
    /// The main loop redraws only when this (or input / a tick) changes.
    pub fn external_key(&self) -> ([u64; 10], bool) {
        let v = |o: Option<u64>| o.unwrap_or(0);
        let sv = v(self.sockets.try_lock().ok().map(|s| s.version));
        let fv = v(self.files.try_lock().ok().map(|s| s.version));
        // Only views that show a store need to redraw when it changes.
        let ni = if self.tab == Tab::Routes { v(self.net.netinfo.try_lock().ok().map(|s| s.version)) } else { 0 };
        let pr = if self.tab == Tab::Probes { v(self.net.probes.try_lock().ok().map(|s| s.version)) } else { 0 };
        let fw = if self.tab == Tab::Firewall { v(self.net.fw.try_lock().ok().map(|s| s.version)) } else { 0 };
        let cap = v(self.net.capture.try_lock().ok().map(|s| s.version));
        let ct = if self.tab == Tab::Containers { v(self.net.containers.try_lock().ok().map(|s| s.version)) } else { 0 };
        let sys = if self.tab == Tab::System {
            v(self.net.services.try_lock().ok().map(|s| s.version)) + v(self.net.kmsg.try_lock().ok().map(|s| s.version))
        } else {
            0
        };
        let tr = if self.tab == Tab::Probes { v(self.net.trace.try_lock().ok().map(|s| s.version)) } else { 0 }
            + if self.tab == Tab::Troubleshoot {
                v(self.net.tools.try_lock().ok().map(|s| s.version)) + v(self.net.l2.try_lock().ok().map(|s| s.version))
            } else {
                0
            }
            + if self.tab == Tab::Users { v(self.net.sessions.try_lock().ok().map(|s| s.version)) } else { 0 }
            + if self.inspect.is_some() {
                v(self.inspect_files.try_lock().ok().map(|s| s.version)) + v(self.net.services.try_lock().ok().map(|s| s.version))
            } else {
                0
            };
        let status_live = self
            .status
            .as_ref()
            .is_some_and(|(_, _, at)| at.elapsed() < Duration::from_secs(4))
            || self.net.capture.try_lock().map(|c| c.running.is_some()).unwrap_or(false);
        ([sv, fv, self.sampler.slow_version(), ni, pr, fw, cap, ct, sys, tr], status_live)
    }

    pub fn warn(&mut self, msg: impl Into<String>) {
        self.set_status(msg, theme::yellow());
    }

    fn set_status(&mut self, msg: impl Into<String>, color: Color) {
        self.status = Some((msg.into(), color, Instant::now()));
    }

    // ───────────────────────────── processes ─────────────────────────────

    fn cmp_procs(&self, a: &ProcInfo, b: &ProcInfo) -> Ordering {
        let o = match self.proc_sort {
            ProcSort::Cpu => a.cpu.partial_cmp(&b.cpu).unwrap_or(Ordering::Equal),
            ProcSort::Mem => a.mem.cmp(&b.mem),
            ProcSort::Pid => a.pid.cmp(&b.pid),
            ProcSort::Name => lower_cmp(&b.name, &a.name),
            ProcSort::User => b.user.cmp(&a.user),
            ProcSort::Io => (a.read_rate + a.write_rate)
                .partial_cmp(&(b.read_rate + b.write_rate))
                .unwrap_or(Ordering::Equal),
            ProcSort::Fds => {
                let f = |p: &ProcInfo| self.fd_info(p.pid).map(|(n, _)| n).unwrap_or(0);
                f(a).cmp(&f(b))
            }
            ProcSort::Net => {
                let n = |p: &ProcInfo| self.proc_net.get(&p.pid).map(|(t, r)| t + r).unwrap_or(0.0);
                n(a).total_cmp(&n(b))
            }
            ProcSort::Conn => self
                .conn_counts
                .get(&a.pid)
                .unwrap_or(&0)
                .cmp(self.conn_counts.get(&b.pid).unwrap_or(&0)),
        };
        let o = o.then(b.pid.cmp(&a.pid));
        if self.proc_desc {
            o.reverse()
        } else {
            o
        }
    }

    fn rebuild_procs(&mut self) {
        let procs = &self.sampler.procs;
        let filter = self.proc_filter.to_ascii_lowercase();
        let mut idxs: Vec<usize> = (0..procs.len())
            .filter(|&i| {
                filter.is_empty() || {
                    let p = &procs[i];
                    icontains(&p.name, &filter)
                        || icontains(&p.cmd, &filter)
                        || icontains(&p.user, &filter)
                        || p.pid.to_string() == filter
                }
            })
            .collect();
        idxs.sort_by(|&a, &b| self.cmp_procs(&procs[a], &procs[b]));

        self.proc_rows = if self.proc_tree && filter.is_empty() {
            self.build_tree(&idxs)
        } else {
            idxs.into_iter()
                .map(|idx| ProcRow { idx, prefix: String::new() })
                .collect()
        };

        // Keep the same process selected across refreshes.
        let len = self.proc_rows.len();
        if let Some(pid) = self.selected_pid {
            if let Some(pos) = self
                .proc_rows
                .iter()
                .position(|r| self.sampler.procs[r.idx].pid == pid)
            {
                self.proc_state.select(Some(pos));
                return;
            }
        }
        let sel = self.proc_state.selected().unwrap_or(0).min(len.saturating_sub(1));
        self.proc_state.select(Some(sel));
        self.sync_selected_pid();
    }

    fn build_tree(&self, sorted: &[usize]) -> Vec<ProcRow> {
        let procs = &self.sampler.procs;
        let pids: HashSet<u32> = sorted.iter().map(|&i| procs[i].pid).collect();
        let mut children: HashMap<u32, Vec<usize>> = HashMap::new();
        let mut roots = Vec::new();
        for &i in sorted {
            match procs[i].ppid {
                Some(pp) if pp != procs[i].pid && pids.contains(&pp) => {
                    children.entry(pp).or_default().push(i)
                }
                _ => roots.push(i),
            }
        }
        let mut out = Vec::with_capacity(sorted.len());
        fn walk(
            i: usize,
            prefix: &str,
            branch: &str,
            procs: &[ProcInfo],
            children: &HashMap<u32, Vec<usize>>,
            out: &mut Vec<ProcRow>,
            depth: usize,
        ) {
            out.push(ProcRow { idx: i, prefix: format!("{prefix}{branch}") });
            if depth > 64 {
                return;
            }
            if let Some(kids) = children.get(&procs[i].pid) {
                let (mid, last, cont_mid, cont_last) = theme::tree();
                let cont = if branch == mid {
                    cont_mid
                } else if branch == last {
                    cont_last
                } else {
                    ""
                };
                let next_prefix = format!("{prefix}{cont}");
                for (n, &k) in kids.iter().enumerate() {
                    let b = if n + 1 == kids.len() { last } else { mid };
                    walk(k, &next_prefix, b, procs, children, out, depth + 1);
                }
            }
        }
        for r in roots {
            walk(r, "", "", procs, &children, &mut out, 0);
        }
        out
    }

    fn sync_selected_pid(&mut self) {
        self.selected_pid = self
            .proc_state
            .selected()
            .and_then(|i| self.proc_rows.get(i))
            .map(|r| self.sampler.procs[r.idx].pid);
    }

    pub fn selected_proc(&self) -> Option<&ProcInfo> {
        self.proc_state
            .selected()
            .and_then(|i| self.proc_rows.get(i))
            .map(|r| &self.sampler.procs[r.idx])
    }

    // ───────────────────────────── sockets / files ─────────────────────────────

    pub fn socket_rows(&self) -> &RowView {
        &self.sock_rows
    }

    pub fn file_rows(&self) -> &RowView {
        &self.files_rows
    }

    /// Re-filter / re-sort socket and file lists only when their inputs changed.
    /// Rows are indices into the shared snapshot: nothing is cloned.
    pub fn update_caches(&mut self) {
        if let Ok(store) = self.sockets.try_lock() {
            let key = (store.version, self.sock_filter.clone(), self.sock_listen_only, self.sock_sort);
            if self.sock_key.as_ref() != Some(&key) {
                let snap = store.entries.clone();
                drop(store);
                let f = self.sock_filter.to_ascii_lowercase();
                let mut idx: Vec<u32> = snap
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| !self.sock_listen_only || e.is_listening())
                    .filter(|(_, e)| {
                        f.is_empty()
                            || icontains(&e.command, &f)
                            || icontains(&e.name, &f)
                            || icontains(&e.state, &f)
                            || icontains(&e.proto, &f)
                            || icontains(&e.user, &f)
                            || e.net.as_ref().and_then(|n| n.netns.as_deref()).is_some_and(|ns| icontains(ns, &f))
                            || e.pid.to_string() == f
                    })
                    .map(|(i, _)| i as u32)
                    .collect();
                let at = |i: &u32| &snap[*i as usize];
                let rtt = |e: &OpenFile| e.net.as_ref().and_then(|n| n.tcp).map(|t| t.rtt_us).unwrap_or(0);
                let traffic = |e: &OpenFile| e.net.as_ref().map(|n| n.tx_rate + n.rx_rate).unwrap_or(0.0);
                match self.sock_sort {
                    SockSort::Process => idx.sort_by(|a, b| {
                        let (a, b) = (at(a), at(b));
                        lower_cmp(&a.command, &b.command).then(a.pid.cmp(&b.pid))
                    }),
                    SockSort::Port => idx.sort_by_key(|i| at(i).local_port().unwrap_or(u16::MAX)),
                    SockSort::State => idx.sort_by(|a, b| at(a).state.cmp(&at(b).state)),
                    SockSort::Proto => idx.sort_by(|a, b| {
                        let (a, b) = (at(a), at(b));
                        a.proto.cmp(&b.proto).then(a.ftype.cmp(&b.ftype))
                    }),
                    SockSort::Remote => idx.sort_by(|a, b| at(b).endpoints().1.cmp(at(a).endpoints().1)),
                    SockSort::Rtt => idx.sort_by_key(|i| std::cmp::Reverse(rtt(at(i)))),
                    SockSort::Traffic => idx.sort_by(|a, b| traffic(at(b)).total_cmp(&traffic(at(a)))),
                }
                self.sock_rows = RowView { snap, idx };
                self.sock_key = Some(key);
            }
        }
        if let Ok(store) = self.files.try_lock() {
            let key = (store.version, self.files_filter.clone());
            if self.files_key.as_ref() != Some(&key) {
                let snap = store.entries.clone();
                drop(store);
                let f = self.files_filter.to_ascii_lowercase();
                let idx = snap
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| {
                        f.is_empty()
                            || icontains(&e.name, &f)
                            || icontains(&e.command, &f)
                            || icontains(&e.ftype, &f)
                            || e.fd.eq_ignore_ascii_case(&f)
                    })
                    .map(|(i, _)| i as u32)
                    .collect();
                self.files_rows = RowView { snap, idx };
                self.files_key = Some(key);
            }
        }
    }

    pub fn run_query(&mut self, q: Query) {
        lsof::spawn_query(self.files.clone(), q);
        self.files_state.select(Some(0));
        self.files_filter.clear();
        self.tab = Tab::Files;
    }

    // ───────────────────────────── input ─────────────────────────────

    fn list_len(&self) -> usize {
        match self.tab {
            Tab::Processes => self.proc_rows.len(),
            Tab::Sockets => self.socket_rows().len(),
            Tab::Files => self.file_rows().len(),
            Tab::Network => self.sampler.ifaces.len(),
            Tab::Routes => self.net.netinfo.try_lock().map(|n| n.routes.len()).unwrap_or(0),
            Tab::Probes => self.net.probes.try_lock().map(|p| p.probes.len()).unwrap_or(0),
            Tab::Firewall => self.fw_rows().len(),
            Tab::Containers => self.net.containers.try_lock().map(|c| c.containers.len()).unwrap_or(0),
            Tab::System if self.sys_events_focus => self.net.kmsg.try_lock().map(|k| k.events.len()).unwrap_or(0),
            Tab::System => self.net.services.try_lock().map(|s| s.units.len()).unwrap_or(0),
            Tab::Users => self.net.sessions.try_lock().map(|s| s.sessions.len()).unwrap_or(0),
            Tab::Troubleshoot => self.net.tools.try_lock().map(|s| s.lines.len()).unwrap_or(0),
            _ => 0,
        }
    }

    fn table_state(&mut self) -> Option<&mut TableState> {
        match self.tab {
            Tab::Processes => Some(&mut self.proc_state),
            Tab::Sockets => Some(&mut self.sock_state),
            Tab::Files => Some(&mut self.files_state),
            Tab::Network => Some(&mut self.net_state),
            Tab::Routes => Some(&mut self.route_state),
            Tab::Probes => Some(&mut self.probe_state),
            Tab::Firewall => Some(&mut self.fw_state),
            Tab::Containers => Some(&mut self.ctr_state),
            Tab::System if self.sys_events_focus => Some(&mut self.ev_state),
            Tab::System => Some(&mut self.svc_state),
            Tab::Users => Some(&mut self.users_state),
            Tab::Troubleshoot => Some(&mut self.tool_state),
            _ => None,
        }
    }

    fn move_sel(&mut self, delta: isize) {
        let len = self.list_len();
        let tail = self.tab == Tab::Troubleshoot;
        if let Some(st) = self.table_state() {
            if len == 0 {
                st.select(Some(0));
                return;
            }
            // The Troubleshoot output follows the tail until you scroll: start from the end.
            let cur = st.selected().unwrap_or(if tail { len } else { 0 }) as isize;
            let next = (cur + delta).clamp(0, len as isize - 1) as usize;
            st.select(Some(next));
        }
        if self.tab == Tab::Processes {
            self.sync_selected_pid();
        }
    }

    fn filter_mut(&mut self) -> Option<&mut String> {
        match self.tab {
            Tab::Processes => Some(&mut self.proc_filter),
            Tab::Sockets => Some(&mut self.sock_filter),
            Tab::Files => Some(&mut self.files_filter),
            Tab::Firewall => Some(&mut self.fw_filter),
            _ => None,
        }
    }

    pub fn on_mouse(&mut self, m: MouseEvent) {
        match m.kind {
            MouseEventKind::ScrollDown if self.show_help => self.help_scroll = self.help_scroll.saturating_add(3),
            MouseEventKind::ScrollUp if self.show_help => self.help_scroll = self.help_scroll.saturating_sub(3),
            MouseEventKind::ScrollDown => self.move_sel(3),
            MouseEventKind::ScrollUp => self.move_sel(-3),
            MouseEventKind::Down(crossterm::event::MouseButton::Left) if self.mode == Mode::Normal => {
                let (x, y) = (m.column, m.row);
                if let Some(&(_, _, _, t)) = self.hits.tabs.iter().find(|(x0, x1, ty, _)| y == *ty && x >= *x0 && x < *x1) {
                    self.inspect = None;
                    self.tab = t;
                    self.sync_activity();
                    return;
                }
                if let Some((area, off)) = self.hits.table {
                    let inside_x = x > area.x && x < area.x + area.width.saturating_sub(1);
                    if inside_x && y == area.y + 1 && self.tab == Tab::Processes {
                        if let Some(&(_, _, s)) = self.hits.proc_headers.iter().find(|(x0, x1, _)| x >= *x0 && x < *x1) {
                            self.set_proc_sort(s);
                        }
                        return;
                    }
                    let first = area.y + 2;
                    let last = area.y + area.height.saturating_sub(1);
                    if inside_x && y >= first && y < last {
                        let idx = off + (y - first) as usize;
                        if idx < self.list_len() {
                            if let Some(st) = self.table_state() {
                                st.select(Some(idx));
                            }
                            if self.tab == Tab::Processes {
                                self.sync_selected_pid();
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // ───────────────────────────── inspector ─────────────────────────────

    pub fn open_inspector(&mut self, pid: u32) {
        self.inspect_info = self.sampler.deep_info(pid);
        if self.inspect_info.is_none() {
            self.set_status(format!("process {pid} no longer exists"), theme::yellow());
            return;
        }
        self.inspect = Some(pid);
        self.inspect_env = false;
        lsof::spawn_query(self.inspect_files.clone(), Query::Pid(pid));
        if let Some(unit) = self.inspect_info.as_ref().and_then(|d| d.unit.clone()) {
            services::load_journal(self.net.services.clone(), unit);
        }
    }

    fn key_inspect(&mut self, k: KeyEvent) -> bool {
        let Some(pid) = self.inspect else { return false };
        match k.code {
            KeyCode::Esc | KeyCode::Backspace | KeyCode::Char('q') => self.inspect = None,
            KeyCode::Char('v') => self.inspect_env = !self.inspect_env,
            KeyCode::Char('f') => {
                self.inspect = None;
                self.run_query(Query::Pid(pid));
            }
            KeyCode::Char('x') | KeyCode::Char('K') => {
                let name = self.sampler.procs.iter().find(|p| p.pid == pid).map(|p| p.name.to_string()).unwrap_or_default();
                self.open_signal_dialog(pid, name);
            }
            KeyCode::Char('r') => self.open_inspector(pid),
            KeyCode::Char('y') | KeyCode::Char('E') | KeyCode::Char('?') | KeyCode::Char('T') | KeyCode::Char(' ') => return false,
            _ => {}
        }
        true
    }

    // ───────────────────────────── copy & export ─────────────────────────────

    /// What `y` copies in the current context.
    fn copy_target(&self) -> Option<(String, String)> {
        if let Some(pid) = self.inspect {
            let p = self.sampler.procs.iter().find(|p| p.pid == pid)?;
            return Some(("command line".into(), if p.cmd.is_empty() { p.name.to_string() } else { p.cmd.to_string() }));
        }
        match self.tab {
            Tab::Processes => self.selected_proc().map(|p| {
                ("command line".into(), if p.cmd.is_empty() { p.name.to_string() } else { p.cmd.to_string() })
            }),
            Tab::Sockets => self.selected_socket().map(|s| {
                let (l, r) = s.endpoints();
                if r.is_empty() { ("address".into(), l.to_string()) } else { ("remote address".into(), r.to_string()) }
            }),
            Tab::Files => {
                let i = self.files_state.selected()?;
                self.file_rows().get(i).map(|f| ("path".into(), f.name.clone()))
            }
            Tab::Containers => {
                let c = self.net.containers.try_lock().ok()?;
                c.containers.get(self.ctr_state.selected()?).map(|c| ("container id".into(), c.id.clone()))
            }
            Tab::System => {
                let s = self.net.services.try_lock().ok()?;
                s.units.get(self.svc_state.selected()?).map(|u| ("unit".into(), u.name.clone()))
            }
            Tab::Probes => {
                let p = self.net.probes.try_lock().ok()?;
                p.probes.get(self.probe_state.selected()?).map(|p| ("probe target".into(), p.target.spec()))
            }
            Tab::Routes => {
                let n = self.net.netinfo.try_lock().ok()?;
                n.routes.get(self.route_state.selected()?).map(|r| ("route".into(), format!("{} via {} dev {}", r.dst, r.gateway, r.dev)))
            }
            Tab::Firewall => {
                let rows = self.fw_rows();
                rows.get(self.fw_state.selected()?).map(|r| ("rule".into(), format!("{} {}", r.rule, r.verdict)))
            }
            Tab::Users => {
                let s = self.net.sessions.try_lock().ok()?;
                s.sessions.get(self.users_state.selected()?).map(|u| ("address".into(), if u.from.is_empty() { u.user.clone() } else { u.from.clone() }))
            }
            Tab::Network => self.net_state.selected().and_then(|i| self.sampler.ifaces.get(i)).map(|i| ("interface".into(), i.name.clone())),
            Tab::Troubleshoot => {
                let t = self.net.tools.try_lock().ok()?;
                match self.tool_state.selected() {
                    Some(i) => t.lines.get(i).map(|l| ("line".into(), l.text.trim().to_string())),
                    // Nothing selected (following the output): copy all of it.
                    None if !t.lines.is_empty() => {
                        let all = t.lines.iter().map(|l| l.text.trim_end()).collect::<Vec<_>>().join("\n");
                        Some((format!("{} lines of {}", t.lines.len(), t.kind.map(|k| k.title()).unwrap_or("output")), all))
                    }
                    None => None,
                }
            }
            _ => None,
        }
    }

    /// Search everything vigil knows for `q` (case-insensitive), best first.
    pub fn search(&self, q: &str) -> Vec<SearchHit> {
        const MAX: usize = 200;
        let q = q.trim().to_ascii_lowercase();
        let mut out = Vec::new();
        if q.is_empty() {
            return out;
        }
        let mut push = |tab, kind, text: String, target| {
            if out.len() < MAX {
                out.push(SearchHit { tab, kind, text, target });
            }
        };
        let pid_q: Option<u32> = q.parse().ok();
        for p in &self.sampler.procs {
            if pid_q == Some(p.pid) || icontains(&p.name, &q) || icontains(&p.cmd, &q) || icontains(&p.user, &q) {
                push(Tab::Processes, "proc", format!("{} {}  {}  {}", p.pid, p.name, p.user, crate::util::truncate(&p.cmd, 90)), p.pid as usize);
            }
        }
        for (i, e) in self.socket_rows().iter().enumerate() {
            if icontains(&e.name, &q) || icontains(&e.command, &q) || icontains(&e.state, &q) || (q.starts_with(':') && e.name.contains(&q)) {
                push(Tab::Sockets, "socket", format!("{} {} {}  {} ({})", e.proto, e.name, e.state, e.command, e.pid), i);
            }
        }
        if let Ok(sv) = self.net.services.try_lock() {
            for (i, u) in sv.units.iter().enumerate() {
                if icontains(&u.name, &q) || icontains(&u.description, &q) {
                    push(Tab::System, "service", format!("{}  {}/{}  {}", u.name, u.active, u.sub, u.description), i);
                }
            }
        }
        if let Ok(c) = self.net.containers.try_lock() {
            for (i, k) in c.containers.iter().enumerate() {
                if icontains(&k.name, &q) || icontains(&k.id, &q) || icontains(&k.path, &q) {
                    push(Tab::Containers, "container", format!("{}  {}  {}", k.name, k.runtime, &k.id[..k.id.len().min(12)]), i);
                }
            }
        }
        if let Ok(n) = self.net.netinfo.try_lock() {
            for (i, r) in n.routes.iter().enumerate() {
                if icontains(&r.dst, &q) || icontains(&r.gateway, &q) || icontains(&r.dev, &q) {
                    push(Tab::Routes, "route", format!("{} via {} dev {}", r.dst, if r.gateway.is_empty() { "-" } else { &r.gateway }, r.dev), i);
                }
            }
            for nb in &n.neighbors {
                if icontains(&nb.ip, &q) || icontains(&nb.mac, &q) {
                    push(Tab::Routes, "neighbour", format!("{} {} {} {}", nb.ip, nb.mac, nb.dev, nb.state), usize::MAX);
                }
            }
        }
        if let Ok(ss) = self.net.sessions.try_lock() {
            for (i, u) in ss.sessions.iter().enumerate() {
                if icontains(&u.user, &q) || icontains(&u.from, &q) || icontains(&u.what, &q) {
                    push(Tab::Users, "session", format!("{} {} {} {}", u.user, u.tty, u.from, u.what), i);
                }
            }
        }
        for (i, r) in self.fw_rows().iter().enumerate() {
            if icontains(&r.rule, &q) || icontains(&r.chain, &q) {
                push(Tab::Firewall, "rule", format!("{} {}  {}  {}", r.table, r.chain, crate::util::truncate(&r.rule, 80), r.verdict), i);
            }
        }
        if let Ok(p) = self.net.probes.try_lock() {
            for (i, pr) in p.probes.iter().enumerate() {
                if icontains(&pr.name, &q) || icontains(&pr.target.spec(), &q) {
                    push(Tab::Probes, "probe", format!("{}  {}", pr.name, pr.target.spec()), i);
                }
            }
        }
        for (i, f) in self.sampler.ifaces.iter().enumerate() {
            if icontains(&f.name, &q) || f.addrs.iter().any(|a| icontains(a, &q)) || icontains(&f.mac, &q) {
                push(Tab::Network, "interface", format!("{}  {}  {}", f.name, f.addrs.join(" "), f.mac), i);
            }
        }
        out
    }

    fn key_search(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Esc => {
                self.input.clear();
                self.mode = Mode::Normal;
            }
            KeyCode::Up => self.search_sel = self.search_sel.saturating_sub(1),
            KeyCode::Down | KeyCode::Tab => self.search_sel = (self.search_sel + 1).min(self.search_hits.len().saturating_sub(1)),
            KeyCode::Enter => {
                self.mode = Mode::Normal;
                if let Some(h) = self.search_hits.get(self.search_sel).cloned() {
                    self.jump_to(&h);
                }
            }
            KeyCode::Backspace => {
                self.input.pop();
                self.search_hits = self.search(&self.input);
                self.search_sel = 0;
            }
            KeyCode::Char(c) => {
                self.input.push(c);
                self.search_hits = self.search(&self.input);
                self.search_sel = 0;
            }
            _ => {}
        }
    }

    fn jump_to(&mut self, h: &SearchHit) {
        self.inspect = None;
        self.tab = h.tab;
        match h.tab {
            Tab::Processes => {
                let pid = h.target as u32;
                if !self.proc_rows.iter().any(|r| self.sampler.procs[r.idx].pid == pid) {
                    self.proc_filter.clear();
                    self.rebuild_procs();
                }
                if let Some(i) = self.proc_rows.iter().position(|r| self.sampler.procs[r.idx].pid == pid) {
                    self.proc_state.select(Some(i));
                    self.sync_selected_pid();
                }
            }
            Tab::System => {
                self.sys_events_focus = false;
                self.svc_state.select(Some(h.target));
            }
            _ => {
                if h.target != usize::MAX {
                    if let Some(st) = self.table_state() {
                        st.select(Some(h.target));
                    }
                }
            }
        }
        self.set_status(format!("{}: {}", h.kind, crate::util::truncate(&h.text, 70)), theme::cyan());
    }

    /// The term explain mode should describe for the current selection.
    pub fn explain_term(&self) -> Option<String> {
        match self.tab {
            Tab::Processes => self.selected_proc().map(|p| p.status.to_string()),
            Tab::Sockets => {
                let s = self.sock_state.selected().and_then(|i| self.socket_rows().get(i))?;
                Some(if s.proto == "UDP" { "UDP".into() } else { s.state.clone() })
            }
            Tab::Network => {
                let i = self.sampler.ifaces.get(self.net_state.selected()?)?;
                Some(if i.rx_errors + i.tx_errors > 0 { "CRC" } else if i.rx_dropped + i.tx_dropped > 0 { "drops" } else if i.duplex.as_deref() == Some("half") { "duplex" } else { "MTU" }.into())
            }
            Tab::Routes => {
                let n = self.net.netinfo.try_lock().ok()?;
                let r = n.routes.get(self.route_state.selected()?)?;
                Some(if matches!(r.dst.as_str(), "default" | "0.0.0.0/0" | "::/0") {
                    "default".into()
                } else if r.gateway.is_empty() {
                    if r.proto.is_empty() { "link".into() } else { r.proto.clone() }
                } else if !r.proto.is_empty() {
                    r.proto.clone()
                } else {
                    "metric".into()
                })
            }
            Tab::Probes => {
                let p = self.net.probes.try_lock().ok()?;
                let pr = p.probes.get(self.probe_state.selected()?)?;
                if pr.silent() {
                    return Some("no reply".into());
                }
                let k = pr.target.kind();
                Some(if k.starts_with("http") { "https".into() } else { k.to_string() })
            }
            Tab::Firewall => {
                let rows = self.fw_rows();
                let r = rows.get(self.fw_state.selected()?)?;
                Some(if r.verdict.is_empty() { "policy".into() } else { r.verdict.to_ascii_uppercase() })
            }
            Tab::System if self.sys_events_focus => {
                let k = self.net.kmsg.try_lock().ok()?;
                let n = k.events.len();
                k.events.get(n.checked_sub(1 + self.ev_state.selected()?)?).map(|e| e.kind.to_string())
            }
            Tab::System => {
                let sv = self.net.services.try_lock().ok()?;
                let u = sv.units.get(self.svc_state.selected()?)?;
                Some(if u.failed() { "failed" } else if u.restarts > 0 { "restarts" } else if u.active == "activating" { "activating" } else { return None }.into())
            }
            Tab::Containers => {
                let c = self.net.containers.try_lock().ok()?;
                let c = c.containers.get(self.ctr_state.selected()?)?;
                Some(if c.oom_kills > 0 { "OOM" } else { "throttled" }.into())
            }
            Tab::Troubleshoot => {
                let t = self.net.tools.try_lock().ok()?;
                let sel = self.tool_state.selected().and_then(|i| t.lines.get(i)).map(|l| l.text.clone());
                // Tools other than the doctor: explain the tool, or the selected line's verdict.
                let line_or = |dflt: &str| -> Option<String> {
                    let l = sel.clone().unwrap_or_default();
                    let kinds = ["ERRDISABLE", "ROUTING", "SECURITY", "CONFIG", "DUPLEX", "LOGIN", "LINK", "STP", "HW"];
                    if let Some(k) = kinds.iter().find(|k| l.contains(&format!(" {k} "))) {
                        return Some(k.to_string());
                    }
                    for (needle, key) in [(" open ", "open"), (" refused ", "refused"), (" filtered ", "filtered"), ("CRC", "CRC"), ("DOWN", "port down"), ("discards", "discards")] {
                        if l.contains(needle) {
                            return Some(key.into());
                        }
                    }
                    Some(dflt.into())
                };
                match t.kind {
                    Some(tools::Kind::Syslog) => return line_or("syslog"),
                    Some(tools::Kind::Reach) => return line_or("reach"),
                    Some(tools::Kind::Snmp) => return line_or("snmp"),
                    Some(tools::Kind::Dhcp) => return Some("dhcp servers".into()),
                    Some(tools::Kind::Wifi) => return Some("Wi-Fi".into()),
                    Some(tools::Kind::Trace) => return Some("trace".into()),
                    Some(tools::Kind::Capture) => return Some("capture".into()),
                    _ => {}
                }
                let line = match sel {
                    Some(l) => l,
                    None => {
                        let c = t.checks.iter().find(|c| c.status == tools::doctor::Status::Fail).or_else(|| t.checks.iter().find(|c| c.status == tools::doctor::Status::Warn))?;
                        return Some(c.name.to_string());
                    }
                };
                // "  ✔ Gateway ping       10.0.0.1: …" → the check name.
                let body: String = line.trim_start().chars().skip_while(|c| !c.is_whitespace()).collect();
                let names: Vec<&str> = t.checks.iter().map(|c| c.name).collect();
                names.into_iter().find(|n| body.trim_start().starts_with(n)).map(String::from).or_else(|| {
                    if line.contains("MTU") { Some("MTU".into()) } else if line.contains("ARP") { Some("ARP change".into()) } else { None }
                })
            }
            Tab::Overview => {
                let mut alerts = self.alerts();
                alerts.sort_by_key(|(_, c)| *c != theme::red());
                Some(match alerts.first() {
                    Some((t, _)) => badge_key(t).to_string(),
                    None => "healthy".into(),
                })
            }
            Tab::Files => {
                let f = self.file_rows().get(self.files_state.selected()?)?;
                Some(if f.name.contains("(deleted)") {
                    "deleted".into()
                } else if matches!(f.fd.as_str(), "cwd" | "txt" | "mem") {
                    f.fd.clone()
                } else if f.ftype.starts_with("IPv") {
                    "IPv4".into()
                } else {
                    f.ftype.clone()
                })
            }
            Tab::Storage => Some("storage".into()),
            Tab::Users => {
                let failed = self.net.sessions.try_lock().map(|s| s.failed_total).unwrap_or(0);
                Some(if failed > 0 { "SSH FAILS" } else { "sessions" }.into())
            }
        }
    }

    fn copy(&mut self) {
        match self.copy_target() {
            Some((what, text)) => {
                crate::util::osc52_copy(&text);
                self.set_status(format!("copied {what}: {}", crate::util::truncate(&text, 60)), theme::green());
            }
            None => self.set_status("nothing to copy here", theme::yellow()),
        }
    }

    /// Rows of the current view as (name, headers, rows) for CSV export.
    fn export_table(&self) -> Option<ExportTable> {
        let fmt = |v: f64| format!("{v:.2}");
        Some(match self.tab {
            Tab::Processes => (
                "processes",
                vec!["pid", "ppid", "user", "name", "cpu_pct", "rss_bytes", "read_bps", "write_bps", "sockets", "net_bps", "fds", "status", "runtime_s", "command"],
                self.proc_rows
                    .iter()
                    .map(|r| {
                        let p = &self.sampler.procs[r.idx];
                        vec![
                            p.pid.to_string(),
                            p.ppid.map(|x| x.to_string()).unwrap_or_default(),
                            p.user.to_string(),
                            p.name.to_string(),
                            fmt(p.cpu as f64),
                            p.mem.to_string(),
                            fmt(p.read_rate),
                            fmt(p.write_rate),
                            self.conn_counts.get(&p.pid).copied().unwrap_or(0).to_string(),
                            fmt(self.proc_net.get(&p.pid).map(|(t, r)| t + r).unwrap_or(0.0)),
                            self.fd_info(p.pid).map(|(n, _)| n.to_string()).unwrap_or_default(),
                            p.status.to_string(),
                            p.run_time.to_string(),
                            p.cmd.to_string(),
                        ]
                    })
                    .collect(),
            ),
            Tab::Sockets => (
                "sockets",
                vec!["proto", "local", "remote", "state", "pid", "process", "user", "rtt_ms", "retrans", "rx_bps", "tx_bps", "netns"],
                self.socket_rows()
                    .iter()
                    .map(|e| {
                        let (l, r) = e.endpoints();
                        let n = e.net.as_deref();
                        let t = n.and_then(|n| n.tcp);
                        vec![
                            format!("{} {}", e.proto, e.ftype),
                            l.to_string(),
                            r.to_string(),
                            e.state.clone(),
                            e.pid.to_string(),
                            e.command.clone(),
                            e.user.clone(),
                            t.map(|t| fmt(t.rtt_us as f64 / 1000.0)).unwrap_or_default(),
                            t.map(|t| t.total_retrans.to_string()).unwrap_or_default(),
                            n.map(|n| fmt(n.rx_rate)).unwrap_or_default(),
                            n.map(|n| fmt(n.tx_rate)).unwrap_or_default(),
                            n.and_then(|n| n.netns.as_deref().map(str::to_string)).unwrap_or_default(),
                        ]
                    })
                    .collect(),
            ),
            Tab::Files => (
                "files",
                vec!["pid", "command", "user", "fd", "type", "size_off", "node", "name"],
                self.file_rows()
                    .iter()
                    .map(|e| vec![e.pid.to_string(), e.command.clone(), e.user.clone(), e.fd_display(), e.ftype.clone(), e.size_off(), e.node.clone(), e.name.clone()])
                    .collect(),
            ),
            Tab::Containers => {
                let c = self.net.containers.try_lock().ok()?;
                (
                    "containers",
                    vec!["name", "id", "runtime", "cpu_pct", "cpu_limit", "throttled_pct", "mem_bytes", "mem_limit", "oom_kills", "pids"],
                    c.containers
                        .iter()
                        .map(|c| {
                            vec![
                                c.name.clone(),
                                c.id.clone(),
                                c.runtime.into(),
                                fmt(c.cpu_pct),
                                c.cpu_limit.map(fmt).unwrap_or_default(),
                                fmt(c.throttled_pct),
                                c.mem.to_string(),
                                c.mem_max.map(|m| m.to_string()).unwrap_or_default(),
                                c.oom_kills.to_string(),
                                c.pids.to_string(),
                            ]
                        })
                        .collect(),
                )
            }
            Tab::System => {
                let s = self.net.services.try_lock().ok()?;
                (
                    "units",
                    vec!["unit", "active", "sub", "restarts", "pid", "memory", "description"],
                    s.units
                        .iter()
                        .map(|u| {
                            vec![
                                u.name.clone(),
                                u.active.clone(),
                                u.sub.clone(),
                                u.restarts.to_string(),
                                u.main_pid.to_string(),
                                u.memory.map(|m| m.to_string()).unwrap_or_default(),
                                u.description.clone(),
                            ]
                        })
                        .collect(),
                )
            }
            Tab::Probes => {
                let p = self.net.probes.try_lock().ok()?;
                (
                    "probes",
                    vec!["name", "target", "last_ms", "min_ms", "avg_ms", "max_ms", "jitter_ms", "loss_pct", "http_status", "cert_days"],
                    p.probes
                        .iter()
                        .map(|pr| {
                            let st = pr.stats();
                            vec![
                                pr.name.clone(),
                                pr.target.spec(),
                                pr.last_ms.map(fmt).unwrap_or_default(),
                                st.map(|s| fmt(s.0)).unwrap_or_default(),
                                st.map(|s| fmt(s.1)).unwrap_or_default(),
                                st.map(|s| fmt(s.2)).unwrap_or_default(),
                                st.map(|s| fmt(s.3)).unwrap_or_default(),
                                fmt(pr.loss_pct()),
                                pr.http_status.map(|s| s.to_string()).unwrap_or_default(),
                                pr.cert_days.map(|d| d.to_string()).unwrap_or_default(),
                            ]
                        })
                        .collect(),
                )
            }
            Tab::Firewall => (
                "firewall",
                vec!["family", "table", "chain", "rule", "verdict", "packets", "bytes", "pps", "bps"],
                self.fw_rows()
                    .iter()
                    .map(|r| vec![r.family.clone(), r.table.clone(), r.chain.clone(), r.rule.clone(), r.verdict.clone(), r.packets.to_string(), r.bytes.to_string(), fmt(r.pps), fmt(r.bps)])
                    .collect(),
            ),
            Tab::Routes => {
                let n = self.net.netinfo.try_lock().ok()?;
                (
                    "routes",
                    vec!["family", "destination", "gateway", "dev", "proto", "metric", "src"],
                    n.routes.iter().map(|r| vec![r.family.into(), r.dst.clone(), r.gateway.clone(), r.dev.clone(), r.proto.clone(), r.metric.clone(), r.src.clone()]).collect(),
                )
            }
            Tab::Network => (
                "interfaces",
                vec!["name", "state", "speed_mbps", "mtu", "rx_bps", "tx_bps", "rx_total", "tx_total", "rx_errors", "tx_errors", "dropped", "addresses"],
                self.sampler
                    .ifaces
                    .iter()
                    .map(|i| {
                        vec![
                            i.name.clone(),
                            i.oper.clone().unwrap_or_default(),
                            i.speed_mbps.map(|s| s.to_string()).unwrap_or_default(),
                            i.mtu.to_string(),
                            fmt(i.rx_rate),
                            fmt(i.tx_rate),
                            i.rx_total.to_string(),
                            i.tx_total.to_string(),
                            i.rx_errors.to_string(),
                            i.tx_errors.to_string(),
                            (i.rx_dropped + i.tx_dropped).to_string(),
                            i.addrs.join(" "),
                        ]
                    })
                    .collect(),
            ),
            Tab::Troubleshoot => {
                let t = self.net.tools.try_lock().ok()?;
                (
                    "troubleshoot",
                    vec!["tone", "text"],
                    t.lines.iter().map(|l| vec![format!("{:?}", l.tone).to_ascii_lowercase(), l.text.clone()]).collect(),
                )
            }
            Tab::Users => {
                let s = self.net.sessions.try_lock().ok()?;
                (
                    "sessions",
                    vec!["user", "tty", "from", "login", "idle", "what"],
                    s.sessions.iter().map(|u| vec![u.user.clone(), u.tty.clone(), u.from.clone(), u.login.clone(), u.idle.clone(), u.what.clone()]).collect(),
                )
            }
            _ => return None,
        })
    }

    fn export(&mut self) {
        let Some((name, headers, rows)) = self.export_table() else {
            self.set_status("this view has no table to export", theme::yellow());
            return;
        };
        match crate::util::write_csv(name, &headers, &rows) {
            Ok(p) => self.set_status(format!("exported {} rows to {}", rows.len(), p.display()), theme::green()),
            Err(e) => self.set_status(format!("export failed: {e}"), theme::red()),
        }
    }

    pub fn on_key(&mut self, k: KeyEvent) {
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        // `[keys]` remaps apply in normal mode only, never while typing.
        let k = if self.mode == Mode::Normal && !self.show_help { self.key_map.get(&normalize_key(k)).copied().unwrap_or(k) } else { k };
        match self.mode {
            Mode::Filter => self.key_filter(k),
            Mode::Query | Mode::AddProbe | Mode::ToolInput => self.key_query(k),
            Mode::Search => self.key_search(k),
            Mode::ConfirmClose => self.key_confirm_close(k),
            Mode::Signal => self.key_signal(k),
            Mode::Theme => self.key_theme(k),
            Mode::Normal => self.key_normal(k),
        }
        self.update_caches();
        self.sync_activity();
    }

    fn key_filter(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Esc => {
                if let Some(f) = self.filter_mut() {
                    f.clear();
                }
                self.mode = Mode::Normal;
            }
            KeyCode::Enter | KeyCode::Down | KeyCode::Up => self.mode = Mode::Normal,
            KeyCode::Backspace => {
                if let Some(f) = self.filter_mut() {
                    f.pop();
                }
            }
            KeyCode::Char(c) => {
                if let Some(f) = self.filter_mut() {
                    f.push(c);
                }
            }
            _ => {}
        }
        if let Some(st) = self.table_state() {
            st.select(Some(0));
        }
        self.selected_pid = None;
        self.rebuild_procs();
    }

    fn key_query(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Esc => {
                self.input.clear();
                self.mode = Mode::Normal;
            }
            KeyCode::Enter => {
                let mode = self.mode;
                self.mode = Mode::Normal;
                let input = std::mem::take(&mut self.input);
                if mode == Mode::ToolInput {
                    self.run_tool(self.tool_kind, input);
                } else if mode == Mode::AddProbe {
                    let res = self.net.probes.lock().map_err(|_| "busy".to_string()).and_then(|mut p| p.add(&input));
                    match res {
                        Ok(()) => self.set_status(format!("probe {input} added (saved on quit)"), theme::green()),
                        Err(e) => self.set_status(e, theme::red()),
                    }
                } else if let Some(q) = Query::parse(&input) {
                    self.run_query(q);
                }
            }
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Char(c) => self.input.push(c),
            _ => {}
        }
    }

    fn key_signal(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.mode = Mode::Normal;
                self.signal_target = None;
            }
            KeyCode::Up | KeyCode::Char('k') => self.signal_idx = self.signal_idx.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                self.signal_idx = (self.signal_idx + 1).min(signals().len() - 1)
            }
            KeyCode::Char(c @ '1'..='9') => {
                self.signal_idx = (c as usize - '1' as usize).min(signals().len() - 1)
            }
            KeyCode::Enter | KeyCode::Char('y') => {
                if let Some((pid, name)) = self.signal_target.take() {
                    let (sname, _, sig) = signals()[self.signal_idx.min(signals().len() - 1)];
                    match self.sampler.send_signal(pid, sig) {
                        Ok(()) => self.set_status(format!("sent {sname} to {name} ({pid})"), theme::green()),
                        Err(e) => self.set_status(e, theme::red()),
                    }
                }
                self.mode = Mode::Normal;
            }
            _ => {}
        }
    }

    fn key_theme(&mut self, k: KeyEvent) {
        let n = theme::all().len();
        match k.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                theme::set(self.theme_before);
                self.mode = Mode::Normal;
            }
            KeyCode::Up | KeyCode::Char('k') => theme::set((theme::index() + n - 1) % n),
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Char('T') => {
                theme::set((theme::index() + 1) % n)
            }
            KeyCode::Char('b') => self.cfg.background = !self.cfg.background,
            KeyCode::Enter => {
                self.mode = Mode::Normal;
                self.theme_user_set = true;
                self.set_status(format!("theme {} (saved on quit)", theme::pal().name), theme::green());
            }
            _ => {}
        }
    }

    fn key_confirm_close(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Char('y') | KeyCode::Enter => {
                if let Some(sk) = self.close_target.take() {
                    let id = sk.net.as_ref().and_then(|n| n.diag);
                    match id.map(|id| crate::collect::sockdiag::destroy(&id)) {
                        Some(Ok(())) => self.set_status(format!("closed {}", sk.name), theme::green()),
                        Some(Err(e)) => self.set_status(format!("close failed: {e} (needs root and CONFIG_INET_DIAG_DESTROY)"), theme::red()),
                        None => {}
                    }
                }
                self.mode = Mode::Normal;
            }
            _ => {
                self.close_target = None;
                self.mode = Mode::Normal;
            }
        }
    }

    /// Start a troubleshooting tool; its output streams into the Troubleshoot view.
    pub fn run_tool(&mut self, kind: tools::Kind, arg: String) {
        if self.net.tools.try_lock().map(|t| t.running).unwrap_or(false) {
            self.set_status("a tool is still running", theme::yellow());
            return;
        }
        let dns = self.net.netinfo.try_lock().map(|n| n.dns.servers.clone()).unwrap_or_default();
        let mut settings = tools::Settings::from(&self.cfg.troubleshoot);
        settings.capture_secs = self.cfg.network.capture_seconds;
        settings.snmp = self.cfg.snmp.clone();
        tools::start(self.net.tools.clone(), kind, arg, settings, dns);
        self.tool_kind = kind;
        self.tool_state.select(None);
        *self.tool_state.offset_mut() = 0;
        self.tab = Tab::Troubleshoot;
    }

    fn key_troubleshoot(&mut self, k: KeyEvent) {
        let kind = match k.code {
            KeyCode::Char('d') => {
                self.run_tool(tools::Kind::Doctor, String::new());
                return;
            }
            KeyCode::Char('c') => tools::Kind::Calc,
            KeyCode::Char('m') => tools::Kind::Mtu,
            KeyCode::Char('n') => tools::Kind::Dns,
            KeyCode::Char('p') => tools::Kind::Perf,
            KeyCode::Char('t') => tools::Kind::Capture,
            KeyCode::Char('r') => tools::Kind::Reach,
            KeyCode::Char('l') => tools::Kind::Syslog,
            KeyCode::Char('s') => tools::Kind::Snmp,
            KeyCode::Char('o') => tools::Kind::Dhcp,
            KeyCode::Char('e') => tools::Kind::Trace,
            KeyCode::Char('w') => {
                self.run_tool(tools::Kind::Wifi, String::new());
                return;
            }
            KeyCode::Char('x') => {
                let running = self
                    .net
                    .tools
                    .try_lock()
                    .map(|t| {
                        t.stop.store(true, std::sync::atomic::Ordering::Relaxed);
                        t.running
                    })
                    .unwrap_or(false);
                if running {
                    self.set_status("stopping…", theme::yellow());
                }
                return;
            }
            _ => return,
        };
        self.tool_kind = kind;
        self.input.clear();
        self.mode = Mode::ToolInput;
    }

    fn key_probes(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Char('a') => {
                self.input.clear();
                self.mode = Mode::AddProbe;
            }
            KeyCode::Char('t') => {
                // TCP probes trace with TCP to their port (firewalls often drop ICMP/UDP).
                let target = self.net.probes.try_lock().ok().and_then(|p| {
                    p.probes.get(self.probe_state.selected().unwrap_or(0)).map(|pr| match &pr.target {
                        probes::Target::Icmp(ip) => (ip.to_string(), trace::Mode::Icmp),
                        probes::Target::Tcp(h, port) => (h.clone(), trace::Mode::Tcp(*port)),
                        probes::Target::Dns(h) => (h.clone(), trace::Mode::Icmp),
                        probes::Target::Http(u) => {
                            let https = u.starts_with("https");
                            (u.split("://").nth(1).unwrap_or(u).split(['/', ':']).next().unwrap_or("").to_string(), trace::Mode::Tcp(if https { 443 } else { 80 }))
                        }
                    })
                });
                if let Some((t, mode)) = target.filter(|(t, _)| !t.is_empty()) {
                    let mode = if cfg!(windows) { trace::Mode::Icmp } else { mode };
                    trace::start(self.net.trace.clone(), t.clone(), mode);
                    self.set_status(format!("tracing the path to {t} ({})…", mode.label()), theme::cyan());
                }
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                let i = self.probe_state.selected().unwrap_or(0);
                let auto = match self.net.probes.lock() {
                    Ok(mut p) => match p.probes.get(i).map(|pr| pr.auto) {
                        Some(false) => {
                            p.remove(i);
                            false
                        }
                        Some(true) => true,
                        None => false,
                    },
                    Err(_) => false,
                };
                if auto {
                    self.set_status("auto probes follow the gateway/DNS; set auto_probes = false to hide them", theme::yellow());
                }
            }
            _ => {}
        }
    }

    fn key_system(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Char('e') => self.sys_events_focus = !self.sys_events_focus,
            KeyCode::Enter | KeyCode::Char('l') => self.load_selected_journal(true),
            _ => {}
        }
    }

    /// Show the journal of the selected unit (loads in the background).
    pub fn load_selected_journal(&mut self, force: bool) {
        let unit = self
            .net
            .services
            .try_lock()
            .ok()
            .and_then(|s| self.svc_state.selected().and_then(|i| s.units.get(i)).map(|u| u.name.clone()));
        if let Some(u) = unit {
            if force {
                if let Ok(mut s) = self.net.services.lock() {
                    s.journal_unit = None;
                }
            }
            services::load_journal(self.net.services.clone(), u);
        }
    }

    fn key_firewall(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Char('z') => self.fw_hide_zero = !self.fw_hide_zero,
            KeyCode::Char('s') => self.fw_by_rate = !self.fw_by_rate,
            _ => {}
        }
    }

    fn open_signal_dialog(&mut self, pid: u32, name: String) {
        if pid == 0 {
            self.set_status("socket has no owning process (kernel-held, e.g. TIME_WAIT)", theme::yellow());
            return;
        }
        self.signal_target = Some((pid, name));
        self.signal_idx = 0;
        self.mode = Mode::Signal;
    }

    fn key_normal(&mut self, k: KeyEvent) {
        if self.show_help {
            self.key_help(k);
            return;
        }
        if self.key_inspect(k) {
            return;
        }
        let page = 15;
        match k.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') | KeyCode::F(1) => {
                self.show_help = true;
                self.help_scroll = 0;
                self.help_typing = false;
                self.help_filter.clear();
            }
            KeyCode::Char('h') => self.explain = !self.explain,
            KeyCode::Char('F') => {
                self.input.clear();
                self.search_hits.clear();
                self.search_sel = 0;
                self.mode = Mode::Search;
            }
            KeyCode::Char('T') => {
                self.theme_before = theme::index();
                self.mode = Mode::Theme;
            }
            KeyCode::Char('R') => self.write_report(),
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('L') => {
                self.tab = Tab::ALL[(self.tab.index() + 1) % Tab::ALL.len()]
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('H') => {
                self.tab = Tab::ALL[(self.tab.index() + Tab::ALL.len() - 1) % Tab::ALL.len()]
            }
            KeyCode::Char(c @ '1'..='9') => {
                self.inspect = None;
                self.tab = Tab::ALL[c as usize - '1' as usize]
            }
            KeyCode::Char('0') => self.tab = Tab::Containers,
            KeyCode::Char('S') => self.tab = Tab::System,
            KeyCode::Char('U') => self.tab = Tab::Users,
            KeyCode::Char('W') => self.tab = Tab::Troubleshoot,
            KeyCode::Char('y') => self.copy(),
            KeyCode::Char('E') => self.export(),
            KeyCode::Char('N') => {
                self.show_names = !self.show_names;
                if self.show_names && self.resolver.is_none() {
                    self.resolver = Some(Resolver::new());
                }
                let msg = if self.show_names { "reverse DNS on" } else { "reverse DNS off" };
                self.set_status(msg, theme::cyan());
            }
            KeyCode::Char(' ') => {
                self.paused = !self.paused;
                let msg = if self.paused { "paused" } else { "resumed" };
                self.set_status(msg, theme::yellow());
            }
            KeyCode::Char('+') | KeyCode::Char('=') => {
                self.interval = (self.interval + Duration::from_millis(250)).min(Duration::from_secs(10));
                self.set_status(format!("refresh interval {}ms", self.interval.as_millis()), theme::cyan());
            }
            KeyCode::Char('-') => {
                self.interval = self
                    .interval
                    .saturating_sub(Duration::from_millis(250))
                    .max(Duration::from_millis(250));
                self.set_status(format!("refresh interval {}ms", self.interval.as_millis()), theme::cyan());
            }
            KeyCode::Char('/') => {
                if self.filter_mut().is_none() {
                    self.tab = Tab::Processes;
                }
                self.mode = Mode::Filter;
            }
            KeyCode::Char(':') => {
                self.input.clear();
                self.mode = Mode::Query;
            }
            KeyCode::Esc => {
                if self.tab == Tab::Troubleshoot {
                    self.tool_state.select(None);
                }
                if let Some(f) = self.filter_mut() {
                    f.clear();
                }
                self.rebuild_procs();
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_sel(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_sel(-1),
            KeyCode::PageDown => self.move_sel(page),
            KeyCode::PageUp => self.move_sel(-page),
            KeyCode::Home | KeyCode::Char('g') => self.move_sel(-1_000_000),
            KeyCode::End | KeyCode::Char('G') => self.move_sel(1_000_000),
            _ => match self.tab {
                Tab::Processes => self.key_procs(k),
                Tab::Sockets => self.key_sockets(k),
                Tab::Files => self.key_files(k),
                Tab::Probes => self.key_probes(k),
                Tab::System => self.key_system(k),
                Tab::Firewall => self.key_firewall(k),
                Tab::Troubleshoot => self.key_troubleshoot(k),
                Tab::Network => {
                    // C: capture on the selected interface (Troubleshoot shows the progress).
                    if k.code == KeyCode::Char('C') {
                        if let Some(name) = self.net_state.selected().and_then(|i| self.sampler.ifaces.get(i)).map(|i| i.name.clone()) {
                            self.run_tool(tools::Kind::Capture, name);
                        }
                    }
                }
                _ => {}
            },
        }
    }

    /// The help screen: scroll, search, close. All from the keyboard.
    fn key_help(&mut self, k: KeyEvent) {
        if self.help_typing {
            match k.code {
                KeyCode::Esc => {
                    self.help_filter.clear();
                    self.help_typing = false;
                }
                KeyCode::Enter | KeyCode::Down | KeyCode::Up => self.help_typing = false,
                KeyCode::Backspace => {
                    self.help_filter.pop();
                }
                KeyCode::Char(c) => self.help_filter.push(c),
                _ => {}
            }
            self.help_scroll = 0;
            return;
        }
        let page = self.help_page.max(1);
        match k.code {
            KeyCode::Esc if !self.help_filter.is_empty() => self.help_filter.clear(),
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char('?') | KeyCode::F(1) => self.show_help = false,
            KeyCode::Char('/') => self.help_typing = true,
            // (The view clamps the position to the last page when it draws.)
            KeyCode::Down | KeyCode::Char('j') => self.help_scroll = self.help_scroll.saturating_add(1),
            KeyCode::Up | KeyCode::Char('k') => self.help_scroll = self.help_scroll.saturating_sub(1),
            KeyCode::PageDown | KeyCode::Char(' ') => self.help_scroll = self.help_scroll.saturating_add(page),
            KeyCode::PageUp => self.help_scroll = self.help_scroll.saturating_sub(page),
            KeyCode::Home | KeyCode::Char('g') => self.help_scroll = 0,
            KeyCode::End | KeyCode::Char('G') => self.help_scroll = u16::MAX,
            _ => {}
        }
    }

    fn set_proc_sort(&mut self, s: ProcSort) {
        if self.proc_sort == s {
            self.proc_desc = !self.proc_desc;
        } else {
            self.proc_sort = s;
            self.proc_desc = !matches!(s, ProcSort::Name | ProcSort::User | ProcSort::Pid);
        }
        self.rebuild_procs();
    }

    fn key_procs(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Char('c') => self.set_proc_sort(ProcSort::Cpu),
            KeyCode::Char('m') => self.set_proc_sort(ProcSort::Mem),
            KeyCode::Char('p') => self.set_proc_sort(ProcSort::Pid),
            KeyCode::Char('n') => self.set_proc_sort(ProcSort::Name),
            KeyCode::Char('u') => self.set_proc_sort(ProcSort::User),
            KeyCode::Char('i') => self.set_proc_sort(ProcSort::Io),
            KeyCode::Char('o') => self.set_proc_sort(ProcSort::Conn),
            KeyCode::Char('w') => self.set_proc_sort(ProcSort::Net),
            KeyCode::Char('e') => self.set_proc_sort(ProcSort::Fds),
            KeyCode::Char('r') => {
                self.proc_desc = !self.proc_desc;
                self.rebuild_procs();
            }
            KeyCode::Char('t') => {
                self.proc_tree = !self.proc_tree;
                self.rebuild_procs();
            }
            KeyCode::Enter | KeyCode::Char('I') => {
                if let Some(pid) = self.selected_proc().map(|p| p.pid) {
                    self.open_inspector(pid);
                }
            }
            KeyCode::Char('f') => {
                if let Some(p) = self.selected_proc() {
                    let pid = p.pid;
                    self.run_query(Query::Pid(pid));
                }
            }
            KeyCode::Char('x') | KeyCode::Char('K') | KeyCode::Delete => {
                if let Some(p) = self.selected_proc() {
                    let (pid, name) = (p.pid, p.name.to_string());
                    self.open_signal_dialog(pid, name);
                }
            }
            _ => {}
        }
    }

    fn selected_socket(&self) -> Option<OpenFile> {
        let i = self.sock_state.selected()?;
        self.socket_rows().get(i).cloned()
    }

    fn key_sockets(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Char('i') => {
                if let Some(pid) = self.selected_socket().map(|s| s.pid).filter(|p| *p != 0) {
                    self.open_inspector(pid);
                }
            }
            KeyCode::Char('l') => {
                self.sock_listen_only = !self.sock_listen_only;
                self.sock_state.select(Some(0));
            }
            KeyCode::Char('s') => self.sock_sort = self.sock_sort.next(),
            KeyCode::Char('C') => {
                if let Some(sk) = self.selected_socket() {
                    let (l, r) = sk.endpoints();
                    match capture::bpf_filter(l, r) {
                        Some(f) => match capture::start(self.net.capture.clone(), f.clone(), self.cfg.network.capture_seconds) {
                            Ok(p) => self.set_status(format!("capturing \"{f}\" for {}s → {}", self.cfg.network.capture_seconds, p.display()), theme::red()),
                            Err(e) => self.set_status(e, theme::red()),
                        },
                        None => self.set_status("can't build a capture filter for this socket", theme::yellow()),
                    }
                }
            }
            KeyCode::Char('D') => {
                if let Some(sk) = self.selected_socket() {
                    if sk.net.as_ref().and_then(|n| n.diag).is_some() {
                        self.close_target = Some(sk);
                        self.mode = Mode::ConfirmClose;
                    } else {
                        self.set_status("closing single connections needs Linux sock_diag on a host-namespace TCP socket", theme::yellow());
                    }
                }
            }
            KeyCode::Enter | KeyCode::Char('f') => {
                if let Some(s) = self.selected_socket().filter(|s| s.pid != 0) {
                    self.run_query(Query::Pid(s.pid));
                }
            }
            KeyCode::Char('P') => {
                if let Some(port) = self.selected_socket().and_then(|s| s.local_port()) {
                    self.run_query(Query::Port(format!(":{port}")));
                }
            }
            KeyCode::Char('x') | KeyCode::Char('K') | KeyCode::Delete => {
                if let Some(s) = self.selected_socket() {
                    self.open_signal_dialog(s.pid, s.command);
                }
            }
            _ => {}
        }
    }

    fn key_files(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Char('R') | KeyCode::Char('r') => {
                let q = self.files.lock().ok().and_then(|s| s.query.clone());
                if let Some(q) = q {
                    lsof::spawn_query(self.files.clone(), q);
                }
            }
            KeyCode::Enter => {
                let row = self
                    .files_state
                    .selected()
                    .and_then(|i| self.file_rows().get(i).cloned());
                if let Some(f) = row {
                    if f.name.starts_with('/') {
                        // Who else has this file open?
                        let path = f.name.split(" (").next().unwrap_or(&f.name).to_string();
                        self.run_query(Query::Path(path));
                    } else if f.is_network() {
                        if let Some(port) = f.local_port() {
                            self.run_query(Query::Port(format!(":{port}")));
                        }
                    }
                }
            }
            KeyCode::Char('p') => {
                let row = self
                    .files_state
                    .selected()
                    .and_then(|i| self.file_rows().get(i).cloned());
                if let Some(f) = row {
                    self.run_query(Query::Pid(f.pid));
                }
            }
            KeyCode::Char('x') | KeyCode::Char('K') => {
                let row = self
                    .files_state
                    .selected()
                    .and_then(|i| self.file_rows().get(i).cloned());
                if let Some(f) = row {
                    self.open_signal_dialog(f.pid, f.command);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn every_badge_has_an_explanation() {
        for b in ["MEM 96%", "SWAP 60%", "DISK /var 94%", "LOAD 2.1/core", "CLOSE_WAIT 412", "TIME_WAIT 30000", "TEMP 95°C", "RETRANS 3.1%", "LISTEN DROPS 4/s", "UDP DROPS 2/s", "CONNTRACK 91%", "eth0 DROPS 12/s", "LOSS gateway 10.0.0.1 40%", "FDS nginx 95%", "FILES 85%", "EPHEMERAL PORTS 88%", "INODES /var 99%", "nvme0n1 AWAIT 140ms", "sda BUSY 99%", "CERT api 9d", "HTTP api 503", "THROTTLED web 40%", "OOM web", "OOM KILLS 2", "NEEDS RESTART 4", "SSH FAILS 1400/h", "FAILED UNITS 2", "eth0 ERR 3/s", "PSI io 37%", "GATEWAY MAC CHANGED"] {
            let k = badge_key(b);
            assert_ne!(k, "healthy", "{b}");
            assert!(crate::explain::lookup(k).is_some(), "{b} → {k} has no entry");
        }
    }

    #[test]
    fn parses_key_names_and_remaps() {
        assert_eq!(parse_key("F5"), Some(KeyEvent::new(KeyCode::F(5), KeyModifiers::NONE)));
        assert_eq!(parse_key("ctrl-K"), Some(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL)));
        assert_eq!(parse_key("alt+x"), Some(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::ALT)));
        assert_eq!(parse_key("PgDn"), Some(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE)));
        assert_eq!(parse_key("Q").map(|k| k.code), Some(KeyCode::Char('Q')));
        assert_eq!(parse_key("nonsense"), None);
        let keys = [("Q".to_string(), "q".to_string()), ("bad key".into(), "q".into())].into_iter().collect();
        let (m, w) = key_map(&keys);
        assert_eq!(w.len(), 1);
        // Terminals send Shift+Q as Char('Q') with SHIFT set.
        let pressed = KeyEvent::new(KeyCode::Char('Q'), KeyModifiers::SHIFT);
        assert_eq!(m.get(&normalize_key(pressed)).map(|k| k.code), Some(KeyCode::Char('q')));
    }
}
