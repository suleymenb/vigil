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
use crate::collect::firewall::{self, FwRule, FwStore};
use crate::collect::ipinfo::{self, Resolver};
use crate::collect::lsof::{self, FilesStore, OpenFile, Query, SocketStore};
use crate::collect::netinfo::{self, NetInfo};
use crate::collect::probes::{self, ProbeStore};
use crate::collect::system::{ProcInfo, Sampler};
use crate::config::{Alerts, Config};
use crate::theme;

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
}

impl Tab {
    pub const ALL: [Tab; 9] = [
        Tab::Overview,
        Tab::Processes,
        Tab::Network,
        Tab::Sockets,
        Tab::Files,
        Tab::Storage,
        Tab::Routes,
        Tab::Probes,
        Tab::Firewall,
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
}

pub const SIGNALS: [(&str, &str, Signal); 9] = [
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

/// Every `[alerts]` threshold that is exceeded. Shared by the header badges and `vigil report`.
pub fn compute_alerts(
    s: &Sampler,
    a: &Alerts,
    close_wait: usize,
    time_wait: usize,
    probe_losses: &[(String, f64)],
) -> Vec<(String, Color)> {
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
    pub route_state: TableState,
    pub probe_state: TableState,
    pub fw_state: TableState,
    pub fw_filter: String,
    pub fw_hide_zero: bool,
    pub fw_by_rate: bool,
    pub close_target: Option<OpenFile>,
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
        let mut app = Self {
            tab,
            sampler,
            sockets,
            files,
            interval,
            paused: false,
            show_help: false,
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
            route_state: TableState::default().with_selected(0),
            probe_state: TableState::default().with_selected(0),
            fw_state: TableState::default().with_selected(0),
            fw_filter: String::new(),
            fw_hide_zero: false,
            fw_by_rate: false,
            close_target: None,
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
        if let Ok(s) = self.sockets.lock() {
            if s.version != self.conn_version {
                self.conn_version = s.version;
                self.conn_counts.clear();
                self.proc_net.clear();
                self.close_wait = 0;
                self.time_wait = 0;
                for e in s.entries.iter() {
                    if let (Some(n), true) = (&e.net, e.pid != 0) {
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
    }

    /// Health badges for the header: every threshold from `[alerts]` that is exceeded.
    pub fn alerts(&self) -> Vec<(String, Color)> {
        let losses: Vec<(String, f64)> = self
            .net
            .probes
            .try_lock()
            .map(|p| p.probes.iter().filter(|p| p.sent() >= 5).map(|p| (p.name.clone(), p.loss_pct())).collect())
            .unwrap_or_default();
        compute_alerts(&self.sampler, &self.cfg.alerts, self.close_wait, self.time_wait, &losses)
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
        match crate::report::write_from_tui(&self.sampler, &entries, backend, &self.cfg.alerts) {
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
    pub fn external_key(&self) -> ([u64; 7], bool) {
        let v = |o: Option<u64>| o.unwrap_or(0);
        let sv = v(self.sockets.try_lock().ok().map(|s| s.version));
        let fv = v(self.files.try_lock().ok().map(|s| s.version));
        // Only views that show a store need to redraw when it changes.
        let ni = if self.tab == Tab::Routes { v(self.net.netinfo.try_lock().ok().map(|s| s.version)) } else { 0 };
        let pr = if self.tab == Tab::Probes { v(self.net.probes.try_lock().ok().map(|s| s.version)) } else { 0 };
        let fw = if self.tab == Tab::Firewall { v(self.net.fw.try_lock().ok().map(|s| s.version)) } else { 0 };
        let cap = v(self.net.capture.try_lock().ok().map(|s| s.version));
        let status_live = self
            .status
            .as_ref()
            .is_some_and(|(_, _, at)| at.elapsed() < Duration::from_secs(4))
            || self.net.capture.try_lock().map(|c| c.running.is_some()).unwrap_or(false);
        ([sv, fv, self.sampler.slow_version(), ni, pr, fw, cap], status_live)
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
            _ => None,
        }
    }

    fn move_sel(&mut self, delta: isize) {
        let len = self.list_len();
        if let Some(st) = self.table_state() {
            if len == 0 {
                st.select(Some(0));
                return;
            }
            let cur = st.selected().unwrap_or(0) as isize;
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
            MouseEventKind::ScrollDown => self.move_sel(3),
            MouseEventKind::ScrollUp => self.move_sel(-3),
            _ => {}
        }
    }

    pub fn on_key(&mut self, k: KeyEvent) {
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        match self.mode {
            Mode::Filter => self.key_filter(k),
            Mode::Query | Mode::AddProbe => self.key_query(k),
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
                if mode == Mode::AddProbe {
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
                self.signal_idx = (self.signal_idx + 1).min(SIGNALS.len() - 1)
            }
            KeyCode::Char(c @ '1'..='9') => {
                self.signal_idx = (c as usize - '1' as usize).min(SIGNALS.len() - 1)
            }
            KeyCode::Enter | KeyCode::Char('y') => {
                if let Some((pid, name)) = self.signal_target.take() {
                    let (sname, _, sig) = SIGNALS[self.signal_idx];
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
        let n = theme::THEMES.len();
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

    fn key_probes(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Char('a') => {
                self.input.clear();
                self.mode = Mode::AddProbe;
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
            self.show_help = false;
            return;
        }
        let page = 15;
        match k.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') | KeyCode::F(1) => self.show_help = true,
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
            KeyCode::Char(c @ '1'..='9') => self.tab = Tab::ALL[c as usize - '1' as usize],
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
                Tab::Firewall => self.key_firewall(k),
                _ => {}
            },
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
            KeyCode::Char('r') => {
                self.proc_desc = !self.proc_desc;
                self.rebuild_procs();
            }
            KeyCode::Char('t') => {
                self.proc_tree = !self.proc_tree;
                self.rebuild_procs();
            }
            KeyCode::Enter | KeyCode::Char('f') => {
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
