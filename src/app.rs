//! Application state and input handling.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use ratatui::style::Color;
use ratatui::widgets::TableState;
use sysinfo::Signal;

use crate::collect::lsof::{self, FilesStore, OpenFile, Query, SocketStore};
use crate::collect::system::{ProcInfo, Sampler};
use crate::theme;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Overview,
    Processes,
    Network,
    Sockets,
    Files,
    Storage,
}

impl Tab {
    pub const ALL: [Tab; 6] = [
        Tab::Overview,
        Tab::Processes,
        Tab::Network,
        Tab::Sockets,
        Tab::Files,
        Tab::Storage,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Processes => "Processes",
            Tab::Network => "Network",
            Tab::Sockets => "Sockets",
            Tab::Files => "Open Files",
            Tab::Storage => "Storage",
        }
    }

    pub fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    pub fn from_name(s: &str) -> Option<Tab> {
        let s = s.to_ascii_lowercase();
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
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SockSort {
    Process,
    Port,
    State,
    Proto,
    Remote,
}

impl SockSort {
    fn next(self) -> Self {
        match self {
            SockSort::Process => SockSort::Port,
            SockSort::Port => SockSort::State,
            SockSort::State => SockSort::Proto,
            SockSort::Proto => SockSort::Remote,
            SockSort::Remote => SockSort::Process,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            SockSort::Process => "process",
            SockSort::Port => "port",
            SockSort::State => "state",
            SockSort::Proto => "proto",
            SockSort::Remote => "remote",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Normal,
    Filter,
    Query,
    Signal,
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

pub struct ProcRow {
    pub idx: usize,
    pub prefix: String,
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
    sock_cache: Vec<OpenFile>,
    sock_key: Option<(u64, String, bool, SockSort)>,
    files_cache: Vec<OpenFile>,
    files_key: Option<(u64, String)>,
    conn_version: u64,
}

impl App {
    pub fn new(
        sampler: Sampler,
        sockets: Arc<Mutex<SocketStore>>,
        files: Arc<Mutex<FilesStore>>,
        interval: Duration,
        tab: Tab,
    ) -> Self {
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
            proc_sort: ProcSort::Cpu,
            proc_desc: true,
            proc_tree: false,
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
            sock_cache: Vec::new(),
            sock_key: None,
            files_cache: Vec::new(),
            files_key: None,
            conn_version: u64::MAX,
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
                for e in s.entries.iter().filter(|e| e.pid != 0) {
                    *self.conn_counts.entry(e.pid).or_default() += 1;
                }
            }
        }
        self.sampler
            .sensors_fast
            .store(self.tab == Tab::Storage, std::sync::atomic::Ordering::Relaxed);
        self.rebuild_procs();
        self.update_caches();
    }

    /// Everything that can change the screen without user input.
    /// The main loop redraws only when this (or input / a tick) changes.
    pub fn external_key(&self) -> (u64, u64, u64, bool) {
        let sv = self.sockets.try_lock().map(|s| s.version).unwrap_or(0);
        let fv = self.files.try_lock().map(|s| s.version).unwrap_or(0);
        let status_live = self
            .status
            .as_ref()
            .is_some_and(|(_, _, at)| at.elapsed() < Duration::from_secs(4));
        (sv, fv, self.sampler.slow_version(), status_live)
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
            ProcSort::Name => b.name.to_lowercase().cmp(&a.name.to_lowercase()),
            ProcSort::User => b.user.cmp(&a.user),
            ProcSort::Io => (a.read_rate + a.write_rate)
                .partial_cmp(&(b.read_rate + b.write_rate))
                .unwrap_or(Ordering::Equal),
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
        let filter = self.proc_filter.to_lowercase();
        let mut idxs: Vec<usize> = (0..procs.len())
            .filter(|&i| {
                filter.is_empty() || {
                    let p = &procs[i];
                    p.name.to_lowercase().contains(&filter)
                        || p.cmd.to_lowercase().contains(&filter)
                        || p.user.to_lowercase().contains(&filter)
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
                let cont = match branch {
                    "├─ " => "│  ",
                    "└─ " => "   ",
                    _ => "",
                };
                let next_prefix = format!("{prefix}{cont}");
                for (n, &k) in kids.iter().enumerate() {
                    let b = if n + 1 == kids.len() { "└─ " } else { "├─ " };
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

    pub fn socket_rows(&self) -> &[OpenFile] {
        &self.sock_cache
    }

    pub fn file_rows(&self) -> &[OpenFile] {
        &self.files_cache
    }

    /// Re-filter / re-sort socket and file lists only when their inputs changed.
    pub fn update_caches(&mut self) {
        if let Ok(store) = self.sockets.try_lock() {
            let key = (store.version, self.sock_filter.clone(), self.sock_listen_only, self.sock_sort);
            if self.sock_key.as_ref() != Some(&key) {
                let f = self.sock_filter.to_lowercase();
                let mut rows: Vec<OpenFile> = store
                    .entries
                    .iter()
                    .filter(|e| !self.sock_listen_only || e.is_listening())
                    .filter(|e| {
                        f.is_empty()
                            || e.command.to_lowercase().contains(&f)
                            || e.name.to_lowercase().contains(&f)
                            || e.state.to_lowercase().contains(&f)
                            || e.proto.to_lowercase().contains(&f)
                            || e.user.to_lowercase().contains(&f)
                            || e.pid.to_string() == f
                    })
                    .cloned()
                    .collect();
                match self.sock_sort {
                    SockSort::Process => rows.sort_by(|a, b| {
                        a.command.to_lowercase().cmp(&b.command.to_lowercase()).then(a.pid.cmp(&b.pid))
                    }),
                    SockSort::Port => rows.sort_by_key(|e| e.local_port().unwrap_or(u16::MAX)),
                    SockSort::State => rows.sort_by(|a, b| a.state.cmp(&b.state)),
                    SockSort::Proto => {
                        rows.sort_by(|a, b| a.proto.cmp(&b.proto).then(a.ftype.cmp(&b.ftype)))
                    }
                    SockSort::Remote => rows.sort_by(|a, b| b.endpoints().1.cmp(a.endpoints().1)),
                }
                self.sock_cache = rows;
                self.sock_key = Some(key);
            }
        }
        if let Ok(store) = self.files.try_lock() {
            let key = (store.version, self.files_filter.clone());
            if self.files_key.as_ref() != Some(&key) {
                let f = self.files_filter.to_lowercase();
                self.files_cache = store
                    .entries
                    .iter()
                    .filter(|e| {
                        f.is_empty()
                            || e.name.to_lowercase().contains(&f)
                            || e.command.to_lowercase().contains(&f)
                            || e.ftype.to_lowercase().contains(&f)
                            || e.fd.to_lowercase() == f
                    })
                    .cloned()
                    .collect();
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
            _ => 0,
        }
    }

    fn table_state(&mut self) -> Option<&mut TableState> {
        match self.tab {
            Tab::Processes => Some(&mut self.proc_state),
            Tab::Sockets => Some(&mut self.sock_state),
            Tab::Files => Some(&mut self.files_state),
            Tab::Network => Some(&mut self.net_state),
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
            Mode::Query => self.key_query(k),
            Mode::Signal => self.key_signal(k),
            Mode::Normal => self.key_normal(k),
        }
        self.update_caches();
        self.sampler
            .sensors_fast
            .store(self.tab == Tab::Storage, std::sync::atomic::Ordering::Relaxed);
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
                self.mode = Mode::Normal;
                let input = std::mem::take(&mut self.input);
                if let Some(q) = Query::parse(&input) {
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
                        Ok(()) => self.set_status(format!("sent {sname} to {name} ({pid})"), theme::GREEN),
                        Err(e) => self.set_status(e, theme::RED),
                    }
                }
                self.mode = Mode::Normal;
            }
            _ => {}
        }
    }

    fn open_signal_dialog(&mut self, pid: u32, name: String) {
        if pid == 0 {
            self.set_status("socket has no owning process (kernel-held, e.g. TIME_WAIT)", theme::YELLOW);
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
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('L') => {
                self.tab = Tab::ALL[(self.tab.index() + 1) % Tab::ALL.len()]
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('H') => {
                self.tab = Tab::ALL[(self.tab.index() + Tab::ALL.len() - 1) % Tab::ALL.len()]
            }
            KeyCode::Char(c @ '1'..='6') => self.tab = Tab::ALL[c as usize - '1' as usize],
            KeyCode::Char(' ') => {
                self.paused = !self.paused;
                let msg = if self.paused { "paused" } else { "resumed" };
                self.set_status(msg, theme::YELLOW);
            }
            KeyCode::Char('+') | KeyCode::Char('=') => {
                self.interval = (self.interval + Duration::from_millis(250)).min(Duration::from_secs(10));
                self.set_status(format!("refresh interval {}ms", self.interval.as_millis()), theme::CYAN);
            }
            KeyCode::Char('-') => {
                self.interval = self
                    .interval
                    .saturating_sub(Duration::from_millis(250))
                    .max(Duration::from_millis(250));
                self.set_status(format!("refresh interval {}ms", self.interval.as_millis()), theme::CYAN);
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
