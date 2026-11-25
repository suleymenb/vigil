//! lsof integration: parses `lsof -F` machine-readable output.
//! Socket listing runs on a background thread; ad-hoc queries (by pid, port,
//! path or raw arguments) run on demand without blocking the UI.

use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::util::fmt_bytes;

const FIELDS: &str = "-FpcLuftasoinPT";
const MAX_ENTRIES: usize = 50_000;

#[derive(Clone, Debug, Default)]
pub struct OpenFile {
    pub pid: u32,
    pub command: String,
    pub user: String,
    pub fd: String,
    pub access: String,
    pub ftype: String,
    pub size: Option<u64>,
    pub offset: Option<String>,
    pub node: String,
    pub name: String,
    pub proto: String,
    pub state: String,
}

impl OpenFile {
    pub fn fd_display(&self) -> String {
        format!("{}{}", self.fd, self.access)
    }

    pub fn size_off(&self) -> String {
        match (&self.size, &self.offset) {
            (Some(s), _) => fmt_bytes(*s),
            (None, Some(o)) => o.clone(),
            _ => String::new(),
        }
    }

    /// Split a network name `local->remote` into its endpoints.
    pub fn endpoints(&self) -> (&str, &str) {
        match self.name.split_once("->") {
            Some((l, r)) => (l, r),
            None => (self.name.as_str(), ""),
        }
    }

    pub fn local_port(&self) -> Option<u16> {
        self.endpoints().0.rsplit(':').next()?.parse().ok()
    }

    pub fn is_listening(&self) -> bool {
        self.state == "LISTEN" || (self.proto == "UDP" && self.endpoints().1.is_empty())
    }

    pub fn is_network(&self) -> bool {
        self.ftype.starts_with("IPv")
    }
}

pub fn run(args: &[String]) -> Result<(Vec<OpenFile>, Duration), String> {
    let start = Instant::now();
    let out = Command::new("lsof")
        .arg("-w")
        .arg(FIELDS)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run lsof: {e} (is lsof installed?)"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() && stdout.trim().is_empty() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        // lsof exits 1 with no output when nothing matched.
        if err.is_empty() {
            return Ok((Vec::new(), start.elapsed()));
        }
        return Err(err.lines().next().unwrap_or("lsof failed").to_string());
    }
    let mut entries = parse(&stdout);
    entries.truncate(MAX_ENTRIES);
    Ok((entries, start.elapsed()))
}

pub fn parse(s: &str) -> Vec<OpenFile> {
    let mut out = Vec::new();
    let mut pid = 0u32;
    let mut cmd = String::new();
    let mut user = String::new();
    let mut cur: Option<OpenFile> = None;

    for line in s.lines() {
        let mut chars = line.chars();
        let Some(tag) = chars.next() else { continue };
        let val = chars.as_str();
        match tag {
            'p' => {
                out.extend(cur.take());
                pid = val.parse().unwrap_or(0);
                cmd.clear();
                user.clear();
            }
            'c' => cmd = val.to_string(),
            'u' | 'L' => user = val.to_string(),
            'f' => {
                out.extend(cur.take());
                cur = Some(OpenFile {
                    pid,
                    command: cmd.clone(),
                    user: user.clone(),
                    fd: val.to_string(),
                    ..Default::default()
                });
            }
            _ => {
                if let Some(f) = cur.as_mut() {
                    match tag {
                        'a' => f.access = val.trim().to_string(),
                        't' => f.ftype = val.to_string(),
                        's' => f.size = val.parse().ok(),
                        'o' => f.offset = Some(val.to_string()),
                        'i' => f.node = val.to_string(),
                        'n' => f.name = val.to_string(),
                        'P' => f.proto = val.to_string(),
                        'T' => {
                            if let Some(st) = val.strip_prefix("ST=") {
                                f.state = st.to_string();
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    out.extend(cur);
    out
}

// ───────────────────────── background socket scanner ─────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SocketBackend {
    /// Native /proc/net reader (Linux only).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    ProcNet,
    /// `lsof -nP -i` (macOS, BSD, or forced with --lsof-sockets).
    Lsof,
}

impl SocketBackend {
    pub fn label(self) -> &'static str {
        match self {
            SocketBackend::ProcNet => "/proc/net",
            SocketBackend::Lsof => "lsof -nP -i",
        }
    }
}

pub struct SocketStore {
    pub entries: Vec<OpenFile>,
    pub updated: Option<Instant>,
    pub took: Duration,
    pub error: Option<String>,
    pub backend: SocketBackend,
    /// Bumped on every write so the UI can skip work when nothing changed.
    pub version: u64,
}

impl Default for SocketStore {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            updated: None,
            took: Duration::ZERO,
            error: None,
            backend: SocketBackend::Lsof,
            version: 0,
        }
    }
}

pub fn spawn_socket_worker(store: Arc<Mutex<SocketStore>>, interval: Duration, force_lsof: bool) {
    thread::spawn(move || {
        #[cfg(target_os = "linux")]
        let mut native = if force_lsof { None } else { super::procnet::Scanner::new() };
        #[cfg(not(target_os = "linux"))]
        let _ = force_lsof;

        loop {
            let start = Instant::now();
            #[cfg(target_os = "linux")]
            let (res, backend) = match native.as_mut() {
                Some(sc) => (Ok((sc.scan(), start.elapsed())), SocketBackend::ProcNet),
                None => (run(&["-nP".into(), "-i".into()]), SocketBackend::Lsof),
            };
            #[cfg(not(target_os = "linux"))]
            let (res, backend) = (run(&["-nP".into(), "-i".into()]), SocketBackend::Lsof);
            let _ = start;

            if let Ok(mut s) = store.lock() {
                s.backend = backend;
                match res {
                    Ok((entries, took)) => {
                        s.entries = entries;
                        s.took = took;
                        s.error = None;
                    }
                    Err(e) => s.error = Some(e),
                }
                s.updated = Some(Instant::now());
                s.version += 1;
            }
            thread::sleep(interval);
        }
    });
}

// ───────────────────────────── on-demand queries ─────────────────────────────

#[derive(Clone, Debug)]
pub enum Query {
    Pid(u32),
    Port(String),
    Path(String),
    Raw(Vec<String>),
}

impl Query {
    /// Smart parse of the `:` prompt:
    /// `1234` → pid, `:443` / `tcp:443` / `udp` → network, `/path` → who opens it,
    /// `-u root -i` → raw lsof arguments.
    pub fn parse(s: &str) -> Option<Query> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        if let Ok(pid) = s.parse::<u32>() {
            return Some(Query::Pid(pid));
        }
        let lower = s.to_ascii_lowercase();
        if s.starts_with(':')
            || lower.starts_with("tcp")
            || lower.starts_with("udp")
            || lower.starts_with('@')
        {
            return Some(Query::Port(s.to_string()));
        }
        if s.starts_with('-') || s.starts_with('+') {
            return Some(Query::Raw(s.split_whitespace().map(String::from).collect()));
        }
        Some(Query::Path(s.to_string()))
    }

    pub fn args(&self) -> Vec<String> {
        let mut a = vec!["-nP".to_string()];
        match self {
            Query::Pid(p) => a.extend(["-p".into(), p.to_string()]),
            Query::Port(p) => a.extend(["-i".into(), p.clone()]),
            Query::Path(p) => a.push(p.clone()),
            Query::Raw(r) => a.extend(r.iter().cloned()),
        }
        a
    }

    pub fn label(&self) -> String {
        format!("lsof {}", self.args().join(" "))
    }
}

#[derive(Default)]
pub struct FilesStore {
    pub query: Option<Query>,
    pub entries: Vec<OpenFile>,
    pub loading: bool,
    pub error: Option<String>,
    pub took: Duration,
    pub version: u64,
    generation: u64,
}

pub fn spawn_query(store: Arc<Mutex<FilesStore>>, q: Query) {
    let gen = {
        let mut s = store.lock().unwrap();
        s.generation += 1;
        s.query = Some(q.clone());
        s.loading = true;
        s.error = None;
        s.version += 1;
        s.generation
    };
    thread::spawn(move || {
        let res = run(&q.args());
        let mut s = store.lock().unwrap();
        if s.generation != gen {
            return; // superseded by a newer query
        }
        s.loading = false;
        s.version += 1;
        match res {
            Ok((entries, took)) => {
                s.entries = entries;
                s.took = took;
            }
            Err(e) => {
                s.entries.clear();
                s.error = Some(e);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_network_and_files() {
        let out = "p123\ncnginx\nu0\nLroot\nf6\nau\ntIPv4\nPTCP\nn*:80\nTST=LISTEN\nf7\nau\ntIPv4\nPTCP\nn10.0.0.1:80->10.0.0.2:5555\nTST=ESTABLISHED\np9\ncbash\nLdev\nfcwd\ntDIR\ns4096\nn/home/dev\n";
        let v = parse(out);
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].user, "root");
        assert!(v[0].is_listening());
        assert_eq!(v[0].local_port(), Some(80));
        assert_eq!(v[1].endpoints().1, "10.0.0.2:5555");
        assert_eq!(v[2].command, "bash");
        assert_eq!(v[2].size, Some(4096));
    }

    #[test]
    fn query_parsing() {
        assert!(matches!(Query::parse("42"), Some(Query::Pid(42))));
        assert!(matches!(Query::parse(":443"), Some(Query::Port(_))));
        assert!(matches!(Query::parse("tcp:22"), Some(Query::Port(_))));
        assert!(matches!(Query::parse("/var/log"), Some(Query::Path(_))));
        assert!(matches!(Query::parse("-u root"), Some(Query::Raw(_))));
    }
}

#[cfg(test)]
mod raw_query_tests {
    use super::*;

    /// The example queries from docs/handbook.html must actually run.
    #[test]
    fn manual_queries_run() {
        for q in ["+L1", "-u root", "@127.0.0.1", "tcp:443", ":22"] {
            let parsed = Query::parse(q).unwrap();
            assert!(run(&parsed.args()).is_ok(), "query {q} failed: {:?}", parsed.args());
        }
    }
}
