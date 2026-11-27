//! Services: systemd units (Linux) or launchd jobs (macOS), with failed units
//! and restart loops first, plus the journal of the selected unit.
//!
//! Linux: `systemctl list-units` + one batched `systemctl show` for restart
//! counts, main pid and memory; `journalctl -u <unit>` on demand.
//! macOS: `launchctl list` (pid and last exit status).
//! Windows: `sc queryex` (state, pid, exit code); Service Control Manager
//! events from the System log instead of a journal.
//! Polled every 5 s while the System view is open, every 60 s otherwise.

use std::collections::HashMap;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default)]
pub struct Unit {
    pub name: String,
    pub active: String,
    pub sub: String,
    pub description: String,
    pub restarts: u64,
    pub main_pid: u32,
    pub memory: Option<u64>,
    /// macOS launchd: last exit status.
    pub exit_status: Option<i64>,
}

impl Unit {
    pub fn failed(&self) -> bool {
        self.active == "failed" || self.exit_status.is_some_and(|s| s != 0 && s != -15 && s != -9)
    }
}

#[derive(Default)]
pub struct ServiceStore {
    pub units: Vec<Unit>,
    pub manager: &'static str,
    pub error: Option<String>,
    pub journal_unit: Option<String>,
    pub journal: Vec<String>,
    pub journal_loading: bool,
    pub version: u64,
}

/// `systemctl list-units --type=service --all --plain --no-legend --no-pager`.
pub fn parse_list_units(text: &str) -> Vec<Unit> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim_start_matches(['●', '*', ' ']);
            let mut it = l.split_whitespace();
            let name = it.next()?.to_string();
            if !name.ends_with(".service") {
                return None;
            }
            let _load = it.next()?;
            Some(Unit {
                name,
                active: it.next()?.to_string(),
                sub: it.next()?.to_string(),
                description: it.collect::<Vec<_>>().join(" "),
                ..Default::default()
            })
        })
        .collect()
}

/// Batched `systemctl show -p Id,NRestarts,MainPID,MemoryCurrent a b c`.
pub fn parse_show(text: &str) -> HashMap<String, (u64, u32, Option<u64>)> {
    let mut out = HashMap::new();
    for block in text.split("\n\n") {
        let mut id = None;
        let (mut r, mut pid, mut mem) = (0, 0, None);
        for l in block.lines() {
            match l.split_once('=') {
                Some(("Id", v)) => id = Some(v.to_string()),
                Some(("NRestarts", v)) => r = v.parse().unwrap_or(0),
                Some(("MainPID", v)) => pid = v.parse().unwrap_or(0),
                Some(("MemoryCurrent", v)) => mem = v.parse().ok().filter(|m: &u64| *m < u64::MAX / 2),
                _ => {}
            }
        }
        if let Some(id) = id {
            out.insert(id, (r, pid, mem));
        }
    }
    out
}

/// `launchctl list`: `PID\tStatus\tLabel`.
pub fn parse_launchctl(text: &str) -> Vec<Unit> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let mut it = l.split('\t');
            let pid = it.next()?.trim();
            let status: i64 = it.next()?.trim().parse().unwrap_or(0);
            let label = it.next()?.trim().to_string();
            let running = pid != "-";
            Some(Unit {
                name: label,
                active: if running { "active".into() } else { "inactive".into() },
                sub: if running { "running".into() } else { "exited".into() },
                main_pid: pid.parse().unwrap_or(0),
                exit_status: Some(status),
                ..Default::default()
            })
        })
        .collect()
}

fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let o = Command::new(cmd).args(args).output().map_err(|e| format!("{cmd}: {e}"))?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&o.stderr).lines().next().unwrap_or("failed").to_string())
    }
}

fn collect() -> (Result<Vec<Unit>, String>, &'static str) {
    if cfg!(target_os = "macos") {
        return (run("launchctl", &["list"]).map(|t| parse_launchctl(&t)), "launchd");
    }
    if cfg!(windows) {
        return (run("sc", &["queryex", "type=", "service", "state=", "all"]).map(|t| super::windows::parse_sc_query(&t)), "scm");
    }
    let mut units = match run("systemctl", &["list-units", "--type=service", "--all", "--plain", "--no-legend", "--no-pager"]) {
        Ok(t) => parse_list_units(&t),
        Err(e) => return (Err(format!("systemd not available: {e}")), "systemd"),
    };
    let names: Vec<&str> = units.iter().map(|u| u.name.as_str()).collect();
    let mut args = vec!["show", "-p", "Id,NRestarts,MainPID,MemoryCurrent"];
    args.extend(names.iter().copied());
    if let Ok(t) = run("systemctl", &args) {
        let m = parse_show(&t);
        for u in &mut units {
            if let Some((r, pid, mem)) = m.get(&u.name) {
                u.restarts = *r;
                u.main_pid = *pid;
                u.memory = *mem;
            }
        }
    }
    (Ok(units), "systemd")
}

/// One synchronous collection (used by `vigil report`).
pub fn collect_once() -> Vec<Unit> {
    let mut u = collect().0.unwrap_or_default();
    sort_units(&mut u);
    u
}

/// Failed first, then restart loops, then running, then the rest by name.
pub fn sort_units(units: &mut [Unit]) {
    units.sort_by_key(|u| (!u.failed(), std::cmp::Reverse(u.restarts), u.active != "active", u.name.clone()));
}

pub fn spawn_worker(store: Arc<Mutex<ServiceStore>>, active: Arc<AtomicBool>) {
    crate::util::spawn_named("services", move || {
        let mut last: Option<Instant> = None;
        loop {
            let iv = if active.load(Ordering::Relaxed) { 5 } else { 60 };
            if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(iv)) {
                let (res, manager) = collect();
                if let Ok(mut s) = store.lock() {
                    s.manager = manager;
                    match res {
                        Ok(mut u) => {
                            sort_units(&mut u);
                            s.units = u;
                            s.error = None;
                        }
                        Err(e) => s.error = Some(e),
                    }
                    s.version += 1;
                }
                last = Some(Instant::now());
            }
            thread::sleep(Duration::from_millis(250));
        }
    });
}

/// Fetch the last log lines of a unit in the background.
pub fn load_journal(store: Arc<Mutex<ServiceStore>>, unit: String) {
    if let Ok(mut s) = store.lock() {
        if s.journal_unit.as_deref() == Some(&unit) && (s.journal_loading || !s.journal.is_empty()) {
            return;
        }
        s.journal_unit = Some(unit.clone());
        s.journal.clear();
        s.journal_loading = true;
        s.version += 1;
    }
    crate::util::spawn_named("journal", move || {
        let lines = if cfg!(target_os = "macos") {
            vec!["journal: Linux only (macOS keeps logs in the unified log: `log show`)".to_string()]
        } else if cfg!(windows) {
            super::windows::service_events(&unit)
        } else {
            match run("journalctl", &["-u", &unit, "-n", "200", "--no-pager", "-o", "short-iso", "-q"]) {
                Ok(t) if !t.trim().is_empty() => t.lines().map(String::from).collect(),
                Ok(_) => vec!["no journal entries (run with sudo to read other units' logs)".to_string()],
                Err(e) => vec![format!("journalctl: {e}")],
            }
        };
        if let Ok(mut s) = store.lock() {
            if s.journal_unit.as_deref() == Some(&unit) {
                s.journal = lines;
                s.journal_loading = false;
                s.version += 1;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_parsers() {
        let lu = "  nginx.service   loaded active running A high performance web server\n● app.service loaded failed failed My App\n  dbus.socket loaded active running D-Bus Socket\n";
        let mut u = parse_list_units(lu);
        assert_eq!(u.len(), 2);
        assert_eq!(u[1].active, "failed");
        let show = "Id=nginx.service\nNRestarts=0\nMainPID=812\nMemoryCurrent=12345678\n\nId=app.service\nNRestarts=17\nMainPID=0\nMemoryCurrent=[not set]\n";
        let m = parse_show(show);
        assert_eq!(m["app.service"].0, 17);
        assert_eq!(m["nginx.service"].2, Some(12345678));
        u[0].restarts = 0;
        sort_units(&mut u);
        assert_eq!(u[0].name, "app.service");
    }

    #[test]
    fn launchctl_parser() {
        let t = "PID\tStatus\tLabel\n412\t0\tcom.apple.Finder\n-\t78\tcom.example.broken\n-\t0\tcom.example.idle\n";
        let u = parse_launchctl(t);
        assert_eq!(u.len(), 3);
        assert!(u[1].failed());
        assert!(!u[2].failed());
        assert_eq!(u[0].main_pid, 412);
    }
}
