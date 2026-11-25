//! Who is on this machine: logged-in sessions (like `w`), plus SSH login
//! attempts from the last hour: failed attempts grouped by source address and
//! the most recent accepted logins (Linux, from the journal of sshd).
//!
//! Polled every 10 s while the Users view is open, every 60 s otherwise.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::HashMap;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Session {
    pub user: String,
    pub tty: String,
    pub from: String,
    pub login: String,
    pub idle: String,
    pub what: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct FailedSource {
    pub ip: String,
    pub attempts: u32,
    /// Distinct user names tried, most recent first (max 5).
    pub users: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Accepted {
    pub user: String,
    pub ip: String,
    pub method: String,
}

#[derive(Default)]
pub struct SessionStore {
    pub sessions: Vec<Session>,
    pub failed: Vec<FailedSource>,
    pub failed_total: u32,
    pub accepted: Vec<Accepted>,
    /// Why SSH history is unavailable (no journal, no permission, macOS).
    pub ssh_note: Option<String>,
    pub version: u64,
}

/// `w -h` (macOS: user tty from login@ idle what) or
/// `w -h -s -i` (Linux: user tty from idle what).
pub fn parse_w(text: &str, linux_short: bool) -> Vec<Session> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let min = if linux_short { 4 } else { 5 };
            if f.len() < min {
                return None;
            }
            let (login, idle, rest) = if linux_short { ("", f[3], 4) } else { (f[3], f[4], 5) };
            Some(Session {
                user: f[0].to_string(),
                tty: f[1].to_string(),
                from: if f[2] == "-" { String::new() } else { f[2].to_string() },
                login: login.to_string(),
                idle: if idle == "-" { String::new() } else { idle.to_string() },
                what: f.get(rest..).map(|w| w.join(" ")).unwrap_or_default(),
            })
        })
        .collect()
}

fn word_after<'a>(l: &'a str, marker: &str) -> Option<&'a str> {
    l.split_once(marker)?.1.split_whitespace().next()
}

/// Parse sshd journal lines (`journalctl _COMM=sshd -o cat`).
pub fn parse_sshd(text: &str) -> (Vec<FailedSource>, u32, Vec<Accepted>) {
    let mut failed: HashMap<String, FailedSource> = HashMap::new();
    let mut total = 0;
    let mut accepted = Vec::new();
    for l in text.lines() {
        if let Some(rest) = l.strip_prefix("Accepted ") {
            // Accepted publickey for deploy from 10.0.0.5 port 51234 ssh2: …
            let method = rest.split_whitespace().next().unwrap_or("").to_string();
            if let (Some(user), Some(ip)) = (word_after(l, " for "), word_after(l, " from ")) {
                accepted.push(Accepted { user: user.to_string(), ip: ip.to_string(), method });
            }
            continue;
        }
        let failed_line = l.starts_with("Failed ") || l.starts_with("Invalid user ");
        if !failed_line {
            continue;
        }
        // "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
        // "Failed password for root from 1.2.3.4 port 22 ssh2"
        // "Invalid user test from 1.2.3.4 port 1234"
        let Some(ip) = word_after(l, " from ") else { continue };
        let user = word_after(l, "invalid user ")
            .or_else(|| word_after(l, "Invalid user "))
            .or_else(|| word_after(l, " for "))
            .unwrap_or("?");
        // An "Invalid user" line is followed by its own "Failed password"; count attempts once.
        if l.starts_with("Invalid user ") {
            let e = failed.entry(ip.to_string()).or_insert_with(|| FailedSource { ip: ip.to_string(), ..Default::default() });
            if !e.users.iter().any(|u| u == user) {
                e.users.insert(0, user.to_string());
                e.users.truncate(5);
            }
            continue;
        }
        total += 1;
        let e = failed.entry(ip.to_string()).or_insert_with(|| FailedSource { ip: ip.to_string(), ..Default::default() });
        e.attempts += 1;
        if !e.users.iter().any(|u| u == user) {
            e.users.insert(0, user.to_string());
            e.users.truncate(5);
        }
    }
    let mut v: Vec<FailedSource> = failed.into_values().filter(|f| f.attempts > 0).collect();
    v.sort_by(|a, b| b.attempts.cmp(&a.attempts).then(a.ip.cmp(&b.ip)));
    accepted.reverse(); // newest first
    accepted.truncate(20);
    (v, total, accepted)
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let o = Command::new(cmd).args(args).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

fn collect() -> SessionStore {
    let linux = cfg!(target_os = "linux");
    let sessions = if linux {
        run("w", &["-h", "-s", "-i"]).map(|t| parse_w(&t, true)).unwrap_or_default()
    } else {
        run("w", &["-h"]).map(|t| parse_w(&t, false)).unwrap_or_default()
    };
    let mut st = SessionStore { sessions, ..Default::default() };
    if linux {
        match run("journalctl", &["_COMM=sshd", "--since", "-1h", "-o", "cat", "-q", "--no-pager"]) {
            Some(t) => {
                let (failed, total, accepted) = parse_sshd(&t);
                st.failed = failed;
                st.failed_total = total;
                st.accepted = accepted;
                if t.trim().is_empty() {
                    st.ssh_note = Some("no sshd entries in the last hour (run as root to read the journal)".into());
                }
            }
            None => st.ssh_note = Some("journalctl not available: SSH history needs systemd's journal".into()),
        }
    } else {
        st.ssh_note = Some("SSH login history: Linux only".into());
    }
    st
}

pub fn spawn_worker(store: Arc<Mutex<SessionStore>>, active: Arc<AtomicBool>) {
    thread::spawn(move || {
        let mut last: Option<Instant> = None;
        loop {
            let iv = if active.load(Ordering::Relaxed) { 10 } else { 60 };
            if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(iv)) {
                let fresh = collect();
                if let Ok(mut s) = store.lock() {
                    let v = s.version + 1;
                    *s = fresh;
                    s.version = v;
                }
                last = Some(Instant::now());
            }
            thread::sleep(Duration::from_millis(250));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn w_output() {
        let mac = "suleymen   console  -       9:05    4:58 -\nsuleymen   s001     -      13:56       - vigil -t procs\n";
        let s = parse_w(mac, false);
        assert_eq!(s.len(), 2);
        assert_eq!(s[1].what, "vigil -t procs");
        assert_eq!(s[1].idle, "");
        let linux = "deploy   pts/0    10.0.0.5          2.00s -bash\nroot     pts/1    203.0.113.7       0.00s vigil\n";
        let s = parse_w(linux, true);
        assert_eq!(s[0].from, "10.0.0.5");
        assert_eq!(s[1].what, "vigil");
    }

    #[test]
    fn sshd_journal() {
        let t = "Invalid user admin from 203.0.113.7 port 50122\n\
Failed password for invalid user admin from 203.0.113.7 port 50122 ssh2\n\
Failed password for root from 203.0.113.7 port 50124 ssh2\n\
Failed password for root from 198.51.100.4 port 40000 ssh2\n\
Accepted publickey for deploy from 10.0.0.5 port 51234 ssh2: ED25519 SHA256:abc\n\
Connection closed by authenticating user root 198.51.100.4 port 40001 [preauth]\n";
        let (failed, total, acc) = parse_sshd(t);
        assert_eq!(total, 3);
        assert_eq!(failed[0].ip, "203.0.113.7");
        assert_eq!(failed[0].attempts, 2);
        assert_eq!(failed[0].users, vec!["root".to_string(), "admin".to_string()]);
        assert_eq!(acc[0], Accepted { user: "deploy".into(), ip: "10.0.0.5".into(), method: "publickey".into() });
    }
}
