//! Point-in-time system report as Markdown or JSON.
//!
//! `vigil report` samples the system for a short window and prints the report,
//! so it fits in cron jobs, CI steps, incident tickets and post-mortems:
//!
//! ```text
//! vigil report                      # Markdown to stdout
//! vigil report -f json -o snap.json # machine-readable
//! vigil report --fail-on-alert      # exit code 2 when a health threshold is crossed
//! ```
//!
//! Inside the TUI, `R` writes the same Markdown report to a file.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::app::compute_alerts;
use crate::collect::lsof::{OpenFile, SocketBackend, SocketScanner};
use crate::collect::system::{ProcInfo, Sampler};
use crate::config::Alerts;
use crate::util::{fmt_bytes, fmt_duration, fmt_rate};

#[derive(Serialize)]
pub struct Report {
    pub generated_utc: String,
    pub vigil_version: &'static str,
    pub host: Host,
    pub health: Vec<String>,
    pub cpu: Cpu,
    pub memory: Memory,
    pub psi: Option<Psi>,
    pub processes: Processes,
    pub network: Network,
    pub filesystems: Vec<Filesystem>,
    pub temperatures: Vec<Temperature>,
}

#[derive(Serialize)]
pub struct Host {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub cpu_model: String,
    pub physical_cores: usize,
    pub logical_cores: usize,
    pub uptime_seconds: u64,
}

#[derive(Serialize)]
pub struct Cpu {
    pub total_pct: f64,
    pub core_min_pct: f64,
    pub core_avg_pct: f64,
    pub core_max_pct: f64,
    pub busiest_core: usize,
    pub load: [f64; 3],
    pub load_per_core: f64,
}

#[derive(Serialize)]
pub struct Memory {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub used_pct: f64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub swap_used_pct: f64,
}

#[derive(Serialize)]
pub struct Psi {
    pub cpu_some_avg10: f64,
    pub memory_some_avg10: f64,
    pub io_some_avg10: f64,
}

#[derive(Serialize)]
pub struct Proc {
    pub pid: u32,
    pub user: String,
    pub name: String,
    pub cpu_pct: f32,
    pub rss_bytes: u64,
    pub sockets: usize,
    pub command: String,
}

#[derive(Serialize)]
pub struct Processes {
    pub total: usize,
    pub running: usize,
    pub zombies: usize,
    pub top_cpu: Vec<Proc>,
    pub top_memory: Vec<Proc>,
}

#[derive(Serialize)]
pub struct Listener {
    pub proto: String,
    pub address: String,
    pub port: Option<u16>,
    pub process: String,
    pub pid: u32,
    pub user: String,
    /// True when bound to every interface (`*`, `0.0.0.0`, `[::]`).
    pub exposed: bool,
}

#[derive(Serialize)]
pub struct Peer {
    pub host: String,
    pub connections: usize,
}

#[derive(Serialize)]
pub struct Interface {
    pub name: String,
    pub rx_bytes_per_s: f64,
    pub tx_bytes_per_s: f64,
    pub rx_total_bytes: u64,
    pub tx_total_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub addresses: Vec<String>,
}

#[derive(Serialize)]
pub struct Network {
    pub socket_source: &'static str,
    pub socket_error: Option<String>,
    pub states: BTreeMap<String, usize>,
    pub listening: Vec<Listener>,
    pub top_peers: Vec<Peer>,
    pub interfaces: Vec<Interface>,
}

#[derive(Serialize)]
pub struct Filesystem {
    pub mount: String,
    pub device: String,
    pub fs: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub used_pct: f64,
}

#[derive(Serialize)]
pub struct Temperature {
    pub sensor: String,
    pub celsius: f32,
    pub critical: Option<f32>,
}

// ───────────────────────────── building ─────────────────────────────

fn proc_row(p: &ProcInfo, conns: &BTreeMap<u32, usize>) -> Proc {
    Proc {
        pid: p.pid,
        user: p.user.to_string(),
        name: p.name.to_string(),
        cpu_pct: p.cpu,
        rss_bytes: p.mem,
        sockets: conns.get(&p.pid).copied().unwrap_or(0),
        command: p.cmd.to_string(),
    }
}

pub fn build(
    s: &Sampler,
    sockets: &[OpenFile],
    backend: SocketBackend,
    socket_error: Option<String>,
    alerts: &Alerts,
    top: usize,
) -> Report {
    let pct = |u: u64, t: u64| if t == 0 { 0.0 } else { u as f64 / t as f64 * 100.0 };

    // Socket-derived numbers.
    let mut states: BTreeMap<String, usize> = BTreeMap::new();
    let mut conns: BTreeMap<u32, usize> = BTreeMap::new();
    let mut peers: BTreeMap<String, usize> = BTreeMap::new();
    let mut listening: BTreeMap<(String, String), Listener> = BTreeMap::new();
    for e in sockets {
        let key = if e.state.is_empty() { e.proto.clone() } else { e.state.clone() };
        *states.entry(key).or_default() += 1;
        if e.pid != 0 {
            *conns.entry(e.pid).or_default() += 1;
        }
        let (local, remote) = e.endpoints();
        if !remote.is_empty() {
            let host = remote.rsplit_once(':').map(|(h, _)| h).unwrap_or(remote);
            *peers.entry(host.to_string()).or_default() += 1;
        }
        if e.is_listening() {
            let addr = local.rsplit_once(':').map(|(h, _)| h).unwrap_or(local).to_string();
            let exposed = matches!(addr.as_str(), "*" | "0.0.0.0" | "[::]");
            listening
                .entry((e.proto.clone(), local.to_string()))
                .or_insert(Listener {
                    proto: format!("{} {}", e.proto, e.ftype.trim_start_matches("IP")),
                    address: addr,
                    port: e.local_port(),
                    process: e.command.clone(),
                    pid: e.pid,
                    user: e.user.clone(),
                    exposed,
                });
        }
    }
    let close_wait = states.get("CLOSE_WAIT").copied().unwrap_or(0);
    let time_wait = states.get("TIME_WAIT").copied().unwrap_or(0);
    let mut listening: Vec<Listener> = listening.into_values().collect();
    listening.sort_by_key(|l| (l.port.unwrap_or(u16::MAX), l.proto.clone()));
    let mut top_peers: Vec<Peer> =
        peers.into_iter().map(|(host, connections)| Peer { host, connections }).collect();
    top_peers.sort_by_key(|p| std::cmp::Reverse(p.connections));
    top_peers.truncate(top);

    // CPU.
    let cores: Vec<f64> = s.cpu_cores.iter().map(|h| h.last()).collect();
    let (busiest_core, core_max) = cores
        .iter()
        .copied()
        .enumerate()
        .fold((0, 0.0), |acc, (i, v)| if v > acc.1 { (i, v) } else { acc });
    let core_min = cores.iter().copied().fold(f64::INFINITY, f64::min);
    let core_avg = cores.iter().sum::<f64>() / cores.len().max(1) as f64;

    // Processes.
    let mut by_cpu: Vec<&ProcInfo> = s.procs.iter().collect();
    by_cpu.sort_by(|a, b| b.cpu.total_cmp(&a.cpu));
    let mut by_mem: Vec<&ProcInfo> = s.procs.iter().collect();
    by_mem.sort_by_key(|p| std::cmp::Reverse(p.mem));

    let health = compute_alerts(s, alerts, close_wait, time_wait)
        .into_iter()
        .map(|(t, _)| t)
        .collect();

    Report {
        generated_utc: utc_timestamp(SystemTime::now()),
        vigil_version: env!("CARGO_PKG_VERSION"),
        host: Host {
            hostname: s.host.hostname.clone(),
            os: s.host.os.clone(),
            kernel: s.host.kernel.clone(),
            arch: s.host.arch.clone(),
            cpu_model: s.host.cpu_brand.clone(),
            physical_cores: s.host.physical_cores,
            logical_cores: s.ncores(),
            uptime_seconds: s.uptime,
        },
        health,
        cpu: Cpu {
            total_pct: s.cpu_total.last(),
            core_min_pct: if core_min.is_finite() { core_min } else { 0.0 },
            core_avg_pct: core_avg,
            core_max_pct: core_max,
            busiest_core,
            load: [s.load.0, s.load.1, s.load.2],
            load_per_core: s.load.0 / s.ncores().max(1) as f64,
        },
        memory: Memory {
            total_bytes: s.mem_total,
            used_bytes: s.mem_used,
            available_bytes: s.mem_avail,
            used_pct: pct(s.mem_used, s.mem_total),
            swap_total_bytes: s.swap_total,
            swap_used_bytes: s.swap_used,
            swap_used_pct: pct(s.swap_used, s.swap_total),
        },
        psi: s.psi.map(|p| Psi { cpu_some_avg10: p[0], memory_some_avg10: p[1], io_some_avg10: p[2] }),
        processes: Processes {
            total: s.procs.len(),
            running: s.procs.iter().filter(|p| p.status == "Running").count(),
            zombies: s.procs.iter().filter(|p| p.status == "Zombie").count(),
            top_cpu: by_cpu.iter().take(top).map(|p| proc_row(p, &conns)).collect(),
            top_memory: by_mem.iter().take(top).map(|p| proc_row(p, &conns)).collect(),
        },
        network: Network {
            socket_source: backend.label(),
            socket_error,
            states,
            listening,
            top_peers,
            interfaces: s
                .ifaces
                .iter()
                .filter(|i| i.rx_total + i.tx_total > 0)
                .map(|i| Interface {
                    name: i.name.clone(),
                    rx_bytes_per_s: i.rx_rate,
                    tx_bytes_per_s: i.tx_rate,
                    rx_total_bytes: i.rx_total,
                    tx_total_bytes: i.tx_total,
                    rx_errors: i.rx_errors,
                    tx_errors: i.tx_errors,
                    addresses: i.addrs.clone(),
                })
                .collect(),
        },
        filesystems: s
            .disks_info
            .iter()
            .filter(|d| d.total > 0)
            .map(|d| Filesystem {
                mount: d.mount.clone(),
                device: d.name.clone(),
                fs: d.fs.clone(),
                total_bytes: d.total,
                used_bytes: d.used(),
                used_pct: d.pct(),
            })
            .collect(),
        temperatures: s
            .temps
            .iter()
            .take(top)
            .map(|t| Temperature { sensor: t.label.clone(), celsius: t.temp, critical: t.critical })
            .collect(),
    }
}

// ───────────────────────────── rendering ─────────────────────────────

fn md_escape(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn short(s: &str, n: usize) -> String {
    crate::util::truncate(s, n)
}

pub fn to_markdown(r: &Report) -> String {
    let mut o = String::with_capacity(8 * 1024);
    let h = &r.host;
    let _ = writeln!(o, "# vigil report: {}\n", h.hostname);
    let _ = writeln!(o, "Generated {} · vigil {}\n", r.generated_utc, r.vigil_version);

    let _ = writeln!(o, "## Health\n");
    if r.health.is_empty() {
        let _ = writeln!(o, "**OK**: no thresholds exceeded.\n");
    } else {
        for a in &r.health {
            let _ = writeln!(o, "- **{a}**");
        }
        o.push('\n');
    }

    let _ = writeln!(o, "## System\n");
    let _ = writeln!(o, "| | |\n|---|---|");
    let _ = writeln!(o, "| Host | {} |", md_escape(&h.hostname));
    let _ = writeln!(o, "| OS | {} |", md_escape(&h.os));
    let _ = writeln!(o, "| Kernel | {} ({}) |", md_escape(&h.kernel), h.arch);
    let _ = writeln!(o, "| CPU | {} · {} cores / {} threads |", md_escape(&h.cpu_model), h.physical_cores, h.logical_cores);
    let _ = writeln!(o, "| Uptime | {} |\n", fmt_duration(h.uptime_seconds));

    let c = &r.cpu;
    let m = &r.memory;
    let _ = writeln!(o, "## Resources\n");
    let _ = writeln!(o, "| Metric | Value |\n|---|---|");
    let _ = writeln!(o, "| CPU total | {:.1} % |", c.total_pct);
    let _ = writeln!(
        o,
        "| Per core | min {:.0} % · avg {:.0} % · max {:.0} % (core {}) |",
        c.core_min_pct, c.core_avg_pct, c.core_max_pct, c.busiest_core
    );
    let _ = writeln!(o, "| Load 1/5/15 | {:.2} / {:.2} / {:.2} ({:.2} per core) |", c.load[0], c.load[1], c.load[2], c.load_per_core);
    let _ = writeln!(
        o,
        "| Memory | {} / {} ({:.0} %), {} available |",
        fmt_bytes(m.used_bytes),
        fmt_bytes(m.total_bytes),
        m.used_pct,
        fmt_bytes(m.available_bytes)
    );
    let _ = writeln!(o, "| Swap | {} / {} ({:.0} %) |", fmt_bytes(m.swap_used_bytes), fmt_bytes(m.swap_total_bytes), m.swap_used_pct);
    if let Some(p) = &r.psi {
        let _ = writeln!(
            o,
            "| PSI some avg10 | cpu {:.1} % · memory {:.1} % · io {:.1} % |",
            p.cpu_some_avg10, p.memory_some_avg10, p.io_some_avg10
        );
    }
    let _ = writeln!(
        o,
        "| Processes | {} total · {} running · {} zombie |\n",
        r.processes.total, r.processes.running, r.processes.zombies
    );

    for (title, list) in [("Top processes by CPU", &r.processes.top_cpu), ("Top processes by memory", &r.processes.top_memory)] {
        let _ = writeln!(o, "## {title}\n");
        let _ = writeln!(o, "| PID | User | CPU % | RSS | Sockets | Command |\n|---:|---|---:|---:|---:|---|");
        for p in list {
            let cmd = if p.command.is_empty() { p.name.clone() } else { p.command.clone() };
            let _ = writeln!(
                o,
                "| {} | {} | {:.1} | {} | {} | `{}` |",
                p.pid,
                md_escape(&p.user),
                p.cpu_pct,
                fmt_bytes(p.rss_bytes),
                p.sockets,
                md_escape(&short(&cmd, 90)).replace('`', "'")
            );
        }
        o.push('\n');
    }

    let n = &r.network;
    let _ = writeln!(o, "## Listening ports\n");
    if let Some(e) = &n.socket_error {
        let _ = writeln!(o, "_Socket scan failed: {}_\n", md_escape(e));
    }
    let _ = writeln!(o, "Source: `{}`. Exposed means bound to every interface.\n", n.socket_source);
    let _ = writeln!(o, "| Port | Proto | Address | Process | PID | User | Exposed |\n|---:|---|---|---|---:|---|---|");
    for l in &n.listening {
        let _ = writeln!(
            o,
            "| {} | {} | {} | {} | {} | {} | {} |",
            l.port.map(|p| p.to_string()).unwrap_or_default(),
            l.proto,
            md_escape(&l.address),
            md_escape(&l.process),
            l.pid,
            md_escape(&l.user),
            if l.exposed { "**yes**" } else { "no" }
        );
    }
    o.push('\n');

    let _ = writeln!(o, "## Connections\n");
    let _ = writeln!(o, "| State | Count |\n|---|---:|");
    let mut st: Vec<_> = n.states.iter().collect();
    st.sort_by_key(|(_, c)| std::cmp::Reverse(**c));
    for (k, v) in st {
        let _ = writeln!(o, "| {k} | {v} |");
    }
    o.push('\n');
    if !n.top_peers.is_empty() {
        let _ = writeln!(o, "### Top remote peers\n");
        let _ = writeln!(o, "| Host | Connections |\n|---|---:|");
        for p in &n.top_peers {
            let _ = writeln!(o, "| {} | {} |", md_escape(&p.host), p.connections);
        }
        o.push('\n');
    }

    let _ = writeln!(o, "## Interfaces\n");
    let _ = writeln!(o, "| Interface | RX/s | TX/s | RX total | TX total | Errors RX/TX | Addresses |\n|---|---:|---:|---:|---:|---:|---|");
    for i in &n.interfaces {
        let _ = writeln!(
            o,
            "| {} | {} | {} | {} | {} | {}/{} | {} |",
            i.name,
            fmt_rate(i.rx_bytes_per_s),
            fmt_rate(i.tx_bytes_per_s),
            fmt_bytes(i.rx_total_bytes),
            fmt_bytes(i.tx_total_bytes),
            i.rx_errors,
            i.tx_errors,
            i.addresses.join(", ")
        );
    }
    o.push('\n');

    let _ = writeln!(o, "## Filesystems\n");
    let _ = writeln!(o, "| Mount | Device | FS | Size | Used | Use % |\n|---|---|---|---:|---:|---:|");
    for f in &r.filesystems {
        let _ = writeln!(
            o,
            "| {} | {} | {} | {} | {} | {:.0} % |",
            md_escape(&f.mount),
            md_escape(&f.device),
            f.fs,
            fmt_bytes(f.total_bytes),
            fmt_bytes(f.used_bytes),
            f.used_pct
        );
    }
    o.push('\n');

    if !r.temperatures.is_empty() {
        let _ = writeln!(o, "## Temperatures\n");
        let _ = writeln!(o, "| Sensor | °C | Critical |\n|---|---:|---:|");
        for t in &r.temperatures {
            let _ = writeln!(
                o,
                "| {} | {:.1} | {} |",
                md_escape(&t.sensor),
                t.celsius,
                t.critical.map(|c| format!("{c:.0}")).unwrap_or_else(|| "-".into())
            );
        }
        o.push('\n');
    }
    o
}

pub fn to_json(r: &Report) -> String {
    serde_json::to_string_pretty(r).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

// ───────────────────────────── entry points ─────────────────────────────

pub struct Options {
    pub json: bool,
    pub output: Option<PathBuf>,
    pub top: usize,
    pub sample: Duration,
    pub fail_on_alert: bool,
    pub force_lsof: bool,
}

/// `vigil report`: sample, build, print or write. Returns the process exit code.
pub fn run_cli(opts: Options, alerts: &Alerts) -> std::io::Result<i32> {
    let mut sampler = Sampler::new();
    let (res, backend) = SocketScanner::new(opts.force_lsof).scan();
    std::thread::sleep(opts.sample);
    sampler.refresh();
    let (sockets, err) = match res {
        Ok((e, _)) => (e, None),
        Err(e) => (Vec::new(), Some(e)),
    };
    let report = build(&sampler, &sockets, backend, err, alerts, opts.top);
    let text = if opts.json { to_json(&report) } else { to_markdown(&report) };
    match &opts.output {
        Some(p) => std::fs::write(p, &text)?,
        None => print!("{text}"),
    }
    Ok(if opts.fail_on_alert && !report.health.is_empty() { 2 } else { 0 })
}

/// Write a Markdown report from the TUI's live data. Tries the current
/// directory first, then $HOME. Returns the path written.
pub fn write_from_tui(
    s: &Sampler,
    sockets: &[OpenFile],
    backend: SocketBackend,
    alerts: &Alerts,
) -> Result<PathBuf, String> {
    let report = build(s, sockets, backend, None, alerts, 15);
    let text = to_markdown(&report);
    let name = format!("vigil-report-{}.md", file_stamp(SystemTime::now()));
    let mut dirs: Vec<PathBuf> = vec![PathBuf::from(".")];
    if let Some(h) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(h));
    }
    let mut last_err = String::from("no writable directory");
    for d in dirs {
        let p = d.join(&name);
        match std::fs::write(&p, &text) {
            Ok(()) => return Ok(std::fs::canonicalize(&p).unwrap_or(p)),
            Err(e) => last_err = format!("{}: {e}", Path::new(&d).display()),
        }
    }
    Err(last_err)
}

// ───────────────────────────── time helpers ─────────────────────────────

/// (year, month, day, hour, minute, second) in UTC, without a date crate.
fn civil(t: SystemTime) -> (i64, u32, u32, u32, u32, u32) {
    let secs = t.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400) as u32;
    // Howard Hinnant's days-to-civil algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, sod / 3600, (sod % 3600) / 60, sod % 60)
}

pub fn utc_timestamp(t: SystemTime) -> String {
    let (y, mo, d, h, mi, s) = civil(t);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC")
}

fn file_stamp(t: SystemTime) -> String {
    let (y, mo, d, h, mi, s) = civil(t);
    format!("{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates() {
        let at = |s: u64| utc_timestamp(UNIX_EPOCH + Duration::from_secs(s));
        assert_eq!(at(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(at(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(at(1_798_675_199), "2026-12-30 23:59:59 UTC");
    }

    #[test]
    fn report_builds_and_renders() {
        let mut s = Sampler::new();
        std::thread::sleep(Duration::from_millis(300));
        s.refresh();
        let socks = crate::collect::lsof::parse(
            "p1\ncnginx\nLroot\nf6\ntIPv4\nPTCP\nn*:80\nTST=LISTEN\nf7\ntIPv4\nPTCP\nn10.0.0.1:80->10.0.0.9:5000\nTST=CLOSE_WAIT\n",
        );
        let r = build(&s, &socks, SocketBackend::Lsof, None, &Alerts::default(), 5);
        assert_eq!(r.network.listening.len(), 1);
        assert!(r.network.listening[0].exposed);
        assert_eq!(r.network.states.get("CLOSE_WAIT"), Some(&1));
        let md = to_markdown(&r);
        assert!(md.contains("## Listening ports"));
        let js = to_json(&r);
        let v: serde_json::Value = serde_json::from_str(&js).unwrap();
        assert_eq!(v["network"]["listening"][0]["port"], 80);
    }
}
