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
//! The Markdown is written for humans first: an overall status, a summary
//! table, numbered findings with a recommended action each, then the detail.
//! Inside the TUI, `R` writes the same report to a file.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::app::compute_alerts;
use crate::collect::ipinfo;
use crate::collect::lsof::{OpenFile, SocketBackend, SocketScanner};
use crate::collect::system::{ProcInfo, Sampler};
use crate::config::Alerts;
use crate::theme;
use crate::util::{fmt_bytes, fmt_duration, fmt_rate};

// ───────────────────────────── inputs ─────────────────────────────

/// Data from collectors outside the sampler. The TUI fills it from its live
/// stores; `vigil report` collects it once.
#[derive(Default)]
pub struct Inputs {
    pub health: crate::app::ExtraHealth,
    pub limits: Option<crate::collect::limits::Limits>,
    pub containers: Vec<crate::collect::containers::Container>,
    pub units: Vec<crate::collect::services::Unit>,
    pub events: Vec<crate::collect::kmsg::KEvent>,
}

// ───────────────────────────── data model ─────────────────────────────

#[derive(Serialize)]
pub struct Report {
    pub generated_utc: String,
    pub vigil_version: &'static str,
    /// "healthy", "warning" or "critical".
    pub status: &'static str,
    pub host: Host,
    /// Header badge texts, exactly as the TUI shows them.
    pub health: Vec<String>,
    pub findings: Vec<Finding>,
    pub cpu: Cpu,
    pub memory: Memory,
    pub psi: Option<Psi>,
    pub processes: Processes,
    pub network: Network,
    pub filesystems: Vec<Filesystem>,
    pub devices: Vec<Device>,
    pub limits: LimitsR,
    pub containers: Vec<ContainerR>,
    pub services: Vec<ServiceR>,
    pub kernel_events: Vec<EventR>,
    pub temperatures: Vec<Temperature>,
    /// Set by `vigil report --diff <earlier.json>`.
    pub changes: Option<Changes>,
}

/// What changed compared with an earlier JSON report.
#[derive(Serialize, Default, Debug)]
pub struct Changes {
    pub since_utc: String,
    pub new_findings: Vec<String>,
    pub resolved_findings: Vec<String>,
    pub ports_opened: Vec<String>,
    pub ports_closed: Vec<String>,
    pub services_failed: Vec<String>,
    pub services_recovered: Vec<String>,
    pub containers_started: Vec<String>,
    pub containers_gone: Vec<String>,
    /// (metric, before, after) for numbers that moved noticeably.
    pub metrics: Vec<(String, String, String)>,
    pub new_kernel_events: Vec<String>,
}

impl Changes {
    pub fn is_empty(&self) -> bool {
        self.new_findings.is_empty()
            && self.resolved_findings.is_empty()
            && self.ports_opened.is_empty()
            && self.ports_closed.is_empty()
            && self.services_failed.is_empty()
            && self.services_recovered.is_empty()
            && self.containers_started.is_empty()
            && self.containers_gone.is_empty()
            && self.metrics.is_empty()
            && self.new_kernel_events.is_empty()
    }
}

fn strings(v: &serde_json::Value, path: &str, f: impl Fn(&serde_json::Value) -> Option<String>) -> Vec<String> {
    v.pointer(path).and_then(|a| a.as_array()).map(|a| a.iter().filter_map(f).collect()).unwrap_or_default()
}

fn listener_key(l: &serde_json::Value) -> Option<String> {
    Some(format!(
        "{} {}:{} ({})",
        l.get("proto")?.as_str()?,
        l.get("address")?.as_str()?,
        l.get("port").and_then(|p| p.as_u64()).map(|p| p.to_string()).unwrap_or_default(),
        l.get("process").and_then(|p| p.as_str()).unwrap_or("?")
    ))
}

/// Compare the current report with an earlier one (as JSON).
pub fn diff(prev: &serde_json::Value, cur: &Report) -> Changes {
    let cur_v = serde_json::to_value(cur).unwrap_or_default();
    let added = |a: &[String], b: &[String]| b.iter().filter(|x| !a.contains(x)).cloned().collect::<Vec<_>>();
    let mut c = Changes { since_utc: prev.get("generated_utc").and_then(|v| v.as_str()).unwrap_or("?").to_string(), ..Default::default() };

    let title = |f: &serde_json::Value| f.get("title").and_then(|t| t.as_str()).map(str::to_string);
    let (pf, cf) = (strings(prev, "/findings", title), strings(&cur_v, "/findings", title));
    c.new_findings = added(&pf, &cf);
    c.resolved_findings = added(&cf, &pf);

    let (pl, cl) = (strings(prev, "/network/listening", listener_key), strings(&cur_v, "/network/listening", listener_key));
    c.ports_opened = added(&pl, &cl);
    c.ports_closed = added(&cl, &pl);

    let failed = |u: &serde_json::Value| {
        let st = u.get("state")?.as_str()?;
        st.starts_with("failed").then(|| u.get("name")?.as_str().map(str::to_string))?
    };
    let (ps, cs) = (strings(prev, "/services", failed), strings(&cur_v, "/services", failed));
    c.services_failed = added(&ps, &cs);
    c.services_recovered = added(&cs, &ps);

    let name = |x: &serde_json::Value| x.get("name").and_then(|n| n.as_str()).map(str::to_string);
    let (pc, cc) = (strings(prev, "/containers", name), strings(&cur_v, "/containers", name));
    c.containers_started = added(&pc, &cc);
    c.containers_gone = added(&cc, &pc);

    let num = |v: &serde_json::Value, p: &str| v.pointer(p).and_then(|x| x.as_f64());
    let mut metric = |label: &str, p: &str, min_delta: f64, unit: &str| {
        if let (Some(a), Some(b)) = (num(prev, p), num(&cur_v, p)) {
            if (b - a).abs() >= min_delta {
                c.metrics.push((label.to_string(), format!("{a:.1}{unit}"), format!("{b:.1}{unit}")));
            }
        }
    };
    metric("Memory used", "/memory/used_pct", 5.0, " %");
    metric("Swap used", "/memory/swap_used_pct", 5.0, " %");
    metric("Load per core", "/cpu/load_per_core", 0.25, "");
    metric("Processes", "/processes/total", 25.0, "");
    metric("Established connections", "/network/states/ESTABLISHED", 50.0, "");
    metric("TIME_WAIT", "/network/states/TIME_WAIT", 500.0, "");
    metric("CLOSE_WAIT", "/network/states/CLOSE_WAIT", 10.0, "");
    // Disks: compare per mount.
    let mounts = |v: &serde_json::Value| -> Vec<(String, f64)> {
        v.get("filesystems")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|f| Some((f.get("mount")?.as_str()?.to_string(), f.get("used_pct")?.as_f64()?)))
                    .collect()
            })
            .unwrap_or_default()
    };
    let before = mounts(prev);
    for (m, b) in mounts(&cur_v) {
        if let Some((_, a)) = before.iter().find(|(pm, _)| *pm == m) {
            if (b - a).abs() >= 2.0 {
                c.metrics.push((format!("Disk {m}"), format!("{a:.1} %"), format!("{b:.1} %")));
            }
        }
    }
    c.new_kernel_events = cur
        .kernel_events
        .iter()
        .filter(|e| e.when_utc.as_str() > c.since_utc.as_str())
        .map(|e| format!("{} {}: {}", e.when_utc, e.kind, e.message))
        .collect();
    c
}

fn changes_markdown(c: &Changes, o: &mut String) {
    let _ = writeln!(o, "## Changes since {}\n", c.since_utc);
    if c.is_empty() {
        let _ = writeln!(o, "No significant changes.\n");
        return;
    }
    let list = |o: &mut String, title: &str, items: &[String], mark: &str| {
        if !items.is_empty() {
            let _ = writeln!(o, "**{title}**\n");
            for i in items {
                let _ = writeln!(o, "- {mark} {}", md(i));
            }
            o.push('\n');
        }
    };
    list(o, "New findings", &c.new_findings, "🔴");
    list(o, "Resolved findings", &c.resolved_findings, "🟢");
    list(o, "Ports now listening", &c.ports_opened, "➕");
    list(o, "Ports no longer listening", &c.ports_closed, "➖");
    list(o, "Services that failed", &c.services_failed, "🔴");
    list(o, "Services that recovered", &c.services_recovered, "🟢");
    list(o, "Containers started", &c.containers_started, "➕");
    list(o, "Containers gone", &c.containers_gone, "➖");
    if !c.metrics.is_empty() {
        let _ = writeln!(o, "| Metric | Before | Now |\n|---|---:|---:|");
        for (m, a, b) in &c.metrics {
            let _ = writeln!(o, "| {m} | {a} | {b} |");
        }
        o.push('\n');
    }
    list(o, "New kernel events", &c.new_kernel_events, "⚠️");
}

#[derive(Serialize)]
pub struct Device {
    pub name: String,
    pub reads_per_s: f64,
    pub writes_per_s: f64,
    pub read_bytes_per_s: f64,
    pub write_bytes_per_s: f64,
    pub await_ms: f64,
    pub util_pct: f64,
    pub queue: f64,
}

#[derive(Serialize, Default)]
pub struct LimitsR {
    /// Processes closest to their open-file limit.
    pub fd_top: Vec<FdUse>,
    pub system_files: Option<(u64, u64)>,
    pub ephemeral_range: Option<(u16, u16)>,
    pub ephemeral_used_pct: Option<f64>,
}

#[derive(Serialize)]
pub struct FdUse {
    pub pid: u32,
    pub name: String,
    pub open: u32,
    pub limit: Option<u64>,
    pub pct: Option<f64>,
}

#[derive(Serialize)]
pub struct ContainerR {
    pub name: String,
    pub runtime: &'static str,
    pub cpu_pct: f64,
    pub cpu_limit: Option<f64>,
    pub throttled_pct: f64,
    pub memory_bytes: u64,
    pub memory_limit: Option<u64>,
    pub oom_kills: u64,
    pub pids: u64,
}

#[derive(Serialize)]
pub struct ServiceR {
    pub name: String,
    pub state: String,
    pub restarts: u64,
    pub description: String,
}

#[derive(Serialize)]
pub struct EventR {
    pub when_utc: String,
    pub kind: &'static str,
    pub message: String,
}

#[derive(Serialize)]
pub struct Finding {
    /// "critical", "warning" or "info".
    pub severity: &'static str,
    pub area: &'static str,
    pub title: String,
    pub detail: String,
    pub action: String,
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
    pub service: Option<&'static str>,
    pub process: String,
    pub pid: u32,
    pub user: String,
    /// True when bound to every interface (`*`, `0.0.0.0`, `[::]`).
    pub exposed: bool,
}

#[derive(Serialize)]
pub struct Peer {
    pub host: String,
    pub scope: &'static str,
    pub connections: usize,
}

#[derive(Serialize, Clone)]
pub struct Connection {
    pub local: String,
    pub remote: String,
    pub state: String,
    pub process: String,
    pub pid: u32,
    pub rtt_ms: f64,
    pub retransmits: u32,
    pub rx_bytes_per_s: f64,
    pub tx_bytes_per_s: f64,
}

#[derive(Serialize)]
pub struct Interface {
    pub name: String,
    pub state: Option<String>,
    pub kind: Option<String>,
    pub speed_mbps: Option<u32>,
    pub mtu: u64,
    pub utilization_pct: Option<f64>,
    pub rx_bytes_per_s: f64,
    pub tx_bytes_per_s: f64,
    pub rx_total_bytes: u64,
    pub tx_total_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub dropped: u64,
    pub addresses: Vec<String>,
}

#[derive(Serialize)]
pub struct Kernel {
    pub retransmit_pct: f64,
    pub retransmits_per_s: f64,
    pub listen_overflows_per_s: f64,
    pub udp_buffer_errors_per_s: f64,
    pub tcp_timeouts_per_s: f64,
    pub resets_sent_per_s: f64,
    pub established: u64,
    pub conntrack: Option<(u64, u64)>,
}

#[derive(Serialize)]
pub struct Network {
    pub socket_source: &'static str,
    pub socket_error: Option<String>,
    pub states: BTreeMap<String, usize>,
    pub listening: Vec<Listener>,
    pub kernel: Option<Kernel>,
    pub slowest: Vec<Connection>,
    pub busiest: Vec<Connection>,
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
    pub inodes_used_pct: Option<f64>,
}

#[derive(Serialize)]
pub struct Temperature {
    pub sensor: String,
    pub celsius: f32,
    pub critical: Option<f32>,
}

// ───────────────────────────── findings ─────────────────────────────

/// Services that should rarely listen on every interface.
const SENSITIVE: &[(u16, &str)] = &[
    (2375, "Docker API (unencrypted)"),
    (2379, "etcd"),
    (3306, "MySQL / MariaDB"),
    (5432, "PostgreSQL"),
    (5984, "CouchDB"),
    (6379, "Redis"),
    (9200, "Elasticsearch"),
    (11211, "Memcached"),
    (27017, "MongoDB"),
];

/// Turn a header badge into a finding with an explanation and an action.
fn finding_from_alert(text: &str, critical: bool) -> Finding {
    let sev = if critical { "critical" } else { "warning" };
    let (area, detail, action): (&'static str, &str, &str) = match text.split_whitespace().next().unwrap_or("") {
        "MEM" => ("Memory", "Used memory is above the threshold; the kernel may start reclaiming cache aggressively or invoke the OOM killer.", "Check the top processes by memory below; look for leaks (RSS that keeps growing) or add memory."),
        "SWAP" => ("Memory", "Heavy swap use slows everything that touches swapped pages.", "Find what pushed memory out (top memory table); consider more RAM or lower vm.swappiness."),
        "DISK" => ("Storage", "A filesystem is nearly full. Writes, logs and databases fail when it reaches 100 %.", "Free space or grow the volume. If `du` disagrees with `df`, look for deleted-but-open files: `vigil -q +L1`."),
        "LOAD" => ("CPU", "More runnable tasks than CPUs: work is queueing.", "Check top CPU processes and PSI; a high load with low CPU usually means I/O wait."),
        "CLOSE_WAIT" => ("Network", "The remote side closed these connections but the local application never closed its sockets.", "This is an application bug (missing close()). Find the owner in the Sockets view (filter close_wait) and fix or restart it."),
        "TIME_WAIT" => ("Network", "Many short-lived connections; ephemeral ports can run out (EADDRNOTAVAIL).", "Use keep-alive or connection pooling to the upstreams with the most connections; widen net.ipv4.ip_local_port_range if needed."),
        "TEMP" => ("Hardware", "A sensor is above the temperature threshold; the CPU may throttle.", "Check cooling and sustained CPU load."),
        "PSI" => ("Pressure", "Tasks were stalled waiting for a resource for a large share of the last 10 s.", "The resource named in the badge (cpu, mem, io) is the bottleneck; start there."),
        "RETRANS" => ("Network", "TCP is retransmitting a high share of segments: packets are being lost on the path.", "Look for interface errors/drops and congested links; compare RTT per connection in the Sockets view."),
        "LISTEN" => ("Network", "The accept queue of a listening socket overflowed: new connections were dropped silently.", "The service accepts too slowly. Raise its backlog (and net.core.somaxconn) or add workers."),
        "UDP" => ("Network", "UDP packets were dropped because a socket buffer was full (DNS, syslog, metrics …).", "Raise net.core.rmem_max / the application's SO_RCVBUF, or make the consumer faster."),
        "CONNTRACK" => ("Network", "The connection-tracking table is nearly full. When full, the kernel drops new connections.", "Raise net.netfilter.nf_conntrack_max or shorten conntrack timeouts."),
        "LOSS" => ("Network", "A latency probe is losing packets.", "Check the path to that target: gateway, firewall or upstream link. `t` in the Probes view traces it hop by hop."),
        "FDS" => ("Limits", "A process is close to its open-file limit. At the limit, accept() and open() fail with \"Too many open files\".", "Look for a descriptor leak (count keeps growing) or raise LimitNOFILE / ulimit -n for that service."),
        "FILES" => ("Limits", "The system-wide file table is nearly full.", "Find the processes with the most descriptors (sort Procs by FDS with `e`) or raise fs.file-max."),
        "EPHEMERAL" => ("Network", "Most local ports for outgoing connections are in use; new connections will fail with EADDRNOTAVAIL.", "Reuse connections (keep-alive, pooling), check TIME_WAIT counts, or widen net.ipv4.ip_local_port_range."),
        "INODES" => ("Storage", "A filesystem is running out of inodes: file creation fails even though `df` shows free space.", "Find directories with huge numbers of small files (`du --inodes`, sessions, caches, mail queues) and clean them up."),
        "CERT" => ("TLS", "A TLS certificate checked by a probe expires soon.", "Renew the certificate and verify automatic renewal (certbot/ACME) actually runs."),
        "HTTP" => ("Availability", "An HTTP probe returns a server error.", "Check the service and its upstreams; the System view shows its journal."),
        "THROTTLED" => ("Containers", "A container hits its CPU quota: its threads wait even when the host has idle CPU, which shows up as latency.", "Raise the CPU limit (or remove it and use requests only), or reduce the work in that container."),
        "OOM" => ("Memory", "The kernel killed a process because memory ran out (or a container hit its memory limit).", "Check which process was killed (System view, kernel events) and raise its memory limit or fix its memory use."),
        "FAILED" => ("Services", "One or more systemd units are in the failed state.", "`systemctl status <unit>` and the journal (System view) show why; fix and `systemctl restart`."),
        _ if text.contains("AWAIT") => ("Storage", "A disk takes long to complete requests; everything waiting on I/O slows down.", "Check the device's utilisation and queue in the Storage view and which processes write the most."),
        _ if text.contains("BUSY") => ("Storage", "A disk is busy almost all the time.", "Find the heaviest readers/writers (Storage view) or move load to faster storage."),
        _ if text.contains("DROPS") => ("Network", "An interface is dropping packets.", "Check ring buffers (ethtool -g), CPU saturation on softirq and link utilization."),
        _ => ("System", "A configured health threshold was crossed.", "See the matching section below."),
    };
    Finding { severity: sev, area, title: text.to_string(), detail: detail.into(), action: action.into() }
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

fn conn_row(e: &OpenFile) -> Option<Connection> {
    let n = e.net.as_ref()?;
    let t = n.tcp?;
    let (l, r) = e.endpoints();
    Some(Connection {
        local: l.to_string(),
        remote: r.to_string(),
        state: e.state.clone(),
        process: e.command.clone(),
        pid: e.pid,
        rtt_ms: t.rtt_us as f64 / 1000.0,
        retransmits: t.total_retrans,
        rx_bytes_per_s: n.rx_rate,
        tx_bytes_per_s: n.tx_rate,
    })
}

pub fn build(
    s: &Sampler,
    sockets: &[OpenFile],
    backend: SocketBackend,
    socket_error: Option<String>,
    alerts: &Alerts,
    inputs: &Inputs,
    top: usize,
) -> Report {
    let extra = &inputs.health;
    let pct = |u: u64, t: u64| if t == 0 { 0.0 } else { u as f64 / t as f64 * 100.0 };

    // Socket-derived numbers.
    let mut states: BTreeMap<String, usize> = BTreeMap::new();
    let mut conns: BTreeMap<u32, usize> = BTreeMap::new();
    let mut peers: BTreeMap<String, usize> = BTreeMap::new();
    let mut listening: BTreeMap<(String, String), Listener> = BTreeMap::new();
    let mut tcp_conns: Vec<Connection> = Vec::new();
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
            if let Some(c) = conn_row(e) {
                tcp_conns.push(c);
            }
        }
        if e.is_listening() {
            let addr = local.rsplit_once(':').map(|(h, _)| h).unwrap_or(local).to_string();
            let exposed = matches!(addr.as_str(), "*" | "0.0.0.0" | "[::]");
            let port = e.local_port();
            listening.entry((e.proto.clone(), local.to_string())).or_insert(Listener {
                proto: format!("{} {}", e.proto, e.ftype.trim_start_matches("IP")),
                address: addr,
                port,
                service: port.and_then(|p| ipinfo::service(p, e.proto == "UDP")),
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
    let mut top_peers: Vec<Peer> = peers
        .into_iter()
        .map(|(host, connections)| {
            let scope = host.trim_matches(['[', ']']).parse().map(|ip| ipinfo::scope(&ip)).unwrap_or("");
            Peer { host, scope, connections }
        })
        .collect();
    top_peers.sort_by_key(|p| std::cmp::Reverse(p.connections));
    top_peers.truncate(top);

    let mut slowest: Vec<Connection> =
        tcp_conns.iter().filter(|c| c.rtt_ms > 0.0 && c.state == "ESTABLISHED").cloned().collect();
    slowest.sort_by(|a, b| b.rtt_ms.total_cmp(&a.rtt_ms));
    slowest.truncate(top);
    let mut busiest: Vec<Connection> =
        tcp_conns.into_iter().filter(|c| c.rx_bytes_per_s + c.tx_bytes_per_s >= 1.0).collect();
    busiest.sort_by(|a, b| (b.rx_bytes_per_s + b.tx_bytes_per_s).total_cmp(&(a.rx_bytes_per_s + a.tx_bytes_per_s)));
    busiest.truncate(top);

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
    let zombies = s.procs.iter().filter(|p| p.status == "Zombie").count();

    // Findings: every health badge, plus checks only a report has room for.
    let badges = compute_alerts(s, alerts, close_wait, time_wait, extra);
    let mut findings: Vec<Finding> = badges.iter().map(|(t, c)| finding_from_alert(t, *c == theme::red())).collect();
    for l in listening.iter().filter(|l| l.exposed) {
        if let Some((_, name)) = l.port.and_then(|p| SENSITIVE.iter().find(|(sp, _)| *sp == p)) {
            findings.push(Finding {
                severity: "warning",
                area: "Exposure",
                title: format!("{name} listens on all interfaces (port {})", l.port.unwrap_or(0)),
                detail: format!("{} (pid {}) is bound to {}, so it is reachable from every network this host is on.", l.process, l.pid, l.address),
                action: "Bind it to 127.0.0.1 or a private interface, or make sure a firewall restricts the port.".into(),
            });
        }
    }
    for i in s.ifaces.iter().filter(|i| i.rx_errors + i.tx_errors > 0) {
        findings.push(Finding {
            severity: "info",
            area: "Network",
            title: format!("{} has {} rx / {} tx errors", i.name, i.rx_errors, i.tx_errors),
            detail: "Interface errors point at layer 1/2: cabling, duplex mismatch, optics or driver.".into(),
            action: format!("Check `ethtool -S {}` and the switch port counters.", i.name),
        });
    }
    if zombies > 0 {
        findings.push(Finding {
            severity: "info",
            area: "Processes",
            title: format!("{zombies} zombie process(es)"),
            detail: "Zombies are finished processes whose parent never collected their exit status.".into(),
            action: "Find the parent in the process tree (`t` in vigil) and fix or restart it; zombies ignore signals.".into(),
        });
    }
    let rank = |s: &str| match s {
        "critical" => 0,
        "warning" => 1,
        _ => 2,
    };
    findings.sort_by_key(|f| rank(f.severity));
    let status = match findings.first().map(|f| f.severity) {
        Some("critical") => "critical",
        Some("warning") => "warning",
        _ => "healthy",
    };

    Report {
        generated_utc: utc_timestamp(SystemTime::now()),
        vigil_version: env!("CARGO_PKG_VERSION"),
        status,
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
        health: badges.into_iter().map(|(t, _)| t).collect(),
        findings,
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
            zombies,
            top_cpu: by_cpu.iter().take(top).map(|p| proc_row(p, &conns)).collect(),
            top_memory: by_mem.iter().take(top).map(|p| proc_row(p, &conns)).collect(),
        },
        network: Network {
            socket_source: backend.label(),
            socket_error,
            states,
            listening,
            kernel: s.knet.counters.as_ref().map(|c| Kernel {
                retransmit_pct: c.retrans_pct,
                retransmits_per_s: c.retrans_rate,
                listen_overflows_per_s: c.listen_overflow_rate.max(c.listen_drop_rate),
                udp_buffer_errors_per_s: c.udp_rcvbuf_err_rate + c.udp_sndbuf_err_rate,
                tcp_timeouts_per_s: c.tcp_timeout_rate,
                resets_sent_per_s: c.resets_out_rate,
                established: c.curr_estab,
                conntrack: c.conntrack,
            }),
            slowest,
            busiest,
            top_peers,
            interfaces: s
                .ifaces
                .iter()
                .filter(|i| i.rx_total + i.tx_total > 0)
                .map(|i| Interface {
                    name: i.name.clone(),
                    state: i.oper.clone(),
                    kind: i.kind.clone(),
                    speed_mbps: i.speed_mbps,
                    mtu: i.mtu,
                    utilization_pct: i.util_pct(),
                    rx_bytes_per_s: i.rx_rate,
                    tx_bytes_per_s: i.tx_rate,
                    rx_total_bytes: i.rx_total,
                    tx_total_bytes: i.tx_total,
                    rx_errors: i.rx_errors,
                    tx_errors: i.tx_errors,
                    dropped: i.rx_dropped + i.tx_dropped,
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
                inodes_used_pct: d.inode_pct(),
            })
            .collect(),
        devices: s
            .diskio
            .devices
            .iter()
            .map(|d| Device {
                name: d.name.clone(),
                reads_per_s: d.r_iops,
                writes_per_s: d.w_iops,
                read_bytes_per_s: d.r_bps,
                write_bytes_per_s: d.w_bps,
                await_ms: d.await_ms,
                util_pct: d.util_pct,
                queue: d.queue,
            })
            .collect(),
        limits: inputs
            .limits
            .as_ref()
            .map(|l| {
                let names: std::collections::HashMap<u32, &str> = s.procs.iter().map(|p| (p.pid, &*p.name)).collect();
                let mut v: Vec<FdUse> = l
                    .fds
                    .iter()
                    .map(|(pid, (n, lim))| FdUse {
                        pid: *pid,
                        name: names.get(pid).copied().unwrap_or("?").to_string(),
                        open: *n,
                        limit: *lim,
                        pct: lim.filter(|x| *x > 0).map(|x| *n as f64 / x as f64 * 100.0),
                    })
                    .collect();
                v.sort_by(|a, b| b.pct.unwrap_or(0.0).total_cmp(&a.pct.unwrap_or(0.0)).then(b.open.cmp(&a.open)));
                v.truncate(top);
                LimitsR { fd_top: v, system_files: l.files, ephemeral_range: l.ephemeral, ephemeral_used_pct: extra.ephemeral_pct }
            })
            .unwrap_or_default(),
        containers: inputs
            .containers
            .iter()
            .map(|c| ContainerR {
                name: c.name.clone(),
                runtime: c.runtime,
                cpu_pct: c.cpu_pct,
                cpu_limit: c.cpu_limit,
                throttled_pct: c.throttled_pct,
                memory_bytes: c.mem,
                memory_limit: c.mem_max,
                oom_kills: c.oom_kills,
                pids: c.pids,
            })
            .collect(),
        services: inputs
            .units
            .iter()
            .filter(|u| u.failed() || u.restarts > 0)
            .take(top.max(10))
            .map(|u| ServiceR {
                name: u.name.clone(),
                state: format!("{}/{}", u.active, u.sub),
                restarts: u.restarts,
                description: u.description.clone(),
            })
            .collect(),
        kernel_events: inputs
            .events
            .iter()
            .rev()
            .take(20)
            .map(|e| EventR { when_utc: utc_timestamp(e.at), kind: e.kind, message: e.text.clone() })
            .collect(),
        temperatures: s
            .temps
            .iter()
            .take(top)
            .map(|t| Temperature { sensor: t.label.clone(), celsius: t.temp, critical: t.critical })
            .collect(),
        changes: None,
    }
}

// ───────────────────────────── Markdown ─────────────────────────────

fn md(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn code(s: &str, n: usize) -> String {
    format!("`{}`", md(&crate::util::truncate(s, n)).replace('`', "'"))
}

fn sev_label(s: &str) -> &'static str {
    match s {
        "critical" => "🔴 Critical",
        "warning" => "🟠 Warning",
        _ => "🔵 Info",
    }
}

fn status_cell(bad: bool, label: &'static str) -> &'static str {
    if bad {
        label
    } else {
        "🟢 OK"
    }
}

pub fn to_markdown(r: &Report) -> String {
    let mut o = String::with_capacity(16 * 1024);
    let h = &r.host;
    let n = &r.network;
    let crit = r.findings.iter().filter(|f| f.severity == "critical").count();
    let warn = r.findings.iter().filter(|f| f.severity == "warning").count();
    let info = r.findings.len() - crit - warn;
    let has = |p: &str| r.health.iter().any(|x| x.starts_with(p));

    // ── Title + status banner
    let _ = writeln!(o, "# System report: {}\n", h.hostname);
    let banner = match r.status {
        "critical" => format!("🔴 **CRITICAL**: {crit} critical and {warn} warning finding(s) need attention"),
        "warning" => format!("🟠 **ATTENTION**: {warn} warning finding(s) to review"),
        _ => "🟢 **HEALTHY**: all health checks passed".to_string(),
    };
    let _ = writeln!(o, "> {banner}  ");
    let _ = writeln!(
        o,
        "> {} · {} · kernel {} · up {} · {} · vigil {}\n",
        md(&h.os),
        h.arch,
        md(&h.kernel),
        fmt_duration(h.uptime_seconds),
        r.generated_utc,
        r.vigil_version
    );
    if let Some(c) = &r.changes {
        changes_markdown(c, &mut o);
    }
    let _ = writeln!(
        o,
        "**Contents:** [Summary](#summary) · [Findings](#findings) · [Processes](#processes) · [Network](#network) · [Storage](#storage) · [Limits](#limits) · [Containers](#containers) · [Services](#services) · [Kernel events](#kernel-events) · [System](#system)\n"
    );

    // ── Summary
    let c = &r.cpu;
    let m = &r.memory;
    let fullest = r.filesystems.iter().max_by(|a, b| a.used_pct.total_cmp(&b.used_pct));
    let est = n.states.get("ESTABLISHED").copied().unwrap_or(0);
    let tw = n.states.get("TIME_WAIT").copied().unwrap_or(0);
    let cw = n.states.get("CLOSE_WAIT").copied().unwrap_or(0);
    let exposed = n.listening.iter().filter(|l| l.exposed).count();
    let _ = writeln!(o, "## Summary\n");
    let _ = writeln!(o, "| Area | Measurement | Status |\n|---|---|---|");
    let _ = writeln!(
        o,
        "| CPU | {:.1} % busy · load {:.2} / {:.2} / {:.2} ({:.2} per core) | {} |",
        c.total_pct, c.load[0], c.load[1], c.load[2], c.load_per_core,
        status_cell(has("LOAD"), "🟠 High load")
    );
    let _ = writeln!(
        o,
        "| Memory | {:.0} % used ({} of {}), {} available | {} |",
        m.used_pct, fmt_bytes(m.used_bytes), fmt_bytes(m.total_bytes), fmt_bytes(m.available_bytes),
        status_cell(has("MEM"), "🔴 High")
    );
    let _ = writeln!(
        o,
        "| Swap | {:.0} % used ({} of {}) | {} |",
        m.swap_used_pct, fmt_bytes(m.swap_used_bytes), fmt_bytes(m.swap_total_bytes),
        status_cell(has("SWAP"), "🟠 High")
    );
    if let Some(f) = fullest {
        let _ = writeln!(
            o,
            "| Disk | fullest is `{}` at {:.0} % ({} free) | {} |",
            md(&f.mount), f.used_pct, fmt_bytes(f.total_bytes.saturating_sub(f.used_bytes)),
            status_cell(has("DISK"), "🔴 Nearly full")
        );
    }
    let _ = writeln!(
        o,
        "| Connections | {est} established · {tw} TIME_WAIT · {cw} CLOSE_WAIT | {} |",
        status_cell(has("CLOSE_WAIT") || has("TIME_WAIT"), "🟠 Check")
    );
    if let Some(k) = &n.kernel {
        let _ = writeln!(
            o,
            "| TCP health | {:.2} % retransmitted · {:.1} listen overflows/s · {:.1} UDP drops/s | {} |",
            k.retransmit_pct, k.listen_overflows_per_s, k.udp_buffer_errors_per_s,
            status_cell(has("RETRANS") || has("LISTEN") || has("UDP"), "🟠 Check")
        );
    }
    let _ = writeln!(
        o,
        "| Listening ports | {} total, {exposed} on all interfaces | {} |",
        n.listening.len(),
        status_cell(r.findings.iter().any(|f| f.area == "Exposure"), "🟠 Review")
    );
    let _ = writeln!(
        o,
        "| Processes | {} total · {} zombie | {} |\n",
        r.processes.total, r.processes.zombies,
        status_cell(r.processes.zombies > 0, "🔵 Zombies")
    );
    if let Some(p) = &r.psi {
        let _ = writeln!(
            o,
            "Pressure (PSI, share of the last 10 s with stalled tasks): cpu **{:.1} %** · memory **{:.1} %** · io **{:.1} %**\n",
            p.cpu_some_avg10, p.memory_some_avg10, p.io_some_avg10
        );
    }

    // ── Findings
    let _ = writeln!(o, "## Findings\n");
    if r.findings.is_empty() {
        let _ = writeln!(o, "No findings. All health checks passed.\n");
    } else {
        let _ = writeln!(o, "{crit} critical · {warn} warning · {info} info\n");
        for (i, f) in r.findings.iter().enumerate() {
            let _ = writeln!(o, "### {}. {}: {}\n", i + 1, sev_label(f.severity), md(&f.title));
            let _ = writeln!(o, "- **Area:** {}", f.area);
            let _ = writeln!(o, "- **What it means:** {}", f.detail);
            let _ = writeln!(o, "- **Recommended action:** {}\n", f.action);
        }
    }

    // ── Processes
    let _ = writeln!(o, "## Processes\n");
    for (title, list) in [("Top by CPU", &r.processes.top_cpu), ("Top by memory", &r.processes.top_memory)] {
        let _ = writeln!(o, "### {title}\n");
        let _ = writeln!(o, "| PID | User | CPU % | Memory | Sockets | Command |\n|---:|---|---:|---:|---:|---|");
        for p in list {
            let cmd = if p.command.is_empty() { &p.name } else { &p.command };
            let _ = writeln!(
                o,
                "| {} | {} | {:.1} | {} | {} | {} |",
                p.pid, md(&p.user), p.cpu_pct, fmt_bytes(p.rss_bytes), p.sockets, code(cmd, 80)
            );
        }
        o.push('\n');
    }

    // ── Network
    let _ = writeln!(o, "## Network\n");
    if let Some(e) = &n.socket_error {
        let _ = writeln!(o, "> ⚠️ Socket scan failed: {}\n", md(e));
    }
    let _ = writeln!(o, "### Listening ports\n");
    let _ = writeln!(
        o,
        "Source: `{}`. **Exposed** means bound to every interface (`*`, `0.0.0.0`, `[::]`).\n",
        n.socket_source
    );
    let _ = writeln!(o, "| Port | Service | Proto | Address | Process | PID | User | Exposed |\n|---:|---|---|---|---|---:|---|:---:|");
    for l in &n.listening {
        let _ = writeln!(
            o,
            "| {} | {} | {} | `{}` | {} | {} | {} | {} |",
            l.port.map(|p| p.to_string()).unwrap_or_default(),
            l.service.unwrap_or(""),
            l.proto,
            md(&l.address),
            md(&l.process),
            l.pid,
            md(&l.user),
            if l.exposed { "**yes**" } else { "no" }
        );
    }
    o.push('\n');

    let _ = writeln!(o, "### Connection states\n");
    let _ = writeln!(o, "| State | Count |\n|---|---:|");
    let mut st: Vec<_> = n.states.iter().collect();
    st.sort_by_key(|(_, c)| std::cmp::Reverse(**c));
    for (k, v) in st {
        let _ = writeln!(o, "| {k} | {v} |");
    }
    o.push('\n');

    if let Some(k) = &n.kernel {
        let _ = writeln!(o, "### Kernel TCP/UDP counters\n");
        let _ = writeln!(o, "| Counter | Value |\n|---|---:|");
        let _ = writeln!(o, "| Retransmitted segments | {:.2} % ({:.0}/s) |", k.retransmit_pct, k.retransmits_per_s);
        let _ = writeln!(o, "| Listen-queue overflows | {:.1}/s |", k.listen_overflows_per_s);
        let _ = writeln!(o, "| UDP buffer errors | {:.1}/s |", k.udp_buffer_errors_per_s);
        let _ = writeln!(o, "| TCP timeouts | {:.1}/s |", k.tcp_timeouts_per_s);
        let _ = writeln!(o, "| Resets sent | {:.1}/s |", k.resets_sent_per_s);
        let _ = writeln!(o, "| Established | {} |", k.established);
        if let Some((cnt, max)) = k.conntrack {
            let p = if max > 0 { cnt as f64 / max as f64 * 100.0 } else { 0.0 };
            let _ = writeln!(o, "| Conntrack table | {cnt} / {max} ({p:.0} %) |");
        }
        o.push('\n');
    }

    for (title, list) in [("Slowest connections (RTT)", &n.slowest), ("Busiest connections", &n.busiest)] {
        if list.is_empty() {
            continue;
        }
        let _ = writeln!(o, "### {title}\n");
        let _ = writeln!(o, "| Remote | Local | Process | RTT ms | Retrans | ↓ RX/s | ↑ TX/s |\n|---|---|---|---:|---:|---:|---:|");
        for c in list {
            let _ = writeln!(
                o,
                "| `{}` | `{}` | {} ({}) | {:.1} | {} | {} | {} |",
                md(&c.remote), md(&c.local), md(&c.process), c.pid, c.rtt_ms, c.retransmits,
                fmt_rate(c.rx_bytes_per_s), fmt_rate(c.tx_bytes_per_s)
            );
        }
        o.push('\n');
    }

    if !n.top_peers.is_empty() {
        let _ = writeln!(o, "### Top remote peers\n");
        let _ = writeln!(o, "| Host | Scope | Connections |\n|---|---|---:|");
        for p in &n.top_peers {
            let _ = writeln!(o, "| `{}` | {} | {} |", md(&p.host), p.scope, p.connections);
        }
        o.push('\n');
    }

    let _ = writeln!(o, "### Interfaces\n");
    let _ = writeln!(o, "| Interface | State | Link | MTU | ↓ RX/s | ↑ TX/s | Util | Errors | Dropped | Addresses |\n|---|---|---|---:|---:|---:|---:|---:|---:|---|");
    for i in &n.interfaces {
        let link = match (i.speed_mbps, &i.kind) {
            (Some(s), Some(k)) => format!("{s} Mb/s {k}"),
            (Some(s), None) => format!("{s} Mb/s"),
            (None, Some(k)) => k.clone(),
            _ => String::new(),
        };
        let _ = writeln!(
            o,
            "| `{}` | {} | {} | {} | {} | {} | {} | {}/{} | {} | {} |",
            i.name,
            i.state.clone().unwrap_or_default(),
            link,
            i.mtu,
            fmt_rate(i.rx_bytes_per_s),
            fmt_rate(i.tx_bytes_per_s),
            i.utilization_pct.map(|u| format!("{u:.0} %")).unwrap_or_default(),
            i.rx_errors,
            i.tx_errors,
            i.dropped,
            i.addresses.join(", ")
        );
    }
    o.push('\n');

    // ── Storage
    let _ = writeln!(o, "## Storage\n");
    let _ = writeln!(o, "| Mount | Device | FS | Size | Used | Free | Use | Inodes |\n|---|---|---|---:|---:|---:|---:|---:|");
    for f in &r.filesystems {
        let _ = writeln!(
            o,
            "| `{}` | {} | {} | {} | {} | {} | {:.0} % | {} |",
            md(&f.mount), md(&f.device), f.fs, fmt_bytes(f.total_bytes), fmt_bytes(f.used_bytes),
            fmt_bytes(f.total_bytes.saturating_sub(f.used_bytes)), f.used_pct,
            f.inodes_used_pct.map(|p| format!("{p:.0} %")).unwrap_or_else(|| "-".into())
        );
    }
    o.push('\n');
    if !r.devices.is_empty() {
        let _ = writeln!(o, "### Disk devices\n");
        let _ = writeln!(o, "| Device | Reads/s | Writes/s | Read/s | Write/s | Await ms | Util | Queue |\n|---|---:|---:|---:|---:|---:|---:|---:|");
        for d in &r.devices {
            let _ = writeln!(
                o,
                "| `{}` | {:.0} | {:.0} | {} | {} | {:.1} | {:.0} % | {:.2} |",
                d.name, d.reads_per_s, d.writes_per_s, fmt_rate(d.read_bytes_per_s), fmt_rate(d.write_bytes_per_s),
                d.await_ms, d.util_pct, d.queue
            );
        }
        o.push('\n');
    }
    if !r.temperatures.is_empty() {
        let _ = writeln!(o, "<details><summary>Temperatures ({} sensors)</summary>\n", r.temperatures.len());
        let _ = writeln!(o, "| Sensor | °C | Critical |\n|---|---:|---:|");
        for t in &r.temperatures {
            let _ = writeln!(
                o,
                "| {} | {:.1} | {} |",
                md(&t.sensor), t.celsius, t.critical.map(|c| format!("{c:.0}")).unwrap_or_else(|| "-".into())
            );
        }
        let _ = writeln!(o, "\n</details>\n");
    }

    // ── Limits
    let l = &r.limits;
    if !l.fd_top.is_empty() || l.system_files.is_some() {
        let _ = writeln!(o, "## Limits\n");
        if let Some((n, m)) = l.system_files {
            let _ = writeln!(o, "- **System file handles:** {n} in use of {m}");
        }
        if let (Some((lo, hi)), Some(p)) = (l.ephemeral_range, l.ephemeral_used_pct) {
            let _ = writeln!(o, "- **Ephemeral ports:** {p:.1} % of {lo}–{hi} in use");
        }
        o.push('\n');
        let _ = writeln!(o, "| PID | Process | Open fds | Limit | Use |\n|---:|---|---:|---:|---:|");
        for f in &l.fd_top {
            let _ = writeln!(
                o,
                "| {} | {} | {} | {} | {} |",
                f.pid, md(&f.name), f.open,
                f.limit.map(|x| x.to_string()).unwrap_or_else(|| "-".into()),
                f.pct.map(|p| format!("{p:.0} %")).unwrap_or_else(|| "-".into())
            );
        }
        o.push('\n');
    }

    // ── Containers
    if !r.containers.is_empty() {
        let _ = writeln!(o, "## Containers\n");
        let _ = writeln!(o, "| Container | Runtime | CPU % | Limit | Throttled | Memory | Mem limit | OOM kills | PIDs |\n|---|---|---:|---:|---:|---:|---:|---:|---:|");
        for c in &r.containers {
            let _ = writeln!(
                o,
                "| {} | {} | {:.1} | {} | {:.0} % | {} | {} | {} | {} |",
                md(&c.name), c.runtime, c.cpu_pct,
                c.cpu_limit.map(|x| format!("{x:.1} cpu")).unwrap_or_else(|| "-".into()),
                c.throttled_pct, fmt_bytes(c.memory_bytes),
                c.memory_limit.map(fmt_bytes).unwrap_or_else(|| "-".into()),
                c.oom_kills, c.pids
            );
        }
        o.push('\n');
    }

    // ── Services
    if !r.services.is_empty() {
        let _ = writeln!(o, "## Services\n");
        let _ = writeln!(o, "Failed units and units that restarted.\n");
        let _ = writeln!(o, "| Unit | State | Restarts | Description |\n|---|---|---:|---|");
        for u in &r.services {
            let _ = writeln!(o, "| `{}` | {} | {} | {} |", md(&u.name), u.state, u.restarts, md(&u.description));
        }
        o.push('\n');
    }

    // ── Kernel events
    if !r.kernel_events.is_empty() {
        let _ = writeln!(o, "## Kernel events\n");
        let _ = writeln!(o, "| When | Kind | Message |\n|---|---|---|");
        for e in &r.kernel_events {
            let _ = writeln!(o, "| {} | {} | {} |", e.when_utc, e.kind, code(&e.message, 120));
        }
        o.push('\n');
    }

    // ── System
    let _ = writeln!(o, "## System\n");
    let _ = writeln!(o, "| | |\n|---|---|");
    let _ = writeln!(o, "| Host | `{}` |", md(&h.hostname));
    let _ = writeln!(o, "| Operating system | {} |", md(&h.os));
    let _ = writeln!(o, "| Kernel | {} ({}) |", md(&h.kernel), h.arch);
    let _ = writeln!(o, "| CPU | {} · {} cores / {} threads |", md(&h.cpu_model), h.physical_cores, h.logical_cores);
    let _ = writeln!(
        o,
        "| Per-core load | min {:.0} % · avg {:.0} % · max {:.0} % (core {}) |",
        c.core_min_pct, c.core_avg_pct, c.core_max_pct, c.busiest_core
    );
    let _ = writeln!(o, "| Uptime | {} |", fmt_duration(h.uptime_seconds));
    let _ = writeln!(o, "| Report generated | {} |\n", r.generated_utc);
    let _ = writeln!(
        o,
        "---\n*Generated by [vigil](https://github.com/suleymenb/vigil) {}. Values are a point-in-time sample; rates cover the sampling window.*",
        r.vigil_version
    );
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
    /// Compare with an earlier `vigil report -f json` file.
    pub diff: Option<PathBuf>,
}

/// `vigil report`: sample, build, print or write. Returns the process exit code.
pub fn run_cli(opts: Options, alerts: &Alerts) -> std::io::Result<i32> {
    let mut sampler = Sampler::new();
    let mut scanner = SocketScanner::new(opts.force_lsof);
    let _ = scanner.scan(); // first pass primes per-connection byte counters
    let mut ctr = crate::collect::containers::Collector::new();
    let _ = ctr.collect(); // first pass primes container counters
    std::thread::sleep(opts.sample);
    sampler.refresh();
    let (res, backend) = scanner.scan();
    let mut inputs = Inputs {
        limits: Some(crate::collect::limits::collect_once()),
        containers: ctr.collect().unwrap_or_default(),
        units: crate::collect::services::collect_once(),
        events: crate::collect::kmsg::read_existing(),
        ..Default::default()
    };
    let (sockets, err) = match res {
        Ok((e, _)) => (e, None),
        Err(e) => (Vec::new(), Some(e)),
    };
    let snapshot = std::sync::Arc::new(sockets.clone());
    if let Some(l) = &inputs.limits {
        inputs.health.fill_limits(l, &sampler, Some(snapshot));
    }
    for c in &inputs.containers {
        inputs.health.throttled.push((c.name.clone(), c.throttled_pct));
    }
    inputs.health.failed_units = inputs.units.iter().filter(|u| u.failed() && cfg!(target_os = "linux")).count();
    inputs.health.kernel_ooms = inputs
        .events
        .iter()
        .filter(|e| e.kind == "OOM" && SystemTime::now().duration_since(e.at).map(|d| d.as_secs() < 600).unwrap_or(true))
        .count();
    let mut report = build(&sampler, &sockets, backend, err, alerts, &inputs, opts.top);
    if let Some(p) = &opts.diff {
        let text = std::fs::read_to_string(p).map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", p.display())))?;
        let prev: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{} is not a vigil JSON report: {e}", p.display())))?;
        report.changes = Some(diff(&prev, &report));
    }
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
    inputs: &Inputs,
) -> Result<PathBuf, String> {
    let report = build(s, sockets, backend, None, alerts, inputs, 15);
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
    fn diff_detects_changes() {
        let mut s = Sampler::new();
        std::thread::sleep(Duration::from_millis(200));
        s.refresh();
        let before = crate::collect::lsof::parse("p1\ncnginx\nLroot\nf6\ntIPv4\nPTCP\nn*:80\nTST=LISTEN\n");
        let after = crate::collect::lsof::parse("p1\ncnginx\nLroot\nf6\ntIPv4\nPTCP\nn*:80\nTST=LISTEN\np2\ncpostgres\nLpostgres\nf5\ntIPv4\nPTCP\nn*:5432\nTST=LISTEN\n");
        let a = build(&s, &before, SocketBackend::Lsof, None, &Alerts::default(), &Inputs::default(), 5);
        let prev = serde_json::to_value(&a).unwrap();
        let b = build(&s, &after, SocketBackend::Lsof, None, &Alerts::default(), &Inputs::default(), 5);
        let c = diff(&prev, &b);
        assert_eq!(c.ports_opened.len(), 1, "{:?}", c.ports_opened);
        assert!(c.ports_opened[0].contains("5432"));
        assert!(c.new_findings.iter().any(|f| f.contains("PostgreSQL")));
        assert!(c.ports_closed.is_empty());
        let mut out = String::new();
        changes_markdown(&c, &mut out);
        assert!(out.contains("Ports now listening"));
    }

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
            "p1\ncnginx\nLroot\nf6\ntIPv4\nPTCP\nn*:80\nTST=LISTEN\nf7\ntIPv4\nPTCP\nn10.0.0.1:80->10.0.0.9:5000\nTST=CLOSE_WAIT\np2\ncpostgres\nLpostgres\nf5\ntIPv4\nPTCP\nn*:5432\nTST=LISTEN\n",
        );
        let r = build(&s, &socks, SocketBackend::Lsof, None, &Alerts::default(), &Inputs::default(), 5);
        assert_eq!(r.network.listening.len(), 2);
        assert!(r.network.listening[0].exposed);
        assert_eq!(r.network.states.get("CLOSE_WAIT"), Some(&1));
        // Postgres on all interfaces must become a finding with an action.
        let f = r.findings.iter().find(|f| f.area == "Exposure").expect("exposure finding");
        assert!(f.title.contains("PostgreSQL"));
        assert_ne!(r.status, "healthy");
        let md = to_markdown(&r);
        for section in ["## Summary", "## Findings", "### Listening ports", "## Storage", "Recommended action"] {
            assert!(md.contains(section), "missing {section}");
        }
        let js = to_json(&r);
        let v: serde_json::Value = serde_json::from_str(&js).unwrap();
        assert_eq!(v["network"]["listening"][0]["port"], 80);
        assert!(v["findings"].as_array().unwrap().iter().any(|f| f["area"] == "Exposure"));
    }
}
