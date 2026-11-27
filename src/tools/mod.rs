//! Active troubleshooting tools: things you *run*, as opposed to the
//! collectors in `collect`, which watch. Each tool reports through an `emit`
//! callback, so the same code prints to the terminal (`vigil doctor`,
//! `vigil dns`, …) and streams into the Troubleshoot view (W).

pub mod cli;
pub mod dhcp;
pub mod dnsq;
pub mod doctor;
pub mod mtu;
pub mod netcalc;
pub mod perf;
pub mod reach;
pub mod snmp;
pub mod syslog;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Tone {
    Head,
    Normal,
    Good,
    Warn,
    Bad,
    Dim,
}

#[derive(Clone, Debug)]
pub struct Line {
    pub tone: Tone,
    pub text: String,
}

/// Which tool produced the output in the Troubleshoot view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Doctor,
    Calc,
    Mtu,
    Dns,
    Perf,
    Capture,
    Reach,
    Syslog,
    Snmp,
    Dhcp,
    Wifi,
    Trace,
}

impl Kind {
    pub fn title(self) -> &'static str {
        match self {
            Kind::Doctor => "doctor",
            Kind::Calc => "subnet calculator",
            Kind::Mtu => "path MTU",
            Kind::Dns => "DNS per resolver",
            Kind::Perf => "throughput",
            Kind::Capture => "packet capture",
            Kind::Reach => "port reachability",
            Kind::Syslog => "syslog receiver",
            Kind::Snmp => "SNMP device",
            Kind::Dhcp => "DHCP servers",
            Kind::Wifi => "Wi-Fi",
            Kind::Trace => "path trace",
        }
    }
}

#[derive(Default)]
pub struct ToolStore {
    pub kind: Option<Kind>,
    pub arg: String,
    pub lines: Vec<Line>,
    pub running: bool,
    pub checks: Vec<doctor::Check>,
    /// Set by `x` to stop a long-running tool (capture, syslog).
    pub stop: Arc<AtomicBool>,
    pub version: u64,
}

/// Settings shared by the CLI and the TUI (from `[troubleshoot]` in the config).
#[derive(Clone, Debug)]
pub struct Settings {
    pub internet4: String,
    pub internet6: String,
    pub dns_name: String,
    pub http_url: String,
    pub public_resolvers: Vec<String>,
    pub perf_url: String,
    /// Default length of a capture without a time or packet limit.
    pub capture_secs: u64,
    /// SNMP credentials from `[snmp]` (and VIGIL_SNMP_* environment variables).
    pub snmp: crate::config::Snmp,
}

impl From<&crate::config::Troubleshoot> for Settings {
    fn from(t: &crate::config::Troubleshoot) -> Self {
        Settings {
            internet4: t.internet_target.clone(),
            internet6: t.internet_target6.clone(),
            dns_name: t.dns_test_name.clone(),
            http_url: t.http_test_url.clone(),
            public_resolvers: t.public_resolvers.clone(),
            perf_url: t.perf_url.clone(),
            capture_secs: 20,
            snmp: crate::config::Snmp::default(),
        }
    }
}

/// Status marks; plain ASCII on legacy consoles and ASCII themes.
pub fn mark(t: Tone) -> &'static str {
    let ascii = crate::theme::is_ascii();
    match (t, ascii) {
        (Tone::Good, false) => "✔",
        (Tone::Warn, false) => "▲",
        (Tone::Bad, false) => "✖",
        (Tone::Good, true) => "ok",
        (Tone::Warn, true) => "!!",
        (Tone::Bad, true) => "XX",
        (_, false) => "·",
        (_, true) => "--",
    }
}

/// Start a tool in the background, streaming its lines into `store`.
pub fn start(store: Arc<Mutex<ToolStore>>, kind: Kind, arg: String, settings: Settings, dns_servers: Vec<String>) {
    if let Ok(mut s) = store.lock() {
        if s.running {
            return;
        }
        s.kind = Some(kind);
        s.arg = arg.clone();
        s.lines.clear();
        s.checks.clear();
        s.running = true;
        s.stop.store(false, Ordering::Relaxed);
        s.version += 1;
    }
    let stop = store.lock().map(|s| s.stop.clone()).unwrap_or_default();
    std::thread::spawn(move || {
        let st = store.clone();
        let emit = move |tone: Tone, text: String| {
            if let Ok(mut s) = st.lock() {
                // Long-running tools (syslog) keep the newest 5000 lines.
                if s.lines.len() >= 5000 {
                    s.lines.drain(..1000);
                }
                s.lines.push(Line { tone, text });
                s.version += 1;
            }
        };
        let checks = match kind {
            Kind::Doctor => doctor::run(&settings, &emit),
            Kind::Calc => {
                match netcalc::run(&arg) {
                    Ok(t) => t.lines().for_each(|l| emit(Tone::Normal, l.to_string())),
                    Err(e) => emit(Tone::Bad, e),
                }
                Vec::new()
            }
            Kind::Mtu => {
                let target = if arg.trim().is_empty() { settings.internet4.clone() } else { arg.trim().to_string() };
                mtu::discover(&target, &emit);
                Vec::new()
            }
            Kind::Dns => {
                match dnsq::parse_args(if arg.trim().is_empty() { &settings.dns_name } else { &arg }) {
                    Ok((name, qtype, servers)) => {
                        dnsq::compare(&name, qtype, &dns_servers, &settings.public_resolvers, &servers, &emit);
                    }
                    Err(e) => emit(Tone::Bad, e),
                }
                Vec::new()
            }
            Kind::Capture => {
                use crate::collect::capture;
                let res = capture::parse_spec(&arg, &capture::interfaces(), settings.capture_secs)
                    .and_then(|spec| capture::run(&spec, capture::Out::File(capture::default_path(capture::ext())), Some(&stop), &emit));
                if let Err(e) = res {
                    emit(Tone::Bad, e);
                }
                Vec::new()
            }
            Kind::Reach => {
                let mut w = arg.split_whitespace();
                let res = match (w.next(), w.next()) {
                    (Some(host), Some(ports)) => reach::parse_ports(ports).and_then(|p| reach::run(host, &p, reach::default_timeout(), &emit)).map(|_| ()),
                    _ => Err("give a host and ports: 10.0.0.5 22,443,3389 · db1 5432 · fw1 8000-8010".to_string()),
                };
                if let Err(e) = res {
                    emit(Tone::Bad, e);
                }
                Vec::new()
            }
            Kind::Syslog => {
                let mut w = arg.split_whitespace();
                let first = w.next();
                let (port, filter) = match first.and_then(|p| p.parse::<u16>().ok()) {
                    Some(p) => (p, w.collect::<Vec<_>>().join(" ")),
                    None => (514, arg.trim().to_string()),
                };
                let f = (!filter.is_empty()).then_some(filter.as_str());
                if let Err(e) = syslog::listen(port, f, None, stop.clone(), &emit) {
                    emit(Tone::Bad, e);
                }
                Vec::new()
            }
            Kind::Snmp => {
                let res = match snmp::parse_prompt(&arg) {
                    Some((host, community)) => settings.snmp.auth(community.as_deref()).and_then(|auth| snmp::report(&host, settings.snmp.port, auth, std::time::Duration::from_secs(5), false, &emit)).map(|_| ()),
                    None => Err("give a device: 10.0.0.1 [community] (v3 credentials come from [snmp] in the config)".to_string()),
                };
                if let Err(e) = res {
                    emit(Tone::Bad, e);
                }
                Vec::new()
            }
            Kind::Dhcp => {
                let iface = arg.split_whitespace().next();
                if let Err(e) = dhcp::run(iface, std::time::Duration::from_secs(4), &emit) {
                    emit(Tone::Bad, e);
                }
                Vec::new()
            }
            Kind::Wifi => {
                crate::collect::wifi::report(&emit);
                Vec::new()
            }
            Kind::Trace => {
                let mut w = arg.split_whitespace();
                match w.next() {
                    Some(host) => {
                        let mode = match (w.next(), w.next()) {
                            (Some("tcp"), p) => crate::collect::trace::Mode::Tcp(p.and_then(|p| p.parse().ok()).unwrap_or(443)),
                            (Some("udp"), _) => crate::collect::trace::Mode::Udp,
                            _ => crate::collect::trace::Mode::Icmp,
                        };
                        crate::collect::trace::report(host, mode, &emit);
                    }
                    None => emit(Tone::Bad, "give a host: 1.1.1.1 · app.example.com tcp 443 · 10.0.0.9 udp".into()),
                }
                Vec::new()
            }
            Kind::Perf => {
                let a = arg.trim();
                let res = if a.is_empty() || a == "internet" {
                    perf::internet(&settings.perf_url, &emit)
                } else {
                    let reverse = a.contains(" -R") || a.ends_with(" down");
                    let host = a.split_whitespace().next().unwrap_or(a);
                    perf::client(host, 5, 4, reverse, &emit)
                };
                if let Err(e) = res {
                    emit(Tone::Bad, e);
                }
                Vec::new()
            }
        };
        if let Ok(mut s) = store.lock() {
            s.checks = checks;
            s.running = false;
            s.version += 1;
        }
    });
}
