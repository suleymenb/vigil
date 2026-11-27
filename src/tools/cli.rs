//! Command-line front ends: `vigil doctor | calc | dns | mtu | perf`.

use std::io::{IsTerminal, Write};

use super::{dnsq, doctor, mtu, netcalc, perf, Settings, Tone};

fn color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

/// Print one tool line, coloured when stdout is a terminal.
pub fn print(tone: Tone, text: &str) {
    let code = match tone {
        Tone::Head => "1",
        Tone::Good => "32",
        Tone::Warn => "33",
        Tone::Bad => "31",
        Tone::Dim => "2",
        Tone::Normal => "",
    };
    let mut out = std::io::stdout().lock();
    let _ = if color() && !code.is_empty() { writeln!(out, "\x1b[{code}m{text}\x1b[0m") } else { writeln!(out, "{text}") };
}

fn emit(tone: Tone, text: String) {
    print(tone, &text);
}

fn system_resolvers() -> Vec<String> {
    crate::collect::netinfo::collect().2.servers
}

pub fn doctor(s: &Settings, json: bool) -> i32 {
    let checks = if json { doctor::run(s, &|_, _| {}) } else { doctor::run(s, &emit) };
    if json {
        println!("{}", serde_json::to_string_pretty(&checks).unwrap_or_default());
    }
    i32::from(checks.iter().any(|c| c.status == doctor::Status::Fail))
}

pub fn calc(input: &str) -> i32 {
    match netcalc::run(input) {
        Ok(t) => {
            print!("{t}");
            0
        }
        Err(e) => {
            eprintln!("vigil calc: {e}");
            2
        }
    }
}

pub fn dns(input: &str, s: &Settings) -> i32 {
    match dnsq::parse_args(input) {
        Ok((name, qtype, servers)) => i32::from(!dnsq::compare(&name, qtype, &system_resolvers(), &s.public_resolvers, &servers, &emit)),
        Err(e) => {
            eprintln!("vigil dns: {e}");
            2
        }
    }
}

pub fn mtu(target: &str) -> i32 {
    i32::from(mtu::discover(target, &emit).path_mtu.is_none())
}

#[allow(clippy::too_many_arguments)]
pub fn perf(host: Option<&str>, server: bool, port: u16, secs: u32, streams: usize, reverse: bool, internet: bool, s: &Settings) -> i32 {
    let res = if server {
        perf::serve(port, &|t, l| print(t, &l)).map(|_| 0.0)
    } else if internet {
        perf::internet(&s.perf_url, &emit)
    } else if let Some(h) = host {
        let target = if h.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{h}]:{port}")
        } else if h.starts_with('[') || h.contains(':') {
            h.to_string()
        } else {
            format!("{h}:{port}")
        };
        perf::client(&target, secs, streams, reverse, &emit)
    } else {
        Err("give a host running `vigil perf --server`, or --server, or --internet".into())
    };
    match res {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("vigil perf: {e}");
            1
        }
    }
}

#[cfg(unix)]
extern "C" fn ignore_sigint(_: libc::c_int) {}

/// `vigil capture`: status goes to stderr, because stdout may be the pcap.
pub fn capture(iface: Option<&str>, secs: Option<u64>, count: Option<u64>, write: Option<&std::path::Path>, open: bool, filter: &str) -> i32 {
    use crate::collect::capture::{self, Out, Spec};
    let out = match write {
        Some(p) if p.as_os_str() == "-" => {
            if std::io::stdout().is_terminal() {
                eprintln!("vigil capture: -w - writes binary pcap to stdout; pipe it, e.g. | wireshark -k -i -");
                return 2;
            }
            Out::Stdout
        }
        Some(p) => Out::File(p.to_path_buf()),
        None => Out::File(capture::default_path(capture::ext())),
    };
    // pktmon runs detached, so Windows always needs an end time.
    let secs = if secs.is_none() && count.is_none() && cfg!(windows) { Some(20) } else { secs };
    let spec = Spec { iface: iface.unwrap_or("any").to_string(), filter: filter.trim().to_string(), secs, count };
    if secs.is_none() && count.is_none() {
        eprintln!("ctrl-c stops the capture");
    }
    // ctrl-c reaches tcpdump too; vigil itself keeps running to report the result.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGINT, ignore_sigint as *const () as libc::sighandler_t);
    }
    let emit = |tone: Tone, text: String| {
        let code = match tone {
            Tone::Head => "1",
            Tone::Good => "32",
            Tone::Warn => "33",
            Tone::Bad => "31",
            Tone::Dim => "2",
            Tone::Normal => "",
        };
        if std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none() && !code.is_empty() {
            eprintln!("\x1b[{code}m{text}\x1b[0m");
        } else {
            eprintln!("{text}");
        }
    };
    match capture::run(&spec, out, None, &emit) {
        Ok(d) => {
            if open {
                if let Some(p) = &d.path {
                    if let Err(e) = capture::open_in_wireshark(p) {
                        eprintln!("vigil capture: {e}");
                    }
                }
            }
            0
        }
        Err(e) => {
            eprintln!("vigil capture: {e}");
            1
        }
    }
}

pub fn reach(host: &str, ports: &str, timeout_ms: u64) -> i32 {
    match super::reach::parse_ports(ports).and_then(|p| super::reach::run(host, &p, std::time::Duration::from_millis(timeout_ms.clamp(100, 30_000)), &emit)) {
        Ok(r) => i32::from(!r.iter().any(|(_, s)| matches!(s, super::reach::State::Open(_)))),
        Err(e) => {
            eprintln!("vigil reach: {e}");
            2
        }
    }
}

pub fn trace(host: &str, tcp: Option<u16>, udp: bool) -> i32 {
    use crate::collect::trace::{report, Mode};
    let mode = match (tcp, udp) {
        (Some(p), _) => Mode::Tcp(p),
        (None, true) => Mode::Udp,
        _ => Mode::Icmp,
    };
    i32::from(!report(host, mode, &emit))
}

#[allow(clippy::too_many_arguments)]
pub fn snmp(host: &str, community: Option<&str>, user: Option<&str>, proto: &str, auth_pass: Option<&str>, priv_pass: Option<&str>, port: u16, interval: u64, all: bool, cfg: &crate::config::Snmp) -> i32 {
    use super::snmp::{report, Auth, AuthProto};
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let auth = match user {
        Some(u) => {
            let Some(p) = AuthProto::parse(proto) else {
                eprintln!("vigil snmp: unknown auth protocol {proto} (md5, sha, sha256)");
                return 2;
            };
            let a = auth_pass.map(String::from).or_else(|| env("VIGIL_SNMP_AUTH"));
            let x = priv_pass.map(String::from).or_else(|| env("VIGIL_SNMP_PRIV"));
            Ok(Auth::V3 { user: u.to_string(), auth: a.map(|a| (p, a)), privacy: x })
        }
        None => cfg.auth(community),
    };
    let port = if port == 161 { cfg.port } else { port };
    match auth.and_then(|a| report(host, port, a, std::time::Duration::from_secs(interval.clamp(1, 300)), all, &emit)) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("vigil snmp: {e}");
            1
        }
    }
}

pub fn syslog(port: u16, filter: Option<&str>, save: Option<&std::path::Path>) -> i32 {
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    match super::syslog::listen(port, filter, save, stop, &|t, l| print(t, &l)) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("vigil syslog: {e}");
            1
        }
    }
}

pub fn dhcp(iface: Option<&str>, secs: u64) -> i32 {
    match super::dhcp::run(iface, std::time::Duration::from_secs(secs.clamp(1, 60)), &emit) {
        Ok(offers) => {
            let servers: std::collections::BTreeSet<_> = offers.iter().map(|o| o.server_id).collect();
            match servers.len() {
                1 => 0,
                0 => 1,
                _ => 3, // more than one server: possibly rogue
            }
        }
        Err(e) => {
            eprintln!("vigil dhcp: {e}");
            2
        }
    }
}

pub fn wifi() -> i32 {
    i32::from(crate::collect::wifi::report(&emit) == 0)
}
