//! Command-line front ends: `vigil doctor | calc | dns | mtu | perf`.

use std::io::{IsTerminal, Write};

use super::{dnsq, doctor, mtu, netcalc, perf, Settings, Tone};

fn color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none() && !crate::platform::get().legacy_windows()
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
