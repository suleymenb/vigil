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
    match capture::run(&spec, out, &emit) {
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
