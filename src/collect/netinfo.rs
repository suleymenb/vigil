#![allow(dead_code)] // parsers for other platforms are unit-tested on every OS

//! Routing table, neighbour (ARP/NDP) cache and DNS resolvers.
//!
//! Linux: `ip -j route|neigh` (iproute2 JSON) with /proc/net/route + arp as
//! fallback; /etc/resolv.conf (+ systemd-resolved upstreams).
//! macOS: `netstat -rn`, `arp -an`, `ndp -an` (IPv6 neighbours), `scutil --dns`.
//! Windows: `route print`, `arp -a`, `ipconfig /all` (parsers in `windows.rs`).
//!
//! Runs on its own thread: once at start (probes need the gateway), then every
//! 5 s while the Routes view is open, otherwise once a minute.

use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default)]
pub struct Route {
    pub family: &'static str,
    pub dst: String,
    pub gateway: String,
    pub dev: String,
    pub proto: String,
    pub metric: String,
    pub src: String,
}

#[derive(Clone, Debug, Default)]
pub struct Neighbor {
    pub ip: String,
    pub mac: String,
    pub dev: String,
    pub state: String,
}

#[derive(Clone, Debug, Default)]
pub struct Dns {
    pub servers: Vec<String>,
    pub search: Vec<String>,
    pub note: Option<String>,
}

#[derive(Default)]
pub struct NetInfo {
    pub routes: Vec<Route>,
    pub neighbors: Vec<Neighbor>,
    pub dns: Dns,
    pub updated: Option<Instant>,
    pub error: Option<String>,
    pub version: u64,
}

impl NetInfo {
    /// Default gateways, de-duplicated. Link-local IPv6 gateways keep their
    /// `%interface` scope, because `fe80::1` alone is ambiguous.
    pub fn default_gateways(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for r in self.routes.iter().filter(|r| matches!(r.dst.as_str(), "default" | "0.0.0.0/0" | "::/0") && !r.gateway.is_empty()) {
            let g = if r.gateway.starts_with("fe80") && !r.gateway.contains('%') && !r.dev.is_empty() {
                format!("{}%{}", r.gateway, r.dev)
            } else {
                r.gateway.clone()
            };
            if !out.contains(&g) {
                out.push(g);
            }
        }
        out
    }
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let o = Command::new(cmd).args(args).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

// ───────────────────────────── parsers (all platforms) ─────────────────────────────

pub fn parse_ip_route_json(text: &str, family: &'static str) -> Vec<Route> {
    let Ok(serde_json::Value::Array(arr)) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let s = |v: &serde_json::Value, k: &str| match v.get(k) {
        Some(serde_json::Value::String(x)) => x.clone(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        _ => String::new(),
    };
    arr.iter()
        .map(|r| Route {
            family,
            dst: s(r, "dst"),
            gateway: s(r, "gateway"),
            dev: s(r, "dev"),
            proto: s(r, "protocol"),
            metric: s(r, "metric"),
            src: s(r, "prefsrc"),
        })
        .collect()
}

pub fn parse_ip_neigh_json(text: &str) -> Vec<Neighbor> {
    let Ok(serde_json::Value::Array(arr)) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    arr.iter()
        .map(|n| Neighbor {
            ip: n.get("dst").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            mac: n.get("lladdr").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            dev: n.get("dev").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            state: n
                .get("state")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(","))
                .unwrap_or_default(),
        })
        .collect()
}

/// /proc/net/route fallback (IPv4 only, hex little-endian addresses).
pub fn parse_proc_route(text: &str) -> Vec<Route> {
    let hex_ip = |h: &str| {
        u32::from_str_radix(h, 16)
            .map(|v| std::net::Ipv4Addr::from(v.to_ne_bytes()).to_string())
            .unwrap_or_default()
    };
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 8 {
                return None;
            }
            let dst = hex_ip(f[1]);
            let mask = u32::from_str_radix(f[7], 16).unwrap_or(0).count_ones();
            let gw = hex_ip(f[2]);
            Some(Route {
                family: "inet",
                dst: if dst == "0.0.0.0" && mask == 0 { "default".into() } else { format!("{dst}/{mask}") },
                gateway: if gw == "0.0.0.0" { String::new() } else { gw },
                dev: f[0].to_string(),
                metric: f[6].to_string(),
                ..Default::default()
            })
        })
        .collect()
}

/// macOS `netstat -rn -f inet|inet6`.
pub fn parse_netstat_rn(text: &str, family: &'static str) -> Vec<Route> {
    let mut out = Vec::new();
    let mut in_table = false;
    for l in text.lines() {
        if l.starts_with("Destination") {
            in_table = true;
            continue;
        }
        if !in_table || l.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let gw = f[1];
        out.push(Route {
            family,
            dst: f[0].to_string(),
            gateway: if gw.starts_with("link#") || gw.contains(':') && gw.len() == 17 { String::new() } else { gw.to_string() },
            dev: f[3].to_string(),
            proto: f[2].to_string(), // flags
            ..Default::default()
        });
    }
    out
}

/// macOS `arp -an`: `? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]`.
pub fn parse_arp_an(text: &str) -> Vec<Neighbor> {
    text.lines()
        .filter_map(|l| {
            let ip = l.split_once('(')?.1.split_once(')')?.0.to_string();
            let mac = l.split_once(" at ")?.1.split_whitespace().next()?.to_string();
            let dev = l.split_once(" on ").map(|(_, r)| r.split_whitespace().next().unwrap_or("").to_string()).unwrap_or_default();
            let state = if mac.contains("incomplete") { "INCOMPLETE" } else if l.contains("permanent") { "PERMANENT" } else { "REACHABLE" };
            Some(Neighbor { ip, mac: if state == "INCOMPLETE" { String::new() } else { mac }, dev, state: state.into() })
        })
        .collect()
}

/// macOS `ndp -an`: IPv6 neighbours. "permanent" rows are this host's own addresses.
pub fn parse_ndp_an(text: &str) -> Vec<Neighbor> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 4 || f[3] == "permanent" || f[2].starts_with("lo") {
                return None;
            }
            let incomplete = f[1].starts_with('(');
            let state = match f.get(4).copied().unwrap_or("") {
                _ if incomplete => "INCOMPLETE",
                "R" => "REACHABLE",
                "S" => "STALE",
                "D" => "DELAY",
                "P" => "PROBE",
                "I" => "INCOMPLETE",
                _ => "NOSTATE",
            };
            Some(Neighbor { ip: f[0].to_string(), mac: if incomplete { String::new() } else { f[1].to_string() }, dev: f[2].to_string(), state: state.into() })
        })
        .collect()
}

pub fn parse_resolv_conf(text: &str) -> Dns {
    let mut d = Dns::default();
    for l in text.lines() {
        let mut it = l.split_whitespace();
        match it.next() {
            Some("nameserver") => d.servers.extend(it.next().map(String::from)),
            Some("search") | Some("domain") => d.search.extend(it.map(String::from)),
            _ => {}
        }
    }
    d
}

/// macOS `scutil --dns`.
pub fn parse_scutil_dns(text: &str) -> Dns {
    let mut d = Dns::default();
    for l in text.lines() {
        let l = l.trim();
        if let Some(v) = l.strip_prefix("nameserver[").and_then(|r| r.split_once(':')).map(|x| x.1.trim()) {
            if !d.servers.iter().any(|s| s == v) {
                d.servers.push(v.to_string());
            }
        } else if let Some(v) = l.strip_prefix("search domain[").and_then(|r| r.split_once(':')).map(|x| x.1.trim()) {
            if !d.search.iter().any(|s| s == v) {
                d.search.push(v.to_string());
            }
        }
    }
    d
}

// ───────────────────────────── collection ─────────────────────────────

pub fn collect() -> (Vec<Route>, Vec<Neighbor>, Dns, Option<String>) {
    #[cfg(target_os = "linux")]
    {
        let mut routes = Vec::new();
        let mut err = None;
        match (run("ip", &["-j", "-4", "route", "show"]), run("ip", &["-j", "-6", "route", "show"])) {
            (Some(v4), v6) => {
                routes.extend(parse_ip_route_json(&v4, "inet"));
                if let Some(v6) = v6 {
                    routes.extend(parse_ip_route_json(&v6, "inet6"));
                }
            }
            _ => {
                routes = parse_proc_route(&std::fs::read_to_string("/proc/net/route").unwrap_or_default());
                err = Some("iproute2 (`ip`) not found: IPv4 routes only, no neighbour states".into());
            }
        }
        let neighbors = run("ip", &["-j", "neigh", "show"]).map(|t| parse_ip_neigh_json(&t)).unwrap_or_default();
        let mut dns = parse_resolv_conf(&std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default());
        if dns.servers.iter().all(|s| s.starts_with("127.0.0.53")) && !dns.servers.is_empty() {
            let up = parse_resolv_conf(&std::fs::read_to_string("/run/systemd/resolve/resolv.conf").unwrap_or_default());
            if !up.servers.is_empty() {
                dns.note = Some("systemd-resolved stub 127.0.0.53, upstream servers shown".into());
                dns.servers = up.servers;
            }
        }
        (routes, neighbors, dns, err)
    }
    #[cfg(target_os = "macos")]
    {
        let mut routes = run("netstat", &["-rn", "-f", "inet"]).map(|t| parse_netstat_rn(&t, "inet")).unwrap_or_default();
        routes.extend(run("netstat", &["-rn", "-f", "inet6"]).map(|t| parse_netstat_rn(&t, "inet6")).unwrap_or_default());
        let mut neighbors = run("arp", &["-an"]).map(|t| parse_arp_an(&t)).unwrap_or_default();
        neighbors.extend(run("ndp", &["-an"]).map(|t| parse_ndp_an(&t)).unwrap_or_default());
        let dns = run("scutil", &["--dns"]).map(|t| parse_scutil_dns(&t)).unwrap_or_default();
        (routes, neighbors, dns, None)
    }
    #[cfg(windows)]
    {
        use super::windows as w;
        let routes = run("route", &["print"]).map(|t| w::parse_route_print(&t)).unwrap_or_default();
        let neighbors = run("arp", &["-a"]).map(|t| w::parse_arp_a(&t)).unwrap_or_default();
        let dns = Dns { servers: run("ipconfig", &["/all"]).map(|t| w::parse_ipconfig_dns(&t)).unwrap_or_default(), ..Default::default() };
        (routes, neighbors, dns, None)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        (Vec::new(), Vec::new(), Dns::default(), Some("not supported on this OS".into()))
    }
}

pub fn spawn_worker(store: Arc<Mutex<NetInfo>>, active: Arc<AtomicBool>) {
    thread::spawn(move || {
        let mut last: Option<Instant> = None;
        loop {
            let due = match last {
                None => true,
                Some(t) => {
                    let iv = if active.load(Ordering::Relaxed) { 5 } else { 60 };
                    t.elapsed() >= Duration::from_secs(iv)
                }
            };
            if due {
                let (routes, neighbors, dns, error) = collect();
                if let Ok(mut s) = store.lock() {
                    s.routes = routes;
                    s.neighbors = neighbors;
                    s.dns = dns;
                    s.error = error;
                    s.updated = Some(Instant::now());
                    s.version += 1;
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
    fn ip_json() {
        let r = parse_ip_route_json(r#"[{"dst":"default","gateway":"10.0.0.1","dev":"eth0","protocol":"dhcp","metric":100,"flags":[]},{"dst":"10.0.0.0/24","dev":"eth0","protocol":"kernel","scope":"link","prefsrc":"10.0.0.5","flags":[]}]"#, "inet");
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].gateway, "10.0.0.1");
        assert_eq!(r[0].metric, "100");
        let ni = NetInfo { routes: r, ..Default::default() };
        assert_eq!(ni.default_gateways(), vec!["10.0.0.1"]);
        let n = parse_ip_neigh_json(r#"[{"dst":"10.0.0.1","dev":"eth0","lladdr":"aa:bb:cc:dd:ee:ff","state":["REACHABLE"]},{"dst":"10.0.0.9","dev":"eth0","state":["FAILED"]}]"#);
        assert_eq!(n[1].state, "FAILED");
        assert_eq!(n[0].mac, "aa:bb:cc:dd:ee:ff");
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn proc_route() {
        let t = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\neth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        let r = parse_proc_route(t);
        assert_eq!(r[0].dst, "default");
        assert_eq!(r[0].gateway, "10.0.0.1");
        assert_eq!(r[1].dst, "10.0.0.0/24");
    }

    #[test]
    fn mac_parsers() {
        let a = parse_arp_an("? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]\n? (192.168.1.77) at (incomplete) on en0 ifscope [ethernet]\n");
        assert_eq!(a[0].ip, "192.168.1.1");
        assert_eq!(a[1].state, "INCOMPLETE");
        let d = parse_scutil_dns("resolver #1\n  search domain[0] : corp.example\n  nameserver[0] : 10.0.0.53\n  nameserver[1] : 10.0.0.53\n");
        assert_eq!(d.servers, vec!["10.0.0.53"]);
        assert_eq!(d.search, vec!["corp.example"]);
        let r = parse_netstat_rn("Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\ndefault            192.168.1.1        UGScg                 en0\n", "inet");
        assert_eq!(r[0].gateway, "192.168.1.1");
        assert_eq!(r[0].dev, "en0");
    }

    /// Reads the real routing table of the machine running the tests
    /// (macOS locally, Linux x86_64/arm64 in CI).
    #[test]
    fn real_routing_table() {
        let store = Arc::new(Mutex::new(NetInfo::default()));
        spawn_worker(store.clone(), Arc::new(AtomicBool::new(true)));
        for _ in 0..60 {
            if store.lock().unwrap().updated.is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        let s = store.lock().unwrap();
        assert!(s.updated.is_some(), "netinfo never collected");
        assert!(!s.routes.is_empty(), "no routes read (error: {:?})", s.error);
    }

    #[test]
    fn ndp() {
        let t = "Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs\n2a00:d10::133                  a8:4a:63:5:e1:44     en7 permanent R\nfe80::1%en0                     0:11:22:33:44:55     en0 23h59m58s S  R\nfe80::9%en0                     (incomplete)     en0 expired I\nfe80::1%lo0                             (incomplete)         lo0 permanent R\n";
        let n = parse_ndp_an(t);
        assert_eq!(n.len(), 2);
        assert_eq!((n[0].ip.as_str(), n[0].state.as_str()), ("fe80::1%en0", "STALE"));
        assert_eq!(n[1].state, "INCOMPLETE");
    }

    #[test]
    fn resolv() {
        let d = parse_resolv_conf("# x\nnameserver 1.1.1.1\nnameserver 9.9.9.9\nsearch a.example b.example\n");
        assert_eq!(d.servers.len(), 2);
        assert_eq!(d.search, vec!["a.example", "b.example"]);
    }
}
