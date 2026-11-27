//! Layer 1 and 2: NIC error counters, LLDP neighbours and an ARP watch.
//!
//! * NIC counters: Linux `/sys/class/net/*/statistics` (CRC/FCS, frame,
//!   missed, FIFO, carrier errors, collisions) plus `carrier_changes` to spot
//!   flapping links; macOS `netstat -in` (input/output errors, collisions);
//!   Windows: the error totals sysinfo reads from GetIfTable2.
//! * LLDP: `lldpctl -f json` (lldpd) shows which switch and port each
//!   interface is plugged into, with VLAN and management address.
//! * ARP watch: remembers the MAC of every neighbour and records changes.
//!   A changed MAC for the default gateway is either a failover (VRRP/HSRP,
//!   replaced router) or ARP spoofing, so it raises a health badge.
//!
//! Runs on its own thread: every 2 s while the Troubleshoot view is open,
//! every 30 s otherwise (the ARP watch must keep running to catch changes).

#![allow(dead_code)] // parsers for other platforms are unit-tested on every OS

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use super::netinfo::Neighbor;
use crate::util::History;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct NicStats {
    pub name: String,
    pub oper: Option<String>,
    pub carrier: Option<bool>,
    pub speed_mbps: Option<u32>,
    pub duplex: Option<String>,
    pub mtu: Option<u32>,
    pub carrier_changes: Option<u64>,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    /// CRC/FCS errors: frames damaged on the wire.
    pub rx_crc: u64,
    /// Alignment / framing errors (runts, bad length).
    pub rx_frame: u64,
    /// Frames the NIC had to drop because the host didn't drain the ring.
    pub rx_missed: u64,
    pub rx_fifo: u64,
    pub rx_over: u64,
    pub tx_carrier: u64,
    pub tx_aborted: u64,
    pub collisions: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

impl NicStats {
    /// Errors that point at the physical layer (cable, optics, duplex).
    pub fn physical_errors(&self) -> u64 {
        self.rx_crc + self.rx_frame + self.tx_carrier + self.collisions
    }
    pub fn error_pct(&self) -> f64 {
        let p = (self.rx_packets + self.tx_packets).max(1) as f64;
        (self.rx_errors + self.tx_errors) as f64 / p * 100.0
    }
}

fn virtual_name(n: &str) -> bool {
    ["lo", "veth", "docker", "br-", "virbr", "vnet", "tun", "tap", "wg", "utun", "awdl", "llw", "gif", "stf", "anpi", "ap", "bridge", "cni", "flannel", "cali", "vxlan", "kube"].iter().any(|p| n.starts_with(p))
}

/// Physical-looking interfaces only.
pub fn is_physical(n: &str) -> bool {
    !virtual_name(n)
}

#[cfg(target_os = "linux")]
pub fn read_nics() -> Vec<NicStats> {
    let mut out = Vec::new();
    let Ok(dir) = std::fs::read_dir("/sys/class/net") else { return out };
    for e in dir.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let base = e.path();
        let rd = |f: &str| std::fs::read_to_string(base.join(f)).ok().map(|s| s.trim().to_string());
        let num = |f: &str| rd(f).and_then(|s| s.parse::<i64>().ok()).map(|v| v.max(0) as u64);
        let st = |f: &str| num(&format!("statistics/{f}")).unwrap_or(0);
        out.push(NicStats {
            oper: rd("operstate"),
            carrier: rd("carrier").map(|c| c == "1"),
            speed_mbps: num("speed").filter(|s| *s > 0 && *s < 1_000_000).map(|s| s as u32),
            duplex: rd("duplex").filter(|d| d != "unknown"),
            mtu: num("mtu").map(|m| m as u32),
            carrier_changes: num("carrier_changes"),
            rx_packets: st("rx_packets"),
            tx_packets: st("tx_packets"),
            rx_errors: st("rx_errors"),
            tx_errors: st("tx_errors"),
            rx_crc: st("rx_crc_errors"),
            rx_frame: st("rx_frame_errors") + st("rx_length_errors"),
            rx_missed: st("rx_missed_errors"),
            rx_fifo: st("rx_fifo_errors"),
            rx_over: st("rx_over_errors"),
            tx_carrier: st("tx_carrier_errors"),
            tx_aborted: st("tx_aborted_errors"),
            collisions: st("collisions"),
            rx_dropped: st("rx_dropped"),
            tx_dropped: st("tx_dropped"),
            name,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// macOS / BSD `netstat -in`: one `<Link#n>` row per interface carries the counters.
pub fn parse_netstat_in(text: &str) -> Vec<NicStats> {
    let mut out: Vec<NicStats> = Vec::new();
    let mut lines = text.lines();
    let Some(head) = lines.next() else { return out };
    let cols: Vec<&str> = head.split_whitespace().collect();
    let idx = |n: &str| cols.iter().position(|c| *c == n);
    let (Some(ip), Some(ie), Some(op), Some(oe)) = (idx("Ipkts"), idx("Ierrs"), idx("Opkts"), idx("Oerrs")) else { return out };
    let coll = idx("Coll");
    for l in lines {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 3 || !f[2].starts_with("<Link") {
            continue;
        }
        // Rows without a MAC address have one column less before the counters.
        let shift = if f.len() == cols.len() { 0 } else { cols.len() - f.len() };
        let get = |i: usize| i.checked_sub(shift).and_then(|i| f.get(i)).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        out.push(NicStats {
            name: f[0].trim_end_matches('*').to_string(),
            mtu: f[1].parse().ok(),
            rx_packets: get(ip),
            rx_errors: get(ie),
            tx_packets: get(op),
            tx_errors: get(oe),
            collisions: coll.map(get).unwrap_or(0),
            ..Default::default()
        });
    }
    out
}

#[cfg(not(target_os = "linux"))]
pub fn read_nics() -> Vec<NicStats> {
    if cfg!(target_os = "macos") {
        return std::process::Command::new("netstat")
            .arg("-in")
            .output()
            .ok()
            .map(|o| parse_netstat_in(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default();
    }
    // Windows and others: totals from sysinfo.
    let nets = sysinfo::Networks::new_with_refreshed_list();
    let mut v: Vec<NicStats> = nets
        .iter()
        .map(|(n, d)| NicStats {
            name: n.clone(),
            mtu: Some(d.mtu() as u32),
            rx_packets: d.total_packets_received(),
            tx_packets: d.total_packets_transmitted(),
            rx_errors: d.total_errors_on_received(),
            tx_errors: d.total_errors_on_transmitted(),
            ..Default::default()
        })
        .collect();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    v
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Lldp {
    pub local_port: String,
    pub chassis: String,
    pub port: String,
    pub port_descr: String,
    pub sys_descr: String,
    pub mgmt_ip: String,
    pub vlan: String,
}

fn s(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(a) => a.first().map(s).unwrap_or_default(),
        serde_json::Value::Object(o) => o.get("value").map(s).unwrap_or_default(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// `lldpctl -f json`. lldpd uses an object keyed by name when there is one
/// entry and an array of such objects when there are several.
pub fn parse_lldpctl_json(text: &str) -> Vec<Lldp> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else { return Vec::new() };
    let ifs = &v["lldp"]["interface"];
    let objs: Vec<&serde_json::Value> = match ifs {
        serde_json::Value::Array(a) => a.iter().collect(),
        o => vec![o],
    };
    let entries: Vec<(String, &serde_json::Value)> = objs.into_iter().filter_map(|o| o.as_object()).flat_map(|m| m.iter().map(|(k, v)| (k.clone(), v))).collect();
    entries
        .into_iter()
        .map(|(local, e)| {
            let ch = &e["chassis"];
            let (cname, cval) = ch.as_object().and_then(|m| m.iter().next()).map(|(k, v)| (k.clone(), v)).unwrap_or_default();
            let chassis = if cval.get("id").is_some() || cval.get("descr").is_some() { cname } else { s(&ch["name"]) };
            let chv = if cval.is_null() { ch } else { cval };
            let vlan = match &e["vlan"] {
                serde_json::Value::Array(a) => a.iter().map(|x| s(&x["vlan-id"])).collect::<Vec<_>>().join(","),
                v => s(&v["vlan-id"]),
            };
            Lldp {
                local_port: local,
                chassis,
                port: s(&e["port"]["id"]),
                port_descr: s(&e["port"]["descr"]),
                sys_descr: s(&chv["descr"]).lines().next().unwrap_or("").to_string(),
                mgmt_ip: s(&chv["mgmt-ip"]),
                vlan,
            }
        })
        .collect()
}

#[derive(Clone, Debug)]
pub struct ArpChange {
    pub at: SystemTime,
    pub ip: String,
    pub old_mac: String,
    pub new_mac: String,
    pub dev: String,
    pub gateway: bool,
}

#[derive(Default)]
pub struct ArpWatch {
    known: HashMap<String, String>,
    pub changes: Vec<ArpChange>,
}

fn norm_mac(m: &str) -> String {
    m.split([':', '-']).map(|p| format!("{:0>2}", p.to_ascii_lowercase())).collect::<Vec<_>>().join(":")
}

impl ArpWatch {
    /// Feed the current neighbour table; returns how many new changes were recorded.
    pub fn observe(&mut self, neighbors: &[Neighbor], gateways: &[String]) -> usize {
        let mut n = 0;
        for nb in neighbors.iter().filter(|nb| !nb.mac.is_empty() && nb.mac != "00:00:00:00:00:00") {
            let mac = norm_mac(&nb.mac);
            match self.known.get(&nb.ip) {
                Some(old) if *old != mac => {
                    self.changes.push(ArpChange {
                        at: SystemTime::now(),
                        ip: nb.ip.clone(),
                        old_mac: old.clone(),
                        new_mac: mac.clone(),
                        dev: nb.dev.clone(),
                        gateway: gateways.iter().any(|g| g.split('%').next() == Some(nb.ip.as_str())),
                    });
                    n += 1;
                }
                _ => {}
            }
            self.known.insert(nb.ip.clone(), mac);
        }
        if self.changes.len() > 200 {
            self.changes.drain(..self.changes.len() - 200);
        }
        n
    }

    /// IPs sharing one MAC (besides the gateway's own): proxy ARP or spoofing.
    pub fn shared_macs(&self) -> Vec<(String, Vec<String>)> {
        let mut by_mac: HashMap<&str, Vec<String>> = HashMap::new();
        for (ip, mac) in &self.known {
            if ip.contains('.') {
                by_mac.entry(mac).or_default().push(ip.clone());
            }
        }
        let mut v: Vec<(String, Vec<String>)> = by_mac.into_iter().filter(|(_, ips)| ips.len() > 1).map(|(m, mut ips)| {
            ips.sort();
            (m.to_string(), ips)
        }).collect();
        v.sort();
        v
    }
}

#[derive(Default)]
pub struct L2Store {
    pub nics: Vec<NicStats>,
    /// Per-second error rate per interface (all error counters summed).
    pub err_rate: HashMap<String, f64>,
    pub err_hist: HashMap<String, History>,
    pub lldp: Vec<Lldp>,
    pub lldp_note: Option<String>,
    pub arp: ArpWatch,
    /// Connected Wi-Fi links (refreshed every 15 s while the view is open).
    pub wifi: Vec<super::wifi::Wifi>,
    /// Roaming events: (when, text).
    pub wifi_events: Vec<(SystemTime, String)>,
    pub updated: Option<Instant>,
    pub version: u64,
}

impl L2Store {
    /// Gateway MAC changes in the last hour.
    pub fn gateway_changes(&self) -> usize {
        let now = SystemTime::now();
        self.arp.changes.iter().filter(|c| c.gateway && now.duration_since(c.at).map(|d| d < Duration::from_secs(3600)).unwrap_or(true)).count()
    }
}

fn lldp_once() -> (Vec<Lldp>, Option<String>) {
    if !crate::platform::get().tools.lldpctl {
        return (Vec::new(), Some(if cfg!(target_os = "linux") { "install lldpd to see the switch and port you're plugged into" } else { "LLDP needs lldpd (Linux)" }.into()));
    }
    match std::process::Command::new("lldpctl").args(["-f", "json"]).output() {
        Ok(o) if o.status.success() => {
            let v = parse_lldpctl_json(&String::from_utf8_lossy(&o.stdout));
            let note = v.is_empty().then(|| "no LLDP neighbours (switch doesn't send LLDP, or lldpd just started)".to_string());
            (v, note)
        }
        Ok(o) => (Vec::new(), Some(String::from_utf8_lossy(&o.stderr).lines().next().unwrap_or("lldpctl failed (is lldpd running? try sudo)").to_string())),
        Err(e) => (Vec::new(), Some(format!("lldpctl: {e}"))),
    }
}

pub fn spawn_worker(store: Arc<Mutex<L2Store>>, netinfo: Arc<Mutex<super::netinfo::NetInfo>>, active: Arc<AtomicBool>) {
    crate::util::spawn_named("link-layer", move || {
        let mut last: Option<Instant> = None;
        let mut last_lldp: Option<Instant> = None;
        let mut prev: HashMap<String, u64> = HashMap::new();
        let mut net_version = 0u64;
        // Wi-Fi is slow to read on macOS (~5 s): its own poller, only while the view is open.
        let act = active.clone();
        let wifi_poll = crate::util::Poller::spawn(Duration::from_secs(15), move || act.load(Ordering::Relaxed).then(super::wifi::read));
        let mut wifi_seen = 0u64;
        loop {
            if let Some((_, seq, links)) = wifi_poll.latest(wifi_seen) {
                wifi_seen = seq;
                if let Ok(mut s) = store.lock() {
                    for w in &links {
                        if let Some(old) = s.wifi.iter().find(|o| o.iface == w.iface) {
                            let what = if !w.bssid.is_empty() && !old.bssid.is_empty() && w.bssid != old.bssid {
                                Some(format!("{}: roamed {} → {}", w.iface, old.bssid, w.bssid))
                            } else if w.channel != old.channel && !old.channel.is_empty() {
                                Some(format!("{}: channel {} → {}", w.iface, old.channel, w.channel))
                            } else {
                                None
                            };
                            if let Some(t) = what {
                                s.wifi_events.push((SystemTime::now(), t));
                                if s.wifi_events.len() > 50 {
                                    s.wifi_events.remove(0);
                                }
                            }
                        }
                    }
                    s.wifi = links;
                    s.version += 1;
                }
            }
            let on = active.load(Ordering::Relaxed);
            let iv = if on { 2 } else { 30 };
            if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(iv)) {
                let dt = last.map(|t| t.elapsed().as_secs_f64()).unwrap_or(1.0).max(0.1);
                let nics = read_nics();
                let lldp = if on && last_lldp.is_none_or(|t| t.elapsed() >= Duration::from_secs(30)) {
                    last_lldp = Some(Instant::now());
                    Some(lldp_once())
                } else {
                    None
                };
                let (neigh, gws, nv) = netinfo.lock().map(|n| (n.neighbors.clone(), n.default_gateways(), n.version)).unwrap_or_default();
                if let Ok(mut s) = store.lock() {
                    for n in &nics {
                        let total = n.rx_errors + n.tx_errors + n.rx_crc + n.rx_missed;
                        let p = prev.insert(n.name.clone(), total).unwrap_or(total);
                        let r = total.saturating_sub(p) as f64 / dt;
                        s.err_rate.insert(n.name.clone(), r);
                        s.err_hist.entry(n.name.clone()).or_insert_with(|| History::new(120)).push(r);
                    }
                    s.nics = nics;
                    if let Some((l, note)) = lldp {
                        s.lldp = l;
                        s.lldp_note = note;
                    }
                    if nv != net_version {
                        net_version = nv;
                        s.arp.observe(&neigh, &gws);
                    }
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
    fn netstat_in() {
        let t = "Name       Mtu   Network       Address            Ipkts Ierrs    Opkts Oerrs  Coll\nlo0        16384 <Link#1>                          6962     0     6962     0     0\nlo0        16384 127           127.0.0.1           6962     -     6962     -     -\nen0        1500  <Link#11>   a4:83:e7:12:34:56   901234    12   456789     3     0\n";
        let v = parse_netstat_in(t);
        assert_eq!(v.len(), 2);
        assert_eq!(v[1].name, "en0");
        assert_eq!((v[1].rx_packets, v[1].rx_errors, v[1].tx_packets, v[1].tx_errors), (901234, 12, 456789, 3));
        assert_eq!(v[0].rx_packets, 6962);
    }

    #[test]
    fn lldp_json_single_and_multi() {
        let one = r#"{"lldp":{"interface":{"eth0":{"via":"LLDP","chassis":{"sw-core-1":{"id":{"type":"mac","value":"00:11:22:33:44:55"},"descr":"Juniper Networks, Inc. ex4300-48t\nJUNOS 21.4R3","mgmt-ip":"10.0.0.2"}},"port":{"id":{"type":"ifname","value":"ge-0/0/12"},"descr":"server-rack3","ttl":"120"},"vlan":{"vlan-id":"10","pvid":true}}}}}"#;
        let v = parse_lldpctl_json(one);
        assert_eq!(v[0], Lldp { local_port: "eth0".into(), chassis: "sw-core-1".into(), port: "ge-0/0/12".into(), port_descr: "server-rack3".into(), sys_descr: "Juniper Networks, Inc. ex4300-48t".into(), mgmt_ip: "10.0.0.2".into(), vlan: "10".into() });
        let many = r#"{"lldp":{"interface":[{"eth0":{"chassis":{"a":{"id":{"value":"x"}}},"port":{"id":{"value":"1"}}}},{"eth1":{"chassis":{"b":{"id":{"value":"y"}}},"port":{"id":{"value":"2"}},"vlan":[{"vlan-id":"10"},{"vlan-id":"20"}]}}]}}"#;
        let v = parse_lldpctl_json(many);
        assert_eq!(v.len(), 2);
        assert_eq!(v[1].chassis, "b");
        assert_eq!(v[1].vlan, "10,20");
    }

    #[test]
    fn arp_watch_flags_gateway_mac_change() {
        let nb = |ip: &str, mac: &str| Neighbor { ip: ip.into(), mac: mac.into(), dev: "eth0".into(), state: "REACHABLE".into() };
        let mut w = ArpWatch::default();
        let gws = vec!["10.0.0.1".to_string()];
        assert_eq!(w.observe(&[nb("10.0.0.1", "0:11:22:33:44:55"), nb("10.0.0.9", "aa:aa:aa:aa:aa:aa")], &gws), 0);
        assert_eq!(w.observe(&[nb("10.0.0.1", "00:11:22:33:44:55")], &gws), 0, "same MAC, different notation");
        assert_eq!(w.observe(&[nb("10.0.0.1", "aa:aa:aa:aa:aa:aa")], &gws), 1);
        assert!(w.changes[0].gateway);
        assert_eq!(w.shared_macs(), vec![("aa:aa:aa:aa:aa:aa".to_string(), vec!["10.0.0.1".to_string(), "10.0.0.9".to_string()])]);
    }
}
