//! `vigil doctor`: walk the OSI layers bottom-up and say where it breaks.
//!
//! The order matters: a failing layer usually explains every failure above
//! it, so the verdict names the *lowest* failing layer as the place to start,
//! the way you would troubleshoot by hand (cable → ARP → IP → TCP → TLS → DNS
//! → app). Every finding carries a one-line explanation and the next command
//! to run, including the Junos / Cisco equivalent where one exists.

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;

use super::{dnsq, mark, mtu, Settings, Tone};
use crate::collect::l2;
use crate::collect::netinfo;
use crate::collect::probes::{self, Target};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Info,
    Warn,
    Fail,
    Skip,
}

impl Status {
    fn tone(self) -> Tone {
        match self {
            Status::Pass => Tone::Good,
            Status::Warn => Tone::Warn,
            Status::Fail => Tone::Bad,
            Status::Info | Status::Skip => Tone::Dim,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Check {
    pub layer: u8,
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
    /// What it means and what to run next (empty when all is well).
    pub hint: String,
}

pub const LAYERS: [&str; 8] = ["", "Physical", "Data link", "Network", "Transport", "Session / TLS", "Presentation", "Application"];

struct Run<'a> {
    checks: Vec<Check>,
    layer: u8,
    emit: &'a dyn Fn(Tone, String),
}

impl Run<'_> {
    fn add(&mut self, layer: u8, name: &'static str, status: Status, detail: impl Into<String>, hint: impl Into<String>) {
        if layer != self.layer {
            self.layer = layer;
            (self.emit)(Tone::Head, format!("L{layer} · {}", LAYERS[layer as usize]));
        }
        let (detail, hint) = (detail.into(), hint.into());
        (self.emit)(status.tone(), format!("  {} {name:<18} {detail}", mark(status.tone())));
        if !hint.is_empty() && status != Status::Pass {
            (self.emit)(Tone::Dim, format!("      → {hint}"));
        }
        self.checks.push(Check { layer, name, status, detail, hint });
    }
}

/// `n` pings, 150 ms apart: (loss %, avg ms, max ms) or the error of the last try.
fn ping_series(ip: IpAddr, n: usize) -> Result<(f64, f64, f64), String> {
    let mut rtts = Vec::new();
    let mut last_err = String::new();
    for i in 0..n {
        if i > 0 {
            std::thread::sleep(Duration::from_millis(150));
        }
        match probes::run_once(&Target::Icmp(ip)) {
            Ok(o) => rtts.push(o.ms),
            Err(e) => {
                if e.contains("not permitted") {
                    return Err(e);
                }
                last_err = e;
            }
        }
    }
    if rtts.is_empty() {
        return Err(if last_err.is_empty() { "timeout".into() } else { last_err });
    }
    let loss = (n - rtts.len()) as f64 / n as f64 * 100.0;
    let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
    Ok((loss, avg, rtts.iter().copied().fold(0.0, f64::max)))
}

/// `Date: Wed, 26 Nov 2026 10:00:00 GMT` → seconds since the epoch.
pub fn parse_http_date(v: &str) -> Option<i64> {
    let f: Vec<&str> = v.split_whitespace().collect();
    let (d, m, y, t) = (f.get(1)?.parse::<u32>().ok()?, *f.get(2)?, f.get(3)?.parse::<i64>().ok()?, f.get(4)?);
    let month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].iter().position(|x| x.eq_ignore_ascii_case(m))? as u32 + 1;
    let mut tp = t.split(':').map(|x| x.parse::<i64>().ok());
    let (h, mi, s) = (tp.next()??, tp.next()??, tp.next()??);
    Some(crate::util::days_from_civil(y, month, d) * 86_400 + h * 3600 + mi * 60 + s)
}

struct Http {
    status: u16,
    connect_ms: f64,
    tls_ms: f64,
    ttfb_ms: f64,
    date: Option<i64>,
    cert_days: Option<i64>,
    proxy: bool,
}

fn http_check(url: &str) -> Result<Http, String> {
    if !crate::platform::get().tools.curl {
        return Err("curl not found".into());
    }
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let o = std::process::Command::new("curl")
        .args(["-sS", "-v", "-o", null, "-D", "-", "--max-time", "8", "-w", "\nVIGIL %{http_code} %{time_connect} %{time_appconnect} %{time_starttransfer}\n", url])
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    let out = String::from_utf8_lossy(&o.stdout);
    let err = String::from_utf8_lossy(&o.stderr);
    if !o.status.success() {
        return Err(err.lines().rfind(|l| l.starts_with("curl:")).unwrap_or("request failed").trim_start_matches("curl: ").to_string());
    }
    let w = out.lines().rfind(|l| l.starts_with("VIGIL ")).ok_or("no timing from curl")?;
    let f: Vec<f64> = w.split_whitespace().skip(1).map(|x| x.parse().unwrap_or(0.0)).collect();
    let date = out.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("date")).and_then(|(_, v)| parse_http_date(v.trim())));
    Ok(Http {
        status: f.first().copied().unwrap_or(0.0) as u16,
        connect_ms: f.get(1).copied().unwrap_or(0.0) * 1000.0,
        tls_ms: (f.get(2).copied().unwrap_or(0.0) - f.get(1).copied().unwrap_or(0.0)).max(0.0) * 1000.0,
        ttfb_ms: f.get(3).copied().unwrap_or(0.0) * 1000.0,
        date,
        cert_days: probes::cert_days(&err, SystemTime::now()),
        proxy: err.contains("Uses proxy env") || err.contains("via proxy"),
    })
}

fn is_link_local4(a: &str) -> bool {
    a.starts_with("169.254.")
}

pub fn run(cfg: &Settings, emit: &dyn Fn(Tone, String)) -> Vec<Check> {
    let started = Instant::now();
    let mut r = Run { checks: Vec::new(), layer: 0, emit };
    let mut kn = crate::collect::kernelnet::KernelNet::new();
    kn.refresh();
    emit(Tone::Head, format!("vigil doctor · {}", crate::platform::get().summary()));

    // ── L1 Physical
    let nets = sysinfo::Networks::new_with_refreshed_list();
    let mut addrs: Vec<(String, IpAddr)> = Vec::new();
    for (name, d) in nets.iter() {
        for n in d.ip_networks() {
            if !n.addr.is_loopback() {
                addrs.push((name.clone(), n.addr));
            }
        }
    }
    let nics = l2::read_nics();
    let phys: Vec<&l2::NicStats> = nics.iter().filter(|n| l2::is_physical(&n.name) && (addrs.iter().any(|a| a.0 == n.name) || n.carrier == Some(true))).collect();
    if cfg!(target_os = "linux") {
        let up: Vec<String> = phys
            .iter()
            .filter(|n| n.carrier == Some(true))
            .map(|n| format!("{}{}{}", n.name, n.speed_mbps.map(|s| format!(" {s} Mb/s")).unwrap_or_default(), n.duplex.as_ref().map(|d| format!(" {d}")).unwrap_or_default()))
            .collect();
        let down: Vec<&str> = nics.iter().filter(|n| l2::is_physical(&n.name) && n.oper.as_deref() == Some("down") && n.carrier == Some(false)).map(|n| n.name.as_str()).collect();
        if up.is_empty() {
            r.add(1, "Link", Status::Fail, format!("no interface has carrier{}", if down.is_empty() { String::new() } else { format!(" ({} down)", down.join(", ")) }), "check the cable / Wi-Fi association and `ip link`; on the switch: show interfaces terse (Junos) · show interface status (Cisco)");
        } else if let Some(h) = phys.iter().find(|n| n.duplex.as_deref() == Some("half")) {
            r.add(1, "Link", Status::Warn, format!("{} is half duplex", h.name), "half duplex on a switched network almost always means an autonegotiation mismatch: set both ends to auto (ethtool -s IF autoneg on)");
        } else {
            r.add(1, "Link", Status::Pass, up.join(" · "), "");
        }
    } else if addrs.iter().any(|a| l2::is_physical(&a.0)) {
        let mut names: Vec<&str> = addrs.iter().filter(|a| l2::is_physical(&a.0)).map(|a| a.0.as_str()).collect();
        names.dedup();
        r.add(1, "Link", Status::Pass, format!("{} {} an address", names.join(", "), if names.len() == 1 { "has" } else { "have" }), "");
    } else {
        r.add(1, "Link", Status::Fail, "no physical interface has an address", "check the cable or Wi-Fi connection");
    }
    let mut err_lines = Vec::new();
    let mut worst = Status::Pass;
    for n in &phys {
        let mut parts = Vec::new();
        if n.rx_crc > 0 {
            parts.push(format!("{} CRC", n.rx_crc));
        }
        if n.rx_frame > 0 {
            parts.push(format!("{} frame", n.rx_frame));
        }
        if n.collisions > 0 {
            parts.push(format!("{} collisions", n.collisions));
        }
        if n.tx_carrier > 0 {
            parts.push(format!("{} carrier", n.tx_carrier));
        }
        if n.rx_missed + n.rx_fifo + n.rx_over > 0 {
            parts.push(format!("{} missed/overrun", n.rx_missed + n.rx_fifo + n.rx_over));
        }
        if parts.is_empty() && n.rx_errors + n.tx_errors > 0 {
            parts.push(format!("{} errors ({:.3} %)", n.rx_errors + n.tx_errors, n.error_pct()));
        }
        if let Some(c) = n.carrier_changes.filter(|c| *c > 10) {
            parts.push(format!("link flapped {} times", c / 2));
        }
        if !parts.is_empty() {
            let bad = n.physical_errors() > 0 && n.error_pct() > 0.01;
            if bad || n.carrier_changes.unwrap_or(0) > 10 {
                worst = Status::Warn;
            } else if worst == Status::Pass {
                worst = Status::Info;
            }
            err_lines.push(format!("{}: {}", n.name, parts.join(", ")));
        }
    }
    if err_lines.is_empty() {
        r.add(1, "NIC errors", Status::Pass, "no CRC, frame, collision or carrier errors", "");
    } else {
        r.add(
            1,
            "NIC errors",
            worst,
            err_lines.join(" · "),
            "CRC/frame errors are damage on the wire: bad cable, dirty fibre or SFP, EMI, or a duplex mismatch. Missed/overrun = the host is too slow to drain the NIC ring (ethtool -G). Switch side: show interfaces IF extensive (Junos) · show interfaces counters errors (Cisco)",
        );
    }

    // ── L2 Data link
    let (routes, _, dns, _) = netinfo::collect();
    let ni = netinfo::NetInfo { routes, dns, ..Default::default() };
    let gws = ni.default_gateways();
    let gw4: Option<IpAddr> = gws.iter().filter_map(|g| g.parse::<IpAddr>().ok()).find(|g| g.is_ipv4());
    if let Some(gw) = gw4 {
        // One ping makes sure the gateway is in the ARP cache.
        let _ = probes::run_once(&Target::Icmp(gw));
        let (_, neigh, _, _) = netinfo::collect();
        match neigh.iter().find(|n| n.ip == gw.to_string()) {
            None if neigh.is_empty() => r.add(2, "Gateway MAC", Status::Skip, "neighbour table is empty or unreadable", ""),
            Some(n) if !n.mac.is_empty() && n.state != "FAILED" && n.state != "INCOMPLETE" => r.add(2, "Gateway MAC", Status::Pass, format!("{gw} is at {} on {}", n.mac, n.dev), ""),
            Some(n) => r.add(2, "Gateway MAC", Status::Fail, format!("{gw}: ARP {}", n.state.to_ascii_lowercase()), "the gateway does not answer ARP: wrong VLAN on the switch port, gateway down, or a port-security / DAI block. Switch: show ethernet-switching table (Junos) · show mac address-table (Cisco)"),
            None => r.add(2, "Gateway MAC", Status::Warn, format!("{gw} not in the neighbour table"), "no ARP entry for the gateway: run `arp -a` / `ip neigh` after a ping; the gateway may be on another VLAN"),
        }
    } else {
        r.add(2, "Gateway MAC", Status::Skip, "no IPv4 gateway to look up", "");
    }
    let (lldp, note) = if crate::platform::get().tools.lldpctl {
        std::process::Command::new("lldpctl")
            .args(["-f", "json"])
            .output()
            .ok()
            .map(|o| (l2::parse_lldpctl_json(&String::from_utf8_lossy(&o.stdout)), None))
            .unwrap_or_default()
    } else {
        (Vec::new(), Some("lldpd not installed".to_string()))
    };
    if lldp.is_empty() {
        r.add(2, "LLDP neighbour", Status::Skip, note.unwrap_or_else(|| "none seen".into()), "LLDP shows the switch and port you're plugged into (Linux: install lldpd · switch: show lldp neighbors)");
    } else {
        let d = lldp.iter().map(|l| format!("{} ↔ {} {}{}", l.local_port, l.chassis, l.port, if l.vlan.is_empty() { String::new() } else { format!(" vlan {}", l.vlan) })).collect::<Vec<_>>().join(" · ");
        r.add(2, "LLDP neighbour", Status::Pass, d, "");
    }

    // ── L3 Network
    let v4: Vec<String> = addrs.iter().filter(|a| a.1.is_ipv4()).map(|a| format!("{} {}", a.0, a.1)).collect();
    let usable4 = addrs.iter().any(|a| a.1.is_ipv4() && !is_link_local4(&a.1.to_string()));
    if usable4 {
        r.add(3, "IPv4 address", Status::Pass, v4.into_iter().filter(|a| !a.contains(" 169.254.")).take(4).collect::<Vec<_>>().join(" · "), "");
    } else if !v4.is_empty() {
        r.add(3, "IPv4 address", Status::Fail, v4.join(" · "), "169.254.x.x (APIPA) means DHCP never answered: check the DHCP server / relay (Junos: show dhcp relay binding · Cisco: ip helper-address) and the switch port VLAN");
    } else {
        r.add(3, "IPv4 address", Status::Fail, "no IPv4 address", "no address configured: DHCP client not running, or static config missing");
    }
    match gw4 {
        Some(gw) => r.add(3, "Default route", Status::Pass, format!("via {gw}{}", if gws.len() > 1 { format!(" (+{} more)", gws.len() - 1) } else { String::new() }), ""),
        None => r.add(3, "Default route", Status::Fail, "no IPv4 default route", "without a default route only the local subnet is reachable: DHCP option 3 missing or static route not set (ip route add default via GW · route add 0.0.0.0 mask 0.0.0.0 GW)"),
    }
    let mut icmp_blocked = false;
    let mut gw_ok = false;
    if let Some(gw) = gw4 {
        match ping_series(gw, 5) {
            Ok((loss, avg, max)) => {
                gw_ok = loss < 100.0;
                let d = format!("{gw}: {loss:.0} % loss · avg {avg:.1} ms · max {max:.1} ms");
                if loss > 0.0 {
                    r.add(3, "Gateway ping", Status::Warn, d, "loss to the first hop is local: Wi-Fi interference, a congested uplink, a duplex mismatch, or a busy router control plane (routers rate-limit ICMP to themselves)");
                } else if avg > 15.0 {
                    r.add(3, "Gateway ping", Status::Warn, d, "more than 15 ms to the gateway on a LAN points at Wi-Fi or a saturated link (bufferbloat): compare while idle");
                } else {
                    r.add(3, "Gateway ping", Status::Pass, d, "");
                }
            }
            Err(e) if e.contains("not permitted") => {
                icmp_blocked = true;
                r.add(3, "Gateway ping", Status::Skip, e, "");
            }
            Err(e) => r.add(3, "Gateway ping", Status::Fail, format!("{gw}: {e}"), "the gateway does not answer ICMP: it may filter ping, or it is down (check L2 above)"),
        }
    }
    let inet: Option<IpAddr> = cfg.internet4.parse().ok();
    let mut inet_ok = false;
    if let Some(ip) = inet.filter(|_| !icmp_blocked) {
        match ping_series(ip, 5) {
            Ok((loss, avg, max)) => {
                inet_ok = loss < 100.0;
                let d = format!("{ip}: {loss:.0} % loss · avg {avg:.1} ms · max {max:.1} ms");
                if loss > 0.0 {
                    r.add(3, "Internet ping", Status::Warn, d, if gw_ok { "loss beyond the gateway: the uplink or ISP. Run a trace (Probes view, t) or `mtr` to see the hop where it starts" } else { "loss already starts at the gateway (see above)" });
                } else {
                    r.add(3, "Internet ping", Status::Pass, d, "");
                }
            }
            Err(e) => r.add(3, "Internet ping", if gw_ok { Status::Fail } else { Status::Warn }, format!("{ip}: {e}"), "the gateway answers but the internet doesn't: NAT, upstream routing or the ISP; or ICMP is filtered (the TCP test below tells)"),
        }
    }
    if let Some(ip) = inet.filter(|_| inet_ok) {
        let res = mtu::discover(&ip.to_string(), &|_, _| {});
        match res.path_mtu {
            Some(m) if res.black_hole => r.add(3, "Path MTU", Status::Warn, format!("{m} · {} · no ICMP \"frag needed\" seen", mtu::explain(m)), "PMTU black hole: big packets vanish silently, so TLS/SSH hang after connecting. Clamp TCP MSS on the router (Junos: set security flow tcp-mss all-tcp mss 1360 · Cisco: ip tcp adjust-mss 1360) or permit ICMP type 3 code 4"),
            Some(m) if m < res.local_mtu.unwrap_or(1500) => r.add(3, "Path MTU", Status::Info, format!("{m} · {}", mtu::explain(m)), "smaller than the interface MTU, but routers report it, so TCP adapts"),
            Some(m) => r.add(3, "Path MTU", Status::Pass, format!("{m} · {}", mtu::explain(m)), ""),
            None => r.add(3, "Path MTU", Status::Skip, "could not measure", ""),
        }
    }
    let g6 = addrs.iter().filter(|a| matches!(a.1, IpAddr::V6(v) if v.segments()[0] & 0xe000 == 0x2000)).count();
    let r6 = ni.routes.iter().any(|x| x.family == "inet6" && (x.dst == "default" || x.dst == "::/0"));
    if g6 == 0 {
        r.add(3, "IPv6", Status::Info, "no global IPv6 address", "");
    } else if let Some(ip6) = cfg.internet6.parse::<IpAddr>().ok().filter(|_| r6 && !icmp_blocked) {
        match ping_series(ip6, 3) {
            Ok((loss, avg, _)) => r.add(3, "IPv6", if loss > 0.0 { Status::Warn } else { Status::Pass }, format!("{g6} global address(es) · {ip6}: {loss:.0} % loss · {avg:.1} ms"), "IPv6 loss while IPv4 is clean: check RA / the IPv6 firewall (ICMPv6 must not be blocked)"),
            Err(e) => r.add(3, "IPv6", Status::Warn, format!("{g6} global address(es), but {ip6}: {e}"), "broken IPv6 makes clients wait for the IPv4 fallback (Happy Eyeballs): fix the route/firewall or stop advertising the prefix"),
        }
    } else {
        r.add(3, "IPv6", Status::Info, format!("{g6} global address(es){}", if r6 { "" } else { ", no IPv6 default route" }), "");
    }

    // ── L4 Transport
    if let Some(ip) = inet {
        let t0 = Instant::now();
        match TcpStream::connect_timeout(&SocketAddr::new(ip, 443), Duration::from_secs(3)) {
            Ok(_) => r.add(4, "TCP connect", Status::Pass, format!("{ip}:443 in {:.1} ms{}", t0.elapsed().as_secs_f64() * 1000.0, if !inet_ok && !icmp_blocked { " (ICMP is filtered, TCP works)" } else { "" }), ""),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => r.add(4, "TCP connect", Status::Warn, format!("{ip}:443 refused"), "a RST came back: the path works but something actively rejects 443 (a firewall sending resets?)"),
            Err(e) => r.add(4, "TCP connect", Status::Fail, format!("{ip}:443: {e}"), "outbound TCP is dropped: a firewall or proxy-only network (corporate networks often allow only the web proxy). Check `vigil` Firewall view and HTTPS_PROXY"),
        }
    }

    // ── L5/6 Session, TLS and clock
    let http = http_check(&cfg.http_url);
    let mut tcp_health = |r: &mut Run| {
        kn.refresh();
        if let Some(c) = &kn.counters {
            let mut parts = vec![format!("retransmits {:.2} %", c.retrans_pct)];
            if c.listen_drop_rate > 0.0 {
                parts.push(format!("listen drops {:.1}/s", c.listen_drop_rate));
            }
            if c.udp_rcvbuf_err_rate > 0.0 {
                parts.push(format!("UDP buffer drops {:.1}/s", c.udp_rcvbuf_err_rate));
            }
            let bad = c.retrans_pct > 2.0 && c.out_segs_rate > 50.0;
            r.add(4, "TCP health", if bad || c.listen_drop_rate > 0.0 { Status::Warn } else { Status::Pass }, parts.join(" · "), "retransmits above ~2 % mean loss or congestion somewhere on the path; listen drops = an application can't accept() fast enough (raise its backlog / somaxconn)");
        }
    };
    tcp_health(&mut r);
    match &http {
        Ok(h) => {
            if let Some(d) = h.date {
                let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
                let skew = now - d;
                let st = if skew.abs() > 300 { Status::Fail } else if skew.abs() > 60 { Status::Warn } else { Status::Pass };
                let d = if skew.abs() <= 2 {
                    "in sync with the web server (±2 s)".to_string()
                } else {
                    let a = skew.unsigned_abs();
                    let t = if a < 120 { format!("{a} s") } else if a < 7200 { format!("{} min", a / 60) } else { format!("{:.1} h", a as f64 / 3600.0) };
                    format!("local clock is {t} {} the web server", if skew > 0 { "ahead of" } else { "behind" })
                };
                r.add(5, "Clock", st, d, "TLS certificates, Kerberos / Active Directory and one-time codes break with clock skew: check NTP (timedatectl · w32tm /query /status · sntp -sS time.apple.com)");
            }
            let tls = cfg.http_url.starts_with("https");
            if tls {
                let d = format!("handshake {:.0} ms{}", h.tls_ms, h.cert_days.map(|c| format!(" · certificate valid {c} more days")).unwrap_or_default());
                r.add(5, "TLS", Status::Pass, d, "");
            }
        }
        Err(e) => {
            let low = e.to_ascii_lowercase();
            if low.contains("certificate") || low.contains("ssl") || low.contains("tls") {
                r.add(5, "TLS", Status::Fail, e.clone(), "the certificate chain does not verify: a TLS-inspecting proxy (install its CA), a wrong clock, or an outdated CA bundle");
            } else {
                r.add(5, "TLS", Status::Skip, e.clone(), "");
            }
        }
    }

    // ── L7 Application: DNS and HTTP
    let t0 = Instant::now();
    match dnsq::system_lookup(&cfg.dns_name) {
        Ok(v) => r.add(7, "System resolver", if t0.elapsed() > Duration::from_millis(500) { Status::Warn } else { Status::Pass }, format!("{} → {} in {:.0} ms", cfg.dns_name, v.first().cloned().unwrap_or_default(), t0.elapsed().as_secs_f64() * 1000.0), "slow lookups: the first resolver times out before the next one answers (see below)"),
        Err(e) => r.add(7, "System resolver", Status::Fail, format!("{}: {e}", cfg.dns_name), if inet_ok { "IP works but names don't: the resolvers below are down or unreachable, or /etc/resolv.conf (Windows: ipconfig /all) points at the wrong server" } else { "probably caused by the network problem above" }),
    }
    let mut dns_lines = Vec::new();
    let mut dns_bad = 0;
    for s in ni.dns.servers.iter().take(4) {
        let Ok(ip) = s.parse::<IpAddr>() else { continue };
        match dnsq::query(ip, &cfg.dns_name, 1, Duration::from_secs(2)) {
            Ok(resp) if resp.rcode == 0 => dns_lines.push(format!("{ip} {:.0} ms", resp.ms)),
            Ok(resp) => {
                dns_bad += 1;
                dns_lines.push(format!("{ip} {}", dnsq::rcode_name(resp.rcode)));
            }
            Err(e) => {
                dns_bad += 1;
                dns_lines.push(format!("{ip} {e}"));
            }
        }
    }
    if dns_lines.is_empty() {
        r.add(7, "DNS servers", Status::Info, if ni.dns.note.is_some() { "resolver behind a local stub" } else { "no resolvers found" }, "");
    } else {
        r.add(7, "DNS servers", if dns_bad == 0 { Status::Pass } else { Status::Warn }, dns_lines.join(" · "), "a resolver that doesn't answer costs every lookup its timeout: remove it or fix it. Compare all resolvers with the DNS tool (n) or `vigil dns NAME`");
    }
    match &http {
        Ok(h) => {
            let ok = (200..400).contains(&h.status);
            r.add(7, "HTTP", if ok { Status::Pass } else { Status::Warn }, format!("{} → {} · connect {:.0} ms · first byte {:.0} ms{}", cfg.http_url, h.status, h.connect_ms, h.ttfb_ms, if h.proxy { " · via proxy" } else { "" }), "the server answered with an error status");
        }
        Err(e) => r.add(7, "HTTP", Status::Fail, format!("{}: {e}", cfg.http_url), "no HTTP answer: see the lowest failing layer above"),
    }
    let proxies: Vec<String> = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "NO_PROXY"].iter().filter_map(|k| std::env::var(k).ok().map(|v| format!("{k}={v}"))).collect();
    if !proxies.is_empty() {
        r.add(7, "Proxy", Status::Info, proxies.join(" · "), "");
    }

    // ── Verdict
    let fails = r.checks.iter().filter(|c| c.status == Status::Fail).count();
    let warns = r.checks.iter().filter(|c| c.status == Status::Warn).count();
    let passes = r.checks.iter().filter(|c| c.status == Status::Pass).count();
    emit(Tone::Head, format!("{passes} passed · {warns} warnings · {fails} failed · {:.1} s", started.elapsed().as_secs_f64()));
    if let Some(first) = r.checks.iter().find(|c| c.status == Status::Fail) {
        emit(Tone::Bad, format!("→ start at L{} {} ({}): the layers above depend on it", first.layer, LAYERS[first.layer as usize], first.name));
    } else if let Some(first) = r.checks.iter().find(|c| c.status == Status::Warn) {
        emit(Tone::Warn, format!("→ no hard failures; look at L{} {} first", first.layer, first.name));
    } else {
        emit(Tone::Good, "→ every layer looks healthy".into());
    }
    r.checks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_date() {
        let t = parse_http_date("Wed, 26 Nov 2026 10:00:00 GMT").unwrap();
        assert_eq!(crate::report::utc_timestamp(SystemTime::UNIX_EPOCH + Duration::from_secs(t as u64)), "2026-11-26 10:00:00 UTC");
        assert!(parse_http_date("garbage").is_none());
    }

    #[test]
    fn run_collects_layered_checks() {
        // Offline-safe: unroutable documentation targets, so nothing leaves the machine.
        let s = Settings {
            internet4: "none".into(),
            internet6: "2001:db8::1".into(),
            dns_name: "localhost".into(),
            http_url: "http://127.0.0.1:9/".into(),
            public_resolvers: vec![],
            perf_url: String::new(),
            capture_secs: 20,
            snmp: crate::config::Snmp::default(),
        };
        let lines = std::sync::Mutex::new(Vec::new());
        let checks = run(&s, &|_, l| lines.lock().unwrap().push(l));
        assert!(checks.iter().any(|c| c.layer == 1));
        assert!(checks.iter().any(|c| c.layer == 7 && c.name == "System resolver"));
        assert!(checks.windows(2).all(|w| w[0].layer <= w[1].layer), "layers must come in order");
        assert!(lines.lock().unwrap().iter().any(|l| l.contains("passed")));
    }
}
