//! Kernel network counters: TCP retransmits, listen-queue overflows, UDP buffer
//! drops, resets, timeouts and conntrack table usage.
//!
//! Linux: `/proc/net/snmp` + `/proc/net/netstat` (header/value line pairs) and
//! `/proc/sys/net/netfilter/nf_conntrack_{count,max}`. Two small reads per tick.
//! Windows: `GetTcpStatisticsEx` / `GetUdpStatisticsEx` (IPv4 + IPv6 summed).
//! macOS: `netstat -s -p tcp|udp` every 2 s on a poller thread (TCP counters need root).

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::HashMap;
use std::time::Instant;

use crate::util::History;

/// Parse the `Prefix: name name …` / `Prefix: v v …` line pairs used by
/// /proc/net/snmp and /proc/net/netstat into `"Prefix.name" → value`.
pub fn parse_pairs(text: &str, out: &mut HashMap<String, u64>) {
    let mut lines = text.lines();
    while let (Some(h), Some(v)) = (lines.next(), lines.next()) {
        let (Some((hp, hnames)), Some((vp, vvals))) = (h.split_once(':'), v.split_once(':')) else {
            continue;
        };
        if hp != vp {
            continue;
        }
        for (n, val) in hnames.split_whitespace().zip(vvals.split_whitespace()) {
            if let Ok(x) = val.parse::<i64>() {
                out.insert(format!("{hp}.{n}"), x.max(0) as u64);
            }
        }
    }
}

/// macOS / BSD `netstat -s -p tcp` and `-p udp`, mapped to the Linux names.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
/// Without root the kernel reports zeros for TCP (UDP is always readable).
pub fn parse_netstat_s(text: &str, out: &mut HashMap<String, u64>) {
    let mut section = "";
    for line in text.lines() {
        if !line.starts_with('\t') {
            section = match line.trim_end_matches(':') {
                "tcp" => "tcp",
                "udp" => "udp",
                _ => "",
            };
            continue;
        }
        let depth = line.chars().take_while(|c| *c == '\t').count();
        let t = line.trim();
        let Some((n, rest)) = t.split_once(' ') else { continue };
        let Ok(n) = n.parse::<u64>() else { continue };
        let has = |s: &str| rest.contains(s);
        let key = match (section, depth) {
            ("tcp", 1) if rest.starts_with("packet") && has("sent") => "Tcp.OutSegs",
            ("tcp", 1) if rest.starts_with("packet") && has("received") => "Tcp.InSegs",
            ("tcp", 1) if rest.starts_with("connection request") => "Tcp.ActiveOpens",
            ("tcp", 1) if rest.starts_with("connection accept") => "Tcp.PassiveOpens",
            ("tcp", 1) if rest.starts_with("bad connection attempt") => "Tcp.AttemptFails",
            ("tcp", 1) if rest.starts_with("listen queue overflow") => "TcpExt.ListenOverflows",
            ("tcp", 1) if rest.starts_with("retransmit timeout") => "TcpExt.TCPTimeouts",
            ("tcp", 2) if rest.starts_with("data packet") && has("retransmitted") => "Tcp.RetransSegs",
            ("udp", 1) if rest.starts_with("datagram") && has("received") => "Udp.InDatagrams",
            ("udp", 1) if rest.starts_with("datagram") && has("output") => "Udp.OutDatagrams",
            ("udp", 2) if has("dropped due to no socket") => "Udp.NoPorts",
            ("udp", 2) if has("dropped due to full socket buffers") => "Udp.RcvbufErrors",
            ("udp", 2) if has("with incomplete header") || has("with bad data length") || has("with bad checksum") => "Udp.InErrors",
            _ => continue,
        };
        *out.entry(key.to_string()).or_insert(0) += n;
    }
}

#[derive(Clone, Debug, Default)]
pub struct NetCounters {
    pub out_segs_rate: f64,
    pub retrans_rate: f64,
    /// Retransmitted / sent segments over the last interval, in percent.
    pub retrans_pct: f64,
    pub listen_overflow_rate: f64,
    pub listen_drop_rate: f64,
    pub udp_rcvbuf_err_rate: f64,
    pub udp_sndbuf_err_rate: f64,
    pub udp_in_err_rate: f64,
    pub tcp_timeout_rate: f64,
    pub syn_retrans_rate: f64,
    pub resets_out_rate: f64,
    pub est_resets_rate: f64,
    pub active_opens_rate: f64,
    pub passive_opens_rate: f64,
    pub curr_estab: u64,
    pub conntrack: Option<(u64, u64)>,
}

impl NetCounters {
    pub fn conntrack_pct(&self) -> Option<f64> {
        self.conntrack
            .filter(|(_, max)| *max > 0)
            .map(|(c, m)| c as f64 / m as f64 * 100.0)
    }
}

pub struct KernelNet {
    prev: HashMap<String, u64>,
    cur: HashMap<String, u64>,
    last: Option<Instant>,
    pub counters: Option<NetCounters>,
    pub retrans_hist: History,
    /// macOS without root: the kernel hides TCP statistics (all zero).
    pub tcp_hidden: bool,
    /// macOS: netstat runs on a poller thread.
    #[cfg(target_os = "macos")]
    poller: Option<(crate::util::Poller<HashMap<String, u64>>, u64)>,
}

impl KernelNet {
    pub fn new() -> Self {
        Self {
            prev: HashMap::new(),
            cur: HashMap::new(),
            last: None,
            counters: None,
            retrans_hist: History::new(crate::collect::system::HISTORY),
            tcp_hidden: false,
            #[cfg(target_os = "macos")]
            poller: None,
        }
    }

    /// Fill `self.cur` with this OS's counters under the /proc/net/snmp names.
    /// Returns the conntrack (count, max) where the OS has one.
    /// Fill `self.cur`; returns (conntrack, sample time), or None when no new sample exists.
    fn read(&mut self) -> Option<(Option<(u64, u64)>, Instant)> {
        self.cur.clear();
        #[cfg(target_os = "linux")]
        {
            for f in ["/proc/net/snmp", "/proc/net/netstat"] {
                if let Ok(t) = std::fs::read_to_string(f) {
                    parse_pairs(&t, &mut self.cur);
                }
            }
            let read_u64 = |p: &str| std::fs::read_to_string(p).ok()?.trim().parse::<u64>().ok();
            Some((read_u64("/proc/sys/net/netfilter/nf_conntrack_count").zip(read_u64("/proc/sys/net/netfilter/nf_conntrack_max")), Instant::now()))
        }
        #[cfg(windows)]
        {
            super::windows::counters(&mut self.cur);
            Some((None, Instant::now()))
        }
        #[cfg(target_os = "macos")]
        {
            let (poller, seen) = self.poller.get_or_insert_with(|| {
                // Without root the kernel reports every TCP counter as zero
                // (net.inet.tcp.disable_access_to_stats): once seen, stop asking.
                let root = unsafe { libc::geteuid() } == 0;
                let mut tcp_hidden = false;
                let p = crate::util::Poller::spawn(std::time::Duration::from_secs(2), move || {
                    let mut m = HashMap::new();
                    for proto in ["tcp", "udp"] {
                        if proto == "tcp" && tcp_hidden {
                            continue;
                        }
                        let o = std::process::Command::new("netstat").args(["-s", "-p", proto]).output().ok()?;
                        parse_netstat_s(&String::from_utf8_lossy(&o.stdout), &mut m);
                        if proto == "tcp" && !root {
                            tcp_hidden = ["Tcp.OutSegs", "Tcp.InSegs"].iter().all(|k| m.get(*k).copied().unwrap_or(0) == 0);
                        }
                    }
                    Some(m)
                });
                (p, 0)
            });
            let (at, seq, m) = poller.latest(*seen)?;
            *seen = seq;
            self.cur = m;
            self.tcp_hidden = self.cur.get("Tcp.OutSegs").copied().unwrap_or(0) == 0 && self.cur.get("Tcp.InSegs").copied().unwrap_or(0) == 0;
            Some((None, at))
        }
        #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
        None
    }

    pub fn refresh(&mut self) {
        {
            let Some((conntrack, now)) = self.read() else { return };
            if self.cur.is_empty() {
                return;
            }
            if let Some(last) = self.last {
                let dt = now.duration_since(last).as_secs_f64().max(0.05);
                let rate = |k: &str| {
                    let c = self.cur.get(k).copied().unwrap_or(0);
                    let p = self.prev.get(k).copied().unwrap_or(c);
                    c.saturating_sub(p) as f64 / dt
                };
                let out = rate("Tcp.OutSegs");
                let retr = rate("Tcp.RetransSegs");
                let c = NetCounters {
                    out_segs_rate: out,
                    retrans_rate: retr,
                    retrans_pct: if out > 0.0 { retr / out * 100.0 } else { 0.0 },
                    listen_overflow_rate: rate("TcpExt.ListenOverflows"),
                    listen_drop_rate: rate("TcpExt.ListenDrops"),
                    udp_rcvbuf_err_rate: rate("Udp.RcvbufErrors"),
                    udp_sndbuf_err_rate: rate("Udp.SndbufErrors"),
                    udp_in_err_rate: rate("Udp.InErrors"),
                    tcp_timeout_rate: rate("TcpExt.TCPTimeouts"),
                    syn_retrans_rate: rate("TcpExt.TCPSynRetrans"),
                    resets_out_rate: rate("Tcp.OutRsts"),
                    est_resets_rate: rate("Tcp.EstabResets"),
                    active_opens_rate: rate("Tcp.ActiveOpens"),
                    passive_opens_rate: rate("Tcp.PassiveOpens"),
                    curr_estab: self.cur.get("Tcp.CurrEstab").copied().unwrap_or(0),
                    conntrack,
                };
                self.retrans_hist.push(c.retrans_pct);
                self.counters = Some(c);
            }
            std::mem::swap(&mut self.prev, &mut self.cur);
            self.last = Some(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_netstat_s() {
        let t = "tcp:\n\t1200 packets sent\n\t\t900 data packets (1000 bytes)\n\t\t12 data packets (800 bytes) retransmitted\n\t3000 packets received\n\t5 connection requests\n\t7 connection accepts\n\t1 bad connection attempt\n\t2 listen queue overflows\n\t4 retransmit timeouts\n\t\t1 connection dropped by rexmit timeout\nudp:\n\t788037 datagrams received\n\t\t1 with incomplete header\n\t\t2 with bad checksum\n\t\t1490 dropped due to no socket\n\t\t14769 dropped due to full socket buffers\n\t375639 datagrams output\n";
        let mut m = HashMap::new();
        parse_netstat_s(t, &mut m);
        assert_eq!(m["Tcp.OutSegs"], 1200);
        assert_eq!(m["Tcp.RetransSegs"], 12);
        assert_eq!(m["Tcp.ActiveOpens"], 5);
        assert_eq!(m["TcpExt.ListenOverflows"], 2);
        assert_eq!(m["TcpExt.TCPTimeouts"], 4);
        assert_eq!(m["Udp.RcvbufErrors"], 14769);
        assert_eq!(m["Udp.NoPorts"], 1490);
        assert_eq!(m["Udp.InErrors"], 3);
        assert_eq!(m["Udp.OutDatagrams"], 375639);
    }

    #[test]
    fn parses_snmp_pairs() {
        let t = "Tcp: RtoAlgorithm RetransSegs OutSegs CurrEstab\nTcp: 1 42 1000 7\nUdp: InDatagrams RcvbufErrors\nUdp: 10 3\n";
        let mut m = HashMap::new();
        parse_pairs(t, &mut m);
        assert_eq!(m["Tcp.RetransSegs"], 42);
        assert_eq!(m["Tcp.CurrEstab"], 7);
        assert_eq!(m["Udp.RcvbufErrors"], 3);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_real_kernel_counters() {
        let mut k = KernelNet::new();
        k.refresh();
        std::thread::sleep(std::time::Duration::from_millis(100));
        k.refresh();
        let c = k.counters.expect("counters on Linux");
        assert!(c.retrans_pct >= 0.0);
    }
}
