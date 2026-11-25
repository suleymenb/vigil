//! Kernel network counters: TCP retransmits, listen-queue overflows, UDP buffer
//! drops, resets, timeouts and conntrack table usage.
//!
//! Linux: `/proc/net/snmp` + `/proc/net/netstat` (header/value line pairs) and
//! `/proc/sys/net/netfilter/nf_conntrack_{count,max}`. Two small reads per tick.
//! Other platforms: not available (the UI says so).

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
}

impl KernelNet {
    pub fn new() -> Self {
        Self {
            prev: HashMap::new(),
            cur: HashMap::new(),
            last: None,
            counters: None,
            retrans_hist: History::new(crate::collect::system::HISTORY),
        }
    }

    pub fn refresh(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.cur.clear();
            for f in ["/proc/net/snmp", "/proc/net/netstat"] {
                if let Ok(t) = std::fs::read_to_string(f) {
                    parse_pairs(&t, &mut self.cur);
                }
            }
            if self.cur.is_empty() {
                return;
            }
            let read_u64 = |p: &str| std::fs::read_to_string(p).ok()?.trim().parse::<u64>().ok();
            let conntrack = read_u64("/proc/sys/net/netfilter/nf_conntrack_count")
                .zip(read_u64("/proc/sys/net/netfilter/nf_conntrack_max"));
            let now = Instant::now();
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
