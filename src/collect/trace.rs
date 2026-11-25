//! Path analysis for a probe target: latency and loss per hop.
//!
//! Uses `mtr --json` when installed (loss per hop over several cycles),
//! otherwise `traceroute -n`. Runs on demand (`t` in the Probes view) on its
//! own thread; the result stays attached to the probe until the next run.

use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Hop {
    pub n: u32,
    /// "???" / "*" when the hop didn't answer.
    pub host: String,
    pub loss_pct: f64,
    pub sent: u32,
    pub last: f64,
    pub avg: f64,
    pub best: f64,
    pub worst: f64,
}

#[derive(Clone, Debug, Default)]
pub struct TraceResult {
    pub target: String,
    pub tool: &'static str,
    pub hops: Vec<Hop>,
    pub error: Option<String>,
    pub running: bool,
}

#[derive(Default)]
pub struct TraceStore {
    pub current: Option<TraceResult>,
    pub version: u64,
}

pub fn parse_mtr_json(text: &str) -> Vec<Hop> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else { return Vec::new() };
    let hubs = v.pointer("/report/hubs").and_then(|h| h.as_array()).cloned().unwrap_or_default();
    let f = |h: &serde_json::Value, k: &str| h.get(k).and_then(|x| x.as_f64()).unwrap_or(0.0);
    hubs.iter()
        .map(|h| Hop {
            n: h.get("count").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
            host: h.get("host").and_then(|x| x.as_str()).unwrap_or("???").to_string(),
            loss_pct: f(h, "Loss%"),
            sent: f(h, "Snt") as u32,
            last: f(h, "Last"),
            avg: f(h, "Avg"),
            best: f(h, "Best"),
            worst: f(h, "Wrst"),
        })
        .collect()
}

/// `traceroute -n -q 3` output: ` 3  10.1.1.1  1.2 ms  1.1 ms *`.
pub fn parse_traceroute(text: &str) -> Vec<Hop> {
    let mut hops = Vec::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        let Some(n) = f.first().and_then(|x| x.parse::<u32>().ok()) else { continue };
        let mut host = String::from("*");
        let mut times = Vec::new();
        let mut stars = 0u32;
        let mut i = 1;
        while i < f.len() {
            match f[i] {
                "*" => stars += 1,
                "ms" => {}
                t => {
                    if let Ok(ms) = t.parse::<f64>() {
                        times.push(ms);
                    } else if host == "*" && !t.starts_with('!') && !t.starts_with('(') {
                        host = t.to_string();
                    }
                }
            }
            i += 1;
        }
        let sent = times.len() as u32 + stars;
        let avg = if times.is_empty() { 0.0 } else { times.iter().sum::<f64>() / times.len() as f64 };
        hops.push(Hop {
            n,
            host,
            loss_pct: if sent == 0 { 100.0 } else { stars as f64 / sent as f64 * 100.0 },
            sent,
            last: times.last().copied().unwrap_or(0.0),
            avg,
            best: times.iter().copied().fold(f64::INFINITY, f64::min).min(if times.is_empty() { 0.0 } else { f64::INFINITY }),
            worst: times.iter().copied().fold(0.0, f64::max),
        });
    }
    hops
}

fn run(target: &str) -> (&'static str, Result<Vec<Hop>, String>) {
    let mtr = Command::new("mtr").args(["-n", "--json", "-c", "5", "-r", target]).output();
    if let Ok(o) = mtr {
        if o.status.success() {
            let hops = parse_mtr_json(&String::from_utf8_lossy(&o.stdout));
            if !hops.is_empty() {
                return ("mtr", Ok(hops));
            }
        }
    }
    match Command::new("traceroute").args(["-n", "-q", "3", "-w", "1", "-m", "30", target]).output() {
        Ok(o) => {
            let hops = parse_traceroute(&String::from_utf8_lossy(&o.stdout));
            if hops.is_empty() {
                let e = String::from_utf8_lossy(&o.stderr);
                ("traceroute", Err(e.lines().last().unwrap_or("traceroute failed").to_string()))
            } else {
                ("traceroute", Ok(hops))
            }
        }
        Err(_) => ("-", Err("install mtr or traceroute to trace the path".into())),
    }
}

pub fn start(store: Arc<Mutex<TraceStore>>, target: String) {
    if let Ok(mut s) = store.lock() {
        if s.current.as_ref().is_some_and(|c| c.running) {
            return;
        }
        s.current = Some(TraceResult { target: target.clone(), running: true, ..Default::default() });
        s.version += 1;
    }
    thread::spawn(move || {
        let (tool, res) = run(&target);
        if let Ok(mut s) = store.lock() {
            let (hops, error) = match res {
                Ok(h) => (h, None),
                Err(e) => (Vec::new(), Some(e)),
            };
            s.current = Some(TraceResult { target, tool, hops, error, running: false });
            s.version += 1;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtr_json() {
        let t = r#"{"report":{"mtr":{"dst":"1.1.1.1"},"hubs":[{"count":1,"host":"10.0.0.1","Loss%":0.0,"Snt":5,"Last":0.5,"Avg":0.6,"Best":0.4,"Wrst":0.9,"StDev":0.1},{"count":2,"host":"???","Loss%":100.0,"Snt":5,"Last":0.0,"Avg":0.0,"Best":0.0,"Wrst":0.0,"StDev":0.0}]}}"#;
        let h = parse_mtr_json(t);
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].host, "10.0.0.1");
        assert_eq!(h[1].loss_pct, 100.0);
    }

    #[test]
    fn traceroute_text() {
        let t = "traceroute to 1.1.1.1 (1.1.1.1), 30 hops max, 60 byte packets\n 1  10.0.0.1  0.512 ms  0.401 ms  0.389 ms\n 2  * * *\n 3  100.64.0.1  4.1 ms *  4.3 ms\n";
        let h = parse_traceroute(t);
        assert_eq!(h.len(), 3);
        assert_eq!(h[0].host, "10.0.0.1");
        assert!((h[0].avg - 0.434).abs() < 0.01);
        assert_eq!(h[1].loss_pct, 100.0);
        assert_eq!(h[1].host, "*");
        assert!((h[2].loss_pct - 33.3).abs() < 0.1);
        assert_eq!(h[2].best, 4.1);
    }
}
