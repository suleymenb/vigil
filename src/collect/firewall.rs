#![allow(dead_code)] // parsers for other platforms are unit-tested on every OS

//! Firewall rule counters: which rule is matching (or dropping) traffic now.
//!
//! Linux: `nft -j list ruleset` (nftables JSON), falling back to
//! `iptables-save -c` / `ip6tables-save -c`. macOS: `pfctl -s rules -v`.
//! All need root. Polled every 2 s, only while the Firewall view is open.

use std::collections::HashMap;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

#[derive(Clone, Debug, Default)]
pub struct FwRule {
    pub family: String,
    pub table: String,
    pub chain: String,
    pub rule: String,
    pub verdict: String,
    pub packets: u64,
    pub bytes: u64,
    pub pps: f64,
    pub bps: f64,
    key: String,
}

#[derive(Default)]
pub struct FwStore {
    pub rules: Vec<FwRule>,
    pub source: &'static str,
    pub error: Option<String>,
    pub updated: Option<Instant>,
    pub version: u64,
}

// ───────────────────────────── nftables JSON ─────────────────────────────

fn val(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Array(a) => format!("{{{}}}", a.iter().map(val).collect::<Vec<_>>().join(", ")),
        Value::Object(o) => {
            if let Some(p) = o.get("payload") {
                let proto = p.get("protocol").map(val).unwrap_or_default();
                let field = p.get("field").map(val).unwrap_or_default();
                return format!("{proto} {field}").trim().to_string();
            }
            for k in ["meta", "ct", "fib", "rt", "socket"] {
                if let Some(m) = o.get(k) {
                    let key = m.get("key").map(val).unwrap_or_default();
                    return if k == "meta" { key } else { format!("{k} {key}") };
                }
            }
            if let Some(s) = o.get("set") {
                return val(s);
            }
            if let Some(Value::Array(r)) = o.get("range") {
                return r.iter().map(val).collect::<Vec<_>>().join("-");
            }
            if let Some(p) = o.get("prefix") {
                return format!("{}/{}", p.get("addr").map(val).unwrap_or_default(), p.get("len").map(val).unwrap_or_default());
            }
            o.keys().next().cloned().unwrap_or_default()
        }
        Value::Null => String::new(),
    }
}

/// Turn one nft rule's `expr` array into (match text, verdict, packets, bytes).
pub fn summarize_expr(expr: &[Value]) -> (String, String, u64, u64) {
    let mut parts = Vec::new();
    let mut verdict = String::new();
    let (mut pk, mut by) = (0, 0);
    for e in expr {
        let Some((k, v)) = e.as_object().and_then(|o| o.iter().next()) else { continue };
        match k.as_str() {
            "match" => {
                let op = v.get("op").map(val).unwrap_or_else(|| "==".into());
                let l = v.get("left").map(val).unwrap_or_default();
                let r = v.get("right").map(val).unwrap_or_default();
                parts.push(if op == "==" || op == "in" { format!("{l} {r}") } else { format!("{l} {op} {r}") });
            }
            "counter" => {
                pk = v.get("packets").and_then(Value::as_u64).unwrap_or(0);
                by = v.get("bytes").and_then(Value::as_u64).unwrap_or(0);
            }
            "accept" | "drop" | "return" | "continue" | "queue" => verdict = k.clone(),
            "jump" | "goto" => verdict = format!("{k} {}", v.get("target").map(val).unwrap_or_default()),
            "reject" => verdict = "reject".into(),
            "limit" => parts.push(format!(
                "limit {}/{}",
                v.get("rate").map(val).unwrap_or_default(),
                v.get("per").map(val).unwrap_or_default()
            )),
            "log" => parts.push("log".into()),
            "snat" | "dnat" | "masquerade" | "redirect" => {
                let to = v.get("addr").map(val).unwrap_or_default();
                verdict = if to.is_empty() { k.clone() } else { format!("{k} to {to}") };
            }
            other => parts.push(other.to_string()),
        }
    }
    (parts.join(" "), verdict, pk, by)
}

pub fn parse_nft_json(text: &str) -> Result<Vec<FwRule>, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let items = v.get("nftables").and_then(Value::as_array).ok_or("no nftables array")?;
    let mut out = Vec::new();
    for it in items {
        if let Some(r) = it.get("rule") {
            let expr = r.get("expr").and_then(Value::as_array).cloned().unwrap_or_default();
            let (rule, verdict, packets, bytes) = summarize_expr(&expr);
            let s = |k: &str| r.get(k).map(val).unwrap_or_default();
            let mut rule = rule;
            if let Some(c) = r.get("comment").and_then(Value::as_str) {
                rule = format!("{rule}  # {c}");
            }
            out.push(FwRule {
                key: format!("{}/{}/{}/{}", s("family"), s("table"), s("chain"), s("handle")),
                family: s("family"),
                table: s("table"),
                chain: s("chain"),
                rule,
                verdict,
                packets,
                bytes,
                ..Default::default()
            });
        }
    }
    Ok(out)
}

// ───────────────────────────── iptables-save -c ─────────────────────────────

pub fn parse_iptables_save(text: &str, family: &str) -> Vec<FwRule> {
    let mut table = String::new();
    let mut out = Vec::new();
    for (n, l) in text.lines().enumerate() {
        if let Some(t) = l.strip_prefix('*') {
            table = t.trim().to_string();
            continue;
        }
        let Some(rest) = l.strip_prefix('[') else { continue };
        let Some((counts, rule)) = rest.split_once(']') else { continue };
        let (pk, by) = counts.split_once(':').unwrap_or(("0", "0"));
        let rule = rule.trim();
        let Some(r) = rule.strip_prefix("-A ") else { continue };
        let (chain, spec) = r.split_once(' ').unwrap_or((r, ""));
        let verdict = spec
            .split_once("-j ")
            .map(|(_, v)| v.split_whitespace().next().unwrap_or("").to_string())
            .unwrap_or_default();
        let matches = spec.split(" -j ").next().unwrap_or("").to_string();
        out.push(FwRule {
            key: format!("{family}/{table}/{chain}/{n}"),
            family: family.into(),
            table: table.clone(),
            chain: chain.into(),
            rule: matches,
            verdict: verdict.to_ascii_lowercase(),
            packets: pk.parse().unwrap_or(0),
            bytes: by.parse().unwrap_or(0),
            ..Default::default()
        });
    }
    out
}

// ───────────────────────────── pfctl -s rules -v ─────────────────────────────

pub fn parse_pfctl(text: &str) -> Vec<FwRule> {
    let mut out: Vec<FwRule> = Vec::new();
    for (n, l) in text.lines().enumerate() {
        let t = l.trim_start();
        if let Some(stats) = t.strip_prefix("[ Evaluations:") {
            if let Some(last) = out.last_mut() {
                let num = |k: &str| {
                    stats.split_once(k).and_then(|(_, r)| r.split_whitespace().next()).and_then(|x| x.parse().ok()).unwrap_or(0)
                };
                last.packets = num("Packets:");
                last.bytes = num("Bytes:");
            }
            continue;
        }
        if t.starts_with('[') || t.is_empty() || l.starts_with(' ') {
            continue;
        }
        let verdict = t.split_whitespace().next().unwrap_or("").to_string();
        let chain = if t.contains(" in ") { "in" } else if t.contains(" out ") { "out" } else { "-" };
        out.push(FwRule {
            key: format!("pf/{n}/{t}"),
            family: "pf".into(),
            table: "pf".into(),
            chain: chain.into(),
            rule: t.to_string(),
            verdict,
            ..Default::default()
        });
    }
    out
}

fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let o = Command::new(cmd).args(args).output().map_err(|e| format!("{cmd}: {e}"))?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).into_owned())
    } else {
        let e = String::from_utf8_lossy(&o.stderr).trim().to_string();
        Err(if e.is_empty() { format!("{cmd} failed") } else { e.lines().next().unwrap_or("").to_string() })
    }
}

fn collect() -> (Result<Vec<FwRule>, String>, &'static str) {
    #[cfg(target_os = "linux")]
    {
        let nft = run("nft", &["-j", "list", "ruleset"]).and_then(|t| parse_nft_json(&t));
        if let Ok(r) = &nft {
            if !r.is_empty() {
                return (nft, "nft -j list ruleset");
            }
        }
        {
            {
                let v4 = run("iptables-save", &["-c"]);
                let v6 = run("ip6tables-save", &["-c"]);
                if let Ok(t) = &v4 {
                    let mut r = parse_iptables_save(t, "ip");
                    if let Ok(t6) = &v6 {
                        r.extend(parse_iptables_save(t6, "ip6"));
                    }
                    return (Ok(r), "iptables-save -c");
                }
                let err = match nft {
                    Err(e) => e,
                    Ok(_) => v4.err().unwrap_or_default(),
                };
                (Err(format!("{err} (firewall counters need root)")), "nft / iptables")
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        (run("pfctl", &["-s", "rules", "-v"]).map(|t| parse_pfctl(&t)).map_err(|e| format!("{e} (pfctl needs root)")), "pfctl -s rules -v")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        (Err(crate::platform::unavailable("rule counters", "Windows Defender Firewall keeps no per-rule hit counters (see `netsh advfirewall monitor show firewall`)")), "-")
    }
}

pub fn spawn_worker(store: Arc<Mutex<FwStore>>, active: Arc<AtomicBool>) {
    crate::util::spawn_named("firewall", move || {
        let mut prev: HashMap<String, (u64, u64)> = HashMap::new();
        let mut last = Instant::now();
        loop {
            if active.load(Ordering::Relaxed) {
                let (res, source) = collect();
                let dt = last.elapsed().as_secs_f64().max(0.1);
                last = Instant::now();
                let mut next = HashMap::new();
                let res = res.map(|mut rules| {
                    for r in &mut rules {
                        if let Some(&(p, b)) = prev.get(&r.key) {
                            r.pps = r.packets.saturating_sub(p) as f64 / dt;
                            r.bps = r.bytes.saturating_sub(b) as f64 / dt;
                        }
                        next.insert(r.key.clone(), (r.packets, r.bytes));
                    }
                    rules
                });
                prev = next;
                if let Ok(mut s) = store.lock() {
                    s.source = source;
                    match res {
                        Ok(r) => {
                            s.rules = r;
                            s.error = None;
                        }
                        Err(e) => s.error = Some(e),
                    }
                    s.updated = Some(Instant::now());
                    s.version += 1;
                }
                thread::sleep(Duration::from_secs(2));
            } else {
                thread::sleep(Duration::from_millis(250));
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nft_json() {
        let t = r#"{"nftables":[{"metainfo":{"version":"1.0.9"}},{"table":{"family":"inet","name":"filter","handle":1}},
        {"rule":{"family":"inet","table":"filter","chain":"input","handle":5,"expr":[
            {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"set":[22,443]}}},
            {"counter":{"packets":120,"bytes":9000}},{"accept":null}]}},
        {"rule":{"family":"inet","table":"filter","chain":"input","handle":9,"comment":"drop the rest","expr":[
            {"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"invalid"}},{"counter":{"packets":3,"bytes":180}},{"drop":null}]}}]}"#;
        let r = parse_nft_json(t).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].rule, "tcp dport {22, 443}");
        assert_eq!(r[0].verdict, "accept");
        assert_eq!(r[0].packets, 120);
        assert_eq!(r[1].rule, "ct state invalid  # drop the rest");
        assert_eq!(r[1].verdict, "drop");
    }

    #[test]
    fn iptables() {
        let t = "*filter\n:INPUT DROP [10:600]\n[50:3000] -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n[7:420] -A INPUT -j LOG --log-prefix x\nCOMMIT\n";
        let r = parse_iptables_save(t, "ip");
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].chain, "INPUT");
        assert_eq!(r[0].rule, "-p tcp -m tcp --dport 22");
        assert_eq!(r[0].verdict, "accept");
        assert_eq!(r[0].packets, 50);
    }

    #[test]
    fn pfctl() {
        let t = "block drop in all\n  [ Evaluations: 100       Packets: 42        Bytes: 2520        States: 0     ]\n  [ Inserted: uid 0 pid 1 State Creations: 0     ]\npass out quick on lo0 all flags S/SA keep state\n  [ Evaluations: 5 Packets: 9 Bytes: 900 States: 1 ]\n";
        let r = parse_pfctl(t);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].verdict, "block");
        assert_eq!(r[0].packets, 42);
        assert_eq!(r[1].chain, "out");
        assert_eq!(r[1].bytes, 900);
    }
}
