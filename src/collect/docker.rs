//! Docker Engine API client, for the Containers view where cgroups can't be
//! read directly: macOS and Windows (Docker Desktop runs containers in a VM)
//! and Linux hosts still on cgroup v1.
//!
//! Plain HTTP/1.1 over the Unix socket (`~/.docker/run/docker.sock`,
//! `/var/run/docker.sock`, `DOCKER_HOST=unix://…`) or the Windows named pipe
//! `\\.\pipe\docker_engine`. One `GET /containers/json` plus one one-shot
//! `/stats` per running container per round; rates come from our own
//! previous sample, so a round costs a few milliseconds.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;

use serde_json::Value;

use super::containers::Container;

/// Decode an HTTP/1.1 response (Content-Length or chunked) into (status, body).
pub fn parse_http(resp: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n").ok_or("incomplete HTTP response")?;
    let head = String::from_utf8_lossy(&resp[..split]);
    let body = &resp[split + 4..];
    let status = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).ok_or("bad status line")?;
    let chunked = head.lines().any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:") && l.to_ascii_lowercase().contains("chunked"));
    if !chunked {
        return Ok((status, body.to_vec()));
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < body.len() {
        let eol = body[i..].windows(2).position(|w| w == b"\r\n").ok_or("bad chunk")? + i;
        let size = usize::from_str_radix(String::from_utf8_lossy(&body[i..eol]).split(';').next().unwrap_or("").trim(), 16).map_err(|_| "bad chunk size")?;
        if size == 0 {
            break;
        }
        let start = eol + 2;
        out.extend_from_slice(body.get(start..start + size).ok_or("truncated chunk")?);
        i = start + size + 2;
    }
    Ok((status, out))
}

fn exchange(endpoint: &Path, req: &[u8]) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    #[cfg(unix)]
    {
        let mut s = std::os::unix::net::UnixStream::connect(endpoint).map_err(|e| format!("{}: {e} (is Docker running?)", endpoint.display()))?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
        s.write_all(req).map_err(|e| e.to_string())?;
        s.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    }
    #[cfg(windows)]
    {
        let mut p = std::fs::OpenOptions::new().read(true).write(true).open(endpoint).map_err(|e| format!("{}: {e} (is Docker Desktop running?)", endpoint.display()))?;
        p.write_all(req).map_err(|e| e.to_string())?;
        // The engine closes the pipe after a Connection: close response.
        let _ = p.read_to_end(&mut buf);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (endpoint, req);
        return Err("Docker API not supported on this OS".into());
    }
    Ok(buf)
}

pub fn get(endpoint: &Path, path: &str) -> Result<Value, String> {
    let req = format!("GET {path} HTTP/1.1\r\nHost: docker\r\nUser-Agent: vigil\r\nConnection: close\r\n\r\n");
    let raw = exchange(endpoint, req.as_bytes())?;
    let (status, body) = parse_http(&raw)?;
    if status != 200 {
        return Err(format!("Docker API {path}: HTTP {status}"));
    }
    serde_json::from_slice(&body).map_err(|e| format!("Docker API {path}: {e}"))
}

#[derive(Clone, Copy, Default)]
struct Raw {
    cpu: u64,
    rx: u64,
    tx: u64,
    rd: u64,
    wr: u64,
    periods: u64,
    throttled: u64,
}

fn u(v: &Value) -> u64 {
    v.as_u64().unwrap_or(0)
}

/// Turn one `/stats` document into raw counters, memory and limits.
fn stats_raw(st: &Value, windows: bool) -> (Raw, u64, Option<u64>, u64) {
    let cpu_total = u(&st["cpu_stats"]["cpu_usage"]["total_usage"]);
    // Windows containers report 100 ns units, Linux ones nanoseconds.
    let cpu = if windows { cpu_total * 100 } else { cpu_total };
    let (mut rx, mut tx) = (0, 0);
    if let Some(n) = st["networks"].as_object() {
        for v in n.values() {
            rx += u(&v["rx_bytes"]);
            tx += u(&v["tx_bytes"]);
        }
    }
    let (mut rd, mut wr) = (0, 0);
    if let Some(a) = st["blkio_stats"]["io_service_bytes_recursive"].as_array() {
        for e in a {
            match e["op"].as_str().unwrap_or("").to_ascii_lowercase().as_str() {
                "read" => rd += u(&e["value"]),
                "write" => wr += u(&e["value"]),
                _ => {}
            }
        }
    }
    if windows {
        rd = u(&st["storage_stats"]["read_size_bytes"]);
        wr = u(&st["storage_stats"]["write_size_bytes"]);
    }
    let ms = &st["memory_stats"];
    let mem = if windows {
        u(&ms["privateworkingset"])
    } else {
        // Same as `docker stats`: usage minus reclaimable page cache.
        let cache = ms["stats"]["inactive_file"].as_u64().or_else(|| ms["stats"]["total_inactive_file"].as_u64()).or_else(|| ms["stats"]["cache"].as_u64()).unwrap_or(0);
        u(&ms["usage"]).saturating_sub(cache)
    };
    let limit = ms["limit"].as_u64().filter(|l| *l > 0 && *l < (1 << 62));
    let thr = &st["cpu_stats"]["throttling_data"];
    (Raw { cpu, rx, tx, rd, wr, periods: u(&thr["periods"]), throttled: u(&thr["throttled_periods"]) }, mem, limit, u(&st["pids_stats"]["current"]))
}

pub struct DockerCollector {
    endpoint: std::path::PathBuf,
    prev: HashMap<String, (Raw, Instant)>,
    cpu_limits: HashMap<String, Option<f64>>,
    windows_engine: Option<bool>,
}

impl DockerCollector {
    pub fn new(endpoint: std::path::PathBuf) -> Self {
        Self { endpoint, prev: HashMap::new(), cpu_limits: HashMap::new(), windows_engine: None }
    }

    pub fn collect(&mut self) -> Result<Vec<Container>, String> {
        if self.windows_engine.is_none() {
            let info = get(&self.endpoint, "/version")?;
            self.windows_engine = Some(info["Os"].as_str() == Some("windows"));
        }
        let win = self.windows_engine.unwrap_or(false);
        let list = get(&self.endpoint, "/containers/json")?;
        let now = Instant::now();
        let mut out = Vec::new();
        let mut next = HashMap::new();
        for c in list.as_array().into_iter().flatten().take(40) {
            let id = c["Id"].as_str().unwrap_or("").to_string();
            if id.len() < 12 {
                continue;
            }
            let name = c["Names"][0].as_str().unwrap_or(&id[..12]).trim_start_matches('/').to_string();
            let Ok(st) = get(&self.endpoint, &format!("/containers/{id}/stats?stream=false&one-shot=true")) else { continue };
            let (raw, mem, mem_max, pids) = stats_raw(&st, win);
            let ep = self.endpoint.clone();
            let cpu_limit = *self.cpu_limits.entry(id.clone()).or_insert_with(|| {
                get(&ep, &format!("/containers/{id}/json")).ok().and_then(|i| {
                    let nano = i["HostConfig"]["NanoCpus"].as_u64().unwrap_or(0);
                    let (quota, period) = (i["HostConfig"]["CpuQuota"].as_i64().unwrap_or(0), i["HostConfig"]["CpuPeriod"].as_i64().unwrap_or(0));
                    if nano > 0 {
                        Some(nano as f64 / 1e9)
                    } else if quota > 0 && period > 0 {
                        Some(quota as f64 / period as f64)
                    } else {
                        None
                    }
                })
            });
            let mut k = Container {
                id: id.clone(),
                name,
                runtime: "docker",
                cpu_limit,
                mem,
                mem_max,
                pids,
                path: c["Image"].as_str().unwrap_or("").to_string(),
                ..Default::default()
            };
            if let Some((p, t)) = self.prev.get(&id) {
                let dt = now.duration_since(*t).as_secs_f64().max(0.1);
                let d = |a: u64, b: u64| a.saturating_sub(b) as f64;
                k.cpu_pct = d(raw.cpu, p.cpu) / 1e9 / dt * 100.0;
                let periods = d(raw.periods, p.periods);
                k.throttled_pct = if periods > 0.0 { d(raw.throttled, p.throttled) / periods * 100.0 } else { 0.0 };
                k.net_rx_bps = d(raw.rx, p.rx) / dt;
                k.net_tx_bps = d(raw.tx, p.tx) / dt;
                k.io_read_bps = d(raw.rd, p.rd) / dt;
                k.io_write_bps = d(raw.wr, p.wr) / dt;
            }
            next.insert(id, (raw, now));
            out.push(k);
        }
        self.prev = next;
        out.sort_by(|a, b| b.cpu_pct.total_cmp(&a.cpu_pct).then(a.name.cmp(&b.name)));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_chunked_and_plain() {
        let plain = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n[]";
        assert_eq!(parse_http(plain).unwrap(), (200, b"[]".to_vec()));
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n[{\"a\r\n5\r\n\":1}]\r\n0\r\n\r\n";
        assert_eq!(parse_http(chunked).unwrap(), (200, b"[{\"a\":1}]".to_vec()));
        assert_eq!(parse_http(b"HTTP/1.1 404 Not Found\r\n\r\n").unwrap().0, 404);
    }

    #[test]
    fn stats_document() {
        let st: Value = serde_json::from_str(r#"{"cpu_stats":{"cpu_usage":{"total_usage":5000000000},"throttling_data":{"periods":100,"throttled_periods":7}},"memory_stats":{"usage":300,"limit":1000,"stats":{"inactive_file":100}},"networks":{"eth0":{"rx_bytes":10,"tx_bytes":20},"eth1":{"rx_bytes":1,"tx_bytes":2}},"blkio_stats":{"io_service_bytes_recursive":[{"op":"read","value":4},{"op":"write","value":6},{"op":"Read","value":1}]},"pids_stats":{"current":12}}"#).unwrap();
        let (raw, mem, lim, pids) = stats_raw(&st, false);
        assert_eq!((raw.cpu, raw.rx, raw.tx, raw.rd, raw.wr, raw.throttled), (5_000_000_000, 11, 22, 5, 6, 7));
        assert_eq!((mem, lim, pids), (200, Some(1000), 12));
    }
}
