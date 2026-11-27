//! Throughput test between two machines running vigil (an iperf-style TCP
//! test without installing iperf), plus an HTTP download test via curl.
//!
//!   server:  vigil perf --server            (listens on TCP 5299)
//!   client:  vigil perf 10.0.0.7 -t 10 -P 4 [--reverse]
//!
//! Protocol: each stream opens a TCP connection and sends `VGL1`, a mode byte
//! (`U` client→server, `D` server→client) and the duration in seconds (u32).
//! Upload: the client writes until the time is up and half-closes; the server
//! replies with the byte count it received (u64). Download: the server writes
//! for the duration and closes.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use super::Tone;

pub const DEFAULT_PORT: u16 = 5299;
const MAGIC: &[u8; 4] = b"VGL1";
const BUF: usize = 128 * 1024;
const MAX_SECS: u32 = 120;

pub fn fmt_bps(bytes: f64, secs: f64) -> String {
    let bits = bytes * 8.0 / secs.max(1e-6);
    if bits >= 1e9 {
        format!("{:.2} Gbit/s", bits / 1e9)
    } else if bits >= 1e6 {
        format!("{:.1} Mbit/s", bits / 1e6)
    } else {
        format!("{:.0} kbit/s", bits / 1e3)
    }
}

/// Serve tests until interrupted. Each connection runs on its own thread.
pub fn serve(port: u16, emit: &(dyn Fn(Tone, String) + Sync)) -> Result<(), String> {
    let l = crate::util::bind_tcp_any(port).map_err(|e| format!("listen on {port}: {e}"))?;
    emit(Tone::Head, format!("vigil perf server listening on TCP {port} (ctrl-c to stop)"));
    thread::scope(|s| {
        for conn in l.incoming().flatten() {
            s.spawn(move || {
                let peer = conn.peer_addr().map(|p| p.to_string()).unwrap_or_default();
                match handle(conn) {
                    Ok((mode, bytes, secs)) => emit(Tone::Normal, format!("  {peer}  {}  {}  in {secs:.1} s", if mode == b'U' { "received" } else { "sent" }, fmt_bps(bytes as f64, secs))),
                    Err(e) => emit(Tone::Warn, format!("  {peer}  {e}")),
                }
            });
        }
    });
    Ok(())
}

fn handle(mut c: TcpStream) -> Result<(u8, u64, f64), String> {
    c.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut head = [0u8; 9];
    c.read_exact(&mut head).map_err(|e| e.to_string())?;
    if &head[..4] != MAGIC {
        return Err("not a vigil perf client".into());
    }
    let mode = head[4];
    let secs = u32::from_be_bytes(head[5..9].try_into().unwrap()).min(MAX_SECS);
    let t0 = Instant::now();
    let mut total = 0u64;
    let mut buf = vec![0u8; BUF];
    match mode {
        b'U' => {
            c.set_read_timeout(Some(Duration::from_secs(secs as u64 + 10))).ok();
            loop {
                match c.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => total += n as u64,
                    Err(e) => return Err(e.to_string()),
                }
            }
            c.write_all(&total.to_be_bytes()).map_err(|e| e.to_string())?;
        }
        b'D' => {
            let end = Duration::from_secs(secs as u64);
            while t0.elapsed() < end {
                match c.write(&buf) {
                    Ok(n) => total += n as u64,
                    Err(_) => break,
                }
            }
            let _ = c.shutdown(Shutdown::Write);
        }
        _ => return Err("unknown mode".into()),
    }
    Ok((mode, total, t0.elapsed().as_secs_f64()))
}

/// Parse `host[:port]` (IPv6 in brackets).
pub fn resolve(target: &str) -> Result<SocketAddr, String> {
    let with_port = if target.parse::<std::net::IpAddr>().is_ok() || !target.contains(':') {
        if target.contains(':') {
            format!("[{target}]:{DEFAULT_PORT}")
        } else {
            format!("{target}:{DEFAULT_PORT}")
        }
    } else {
        target.to_string()
    };
    with_port.to_socket_addrs().map_err(|e| format!("{target}: {e}"))?.next().ok_or_else(|| format!("{target}: no address"))
}

/// Run a client test and print one line per second plus a summary.
/// Returns the measured rate in bytes per second.
pub fn client(target: &str, secs: u32, streams: usize, reverse: bool, emit: &dyn Fn(Tone, String)) -> Result<f64, String> {
    let addr = resolve(target)?;
    let secs = secs.clamp(1, MAX_SECS);
    let streams = streams.clamp(1, 16);
    let mode = if reverse { b'D' } else { b'U' };
    emit(Tone::Head, format!("{} {addr} · {secs} s · {streams} stream(s)", if reverse { "download from" } else { "upload to" }));
    let counter = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let mut conns = Vec::new();
    for _ in 0..streams {
        let mut c = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map_err(|e| match e.kind() {
            std::io::ErrorKind::ConnectionRefused => format!("{addr} refused: start `vigil perf --server` there (and open TCP {})", addr.port()),
            std::io::ErrorKind::TimedOut => format!("{addr}: timeout (firewall dropping TCP {}?)", addr.port()),
            _ => format!("{addr}: {e}"),
        })?;
        c.set_nodelay(true).ok();
        let mut head = MAGIC.to_vec();
        head.push(mode);
        head.extend(secs.to_be_bytes());
        c.write_all(&head).map_err(|e| e.to_string())?;
        conns.push(c);
    }
    let t0 = Instant::now();
    let workers: Vec<_> = conns
        .into_iter()
        .map(|mut c| {
            let (counter, stop) = (counter.clone(), stop.clone());
            thread::spawn(move || -> u64 {
                let mut buf = vec![0u8; BUF];
                if mode == b'U' {
                    while !stop.load(Ordering::Relaxed) {
                        match c.write(&buf) {
                            Ok(n) => {
                                counter.fetch_add(n as u64, Ordering::Relaxed);
                            }
                            Err(_) => break,
                        }
                    }
                    let _ = c.shutdown(Shutdown::Write);
                    let mut n = [0u8; 8];
                    c.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    if c.read_exact(&mut n).is_ok() {
                        return u64::from_be_bytes(n);
                    }
                    0
                } else {
                    let mut total = 0;
                    while let Ok(n) = c.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        total += n as u64;
                        counter.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    total
                }
            })
        })
        .collect();
    let mut last = 0u64;
    let mut samples = Vec::new();
    for i in 1..=secs {
        let deadline = Duration::from_secs(i as u64);
        if let Some(d) = deadline.checked_sub(t0.elapsed()) {
            thread::sleep(d);
        }
        let now = counter.load(Ordering::Relaxed);
        let delta = now - last;
        last = now;
        samples.push(delta as f64);
        emit(Tone::Normal, format!("  {:>3}-{:<3} s  {:>14}", i - 1, i, fmt_bps(delta as f64, 1.0)));
    }
    stop.store(true, Ordering::Relaxed);
    let server_counts: Vec<u64> = workers.into_iter().filter_map(|w| w.join().ok()).collect();
    let elapsed = t0.elapsed().as_secs_f64().max(secs as f64);
    let reported: u64 = server_counts.iter().sum();
    let total = if mode == b'U' && reported > 0 { reported } else { counter.load(Ordering::Relaxed) };
    let rate = total as f64 / elapsed;
    let mean = samples.iter().sum::<f64>() / samples.len().max(1) as f64;
    let jitter = (samples.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / samples.len().max(1) as f64).sqrt();
    emit(Tone::Head, format!("result  {}  ({} in {elapsed:.1} s{})", fmt_bps(total as f64, elapsed), crate::util::fmt_bytes(total), if mode == b'U' { ", counted by the server" } else { "" }));
    if mean > 0.0 && jitter / mean > 0.35 {
        emit(Tone::Warn, "→ throughput swings a lot from second to second: congestion, Wi-Fi, or a shaper/policer on the path (compare with -P 4)".into());
    }
    Ok(rate)
}

/// HTTP download test through curl (TLS, real internet path, CDN nearby).
pub fn internet(url: &str, emit: &dyn Fn(Tone, String)) -> Result<f64, String> {
    emit(Tone::Head, format!("download {url}"));
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let o = std::process::Command::new("curl")
        .args(["-sS", "-o", null, "--max-time", "30", "-w", "%{speed_download} %{size_download} %{time_total} %{time_connect} %{time_starttransfer} %{remote_ip}", url])
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    let t = String::from_utf8_lossy(&o.stdout);
    let f: Vec<&str> = t.split_whitespace().collect();
    if !o.status.success() || f.len() < 5 {
        return Err(String::from_utf8_lossy(&o.stderr).trim().trim_start_matches("curl: ").to_string());
    }
    let num = |i: usize| f[i].parse::<f64>().unwrap_or(0.0);
    let (speed, size, total, connect, ttfb) = (num(0), num(1), num(2), num(3), num(4));
    emit(Tone::Normal, format!("  server {}  connect {:.0} ms  first byte {:.0} ms", f.get(5).unwrap_or(&"?"), connect * 1000.0, ttfb * 1000.0));
    emit(Tone::Head, format!("result  {}  ({} in {total:.1} s)", fmt_bps(speed, 1.0), crate::util::fmt_bytes(size as u64)));
    Ok(speed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn loopback_upload_and_download() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        thread::spawn(move || {
            for c in l.incoming().flatten() {
                thread::spawn(move || handle(c));
            }
        });
        let lines = std::sync::Mutex::new(Vec::new());
        let emit = |_t: Tone, s: String| lines.lock().unwrap().push(s);
        let up = client(&format!("127.0.0.1:{port}"), 1, 2, false, &emit).unwrap();
        let down = client(&format!("127.0.0.1:{port}"), 1, 1, true, &emit).unwrap();
        assert!(up > 1e6 && down > 1e6, "up {up} down {down}");
        assert!(lines.lock().unwrap().iter().any(|l| l.starts_with("result")));
        assert_eq!(resolve("127.0.0.1").unwrap().port(), DEFAULT_PORT);
        assert_eq!(resolve("[::1]:9").unwrap().port(), 9);
        assert_eq!(fmt_bps(125_000_000.0, 1.0), "1.00 Gbit/s");
    }
}
