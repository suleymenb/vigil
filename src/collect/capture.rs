//! One-key packet capture: `tcpdump` filtered on the selected connection,
//! for a fixed number of seconds, written to a .pcap you open in Wireshark.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

#[derive(Default)]
pub struct CaptureState {
    pub running: Option<(PathBuf, Instant, Duration)>,
    /// Last finished capture: Ok(path, size) or Err(message).
    pub last: Option<Result<(PathBuf, u64), String>>,
    pub version: u64,
}

/// tcpdump filter for a socket's endpoints: the remote side when connected,
/// otherwise the local port.
pub fn bpf_filter(local: &str, remote: &str) -> Option<String> {
    let host_port = |ep: &str| -> Option<(Option<String>, u16)> {
        let (h, p) = ep.rsplit_once(':')?;
        let h = h.trim_matches(['[', ']']);
        let port = p.parse().ok()?;
        let host = (h != "*" && !h.is_empty()).then(|| h.to_string());
        Some((host, port))
    };
    if !remote.is_empty() {
        let (h, p) = host_port(remote)?;
        return Some(match h {
            Some(h) => format!("host {h} and port {p}"),
            None => format!("port {p}"),
        });
    }
    let (_, p) = host_port(local)?;
    Some(format!("port {p}"))
}

pub fn start(state: Arc<Mutex<CaptureState>>, filter: String, secs: u64) -> Result<PathBuf, String> {
    if state.lock().map(|s| s.running.is_some()).unwrap_or(false) {
        return Err("a capture is already running".into());
    }
    if !crate::platform::get().tools.tcpdump {
        return Err(if cfg!(windows) {
            crate::platform::unavailable("capture", "use `pktmon start --capture` (Windows 10 1809+) or Wireshark")
        } else {
            "tcpdump not found: install it (apt install tcpdump · dnf install tcpdump)".into()
        });
    }
    let stamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let dir = std::env::current_dir().ok().filter(|d| {
        std::fs::metadata(d).map(|m| !m.permissions().readonly()).unwrap_or(false)
    });
    let file = dir
        .or_else(crate::util::home_dir)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!("vigil-capture-{stamp}.pcap"));
    let mut child = Command::new("tcpdump")
        .args(["-i", "any", "-nn", "-U", "-s", "0", "-w"])
        .arg(&file)
        .arg(&filter)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("tcpdump: {e} (is it installed?)"))?;
    let dur = Duration::from_secs(secs.max(1));
    if let Ok(mut s) = state.lock() {
        s.running = Some((file.clone(), Instant::now(), dur));
        s.version += 1;
    }
    let f = file.clone();
    thread::spawn(move || {
        let deadline = Instant::now() + dur;
        let mut early = None;
        while Instant::now() < deadline {
            if let Ok(Some(st)) = child.try_wait() {
                early = Some(st);
                break;
            }
            thread::sleep(Duration::from_millis(200));
        }
        if early.is_none() {
            // SIGINT lets tcpdump flush and close the pcap cleanly.
            #[cfg(unix)]
            unsafe {
                libc::kill(child.id() as i32, libc::SIGINT);
            }
        }
        let out = child.wait_with_output();
        let res = match out {
            Ok(_) if f.exists() => Ok((f.clone(), std::fs::metadata(&f).map(|m| m.len()).unwrap_or(0))),
            Ok(o) => {
                let e = String::from_utf8_lossy(&o.stderr);
                Err(e.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("tcpdump failed (needs root)").to_string())
            }
            Err(e) => Err(e.to_string()),
        };
        if let Ok(mut s) = state.lock() {
            s.running = None;
            s.last = Some(res);
            s.version += 1;
        }
    });
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters() {
        assert_eq!(bpf_filter("10.0.0.5:51000", "93.184.216.34:443").as_deref(), Some("host 93.184.216.34 and port 443"));
        assert_eq!(bpf_filter("[::1]:5432", "[::1]:40000").as_deref(), Some("host ::1 and port 40000"));
        assert_eq!(bpf_filter("*:22", "").as_deref(), Some("port 22"));
    }
}
