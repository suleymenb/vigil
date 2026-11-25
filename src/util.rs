use std::collections::VecDeque;

/// Fixed-capacity ring buffer used for all time-series graphs.
#[derive(Clone, Debug)]
pub struct History {
    buf: VecDeque<f64>,
    cap: usize,
}

impl History {
    pub fn new(cap: usize) -> Self {
        Self { buf: VecDeque::with_capacity(cap), cap }
    }

    pub fn push(&mut self, v: f64) {
        if self.buf.len() == self.cap {
            self.buf.pop_front();
        }
        self.buf.push_back(v);
    }

    pub fn last(&self) -> f64 {
        self.buf.back().copied().unwrap_or(0.0)
    }

    pub fn max(&self) -> f64 {
        self.buf.iter().copied().fold(0.0, f64::max)
    }

    /// Last `n` samples, oldest first.
    pub fn tail(&self, n: usize) -> Vec<f64> {
        let skip = self.buf.len().saturating_sub(n);
        self.buf.iter().skip(skip).copied().collect()
    }
}

/// Compact per-process history (f32 to keep ~1000 processes × 2 series small).
#[derive(Clone, Debug, Default)]
pub struct MiniHist {
    buf: VecDeque<f32>,
}

impl MiniHist {
    pub const CAP: usize = 120;

    pub fn push(&mut self, v: f32) {
        if self.buf.len() == Self::CAP {
            self.buf.pop_front();
        }
        self.buf.push_back(v);
    }

    pub fn tail(&self, n: usize) -> Vec<f64> {
        let skip = self.buf.len().saturating_sub(n);
        self.buf.iter().skip(skip).map(|v| *v as f64).collect()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn first(&self) -> f32 {
        self.buf.front().copied().unwrap_or(0.0)
    }

    pub fn last(&self) -> f32 {
        self.buf.back().copied().unwrap_or(0.0)
    }

    pub fn max(&self) -> f32 {
        self.buf.iter().copied().fold(0.0, f32::max)
    }
}

pub fn fmt_bytes(b: u64) -> String {
    const UNITS: [&str; 6] = ["B", "K", "M", "G", "T", "P"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b}B")
    } else if v >= 100.0 {
        format!("{v:.0}{}", UNITS[i])
    } else if v >= 10.0 {
        format!("{v:.1}{}", UNITS[i])
    } else {
        format!("{v:.2}{}", UNITS[i])
    }
}

pub fn fmt_rate(bps: f64) -> String {
    format!("{}/s", fmt_bytes(bps.max(0.0) as u64))
}

pub fn fmt_duration(secs: u64) -> String {
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if d > 0 {
        format!("{d}d {h:02}:{m:02}")
    } else {
        format!("{h:02}:{m:02}:{s:02}")
    }
}


/// Single-line sparkline string.
pub fn spark(data: &[f64], max: f64) -> String {
    let max = if max <= 0.0 { 1.0 } else { max };
    data.iter()
        .map(|v| {
            let idx = ((v / max).clamp(0.0, 1.0) * 7.0).round() as usize;
            crate::theme::glyphs().spark[idx]
        })
        .collect()
}

/// Char-aware truncation with an ellipsis.
pub fn truncate(s: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let count = s.chars().count();
    if count <= width {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(width.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// Keep the end of a long path: `…/out/vigil-4e0f`.
pub fn truncate_left(s: &str, width: usize) -> String {
    let n = s.chars().count();
    if n <= width || width == 0 {
        return s.to_string();
    }
    let tail: String = s.chars().skip(n - width.saturating_sub(1)).collect();
    format!("…{tail}")
}

pub fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse an OpenSSL-style date `Jan 27 23:59:59 2027 GMT` to Unix seconds.
pub fn parse_cert_date(s: &str) -> Option<i64> {
    let f: Vec<&str> = s.split_whitespace().collect();
    if f.len() < 4 {
        return None;
    }
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let m = MONTHS.iter().position(|x| *x == f[0])? as u32 + 1;
    let d: u32 = f[1].parse().ok()?;
    let mut hms = f[2].split(':').map(|x| x.parse::<i64>().ok());
    let (h, mi, sec) = (hms.next()??, hms.next()??, hms.next()??);
    let y: i64 = f[3].parse().ok()?;
    Some(days_from_civil(y, m, d) * 86_400 + h * 3600 + mi * 60 + sec)
}

#[cfg(test)]
mod date_tests {
    use super::*;

    #[test]
    fn cert_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 2, 29), 11_016);
        assert_eq!(parse_cert_date("Jan  1 00:00:00 1970 GMT"), Some(0));
        assert_eq!(parse_cert_date("Feb 29 00:00:00 2000 GMT"), Some(951_782_400));
        assert_eq!(parse_cert_date("garbage"), None);
    }
}

/// Standard base64 (RFC 4648) for OSC 52.
pub fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Copy text to the system clipboard through the terminal (OSC 52). Works
/// over SSH; inside tmux it needs `set -g set-clipboard on`.
pub fn osc52_copy(text: &str) {
    use std::io::Write;
    let mut out = std::io::stdout();
    let _ = write!(out, "\x1b]52;c;{}\x07", base64(text.as_bytes()));
    let _ = out.flush();
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

pub fn csv(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut o = headers.iter().map(|h| csv_field(h)).collect::<Vec<_>>().join(",");
    o.push('\n');
    for r in rows {
        o.push_str(&r.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(","));
        o.push('\n');
    }
    o
}

/// Write `vigil-<name>-<unix time>.csv` to the current directory, or $HOME.
pub fn write_csv(name: &str, headers: &[&str], rows: &[Vec<String>]) -> Result<std::path::PathBuf, String> {
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let file = format!("vigil-{name}-{stamp}.csv");
    let text = csv(headers, rows);
    let mut dirs = vec![std::path::PathBuf::from(".")];
    if let Some(h) = std::env::var_os("HOME") {
        dirs.push(std::path::PathBuf::from(h));
    }
    let mut err = String::from("no writable directory");
    for d in dirs {
        let p = d.join(&file);
        match std::fs::write(&p, &text) {
            Ok(()) => return Ok(std::fs::canonicalize(&p).unwrap_or(p)),
            Err(e) => err = e.to_string(),
        }
    }
    Err(err)
}

#[cfg(test)]
mod io_tests {
    use super::*;

    #[test]
    fn base64_rfc4648() {
        for (i, o) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foobar", "Zm9vYmFy")] {
            assert_eq!(base64(i.as_bytes()), o);
        }
    }

    #[test]
    fn csv_quoting() {
        let c = csv(&["a", "b"], &[vec!["x,y".into(), "say \"hi\"".into()]]);
        assert_eq!(c, "a,b\n\"x,y\",\"say \"\"hi\"\"\"\n");
    }
}
