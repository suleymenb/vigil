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
