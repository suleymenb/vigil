//! Wi-Fi link details: SSID, BSSID, channel and band, PHY mode, rate, signal
//! (RSSI), noise and SNR. Many "network problems" on laptops are Wi-Fi.
//!
//! macOS: `system_profiler SPAirPortDataType -json` (slow, ~5 s; SSID/BSSID
//! are redacted unless the terminal has Location permission). Linux: `iw dev`
//! and `iw dev IF link`. Windows: `netsh wlan show interfaces`.

#![allow(dead_code)] // parsers for other platforms are unit-tested on every OS

use crate::tools::Tone;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Wifi {
    pub iface: String,
    pub ssid: String,
    pub bssid: String,
    pub channel: String,
    pub phy: String,
    pub rate_mbps: Option<f64>,
    pub rssi: Option<i32>,
    pub noise: Option<i32>,
    pub security: String,
}

impl Wifi {
    pub fn snr(&self) -> Option<i32> {
        Some(self.rssi? - self.noise?)
    }
    /// Rough quality: (label, tone) from RSSI and SNR.
    pub fn quality(&self) -> (&'static str, Tone) {
        match (self.rssi, self.snr()) {
            (Some(r), _) if r < -75 => ("very weak", Tone::Bad),
            (Some(r), _) if r < -70 => ("weak", Tone::Warn),
            (_, Some(s)) if s < 20 => ("noisy", Tone::Warn),
            (Some(r), _) if r >= -60 => ("good", Tone::Good),
            (Some(_), _) => ("fair", Tone::Normal),
            _ => ("unknown", Tone::Dim),
        }
    }
    /// One display line.
    pub fn line(&self) -> String {
        let mut parts = vec![self.iface.clone()];
        parts.push(if self.ssid.is_empty() { "SSID hidden".into() } else { self.ssid.clone() });
        if !self.bssid.is_empty() {
            parts.push(self.bssid.clone());
        }
        if !self.channel.is_empty() {
            parts.push(format!("ch {}", self.channel));
        }
        if !self.phy.is_empty() {
            parts.push(self.phy.clone());
        }
        if let Some(r) = self.rssi {
            parts.push(match (self.noise, self.snr()) {
                (Some(n), Some(s)) => format!("{r} dBm / {n} dBm (SNR {s} dB)"),
                _ => format!("{r} dBm"),
            });
        }
        if let Some(rate) = self.rate_mbps {
            parts.push(format!("{rate:.0} Mb/s"));
        }
        parts.join(" · ")
    }
}

fn dbm(s: &str) -> Option<i32> {
    s.split_whitespace().next()?.trim_end_matches("dBm").parse().ok()
}

/// macOS `system_profiler SPAirPortDataType -json`.
pub fn parse_system_profiler(text: &str) -> Vec<Wifi> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else { return Vec::new() };
    let mut out = Vec::new();
    for top in v["SPAirPortDataType"].as_array().into_iter().flatten() {
        for i in top["spairport_airport_interfaces"].as_array().into_iter().flatten() {
            let c = &i["spairport_current_network_information"];
            if c.get("spairport_network_channel").is_none() {
                continue;
            }
            let s = |k: &str| c[k].as_str().unwrap_or("").to_string();
            let sn = s("spairport_signal_noise");
            let (rssi, noise) = match sn.split_once('/') {
                Some((a, b)) => (dbm(a.trim()), dbm(b.trim())),
                None => (None, None),
            };
            let name = s("_name");
            out.push(Wifi {
                iface: i["_name"].as_str().unwrap_or("").to_string(),
                ssid: if name.starts_with('<') { String::new() } else { name },
                bssid: s("spairport_network_bssid"),
                channel: s("spairport_network_channel"),
                phy: s("spairport_network_phymode"),
                rate_mbps: c["spairport_network_rate"].as_f64(),
                rssi,
                noise,
                security: s("spairport_security_mode").trim_start_matches("spairport_security_mode_").replace('_', " "),
            });
        }
    }
    out
}

/// Linux `iw dev` → managed interface names.
pub fn parse_iw_dev(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    for l in text.lines().map(str::trim) {
        if let Some(n) = l.strip_prefix("Interface ") {
            cur = Some(n.trim().to_string());
        } else if l == "type managed" {
            if let Some(n) = cur.take() {
                out.push(n);
            }
        }
    }
    out
}

fn channel_of(freq: u32) -> String {
    match freq {
        2412..=2472 => format!("{} (2.4GHz)", (freq - 2407) / 5),
        2484 => "14 (2.4GHz)".into(),
        5000..=5900 => format!("{} (5GHz)", (freq - 5000) / 5),
        5925..=7125 => format!("{} (6GHz)", (freq - 5950) / 5),
        f => format!("{f} MHz"),
    }
}

/// Linux `iw dev IF link`.
pub fn parse_iw_link(text: &str, iface: &str) -> Option<Wifi> {
    let mut w = Wifi { iface: iface.to_string(), ..Default::default() };
    let first = text.lines().next()?;
    w.bssid = first.strip_prefix("Connected to ")?.split_whitespace().next()?.to_string();
    for l in text.lines().map(str::trim) {
        if let Some(v) = l.strip_prefix("SSID: ") {
            w.ssid = v.to_string();
        } else if let Some(v) = l.strip_prefix("freq: ") {
            if let Ok(f) = v.split('.').next().unwrap_or("").trim().parse::<u32>() {
                w.channel = channel_of(f);
            }
        } else if let Some(v) = l.strip_prefix("signal: ") {
            w.rssi = dbm(v);
        } else if let Some(v) = l.strip_prefix("tx bitrate: ") {
            w.rate_mbps = v.split_whitespace().next().and_then(|x| x.parse().ok());
            w.phy = ["EHT", "HE", "VHT", "HT"]
                .iter()
                .find(|p| v.contains(&format!("{p}-MCS")))
                .map(|p| match *p {
                    "EHT" => "802.11be",
                    "HE" => "802.11ax",
                    "VHT" => "802.11ac",
                    _ => "802.11n",
                })
                .unwrap_or("")
                .to_string();
        }
    }
    Some(w)
}

/// Windows `netsh wlan show interfaces` (English labels; signal and BSSID
/// are found by shape when labels are translated).
pub fn parse_netsh(text: &str) -> Vec<Wifi> {
    let mut out = Vec::new();
    let mut cur: Option<Wifi> = None;
    let mut connected = false;
    let mut band = String::new();
    let flush = |cur: &mut Option<Wifi>, connected: bool, band: &str, out: &mut Vec<Wifi>| {
        if let Some(mut w) = cur.take() {
            if !band.is_empty() && !w.channel.is_empty() {
                w.channel = format!("{} ({})", w.channel, band.replace(' ', ""));
            }
            if connected && (!w.bssid.is_empty() || !w.ssid.is_empty()) {
                out.push(w);
            }
        }
    };
    for l in text.lines() {
        let Some((k, v)) = l.split_once(" : ").or_else(|| l.split_once(": ")) else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        if k == "name" {
            flush(&mut cur, connected, &band, &mut out);
            cur = Some(Wifi { iface: v.to_string(), ..Default::default() });
            connected = false;
            band.clear();
            continue;
        }
        let Some(w) = cur.as_mut() else { continue };
        match k.as_str() {
            "state" => connected = v.eq_ignore_ascii_case("connected") || v.contains("verbonden") || v.contains("verbunden"),
            "ssid" => w.ssid = v.to_string(),
            "bssid" | "ap bssid" => w.bssid = v.to_string(),
            "radio type" => w.phy = v.to_string(),
            "authentication" => w.security = v.to_string(),
            "channel" => w.channel = v.to_string(),
            "band" => band = v.to_string(),
            "rssi" => w.rssi = v.parse().ok(),
            k if k.starts_with("receive rate") || k.starts_with("transmit rate") => {
                if let Ok(r) = v.parse::<f64>() {
                    w.rate_mbps = Some(w.rate_mbps.map_or(r, |x| x.max(r)));
                }
            }
            _ if v.ends_with('%') && w.rssi.is_none() => {
                // Signal quality %: Windows maps 0..100 % to about -100..-50 dBm.
                if let Ok(p) = v.trim_end_matches('%').trim().parse::<i32>() {
                    w.rssi = Some(p / 2 - 100);
                }
            }
            _ => {}
        }
    }
    flush(&mut cur, connected, &band, &mut out);
    out
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let o = std::process::Command::new(cmd).args(args).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Current Wi-Fi links (empty when there is no Wi-Fi or it is off).
pub fn read() -> Vec<Wifi> {
    if cfg!(target_os = "macos") {
        run("system_profiler", &["SPAirPortDataType", "-json"]).map(|t| parse_system_profiler(&t)).unwrap_or_default()
    } else if cfg!(windows) {
        run("netsh", &["wlan", "show", "interfaces"]).map(|t| parse_netsh(&t)).unwrap_or_default()
    } else {
        let ifs = run("iw", &["dev"]).map(|t| parse_iw_dev(&t)).unwrap_or_default();
        ifs.iter().filter_map(|i| run("iw", &["dev", i, "link"]).and_then(|t| parse_iw_link(&t, i))).collect()
    }
}

/// `vigil wifi`: print the links and what they mean.
pub fn report(emit: &dyn Fn(Tone, String)) -> usize {
    let links = read();
    if links.is_empty() {
        emit(Tone::Dim, "no connected Wi-Fi interface".into());
    }
    for w in &links {
        let (q, tone) = w.quality();
        emit(tone, format!("{} · {q}", w.line()));
        if !w.security.is_empty() {
            emit(Tone::Dim, format!("  security: {}", w.security));
        }
        if let Some(r) = w.rssi {
            if r < -70 {
                emit(Tone::Warn, "→ weak signal: move closer to the access point, or the AP's transmit power / placement needs work (below -67 dBm voice calls suffer)".into());
            }
        }
        if w.snr().is_some_and(|s| s < 20) {
            emit(Tone::Warn, "→ low SNR: interference (busy 2.4 GHz channel, neighbouring networks, microwaves); prefer 5 or 6 GHz".into());
        }
        if w.channel.contains("2.4") {
            emit(Tone::Normal, "→ on 2.4 GHz: slower and more crowded than 5/6 GHz; check band steering on the controller".into());
        }
    }
    if cfg!(target_os = "macos") && links.iter().any(|w| w.ssid.is_empty()) {
        emit(Tone::Dim, "  macOS hides SSID and BSSID unless the terminal app has Location Services permission".into());
    }
    links.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_json() {
        let t = r#"{"SPAirPortDataType":[{"spairport_airport_interfaces":[{"_name":"en0","spairport_current_network_information":{"_name":"<redacted>","spairport_network_channel":"56 (5GHz, 20MHz)","spairport_network_phymode":"802.11ax","spairport_network_rate":229,"spairport_security_mode":"spairport_security_mode_wpa2_personal","spairport_signal_noise":"-53 dBm / -100 dBm"}},{"_name":"awdl0","spairport_current_network_information":{"spairport_network_type":"x"}}]}]}"#;
        let w = parse_system_profiler(t);
        assert_eq!(w.len(), 1);
        assert_eq!((w[0].rssi, w[0].noise, w[0].snr()), (Some(-53), Some(-100), Some(47)));
        assert_eq!(w[0].ssid, "");
        assert_eq!(w[0].security, "wpa2 personal");
        assert_eq!(w[0].quality().0, "good");
    }

    #[test]
    fn linux_iw() {
        assert_eq!(parse_iw_dev("phy#0\n\tInterface wlp2s0\n\t\tifindex 3\n\t\ttype managed\n\tInterface p2p\n\t\ttype P2P-device\n"), vec!["wlp2s0"]);
        let l = "Connected to aa:bb:cc:dd:ee:ff (on wlp2s0)\n\tSSID: corp\n\tfreq: 5180.0\n\tsignal: -72 dBm\n\ttx bitrate: 866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2\n";
        let w = parse_iw_link(l, "wlp2s0").unwrap();
        assert_eq!((w.ssid.as_str(), w.bssid.as_str(), w.channel.as_str(), w.phy.as_str()), ("corp", "aa:bb:cc:dd:ee:ff", "36 (5GHz)", "802.11ac"));
        assert_eq!(w.rssi, Some(-72));
        assert_eq!(w.quality().0, "weak");
        assert!(parse_iw_link("Not connected.\n", "wlan0").is_none());
    }

    #[test]
    fn windows_netsh() {
        let t = "\nThere is 1 interface on the system:\n\n    Name                   : Wi-Fi\n    Description            : Intel(R) Wi-Fi 6 AX201\n    State                  : connected\n    SSID                   : corp\n    BSSID                  : aa:bb:cc:dd:ee:01\n    Radio type             : 802.11ax\n    Authentication         : WPA2-Enterprise\n    Band                   : 5 GHz\n    Channel                : 36\n    Receive rate (Mbps)    : 1201\n    Transmit rate (Mbps)   : 960\n    Signal                 : 84%\n";
        let w = parse_netsh(t);
        assert_eq!(w.len(), 1);
        assert_eq!((w[0].ssid.as_str(), w[0].channel.as_str(), w[0].rate_mbps), ("corp", "36 (5GHz)", Some(1201.0)));
        assert_eq!(w[0].rssi, Some(-58));
    }
}
