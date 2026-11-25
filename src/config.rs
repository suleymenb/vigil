//! Persistent settings in `$XDG_CONFIG_HOME/vigil/config.toml`
//! (default `~/.config/vigil/config.toml`, also on macOS).
//!
//! Precedence: CLI flags > config file > built-in defaults.
//! Theme, interval, sort and tree mode are written back on quit, like btop.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Theme name, or "auto" (truecolor terminals get tokyo-night, others ansi).
    pub theme: String,
    /// Paint the theme background. false = keep the terminal's own (transparent).
    pub background: bool,
    pub interval_ms: u64,
    pub lsof_interval_s: u64,
    pub start_tab: String,
    pub proc_sort: String,
    pub proc_desc: bool,
    pub proc_tree: bool,
    pub mouse: bool,
    pub alerts: Alerts,
    pub network: Network,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Network {
    /// Latency probes: "icmp:1.1.1.1", "tcp:db.internal:5432", "dns:github.com".
    pub probes: Vec<String>,
    /// Also ping the default gateway(s) and DNS servers.
    pub auto_probes: bool,
    pub probe_interval_s: u64,
    /// Length of a one-key packet capture (C in the Sockets view).
    pub capture_seconds: u64,
    /// Show host names instead of IPs (n toggles it).
    pub reverse_dns: bool,
}

impl Default for Network {
    fn default() -> Self {
        Self {
            probes: Vec::new(),
            auto_probes: true,
            probe_interval_s: 5,
            capture_seconds: 20,
            reverse_dns: false,
        }
    }
}

/// Thresholds for the health badges in the header. 0 disables a check.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Alerts {
    pub mem_pct: f64,
    pub swap_pct: f64,
    pub disk_pct: f64,
    /// 1-minute load divided by logical cores.
    pub load_per_core: f64,
    pub close_wait: usize,
    pub time_wait: usize,
    pub temp_c: f32,
    /// Linux PSI `some avg10` percentage for cpu / memory / io.
    pub psi_pct: f64,
    /// TCP retransmitted / sent segments, percent (Linux).
    pub retrans_pct: f64,
    /// Accept-queue overflows or drops per second (Linux).
    pub listen_drops_per_s: f64,
    /// UDP receive/send buffer errors per second (Linux).
    pub udp_drops_per_s: f64,
    /// Conntrack table usage, percent (Linux).
    pub conntrack_pct: f64,
    /// Packets dropped per second on any interface.
    pub iface_drops_per_s: f64,
    /// Latency probe loss over the last 100 probes, percent.
    pub probe_loss_pct: f64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            theme: "auto".into(),
            background: true,
            interval_ms: 1000,
            lsof_interval_s: 3,
            start_tab: "overview".into(),
            proc_sort: "cpu".into(),
            proc_desc: true,
            proc_tree: false,
            mouse: true,
            alerts: Alerts::default(),
            network: Network::default(),
        }
    }
}

impl Default for Alerts {
    fn default() -> Self {
        Self {
            mem_pct: 90.0,
            swap_pct: 50.0,
            disk_pct: 90.0,
            load_per_core: 1.5,
            close_wait: 100,
            time_wait: 20_000,
            temp_c: 90.0,
            psi_pct: 20.0,
            retrans_pct: 2.0,
            listen_drops_per_s: 1.0,
            udp_drops_per_s: 1.0,
            conntrack_pct: 80.0,
            iface_drops_per_s: 10.0,
            probe_loss_pct: 20.0,
        }
    }
}

pub fn path() -> Option<PathBuf> {
    // Under sudo, use the invoking user's config, not root's: `vigil` and
    // `sudo vigil` should share one set of settings.
    if let Some(home) = sudo_user().map(|u| u.home) {
        return Some(home.join(".config").join("vigil").join("config.toml"));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("vigil").join("config.toml"))
}

/// The user who ran `sudo vigil`, when we are root because of sudo.
pub struct SudoUser {
    pub home: PathBuf,
    pub uid: u32,
    pub gid: u32,
}

pub fn sudo_user() -> Option<SudoUser> {
    let name = std::env::var("SUDO_USER").ok().filter(|n| !n.is_empty() && n != "root")?;
    let uid = std::env::var("SUDO_UID").ok()?.parse().ok()?;
    let gid = std::env::var("SUDO_GID").ok()?.parse().ok()?;
    let home = std::fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|t| home_from_passwd(&t, &name))
        .or_else(|| {
            // macOS keeps regular users in Directory Services, not /etc/passwd.
            let p = PathBuf::from("/Users").join(&name);
            (cfg!(target_os = "macos") && p.is_dir()).then_some(p)
        })?;
    Some(SudoUser { home, uid, gid })
}

pub fn home_from_passwd(passwd: &str, user: &str) -> Option<PathBuf> {
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 6 && f[0] == user && !f[5].is_empty()).then(|| PathBuf::from(f[5]))
    })
}

/// Load the config. A broken file never stops vigil: you get defaults plus a warning.
pub fn load(explicit: Option<&PathBuf>) -> (Config, Option<String>) {
    let Some(p) = explicit.cloned().or_else(path) else {
        return (Config::default(), None);
    };
    match std::fs::read_to_string(&p) {
        Ok(s) => match toml::from_str::<Config>(&s) {
            Ok(c) => (c, None),
            Err(e) => (
                Config::default(),
                Some(format!("config {} ignored: {}", p.display(), e.message())),
            ),
        },
        Err(_) => (Config::default(), None),
    }
}

pub fn save(cfg: &Config, explicit: Option<&PathBuf>) -> Result<PathBuf, String> {
    let p = explicit.cloned().or_else(path).ok_or("no HOME directory")?;
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let body = toml::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    let text = format!(
        "# vigil configuration. Written on quit; edit freely.\n\
         # themes: auto, {}\n\n{body}",
        crate::theme::THEMES.iter().map(|t| t.name).collect::<Vec<_>>().join(", ")
    );
    // Write atomically so a crash never leaves a half-written config.
    let tmp = p.with_extension("toml.tmp");
    std::fs::write(&tmp, text).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &p).map_err(|e| e.to_string())?;
    // Written as root under sudo: hand the file back to the real user so a
    // later `vigil` without sudo can still update it.
    #[cfg(unix)]
    if let Some(u) = sudo_user() {
        if let Some(dir) = p.parent() {
            let _ = std::os::unix::fs::chown(dir, Some(u.uid), Some(u.gid));
        }
        let _ = std::os::unix::fs::chown(&p, Some(u.uid), Some(u.gid));
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_config_uses_defaults() {
        let c: Config = toml::from_str("theme = \"nord\"\n[alerts]\ndisk_pct = 80.0\n").unwrap();
        assert_eq!(c.theme, "nord");
        assert_eq!(c.interval_ms, 1000);
        assert_eq!(c.alerts.disk_pct, 80.0);
        assert_eq!(c.alerts.close_wait, 100);
    }

    #[test]
    fn passwd_home_lookup() {
        let pw = "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:User,,,:/home/user:/usr/bin/zsh\n";
        assert_eq!(home_from_passwd(pw, "user"), Some(PathBuf::from("/home/user")));
        assert_eq!(home_from_passwd(pw, "nobody"), None);
    }

    #[test]
    fn roundtrip() {
        let c = Config::default();
        let s = toml::to_string_pretty(&c).unwrap();
        let back: Config = toml::from_str(&s).unwrap();
        assert_eq!(back.interval_ms, c.interval_ms);
    }
}
