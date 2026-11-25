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
        }
    }
}

pub fn path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("vigil").join("config.toml"))
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
    fn roundtrip() {
        let c = Config::default();
        let s = toml::to_string_pretty(&c).unwrap();
        let back: Config = toml::from_str(&s).unwrap();
        assert_eq!(back.interval_ms, c.interval_ms);
    }
}
