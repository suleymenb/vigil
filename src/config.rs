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
    /// Characters for graphs, borders and symbols: "auto" (looks at the
    /// console), "theme" (whatever the theme draws with), "safe" (what the
    /// classic Windows console and the Linux text console can show), "ascii".
    pub glyphs: String,
    pub interval_ms: u64,
    pub lsof_interval_s: u64,
    pub start_tab: String,
    pub proc_sort: String,
    pub proc_desc: bool,
    pub proc_tree: bool,
    pub mouse: bool,
    pub alerts: Alerts,
    pub network: Network,
    pub troubleshoot: Troubleshoot,
    pub snmp: Snmp,
    /// Remap keys in normal mode: `"F5" = "R"`, `"ctrl-k" = "K"`, `"Q" = "q"`.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub keys: std::collections::BTreeMap<String, String>,
    /// Extra themes: name, base theme, glyphs and colour overrides.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub custom_themes: Vec<CustomTheme>,
    /// The file as read (shared part + per-OS sections); not serialized.
    #[serde(skip)]
    pub raw: Option<RawConfig>,
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

/// A theme defined in the config:
///
/// ```toml
/// [[custom_themes]]
/// name = "noc-wall"
/// base = "nord"          # start from this theme
/// glyphs = "neon"        # modern | neon | ascii
/// [custom_themes.colors]
/// bg = "#000000"
/// red = "#ff3355"
/// green = "light-green"  # ANSI names and ansi:N work too
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomTheme {
    pub name: String,
    pub base: String,
    pub glyphs: String,
    pub colors: std::collections::BTreeMap<String, String>,
}

/// Credentials for `vigil snmp` and `s` in the Troubleshoot view. Passwords
/// can stay out of the file: VIGIL_SNMP_COMMUNITY, VIGIL_SNMP_AUTH and
/// VIGIL_SNMP_PRIV override it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Snmp {
    /// "2c" or "3".
    pub version: String,
    pub community: String,
    pub port: u16,
    pub user: String,
    /// md5, sha, sha256
    pub auth_protocol: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub auth_password: String,
    /// AES-128 privacy password (empty: authNoPriv).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub priv_password: String,
}

impl Default for Snmp {
    fn default() -> Self {
        Self { version: "2c".into(), community: "public".into(), port: 161, user: String::new(), auth_protocol: "sha".into(), auth_password: String::new(), priv_password: String::new() }
    }
}

impl Snmp {
    /// Credentials, with environment variables winning over the file and an
    /// explicit community (from the prompt) winning over both.
    pub fn auth(&self, community: Option<&str>) -> Result<crate::tools::snmp::Auth, String> {
        use crate::tools::snmp::{Auth, AuthProto};
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        if self.version.trim_start_matches(['v', 'V']) == "3" && community.is_none() {
            if self.user.is_empty() {
                return Err("SNMPv3 needs [snmp] user = … in the config".into());
            }
            let auth_pass = env("VIGIL_SNMP_AUTH").unwrap_or_else(|| self.auth_password.clone());
            let priv_pass = env("VIGIL_SNMP_PRIV").unwrap_or_else(|| self.priv_password.clone());
            let proto = AuthProto::parse(&self.auth_protocol).ok_or_else(|| format!("unknown auth_protocol \"{}\" (md5, sha, sha256)", self.auth_protocol))?;
            return Ok(Auth::V3 {
                user: self.user.clone(),
                auth: (!auth_pass.is_empty()).then_some((proto, auth_pass)),
                privacy: (!priv_pass.is_empty()).then_some(priv_pass),
            });
        }
        Ok(Auth::V2c { community: community.map(String::from).or_else(|| env("VIGIL_SNMP_COMMUNITY")).unwrap_or_else(|| self.community.clone()) })
    }
}

/// Targets for the Troubleshoot view (W) and `vigil doctor|dns|mtu|perf`.
/// These are only contacted when you run one of those tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Troubleshoot {
    /// Pinged and TCP-connected (port 443) by the doctor; default target for `mtu`.
    pub internet_target: String,
    pub internet_target6: String,
    /// Name the doctor resolves through every configured resolver.
    pub dns_test_name: String,
    /// Fetched for the TLS, clock and HTTP checks.
    pub http_test_url: String,
    /// Compared with your own resolvers by the DNS tool.
    pub public_resolvers: Vec<String>,
    /// Download used by `vigil perf --internet` (and `p` with no host).
    pub perf_url: String,
}

impl Default for Troubleshoot {
    fn default() -> Self {
        Self {
            internet_target: "1.1.1.1".into(),
            internet_target6: "2606:4700:4700::1111".into(),
            dns_test_name: "example.com".into(),
            http_test_url: "https://example.com/".into(),
            public_resolvers: vec!["1.1.1.1".into(), "8.8.8.8".into(), "9.9.9.9".into()],
            perf_url: "https://speed.cloudflare.com/__down?bytes=25000000".into(),
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
    /// Open file descriptors of one process against its limit, percent.
    pub fd_pct: f64,
    /// System-wide file handles in use, percent.
    pub files_pct: f64,
    /// Ephemeral (outgoing) ports in use, percent of ip_local_port_range.
    pub ephemeral_pct: f64,
    /// Inodes used on any filesystem, percent.
    pub inode_pct: f64,
    /// Average disk request latency, ms (Linux).
    pub disk_await_ms: f64,
    /// Disk busy time, percent (Linux).
    pub disk_util_pct: f64,
    /// Days before a TLS certificate (https probe) expires.
    pub cert_days: f64,
    /// Share of CPU periods a container was throttled, percent.
    pub throttle_pct: f64,
    /// Badge for failed systemd units / launchd jobs.
    pub failed_units: bool,
    /// Badge for processes still running replaced binaries or libraries.
    pub needs_restart: bool,
    /// Failed SSH logins in the last hour (Linux).
    pub ssh_failures_per_hour: u32,
    /// NIC error counters (CRC, frame, missed …) rising faster than this per second.
    pub nic_errors_per_s: f64,
    /// The default gateway's MAC address changed (failover or ARP spoofing).
    pub gateway_mac_change: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            theme: "auto".into(),
            background: true,
            glyphs: "auto".into(),
            interval_ms: 1000,
            lsof_interval_s: 3,
            start_tab: "overview".into(),
            proc_sort: "cpu".into(),
            proc_desc: true,
            proc_tree: false,
            mouse: true,
            alerts: Alerts::default(),
            network: Network::default(),
            troubleshoot: Troubleshoot::default(),
            snmp: Snmp::default(),
            keys: Default::default(),
            custom_themes: Vec::new(),
            raw: None,
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
            fd_pct: 90.0,
            files_pct: 80.0,
            ephemeral_pct: 80.0,
            inode_pct: 90.0,
            disk_await_ms: 100.0,
            disk_util_pct: 95.0,
            cert_days: 21.0,
            throttle_pct: 25.0,
            failed_units: true,
            needs_restart: true,
            ssh_failures_per_hour: 100,
            nic_errors_per_s: 1.0,
            gateway_mac_change: true,
        }
    }
}

pub fn path() -> Option<PathBuf> {
    // Windows: %APPDATA%\vigil\config.toml
    if cfg!(windows) {
        return std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("vigil").join("config.toml"));
    }
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
#[cfg_attr(not(unix), allow(dead_code))]
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

const OS_SECTIONS: [&str; 3] = ["linux", "macos", "windows"];

/// Recursively overlay `over` onto `base` (tables merge, values replace).
pub fn merge(base: &mut toml::Table, over: &toml::Table) {
    for (k, v) in over {
        match (base.get_mut(k), v) {
            (Some(toml::Value::Table(b)), toml::Value::Table(o)) => merge(b, o),
            _ => {
                base.insert(k.clone(), v.clone());
            }
        }
    }
}

/// Split a config file into the shared part and the per-OS sections, then
/// apply the section for the OS vigil is running on.
pub fn effective(text: &str, os_key: &str) -> Result<(Config, RawConfig), toml::de::Error> {
    let mut root: toml::Table = toml::from_str(text)?;
    let mut sections = toml::Table::new();
    for k in OS_SECTIONS {
        if let Some(v) = root.remove(k) {
            sections.insert(k.to_string(), v);
        }
    }
    let mut eff = root.clone();
    if let Some(toml::Value::Table(t)) = sections.get(os_key) {
        merge(&mut eff, t);
    }
    let cfg: Config = toml::Value::Table(eff.clone()).try_into()?;
    Ok((cfg, RawConfig { base: root, sections, effective: eff }))
}

/// Load the config. A broken file never stops vigil: you get defaults plus a warning.
/// Sections `[linux]`, `[macos]` and `[windows]` override the shared settings on that OS.
pub fn load(explicit: Option<&PathBuf>) -> (Config, Option<String>) {
    let Some(p) = explicit.cloned().or_else(path) else {
        return (Config::default(), None);
    };
    match std::fs::read_to_string(&p) {
        Ok(s) => match effective(&s, crate::platform::Os::current().key()) {
            Ok((mut c, raw)) => {
                c.raw = Some(raw);
                (c, None)
            }
            Err(e) => (
                Config::default(),
                Some(format!("config {} ignored: {}", p.display(), e.message())),
            ),
        },
        Err(_) => (Config::default(), None),
    }
}

/// The file as it was read, so saving keeps per-OS sections intact.
#[derive(Debug, Clone, Default)]
pub struct RawConfig {
    pub base: toml::Table,
    pub sections: toml::Table,
    pub effective: toml::Table,
}

/// Write back only what changed in the app: into the OS section when that key
/// lives there, otherwise into the shared part.
fn apply_changes(base: &mut toml::Table, section: &mut toml::Table, old: &toml::Table, new: &toml::Table) {
    for (k, nv) in new {
        if old.get(k) == Some(nv) {
            continue;
        }
        match (nv, base.get_mut(k), section.get_mut(k)) {
            (toml::Value::Table(nt), _, Some(toml::Value::Table(st))) => {
                let empty = toml::Table::new();
                let ot = old.get(k).and_then(|v| v.as_table()).unwrap_or(&empty).clone();
                let mut bt = base.get(k).and_then(|v| v.as_table()).cloned().unwrap_or_default();
                apply_changes(&mut bt, st, &ot, nt);
                base.insert(k.clone(), toml::Value::Table(bt));
            }
            (_, _, Some(sv)) => *sv = nv.clone(),
            (toml::Value::Table(nt), Some(toml::Value::Table(bt)), None) => {
                let empty = toml::Table::new();
                let ot = old.get(k).and_then(|v| v.as_table()).unwrap_or(&empty).clone();
                let mut none = toml::Table::new();
                apply_changes(bt, &mut none, &ot, nt);
            }
            _ => {
                base.insert(k.clone(), nv.clone());
            }
        }
    }
}

pub fn render(cfg: &Config, os: &str) -> Result<String, String> {
    let new: toml::Table = toml::Value::try_from(cfg).map_err(|e| e.to_string())?.try_into().map_err(|e: toml::de::Error| e.to_string())?;
    let (base, sections) = match &cfg.raw {
        Some(raw) => {
            let mut base = raw.base.clone();
            let mut sections = raw.sections.clone();
            let mut section = sections.get(os).and_then(|v| v.as_table()).cloned().unwrap_or_default();
            apply_changes(&mut base, &mut section, &raw.effective, &new);
            if !section.is_empty() {
                sections.insert(os.to_string(), toml::Value::Table(section));
            }
            (base, sections)
        }
        None => (new, toml::Table::new()),
    };
    let mut body = toml::to_string_pretty(&base).map_err(|e| e.to_string())?;
    for k in OS_SECTIONS {
        if let Some(toml::Value::Table(t)) = sections.get(k) {
            let mut wrap = toml::Table::new();
            wrap.insert(k.to_string(), toml::Value::Table(t.clone()));
            body.push('\n');
            body.push_str(&toml::to_string_pretty(&wrap).map_err(|e| e.to_string())?);
        }
    }
    Ok(body)
}

pub fn save(cfg: &Config, explicit: Option<&PathBuf>) -> Result<PathBuf, String> {
    let p = explicit.cloned().or_else(path).ok_or("no HOME directory")?;
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let body = render(cfg, crate::platform::Os::current().key())?;
    let text = format!(
        "# vigil configuration. Written on quit; edit freely.\n\
         # themes: auto, {}\n\
         # Per-OS overrides: add [linux], [macos] or [windows] sections with any of the\n\
         # settings below; they apply only on that OS (e.g. [windows] theme = \"ansi\").\n\n{body}",
        crate::theme::names().join(", ")
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
    fn per_os_sections() {
        let text = "theme = \"nord\"\ninterval_ms = 1000\n[alerts]\ndisk_pct = 90.0\n[windows]\ntheme = \"ansi\"\n[windows.alerts]\ndisk_pct = 95.0\n[linux]\ninterval_ms = 500\n";
        let (w, raw) = effective(text, "windows").unwrap();
        assert_eq!(w.theme, "ansi");
        assert_eq!(w.alerts.disk_pct, 95.0);
        assert_eq!(w.interval_ms, 1000);
        let (l, _) = effective(text, "linux").unwrap();
        assert_eq!(l.theme, "nord");
        assert_eq!(l.interval_ms, 500);
        // Saving on Windows after changing the theme updates [windows], not the shared theme.
        let mut c = w;
        c.raw = Some(raw);
        c.theme = "dracula".into();
        let out = render(&c, "windows").unwrap();
        let back: toml::Table = toml::from_str(&out).unwrap();
        assert_eq!(back["theme"].as_str(), Some("nord"));
        assert_eq!(back["windows"]["theme"].as_str(), Some("dracula"));
        assert_eq!(back["linux"]["interval_ms"].as_integer(), Some(500));
    }

    #[test]
    fn roundtrip() {
        let c = Config::default();
        let s = toml::to_string_pretty(&c).unwrap();
        let back: Config = toml::from_str(&s).unwrap();
        assert_eq!(back.interval_ms, c.interval_ms);
    }
}
