//! Runtime platform detection, done once at startup.
//!
//! vigil runs on Linux, macOS and Windows. Which collectors it uses depends on
//! the OS (compile time) and on which helper tools are installed (run time):
//! `lsof`, `curl`, `tcpdump`, `mtr`, `ethtool`, `lldpctl`, `nft`, … Instead of
//! every collector trying a command and failing every few seconds, they ask
//! this module once.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Linux,
    Macos,
    Windows,
    Other,
}

impl Os {
    pub const fn current() -> Os {
        if cfg!(target_os = "linux") {
            Os::Linux
        } else if cfg!(target_os = "macos") {
            Os::Macos
        } else if cfg!(windows) {
            Os::Windows
        } else {
            Os::Other
        }
    }

    /// Name of the config section for this OS: `[linux]`, `[macos]`, `[windows]`.
    pub fn key(self) -> &'static str {
        match self {
            Os::Linux => "linux",
            Os::Macos => "macos",
            Os::Windows => "windows",
            Os::Other => "other",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Os::Linux => "Linux",
            Os::Macos => "macOS",
            Os::Windows => "Windows",
            Os::Other => "this OS",
        }
    }
}

/// Helper programs found in PATH.
#[derive(Clone, Debug, Default)]
pub struct Tools {
    pub lsof: bool,
    pub curl: bool,
    pub tcpdump: bool,
    pub mtr: bool,
    pub traceroute: bool,
    pub tracert: bool,
    pub ip: bool,
    pub lldpctl: bool,
    pub nft: bool,
    pub iptables: bool,
    pub pfctl: bool,
    pub systemctl: bool,
    pub journalctl: bool,
    pub nettop: bool,
    pub iostat: bool,
    /// Docker Engine API endpoint (unix socket, or the Windows named pipe).
    pub docker: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct Platform {
    pub os: Os,
    /// Windows build number (e.g. 19045); None elsewhere.
    pub windows_build: Option<u32>,
    pub admin: bool,
    pub tools: Tools,
}

static PLATFORM: OnceLock<Platform> = OnceLock::new();

pub fn get() -> &'static Platform {
    PLATFORM.get_or_init(detect)
}

/// Is `name` an executable somewhere in PATH (with PATHEXT on Windows)?
pub fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".into())
            .split(';')
            .map(|e| e.to_ascii_lowercase())
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in std::env::split_paths(&path) {
        for ext in &exts {
            let p = dir.join(format!("{name}{ext}"));
            if p.is_file() {
                return Some(p);
            }
        }
    }
    // Some tools live outside a normal user PATH (sbin).
    if cfg!(unix) {
        for d in ["/usr/sbin", "/sbin", "/usr/local/sbin"] {
            let p = Path::new(d).join(name);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

fn has(name: &str) -> bool {
    which(name).is_some()
}

fn docker_endpoint() -> Option<PathBuf> {
    if cfg!(windows) {
        let p = PathBuf::from(r"\\.\pipe\docker_engine");
        return std::fs::metadata(&p).is_ok().then_some(p);
    }
    let mut cands = vec![PathBuf::from("/var/run/docker.sock")];
    if let Some(h) = std::env::var_os("HOME") {
        cands.insert(0, PathBuf::from(h).join(".docker/run/docker.sock"));
    }
    if let Some(d) = std::env::var("DOCKER_HOST").ok().and_then(|h| h.strip_prefix("unix://").map(PathBuf::from)) {
        cands.insert(0, d);
    }
    cands.into_iter().find(|p| p.exists())
}

fn is_admin() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        // `net session` only succeeds in an elevated prompt.
        std::process::Command::new("net")
            .arg("session")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

fn detect() -> Platform {
    let os = Os::current();
    let windows_build = (os == Os::Windows)
        .then(sysinfo::System::kernel_version)
        .flatten()
        .and_then(|k| k.split(|c: char| !c.is_ascii_digit()).rfind(|s| s.len() >= 4).and_then(|s| s.parse().ok()));
    Platform {
        os,
        windows_build,
        admin: is_admin(),
        tools: Tools {
            lsof: has("lsof"),
            curl: has("curl"),
            tcpdump: has("tcpdump"),
            mtr: has("mtr"),
            traceroute: has("traceroute"),
            tracert: has("tracert"),
            ip: has("ip"),
            lldpctl: has("lldpctl"),
            nft: has("nft"),
            iptables: has("iptables-save"),
            pfctl: has("pfctl"),
            systemctl: has("systemctl"),
            journalctl: has("journalctl"),
            nettop: has("nettop"),
            iostat: has("iostat"),
            docker: docker_endpoint(),
        },
    }
}

impl Tools {
    /// Helper tools that matter on this OS: (name, found, what it enables).
    pub fn relevant(&self, os: Os) -> Vec<(&'static str, bool, &'static str)> {
        let docker = self.docker.is_some();
        match os {
            Os::Linux => vec![
                ("lsof", self.lsof, "open-files queries (:)"),
                ("ip", self.ip, "routes and neighbour states"),
                ("tcpdump", self.tcpdump, "packet capture (C)"),
                ("mtr", self.mtr || self.traceroute, "path trace (t)"),
                ("nft", self.nft || self.iptables, "firewall counters"),
                ("systemctl", self.systemctl, "services"),
                ("journalctl", self.journalctl, "journal, SSH history"),
                ("lldpctl", self.lldpctl, "LLDP neighbours"),
                ("curl", self.curl, "HTTP probes, perf test"),
                ("docker", docker, "container names"),
            ],
            Os::Macos => vec![
                ("lsof", self.lsof, "sockets and open files"),
                ("tcpdump", self.tcpdump, "packet capture (C)"),
                ("mtr", self.mtr || self.traceroute, "path trace (t)"),
                ("pfctl", self.pfctl, "firewall counters"),
                ("nettop", self.nettop, "per-process bandwidth"),
                ("iostat", self.iostat, "disk device stats"),
                ("curl", self.curl, "HTTP probes, perf test"),
                ("docker", docker, "containers (Docker API)"),
            ],
            Os::Windows => vec![
                ("tracert", self.tracert || self.mtr, "path trace (t)"),
                ("curl", self.curl, "HTTP probes (Windows 10 1803+)"),
                ("lsof", self.lsof, "open-files queries (:)"),
                ("docker", docker, "containers (Docker API)"),
            ],
            Os::Other => vec![("lsof", self.lsof, "sockets and open files")],
        }
    }
}

impl Platform {
    /// "Windows 10 build 19045 · administrator · missing: lsof (open-files queries)".
    pub fn summary(&self) -> String {
        let mut s = self.os.label().to_string();
        if let Some(b) = self.windows_build {
            let name = if b >= 22_000 { "11" } else { "10" };
            s = format!("Windows {name} build {b}");
        }
        s.push_str(if self.admin { " · root/administrator" } else { " · unprivileged" });
        let missing: Vec<String> = self.tools.relevant(self.os).into_iter().filter(|t| !t.1).map(|t| format!("{} ({})", t.0, t.2)).collect();
        if !missing.is_empty() {
            s.push_str(" · missing: ");
            s.push_str(&missing.join(", "));
        }
        s
    }
}

/// Text for a feature that is missing on this machine.
pub fn unavailable(feature: &str, needs: &str) -> String {
    format!("{feature} is not available on {}: {needs}", get().os.label())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_current_os_and_tools() {
        let p = get();
        assert_eq!(p.os, Os::current());
        assert_ne!(p.os.key(), "");
        // Every CI runner has ping somewhere in PATH.
        assert!(which("ping").is_some() || cfg!(windows));
        assert!(p.summary().starts_with(p.os.label().split(' ').next().unwrap()) || p.windows_build.is_some());
        let w = Platform { os: Os::Windows, windows_build: Some(19045), admin: false, tools: Tools { curl: true, ..Default::default() } };
        assert!(w.summary().starts_with("Windows 10 build 19045 · unprivileged · missing: tracert"), "{}", w.summary());
        let w11 = Platform { windows_build: Some(26100), ..w };
        assert!(w11.summary().starts_with("Windows 11 build 26100"));
    }
}
