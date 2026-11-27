//! vigil — a modern terminal system monitor for DevOps, networking and
//! Linux administration, with first-class lsof integration.

mod app;
mod collect;
mod config;
mod explain;
mod platform;
mod report;
mod theme;
mod tools;
mod ui;
mod util;

use std::io::stdout;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::{Parser, Subcommand};
use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind};
use crossterm::execute;

use app::{App, Tab};
use collect::lsof::{self, FilesStore, Query, SocketStore};
use collect::system::Sampler;

#[derive(Parser, Debug)]
#[command(name = "vigil", version, about = "Modern terminal system monitor with lsof integration")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Sampling interval in milliseconds [config: interval_ms, default 1000]
    #[arg(short, long)]
    interval: Option<u64>,

    /// Seconds between background socket scans [config: lsof_interval_s, default 3]
    #[arg(long)]
    lsof_interval: Option<u64>,

    /// Start view: overview, procs, network, sockets, files, storage, routes, probes, firewall, containers, system, users, troubleshoot
    #[arg(short, long)]
    tab: Option<String>,

    /// Run an lsof query at startup (same syntax as the `:` prompt, e.g. ":443" or "1234")
    #[arg(short, long)]
    query: Option<String>,

    /// Colour theme (see --list-themes, including [[custom_themes]]), or "auto"
    #[arg(long)]
    theme: Option<String>,

    /// List available themes and exit
    #[arg(long)]
    list_themes: bool,

    /// Config file [default: ~/.config/vigil/config.toml, Windows: %APPDATA%\vigil\config.toml]
    #[arg(long, value_name = "PATH")]
    config: Option<std::path::PathBuf>,

    /// Don't write settings back to the config file on quit
    #[arg(long)]
    no_save: bool,

    /// Disable mouse support
    #[arg(long)]
    no_mouse: bool,

    /// Use `lsof -i` for the socket list even on Linux (default there: native /proc/net)
    #[arg(long)]
    lsof_sockets: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print a point-in-time system report (Markdown or JSON) and exit
    Report {
        /// Output format
        #[arg(short, long, value_parser = ["md", "markdown", "json"], default_value = "md")]
        format: String,
        /// Write to a file instead of stdout
        #[arg(short, long, value_name = "PATH")]
        output: Option<std::path::PathBuf>,
        /// Rows in the top-N tables
        #[arg(long, default_value_t = 10)]
        top: usize,
        /// Sampling window for CPU and rates, in milliseconds
        #[arg(long, default_value_t = 1000)]
        sample_ms: u64,
        /// Exit with code 2 when any health threshold is exceeded (for cron / CI)
        #[arg(long)]
        fail_on_alert: bool,
        /// Compare with an earlier `vigil report -f json` and list what changed
        #[arg(long, value_name = "FILE")]
        diff: Option<std::path::PathBuf>,
    },
    /// Check every layer (link, ARP, IP, MTU, TCP, clock, TLS, DNS, HTTP) and say where it breaks
    Doctor {
        /// Print the checks as JSON
        #[arg(long)]
        json: bool,
    },
    /// Subnet calculator: 10.0.0.0/22 · 10.0.0.5 255.255.252.0 · 2001:db8::/48 (add /24 to split, or an IP to test membership)
    Calc {
        #[arg(required = true, num_args = 1..)]
        input: Vec<String>,
    },
    /// Ask every resolver directly and compare: vigil dns github.com MX [@1.1.1.1]
    Dns {
        #[arg(required = true, num_args = 1..)]
        query: Vec<String>,
    },
    /// Discover the path MTU with don't-fragment pings (default target: [troubleshoot] internet_target)
    Mtu { target: Option<String> },
    /// Throughput test: `vigil perf --server` on one machine, `vigil perf HOST` on the other
    Perf {
        /// Host (or host:port) running `vigil perf --server`
        host: Option<String>,
        /// Listen for tests instead of running one
        #[arg(long)]
        server: bool,
        /// Port to listen on (server) or connect to (client)
        #[arg(short, long, default_value_t = tools::perf::DEFAULT_PORT)]
        port: u16,
        /// Test duration in seconds
        #[arg(short = 't', long, default_value_t = 10)]
        time: u32,
        /// Parallel TCP streams
        #[arg(short = 'P', long, default_value_t = 1)]
        parallel: usize,
        /// Reverse: the server sends, this machine receives (download)
        #[arg(short = 'R', long)]
        reverse: bool,
        /// HTTP download test via curl instead ([troubleshoot] perf_url)
        #[arg(long)]
        internet: bool,
    },
    /// Capture packets to a .pcap for Wireshark: vigil capture -i en0 -t 30 port 443
    Capture {
        /// Interface (default: any)
        #[arg(short, long)]
        interface: Option<String>,
        /// Stop after this many seconds (default: until ctrl-c; Windows: 20)
        #[arg(short = 't', long)]
        time: Option<u64>,
        /// Stop after this many packets
        #[arg(short = 'c', long)]
        count: Option<u64>,
        /// Output file, or - to stream pcap to stdout (… | wireshark -k -i -)
        #[arg(short = 'w', long, value_name = "FILE")]
        write: Option<std::path::PathBuf>,
        /// Open the capture in Wireshark when it finishes
        #[arg(long)]
        open: bool,
        /// BPF filter, e.g. port 443 · host 10.0.0.5 and tcp
        filter: Vec<String>,
    },
    /// Is a TCP port open, refused or filtered from here? vigil reach 10.0.0.5 22,443,3389
    Reach {
        host: String,
        /// Ports: 22,443 · 8000-8010 · ssh,https,rdp
        ports: String,
        /// Connect timeout in milliseconds
        #[arg(short = 't', long, default_value_t = 1500)]
        timeout: u64,
    },
    /// Trace the path hop by hop; --tcp/--udp get through firewalls that drop ICMP
    Trace {
        host: String,
        /// Trace with TCP SYNs to this port
        #[arg(long, value_name = "PORT", conflicts_with = "udp")]
        tcp: Option<u16>,
        /// Trace with UDP
        #[arg(long)]
        udp: bool,
    },
    /// Poll a switch/router/firewall: ports, errors, CRC, discards, flaps, LLDP, CPU
    Snmp {
        host: String,
        /// v2c community (default: [snmp] community, VIGIL_SNMP_COMMUNITY, "public")
        #[arg(short, long)]
        community: Option<String>,
        /// SNMPv3 user (switches to v3)
        #[arg(short, long)]
        user: Option<String>,
        /// v3 auth protocol: md5, sha, sha256
        #[arg(short = 'a', long, default_value = "sha")]
        auth_protocol: String,
        /// v3 auth password (or VIGIL_SNMP_AUTH)
        #[arg(short = 'A', long)]
        auth_password: Option<String>,
        /// v3 AES privacy password (or VIGIL_SNMP_PRIV)
        #[arg(short = 'x', long)]
        priv_password: Option<String>,
        /// UDP port
        #[arg(short, long, default_value_t = 161)]
        port: u16,
        /// Seconds between the two counter samples (rates)
        #[arg(short, long, default_value_t = 5)]
        interval: u64,
        /// Show every interface, also disabled and logical ones
        #[arg(long)]
        all: bool,
    },
    /// Receive syslog from network devices and show it live, classified (ctrl-c stops)
    Syslog {
        /// UDP/TCP port (514 needs root; 5514 doesn't)
        #[arg(short, long, default_value_t = 514)]
        port: u16,
        /// Only show lines containing this text
        #[arg(short, long)]
        filter: Option<String>,
        /// Also append every raw message to this file
        #[arg(short, long, value_name = "FILE")]
        write: Option<std::path::PathBuf>,
    },
    /// Which DHCP servers answer here? Finds rogue DHCP servers (needs root)
    Dhcp {
        /// Interface to send the DHCP discover on
        #[arg(short, long)]
        interface: Option<String>,
        /// Seconds to wait for offers
        #[arg(short = 't', long, default_value_t = 4)]
        time: u64,
    },
    /// Wi-Fi link: signal, noise, SNR, channel, band, rate
    Wifi,
    /// Print a shell completion script: vigil completions bash > /etc/bash_completion.d/vigil
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Print the man page (roff): vigil man | man -l -
    Man,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if let Some(Command::Report { format, output, top, sample_ms, fail_on_alert, diff }) = &args.command {
        let (cfg, warn) = config::load(args.config.as_ref());
        if let Some(w) = warn {
            eprintln!("vigil: {w}");
        }
        let code = report::run_cli(
            report::Options {
                json: format == "json",
                output: output.clone(),
                top: (*top).max(1),
                sample: Duration::from_millis((*sample_ms).clamp(250, 60_000)),
                fail_on_alert: *fail_on_alert,
                force_lsof: args.lsof_sockets,
                diff: diff.clone(),
            },
            &cfg.alerts,
        )?;
        std::process::exit(code);
    }
    match &args.command {
        Some(Command::Completions { shell }) => {
            let mut cmd = <Args as clap::CommandFactory>::command();
            clap_complete::generate(*shell, &mut cmd, "vigil", &mut stdout());
            return Ok(());
        }
        Some(Command::Man) => {
            let cmd = <Args as clap::CommandFactory>::command();
            clap_mangen::Man::new(cmd).render(&mut stdout())?;
            return Ok(());
        }
        _ => {}
    }
    if let Some(cmd) = &args.command {
        let (cfg, warn) = config::load(args.config.as_ref());
        if let Some(w) = warn {
            eprintln!("vigil: {w}");
        }
        let settings = tools::Settings::from(&cfg.troubleshoot);
        let code = match cmd {
            Command::Report { .. } | Command::Completions { .. } | Command::Man => unreachable!(),
            Command::Doctor { json } => tools::cli::doctor(&settings, *json),
            Command::Calc { input } => tools::cli::calc(&input.join(" ")),
            Command::Dns { query } => tools::cli::dns(&query.join(" "), &settings),
            Command::Mtu { target } => tools::cli::mtu(target.as_deref().unwrap_or(&settings.internet4)),
            Command::Reach { host, ports, timeout } => tools::cli::reach(host, ports, *timeout),
            Command::Trace { host, tcp, udp } => tools::cli::trace(host, *tcp, *udp),
            Command::Snmp { host, community, user, auth_protocol, auth_password, priv_password, port, interval, all } => {
                tools::cli::snmp(host, community.as_deref(), user.as_deref(), auth_protocol, auth_password.as_deref(), priv_password.as_deref(), *port, *interval, *all, &cfg.snmp)
            }
            Command::Syslog { port, filter, write } => tools::cli::syslog(*port, filter.as_deref(), write.as_deref()),
            Command::Dhcp { interface, time } => tools::cli::dhcp(interface.as_deref(), *time),
            Command::Wifi => tools::cli::wifi(),
            Command::Capture { interface, time, count, write, open, filter } => tools::cli::capture(interface.as_deref(), *time, *count, write.as_deref(), *open, &filter.join(" ")),
            Command::Perf { host, server, port, time, parallel, reverse, internet } => {
                tools::cli::perf(host.as_deref(), *server, *port, *time, *parallel, *reverse, *internet, &settings)
            }
        };
        std::process::exit(code);
    }
    let (cfg, cfg_warning) = config::load(args.config.as_ref());
    let theme_warnings = theme::install_custom(&cfg.custom_themes);
    if args.list_themes {
        for t in theme::all() {
            println!("{}", t.name);
        }
        return Ok(());
    }

    let theme_name = args.theme.clone().unwrap_or_else(|| cfg.theme.clone());
    let theme_idx = if theme_name.eq_ignore_ascii_case("auto") {
        theme::auto_default()
    } else {
        theme::by_name(&theme_name).unwrap_or_else(theme::auto_default)
    };
    theme::set(theme_idx);
    let auto_note = (theme_name.eq_ignore_ascii_case("auto") && theme::pal().name == "ansi").then(|| {
        format!(
            "theme auto → ansi: TERM={} doesn't look truecolor. Press T to pick another theme",
            std::env::var("TERM").unwrap_or_default()
        )
    });
    let unknown_theme = (!theme_name.eq_ignore_ascii_case("auto") && theme::by_name(&theme_name).is_none())
        .then(|| format!("unknown theme \"{theme_name}\", see --list-themes"));

    let tab = args
        .tab
        .as_deref()
        .or(Some(cfg.start_tab.as_str()))
        .and_then(Tab::from_name)
        .unwrap_or(Tab::Overview);
    let interval = args.interval.unwrap_or(cfg.interval_ms).clamp(250, 10_000);
    let lsof_interval = args.lsof_interval.unwrap_or(cfg.lsof_interval_s).max(1);
    let mouse = cfg.mouse && !args.no_mouse;

    let sockets = Arc::new(Mutex::new(SocketStore::default()));
    let files = Arc::new(Mutex::new(FilesStore::default()));
    lsof::spawn_socket_worker(sockets.clone(), Duration::from_secs(lsof_interval), args.lsof_sockets);

    let key_warnings = app::key_map(&cfg.keys).1;
    let sampler = Sampler::new();
    let (net, probe_warnings) = app::NetHandles::start(&cfg);
    let mut app = App::new(sampler, sockets, files, Duration::from_millis(interval), tab, cfg, net);
    for w in probe_warnings {
        app.warn(w);
    }
    if let Some(q) = args.query.as_deref().and_then(Query::parse) {
        app.run_query(q);
    }
    for w in [cfg_warning, unknown_theme, auto_note].into_iter().flatten().chain(theme_warnings).chain(key_warnings) {
        app.warn(w);
    }

    let mut terminal = ratatui::init();
    if mouse {
        let _ = execute!(stdout(), EnableMouseCapture);
    }
    let res = run(&mut terminal, &mut app);
    if mouse {
        let _ = execute!(stdout(), DisableMouseCapture);
    }
    ratatui::restore();

    if !args.no_save {
        if let Err(e) = config::save(&app.snapshot_config(), args.config.as_ref()) {
            eprintln!("vigil: could not save config: {e}");
        }
    }
    res
}

fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> Result<()> {
    let mut last_tick = Instant::now();
    let mut dirty = true;
    let mut drawn_key = app.external_key();
    while !app.quit {
        // Only redraw when input arrived, a tick happened, or a background
        // collector (lsof, sensors) published new data. Idle = zero rendering.
        let key = app.external_key();
        if dirty || key != drawn_key {
            app.update_caches();
            terminal.draw(|f| ui::draw(f, app))?;
            drawn_key = key;
            dirty = false;
        }

        let timeout = app
            .interval
            .saturating_sub(last_tick.elapsed())
            .min(Duration::from_millis(250));
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(k) if k.kind == KeyEventKind::Press => {
                    app.on_key(k);
                    dirty = true;
                }
                Event::Mouse(m) => {
                    app.on_mouse(m);
                    dirty = true;
                }
                Event::Resize(..) => dirty = true,
                _ => {}
            }
        }
        if last_tick.elapsed() >= app.interval {
            app.tick();
            last_tick = Instant::now();
            dirty = true;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// The command must stay `vigil`: the release workflow, the packages, the
    /// Homebrew formula and every install line depend on it, whatever the
    /// package is called on crates.io.
    #[test]
    fn binary_is_named_vigil() {
        assert_eq!(env!("CARGO_BIN_NAME"), "vigil");
    }
}
