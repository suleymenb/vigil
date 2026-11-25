//! vigil — a modern terminal system monitor for DevOps, networking and
//! Linux administration, with first-class lsof integration.

mod app;
mod collect;
mod config;
mod theme;
mod ui;
mod util;

use std::io::stdout;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind};
use crossterm::execute;

use app::{App, Tab};
use collect::lsof::{self, FilesStore, Query, SocketStore};
use collect::system::Sampler;

#[derive(Parser, Debug)]
#[command(name = "vigil", version, about = "Modern terminal system monitor with lsof integration")]
struct Args {
    /// Sampling interval in milliseconds [config: interval_ms, default 1000]
    #[arg(short, long)]
    interval: Option<u64>,

    /// Seconds between background socket scans [config: lsof_interval_s, default 3]
    #[arg(long)]
    lsof_interval: Option<u64>,

    /// Start view: overview, processes, network, sockets, files, storage
    #[arg(short, long)]
    tab: Option<String>,

    /// Run an lsof query at startup (same syntax as the `:` prompt, e.g. ":443" or "1234")
    #[arg(short, long)]
    query: Option<String>,

    /// Colour theme (see --list-themes), or "auto"
    #[arg(long)]
    theme: Option<String>,

    /// List available themes and exit
    #[arg(long)]
    list_themes: bool,

    /// Use a specific config file instead of ~/.config/vigil/config.toml
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

fn main() -> Result<()> {
    let args = Args::parse();
    if args.list_themes {
        for t in theme::THEMES {
            println!("{}", t.name);
        }
        return Ok(());
    }

    let (cfg, cfg_warning) = config::load(args.config.as_ref());

    let theme_name = args.theme.clone().unwrap_or_else(|| cfg.theme.clone());
    let theme_idx = if theme_name.eq_ignore_ascii_case("auto") {
        theme::auto_default()
    } else {
        theme::by_name(&theme_name).unwrap_or_else(theme::auto_default)
    };
    theme::set(theme_idx);

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

    let sampler = Sampler::new();
    let mut app = App::new(sampler, sockets, files, Duration::from_millis(interval), tab, cfg);
    if let Some(q) = args.query.as_deref().and_then(Query::parse) {
        app.run_query(q);
    }
    if let Some(w) = cfg_warning {
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
