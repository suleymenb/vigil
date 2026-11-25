//! vigil — a modern terminal system monitor for DevOps, networking and
//! Linux administration, with first-class lsof integration.

mod app;
mod collect;
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
    /// Sampling interval in milliseconds
    #[arg(short, long, default_value_t = 1000)]
    interval: u64,

    /// How often the background `lsof -i` socket scan runs, in seconds
    #[arg(long, default_value_t = 3)]
    lsof_interval: u64,

    /// Start on a view: overview, processes, network, sockets, files, storage
    #[arg(short, long)]
    tab: Option<String>,

    /// Run an lsof query at startup (same syntax as the `:` prompt, e.g. ":443" or "1234")
    #[arg(short, long)]
    query: Option<String>,

    /// Disable mouse support
    #[arg(long)]
    no_mouse: bool,

    /// Use `lsof -i` for the socket list even on Linux (default there: native /proc/net)
    #[arg(long)]
    lsof_sockets: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let tab = args.tab.as_deref().and_then(Tab::from_name).unwrap_or(Tab::Overview);

    let sockets = Arc::new(Mutex::new(SocketStore::default()));
    let files = Arc::new(Mutex::new(FilesStore::default()));
    lsof::spawn_socket_worker(
        sockets.clone(),
        Duration::from_secs(args.lsof_interval.max(1)),
        args.lsof_sockets,
    );

    let sampler = Sampler::new();
    let mut app = App::new(
        sampler,
        sockets,
        files,
        Duration::from_millis(args.interval.clamp(250, 10_000)),
        tab,
    );
    if let Some(q) = args.query.as_deref().and_then(Query::parse) {
        app.run_query(q);
    }

    let mut terminal = ratatui::init();
    if !args.no_mouse {
        let _ = execute!(stdout(), EnableMouseCapture);
    }
    let res = run(&mut terminal, &mut app);
    if !args.no_mouse {
        let _ = execute!(stdout(), DisableMouseCapture);
    }
    ratatui::restore();
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
