mod overview;
mod views;
pub mod widgets;

use std::time::Duration;

use ratatui::layout::{Alignment, Constraint, Flex, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Tabs, Wrap};
use ratatui::Frame;

use crate::app::{App, Mode, Tab, SIGNALS};
use crate::theme;
use crate::util::fmt_duration;
use widgets::panel;

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    if app.cfg.background && theme::bg() != ratatui::style::Color::Reset {
        f.render_widget(
            Block::new().style(Style::new().bg(theme::bg()).fg(theme::fg())),
            area,
        );
    }
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(area);

    draw_header(f, app, header);
    match app.tab {
        Tab::Overview => overview::draw(f, app, body),
        Tab::Processes => views::processes(f, app, body),
        Tab::Network => views::network(f, app, body),
        Tab::Sockets => views::sockets(f, app, body),
        Tab::Files => views::files(f, app, body),
        Tab::Storage => views::storage(f, app, body),
    }
    draw_footer(f, app, footer);

    if app.mode == Mode::Signal {
        draw_signal_dialog(f, app, area);
    }
    if app.mode == Mode::Theme {
        draw_theme_picker(f, app, area);
    }
    if app.show_help {
        draw_help(f, area);
    }
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let s = &app.sampler;
    let [top, tabs_area] = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
    f.render_widget(Block::new().style(Style::new().bg(theme::header_bg())), top);

    let mut spans = vec![
        Span::styled(if theme::is_ascii() { " VIGIL " } else { " ◆ vigil " }, Style::new().fg(theme::header_bg()).bg(theme::blue()).bold()),
        Span::raw(" "),
        Span::styled(s.host.hostname.clone(), Style::new().fg(theme::cyan()).bold()),
        Span::styled(format!("  {}", s.host.os), Style::new().fg(theme::muted())),
        Span::styled(format!("  {} {}", s.host.kernel, s.host.arch), Style::new().fg(theme::dim())),
        Span::styled("  up ", Style::new().fg(theme::dim())),
        Span::styled(fmt_duration(s.uptime), Style::new().fg(theme::green())),
        Span::styled("  load ", Style::new().fg(theme::dim())),
    ];
    let ncores = s.ncores().max(1) as f64;
    for (i, l) in [s.load.0, s.load.1, s.load.2].into_iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" "));
        }
        spans.push(Span::styled(format!("{l:.2}"), Style::new().fg(theme::heat(l / ncores * 100.0))));
    }
    spans.push(Span::styled("  procs ", Style::new().fg(theme::dim())));
    spans.push(Span::styled(s.proc_count().to_string(), Style::new().fg(theme::purple())));
    f.render_widget(Paragraph::new(Line::from(spans)), top);

    let right = Line::from(vec![
        if app.paused {
            Span::styled(" ⏸ PAUSED ", Style::new().fg(theme::header_bg()).bg(theme::yellow()).bold())
        } else {
            Span::styled(if theme::is_ascii() { "* live" } else { "● live" }, Style::new().fg(theme::green()))
        },
        Span::styled(format!("  {}ms ", app.interval.as_millis()), Style::new().fg(theme::dim())),
        if app.is_root {
            Span::styled(" root ", Style::new().fg(theme::header_bg()).bg(theme::red()).bold())
        } else {
            Span::styled(" user ", Style::new().fg(theme::dim()))
        },
    ])
    .alignment(Alignment::Right);
    f.render_widget(Paragraph::new(right), top);

    let titles: Vec<Line> = Tab::ALL
        .iter()
        .enumerate()
        .map(|(i, t)| {
            Line::from(vec![
                Span::styled(format!("{}", i + 1), Style::new().fg(theme::dim())),
                Span::raw(" "),
                Span::raw(t.title()),
            ])
        })
        .collect();
    let tabs = Tabs::new(titles)
        .select(app.tab.index())
        .style(Style::new().fg(theme::muted()))
        .highlight_style(Style::new().fg(theme::blue()).bold().underlined())
        .divider(Span::styled(theme::glyphs().divider, Style::new().fg(theme::border())))
        .padding(" ", " ");
    // Health badges, right-aligned on the tab row, visible from every view.
    let alerts = app.alerts();
    let mut badges: Vec<Span> = Vec::new();
    if alerts.is_empty() {
        badges.push(Span::styled(if theme::is_ascii() { "[ OK ] " } else { "✓ healthy " }, Style::new().fg(theme::green())));
    } else {
        for (text, color) in alerts {
            badges.push(Span::styled(format!(" {text} "), Style::new().fg(theme::header_bg()).bg(color).bold()));
            badges.push(Span::raw(" "));
        }
    }
    let bw: u16 = badges.iter().map(|s| s.width() as u16).sum();
    let bw = bw.min(tabs_area.width / 2);
    let [tabs_left, badge_area] =
        Layout::horizontal([Constraint::Min(0), Constraint::Length(bw)]).areas(tabs_area);
    f.render_widget(tabs, tabs_left);
    f.render_widget(Paragraph::new(Line::from(badges)).alignment(Alignment::Right), badge_area);
}

fn hints(app: &App) -> Vec<(&'static str, &'static str)> {
    let mut h = match app.tab {
        Tab::Overview => vec![],
        Tab::Processes => vec![
            ("↵", "open files"),
            ("x", "signal"),
            ("t", "tree"),
            ("c/m/p/n/u/i/o", "sort"),
            ("r", "reverse"),
        ],
        Tab::Network => vec![("↑↓", "interface")],
        Tab::Sockets => vec![
            ("l", "listening"),
            ("s", "sort"),
            ("↵", "proc files"),
            ("P", "who uses port"),
            ("x", "signal"),
        ],
        Tab::Files => vec![("↵", "who uses this"), ("p", "proc files"), ("r", "rerun"), ("x", "signal")],
        Tab::Storage => vec![],
    };
    if matches!(app.tab, Tab::Processes | Tab::Sockets | Tab::Files) {
        h.push(("/", "filter"));
    }
    h.extend([(":", "lsof query"), ("R", "report"), ("T", "theme"), ("space", "pause"), ("?", "help"), ("q", "quit")]);
    h
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let line = match app.mode {
        Mode::Filter => {
            let val = match app.tab {
                Tab::Processes => &app.proc_filter,
                Tab::Sockets => &app.sock_filter,
                _ => &app.files_filter,
            };
            Line::from(vec![
                Span::styled(" FILTER ", Style::new().fg(theme::header_bg()).bg(theme::yellow()).bold()),
                Span::raw(" "),
                Span::styled(val.clone(), Style::new().fg(theme::fg())),
                Span::styled("█", Style::new().fg(theme::yellow())),
                Span::styled("   ↵ apply · esc clear", Style::new().fg(theme::dim())),
            ])
        }
        Mode::Query => Line::from(vec![
            Span::styled(" LSOF ", Style::new().fg(theme::header_bg()).bg(theme::purple()).bold()),
            Span::raw(" "),
            Span::styled(app.input.clone(), Style::new().fg(theme::fg())),
            Span::styled("█", Style::new().fg(theme::purple())),
            Span::styled(
                "   1234=pid  :443=port  tcp:22  /path=who has it open  -u root -i=raw args",
                Style::new().fg(theme::dim()),
            ),
        ]),
        _ => {
            if let Some((msg, color, at)) = &app.status {
                if at.elapsed() < Duration::from_secs(4) {
                    let l = Line::from(vec![Span::styled(format!(" {msg}"), Style::new().fg(*color).bold())]);
                    f.render_widget(Paragraph::new(l), area);
                    return;
                }
            }
            let mut spans = vec![Span::raw(" ")];
            for (k, d) in hints(app) {
                spans.push(Span::styled(k, Style::new().fg(theme::blue()).bold()));
                spans.push(Span::styled(format!(" {d}  "), Style::new().fg(theme::dim())));
            }
            Line::from(spans)
        }
    };
    f.render_widget(Paragraph::new(line), area);
}

fn draw_theme_picker(f: &mut Frame, app: &App, area: Rect) {
    let n = theme::THEMES.len() as u16;
    let r = centered(area, 58, n + 6);
    f.render_widget(Clear, r);
    let cur = theme::index();
    let mut lines = vec![Line::raw("")];
    for (i, t) in theme::THEMES.iter().enumerate() {
        let sel = i == cur;
        let mut spans = vec![
            Span::styled(if sel { " ▶ " } else { "   " }, Style::new().fg(theme::blue())),
            Span::styled(
                format!("{:<18}", t.name),
                if sel { Style::new().fg(theme::fg()).bold() } else { Style::new().fg(theme::muted()) },
            ),
        ];
        // Swatches drawn in *that* theme's colours, whatever is active.
        for c in [t.blue, t.purple, t.cyan, t.green, t.yellow, t.orange, t.red] {
            spans.push(Span::styled("██", Style::new().fg(c)));
        }
        spans.push(Span::styled(" ▕", Style::new().fg(t.border)));
        spans.push(Span::styled(" Aa ", Style::new().fg(t.fg).bg(t.bg)));
        lines.push(Line::from(spans));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled("  ↑↓ preview · ↵ keep · esc cancel · b background ", Style::new().fg(theme::dim())),
        Span::styled(if app.cfg.background { "on" } else { "off" }, Style::new().fg(theme::teal())),
    ]));
    f.render_widget(
        Paragraph::new(lines)
            .style(Style::new().bg(theme::bg()))
            .block(panel("theme", theme::purple())),
        r,
    );
}

pub fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let [v] = Layout::vertical([Constraint::Length(h.min(area.height))])
        .flex(Flex::Center)
        .areas(area);
    let [r] = Layout::horizontal([Constraint::Length(w.min(area.width))])
        .flex(Flex::Center)
        .areas(v);
    r
}

fn draw_signal_dialog(f: &mut Frame, app: &App, area: Rect) {
    let Some((pid, name)) = &app.signal_target else { return };
    let r = centered(area, 52, SIGNALS.len() as u16 + 5);
    f.render_widget(Clear, r);
    let block = panel(format!("send signal → {name} ({pid})"), theme::red());
    let mut lines = vec![Line::raw("")];
    for (i, (sname, desc, _)) in SIGNALS.iter().enumerate() {
        let sel = i == app.signal_idx;
        let style = if sel {
            Style::new().fg(theme::header_bg()).bg(theme::red()).bold()
        } else {
            Style::new().fg(theme::fg())
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {} ", i + 1), Style::new().fg(theme::dim())),
            Span::styled(format!(" {sname:<8}"), style),
            Span::styled(format!(" {desc}"), if sel { style } else { Style::new().fg(theme::muted()) }),
        ]));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled("  ↑↓ choose · ↵ send · esc cancel", Style::new().fg(theme::dim())));
    f.render_widget(Paragraph::new(lines).block(block), r);
}

fn draw_help(f: &mut Frame, area: Rect) {
    let r = centered(area, 78, 36);
    f.render_widget(Clear, r);
    let sec = |t: &str| Line::styled(format!(" {t}"), Style::new().fg(theme::purple()).bold());
    let row = |k: &str, d: &str| {
        Line::from(vec![
            Span::styled(format!("   {k:<16}"), Style::new().fg(theme::blue()).bold()),
            Span::styled(d.to_string(), Style::new().fg(theme::fg())),
        ])
    };
    let lines = vec![
        sec("Global"),
        row("1-6 / tab / ←→", "switch view"),
        row("↑↓ j k pgup pgdn", "move selection (g / G = top / bottom)"),
        row("/", "filter current list (esc clears)"),
        row(":", "lsof query: 1234 · :443 · tcp:22 · /var/log/x · -u root -i"),
        row("space", "pause / resume sampling"),
        row("+ / -", "refresh interval ±250ms"),
        row("T", "theme picker (live preview, b = background on/off)"),
        row("R", "write a Markdown report to ./vigil-report-<time>.md"),
        row("? / q", "help / quit"),
        sec("Processes"),
        row("c m p n u i o", "sort cpu · mem · pid · name · user · io · conns"),
        row("r / t", "reverse sort / toggle process tree"),
        row("↵ or f", "open files of process (lsof -p)"),
        row("x / K / del", "send signal (TERM, KILL, HUP, STOP, …)"),
        sec("Sockets (lsof -i)"),
        row("l", "listening sockets only"),
        row("s", "cycle sort: process · port · state · proto · remote"),
        row("↵ / P", "open files of owner / everything on this port"),
        row("x", "signal the owning process"),
        sec("Open Files"),
        row("↵", "who else has this file / port open"),
        row("p / r", "files of this pid / rerun query"),
        sec("Notes"),
        Line::styled(
            "   Run with sudo to see sockets & files of all users.",
            Style::new().fg(theme::muted()),
        ),
        Line::raw(""),
        Line::styled("   press any key to close", Style::new().fg(theme::dim())),
    ];
    f.render_widget(
        Paragraph::new(lines)
            .block(panel("help", theme::blue()))
            .wrap(Wrap { trim: false }),
        r,
    );
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use crate::app::{App, Tab};
    use crate::collect::lsof::{self, FilesStore, Query, SocketStore};
    use crate::collect::system::Sampler;

    fn dump(t: &Terminal<TestBackend>) -> String {
        let buf = t.backend().buffer();
        let mut s = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                s.push_str(buf[(x, y)].symbol());
            }
            s.push('\n');
        }
        s
    }

    #[test]
    fn renders_all_views_at_various_sizes() {
        let sockets = Arc::new(Mutex::new(SocketStore::default()));
        let files = Arc::new(Mutex::new(FilesStore::default()));
        if let Ok((e, took)) = lsof::run(&["-nP".into(), "-i".into()]) {
            let mut s = sockets.lock().unwrap();
            s.entries = e;
            s.took = took;
            s.updated = Some(std::time::Instant::now());
        }
        let mut app = App::new(Sampler::new(), sockets, files.clone(), Duration::from_secs(1), Tab::Overview, Default::default());
        app.run_query(Query::Pid(std::process::id()));
        std::thread::sleep(Duration::from_millis(1500));
        app.tick();
        app.proc_tree = true;

        let dir = std::env::var("VIGIL_SNAP_DIR").ok();
        for (w, h) in [(180u16, 50u16), (100, 30), (60, 15), (20, 6)] {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            for tab in Tab::ALL {
                app.tab = tab;
                term.draw(|f| super::draw(f, &mut app)).unwrap();
                if let (Some(d), 180) = (&dir, w) {
                    std::fs::write(format!("{d}/{:?}.txt", tab), dump(&term)).unwrap();
                }
            }
            app.show_help = true;
            term.draw(|f| super::draw(f, &mut app)).unwrap();
            app.show_help = false;
            app.mode = crate::app::Mode::Theme;
            for i in 0..crate::theme::THEMES.len() {
                crate::theme::set(i);
                term.draw(|f| super::draw(f, &mut app)).unwrap();
                if let (Some(d), 180) = (&dir, w) {
                    std::fs::write(format!("{d}/theme-{}.txt", crate::theme::THEMES[i].name), dump(&term)).unwrap();
                }
            }
            crate::theme::set(0);
            app.mode = crate::app::Mode::Normal;
        }
    }
}

#[cfg(test)]
mod bench {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use crate::app::{App, Tab};
    use crate::collect::lsof::{self, FilesStore, SocketStore};
    use crate::collect::system::Sampler;

    /// cargo test --release bench_ -- --ignored --nocapture
    #[test]
    #[ignore]
    fn bench_hot_paths() {
        let sockets = Arc::new(Mutex::new(SocketStore::default()));
        let files = Arc::new(Mutex::new(FilesStore::default()));
        let t = Instant::now();
        let n = 10;
        for _ in 0..n {
            let _ = lsof::run(&["-nP".into(), "-i".into()]);
        }
        println!("lsof -i            {:>8.2?}/run", t.elapsed() / n);
        let (e, _) = lsof::run(&["-nP".into(), "-i".into()]).unwrap();
        sockets.lock().unwrap().entries = e;

        let mut app = App::new(Sampler::new(), sockets, files, Duration::from_secs(1), Tab::Overview, Default::default());
        std::thread::sleep(Duration::from_millis(300));
        let t = Instant::now();
        for _ in 0..n {
            app.sampler.refresh();
        }
        println!("sampler.refresh    {:>8.2?}/tick", t.elapsed() / n);
        let t = Instant::now();
        for _ in 0..n {
            app.rebuild();
        }
        println!("app.rebuild        {:>8.2?}/tick", t.elapsed() / n);

        let mut term = Terminal::new(TestBackend::new(200, 55)).unwrap();
        for tab in Tab::ALL {
            app.tab = tab;
            let t = Instant::now();
            for _ in 0..50 {
                term.draw(|f| super::draw(f, &mut app)).unwrap();
            }
            println!("draw {:<13} {:>8.2?}/frame", format!("{tab:?}"), t.elapsed() / 50);
        }
    }
}
