mod inspect;
mod netviews;
mod overview;
mod sysviews;
mod troubleshoot;
mod views;
pub mod widgets;

use std::time::Duration;

use ratatui::layout::{Alignment, Constraint, Flex, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Tabs, Wrap};
use ratatui::Frame;

use crate::app::{signals, App, Mode, Tab};
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
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(area);

    draw_header(f, app, header);
    app.hits.table = None;
    app.hits.proc_headers.clear();
    if app.inspect.is_some() {
        inspect::draw(f, app, body);
    } else {
    match app.tab {
        Tab::Overview => overview::draw(f, app, body),
        Tab::Processes => views::processes(f, app, body),
        Tab::Network => views::network(f, app, body),
        Tab::Sockets => views::sockets(f, app, body),
        Tab::Files => views::files(f, app, body),
        Tab::Storage => views::storage(f, app, body),
        Tab::Routes => netviews::routes(f, app, body),
        Tab::Probes => netviews::probes(f, app, body),
        Tab::Firewall => netviews::firewall(f, app, body),
        Tab::Containers => sysviews::containers(f, app, body),
        Tab::System => sysviews::system(f, app, body),
        Tab::Users => sysviews::users(f, app, body),
        Tab::Troubleshoot => troubleshoot::draw(f, app, body),
    }
    }
    if app.explain {
        draw_explain(f, app, body);
    }
    if app.mode == Mode::Search {
        draw_search(f, app, body);
    }
    draw_footer(f, app, footer);

    if app.mode == Mode::Signal {
        draw_signal_dialog(f, app, area);
    }
    if app.mode == Mode::Theme {
        draw_theme_picker(f, app, area);
    }
    if app.mode == Mode::ConfirmClose {
        draw_confirm_close(f, app, area);
    }
    if app.show_help {
        draw_help(f, area);
    }
}

fn draw_header(f: &mut Frame, app: &mut App, area: Rect) {
    let s = &app.sampler;
    // Info line, tab row, and a fixed alerts row: tabs never move or hide
    // because of alerts, and alerts always appear in the same place.
    let [top, tabs_area, alert_area] = Layout::vertical([Constraint::Length(1), Constraint::Length(1), Constraint::Length(1)]).areas(area);
    f.render_widget(Block::new().style(Style::new().bg(theme::header_bg())), top);

    // On a narrow window the kernel string goes first, then the OS name, so
    // the left side never runs under "● live · root" on the right.
    let right_w = 7 + format!("  {}ms ", app.interval.as_millis()).len() + 6 + 1;
    let base_w = 9 + 1 + s.host.hostname.chars().count() + 5 + fmt_duration(s.uptime).len() + 6 + 14 + 8 + s.proc_count().to_string().len();
    let os_txt = format!("  {}", s.host.os);
    let kernel_txt = format!("  {} {}", s.host.kernel, s.host.arch);
    let room = (top.width as usize).saturating_sub(right_w);
    let show_os = base_w + os_txt.chars().count() <= room;
    let show_kernel = show_os && base_w + os_txt.chars().count() + kernel_txt.chars().count() <= room;
    let mut spans = vec![
        Span::styled(if theme::is_ascii() { " VIGIL " } else { " ◆ vigil " }, Style::new().fg(theme::header_bg()).bg(theme::blue()).bold()),
        Span::raw(" "),
        Span::styled(s.host.hostname.clone(), Style::new().fg(theme::cyan()).bold()),
        Span::styled(if show_os { os_txt } else { String::new() }, Style::new().fg(theme::muted())),
        Span::styled(if show_kernel { kernel_txt } else { String::new() }, Style::new().fg(theme::dim())),
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

    // Tab row: full names; on a narrow terminal inactive tabs shrink to their
    // key, longest names first, only as far as the width requires.
    let mut alerts = app.alerts();
    alerts.sort_by_key(|(_, c)| *c != theme::red()); // urgent first (stable)
    let avail = tabs_area.width as usize;
    let label_w = |t: &Tab, short: bool| if short { t.key().len_utf8() } else { t.key().len_utf8() + 1 + t.title().chars().count() };
    let mut short = [false; Tab::ALL.len()];
    let total = |short: &[bool]| -> usize { Tab::ALL.iter().zip(short).map(|(t, s)| label_w(t, *s) + 2).sum::<usize>() + Tab::ALL.len() - 1 };
    let mut order: Vec<usize> = (0..Tab::ALL.len()).filter(|i| Tab::ALL[*i] != app.tab).collect();
    order.sort_by_key(|i| std::cmp::Reverse(Tab::ALL[*i].title().len()));
    for i in order {
        if total(&short) <= avail {
            break;
        }
        short[i] = true;
    }

    let titles: Vec<Line> = Tab::ALL
        .iter()
        .zip(short)
        .map(|(t, s)| {
            let key = Span::styled(t.key().to_string(), Style::new().fg(theme::dim()));
            if s {
                Line::from(key)
            } else {
                Line::from(vec![key, Span::raw(" "), Span::raw(t.title())])
            }
        })
        .collect();
    // Record where each tab is drawn, for mouse clicks (Tabs: " title " + divider).
    app.hits.tabs.clear();
    let mut x = tabs_area.x;
    for (t, s) in Tab::ALL.into_iter().zip(short) {
        let w = label_w(&t, s) as u16 + 2;
        app.hits.tabs.push((x, x + w, tabs_area.y, t));
        x += w + 1;
    }
    let tabs = Tabs::new(titles)
        .select(app.tab.index())
        .style(Style::new().fg(theme::muted()))
        .highlight_style(Style::new().fg(theme::blue()).bold().underlined())
        .divider(Span::styled(theme::glyphs().divider, Style::new().fg(theme::border())))
        .padding(" ", " ");
    f.render_widget(tabs, tabs_area);

    // Alerts row: every crossed threshold, urgent first; "+N" when they don't fit.
    let mut row = vec![Span::raw(" ")];
    row.extend(fit_badges(&alerts, (alert_area.width as usize).saturating_sub(1)));
    if alerts.is_empty() {
        row.push(Span::styled("no thresholds crossed", Style::new().fg(theme::dim())));
    }
    f.render_widget(Paragraph::new(Line::from(row)), alert_area);
}

/// Longest badge text before it is shortened (the value at the end is kept).
const BADGE_MAX: usize = 40;

/// "LOSS gateway fc00:d264:c6f5:748:: 100%" → "LOSS gateway fc00:d264… 100%".
fn short_badge(text: &str) -> String {
    shorten_badge(text, BADGE_MAX)
}

/// Shorten to `max` characters, keeping a short value at the end ("100%").
fn shorten_badge(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let (head, tail) = match text.rsplit_once(' ') {
        Some((h, t)) if t.chars().count() < 10 => (h, format!(" {t}")),
        _ => (text, String::new()),
    };
    let keep = max.saturating_sub(tail.chars().count() + 1);
    format!("{}…{tail}", head.chars().take(keep).collect::<String>().trim_end())
}

/// Badges that fit in `width` columns, plus a "+N" badge for the rest.
fn fit_badges(alerts: &[(String, ratatui::style::Color)], width: usize) -> Vec<Span<'static>> {
    let mut out = Vec::new();
    if alerts.is_empty() {
        let ok = if theme::is_ascii() { "[ OK ] " } else { "✓ healthy " };
        if width >= ok.chars().count() {
            out.push(Span::styled(ok, Style::new().fg(theme::green())));
        }
        return out;
    }
    let mut used = 0;
    for (i, (text, color)) in alerts.iter().enumerate() {
        let mut t = short_badge(text);
        let rest = alerts.len() - i - 1;
        let more_w = if rest > 0 { format!(" +{rest} ").len() + 1 } else { 0 };
        // Squeeze a badge further rather than hide it, down to ~12 characters.
        let room = width.saturating_sub(used + more_w + 3);
        if t.chars().count() > room && room >= 12 {
            t = shorten_badge(&t, room);
        }
        let w = t.chars().count() + 3; // " text " + gap
        if used + w + more_w > width {
            let hidden = alerts.len() - i;
            let label = format!(" +{hidden} ");
            if used + label.len() < width {
                let col = if alerts[i..].iter().any(|(_, c)| *c == theme::red()) { theme::red() } else { theme::orange() };
                out.push(Span::styled(label, Style::new().fg(theme::header_bg()).bg(col).bold()));
                out.push(Span::raw(" "));
            }
            break;
        }
        out.push(Span::styled(format!(" {t} "), Style::new().fg(theme::header_bg()).bg(*color).bold()));
        out.push(Span::raw(" "));
        used += w;
    }
    out
}

fn hints(app: &App) -> Vec<(&'static str, &'static str)> {
    let mut h = match app.tab {
        Tab::Overview => vec![],
        Tab::Processes => vec![
            ("↵", "inspect"),
            ("f", "open files"),
            ("x", "signal"),
            ("t", "tree"),
            ("c/m/p/n/u/i/o/w/e", "sort"),
            ("r", "reverse"),
        ],
        Tab::Network => vec![("↑↓", "interface"), ("C", "capture (pcap)")],
        Tab::Sockets => vec![
            ("l", "listening"),
            ("s", "sort"),
            ("↵", "proc files"),
            ("P", "port"),
            ("i", "inspect owner"),
            ("C", "capture"),
            ("D", "close conn"),
            ("N", "names"),
            ("x", "signal"),
        ],
        Tab::Routes => vec![("↑↓", "routes"), ("N", "names")],
        Tab::Probes => vec![("a", "add probe"), ("d", "delete"), ("t", "trace path"), ("↑↓", "select")],
        Tab::Containers => vec![("↑↓", "select")],
        Tab::System => vec![("e", "units ⇄ kernel events"), ("↵", "reload journal")],
        Tab::Users => vec![("↑↓", "select")],
        Tab::Troubleshoot => vec![("d", "doctor"), ("c", "subnet calc"), ("m", "mtu"), ("n", "dns"), ("p", "perf"), ("t", "capture"), ("↑↓", "select line"), ("esc", "all")],
        Tab::Firewall => vec![("z", "hide zero"), ("s", "sort by rate")],
        Tab::Files => vec![("↵", "who uses this"), ("p", "proc files"), ("r", "rerun"), ("x", "signal")],
        Tab::Storage => vec![],
    };
    if matches!(app.tab, Tab::Processes | Tab::Sockets | Tab::Files | Tab::Firewall) {
        h.push(("/", "filter"));
    }
    if app.inspect.is_some() {
        return vec![("esc", "close"), ("v", "journal ⇄ env"), ("f", "all files"), ("x", "signal"), ("r", "refresh"), ("y", "copy cmd")];
    }
    h.extend([("F", "find"), ("h", "explain"), ("y", "copy"), ("E", "export"), (":", "lsof query"), ("R", "report"), ("T", "theme"), ("space", "pause"), ("?", "help"), ("q", "quit")]);
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
        Mode::AddProbe => Line::from(vec![
            Span::styled(" PROBE ", Style::new().fg(theme::header_bg()).bg(theme::cyan()).bold()),
            Span::raw(" "),
            Span::styled(app.input.clone(), Style::new().fg(theme::fg())),
            Span::styled("█", Style::new().fg(theme::cyan())),
            Span::styled("   1.1.1.1 · icmp:2606:4700::1111 · tcp:db.internal:5432 · dns:github.com", Style::new().fg(theme::dim())),
        ]),
        Mode::ToolInput => {
            let (label, example) = match app.tool_kind {
                crate::tools::Kind::Calc => ("CALC", "10.0.0.0/22 /24 · 192.168.1.7 255.255.255.0 · 10.0.0.0/22 10.0.4.1 · 2001:db8::/48"),
                crate::tools::Kind::Mtu => ("MTU", "host or IP (blank = [troubleshoot] internet_target)"),
                crate::tools::Kind::Dns => ("DNS", "github.com · github.com MX · 8.8.8.8 · name AAAA @10.0.0.53 (blank = dns_test_name)"),
                crate::tools::Kind::Capture => ("CAPTURE", "[iface] [30s|500p] [BPF filter]: en0 30s port 443 · 500p host 10.0.0.5 · udp port 53 (blank: everything, capture_seconds)"),
                crate::tools::Kind::Perf => ("PERF", "host[:port] running `vigil perf --server` · add \" -R\" to download · blank = HTTP download"),
                crate::tools::Kind::Doctor => ("DOCTOR", ""),
            };
            Line::from(vec![
                Span::styled(format!(" {label} "), Style::new().fg(theme::header_bg()).bg(theme::green()).bold()),
                Span::raw(" "),
                Span::styled(app.input.clone(), Style::new().fg(theme::fg())),
                Span::styled("█", Style::new().fg(theme::green())),
                Span::styled(format!("   {example}"), Style::new().fg(theme::dim())),
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
            if let Ok(c) = app.net.capture.try_lock() {
                if let Some((file, start, dur)) = &c.running {
                    let left = dur.saturating_sub(start.elapsed()).as_secs();
                    spans.push(Span::styled(format!(" ● REC {left}s "), Style::new().fg(theme::header_bg()).bg(theme::red()).bold()));
                    spans.push(Span::styled(
                        format!(" {} ", file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()),
                        Style::new().fg(theme::red()),
                    ));
                }
            }
            for (k, d) in hints(app) {
                spans.push(Span::styled(k, Style::new().fg(theme::blue()).bold()));
                spans.push(Span::styled(format!(" {d}  "), Style::new().fg(theme::dim())));
            }
            Line::from(spans)
        }
    };
    f.render_widget(Paragraph::new(line), area);
}

fn draw_confirm_close(f: &mut Frame, app: &App, area: Rect) {
    let Some(sk) = &app.close_target else { return };
    let r = centered(area, 70, 8);
    f.render_widget(Clear, r);
    let lines = vec![
        Line::raw(""),
        Line::from(vec![
            Span::styled("  close ", Style::new().fg(theme::fg())),
            Span::styled(sk.name.clone(), Style::new().fg(theme::cyan()).bold()),
        ]),
        Line::styled(format!("  owned by {} ({}). The process keeps running.", sk.command, sk.pid), Style::new().fg(theme::muted())),
        Line::raw(""),
        Line::styled("  y / ↵ close it · any other key cancels", Style::new().fg(theme::dim())),
    ];
    f.render_widget(Paragraph::new(lines).block(panel("close connection", theme::red())), r);
}

fn draw_theme_picker(f: &mut Frame, app: &App, area: Rect) {
    let n = theme::all().len();
    let r = centered(area, 58, (n as u16 + 6).min(area.height));
    f.render_widget(Clear, r);
    let cur = theme::index();
    // Scroll the list on short terminals so the current theme stays visible.
    let rows = (r.height as usize).saturating_sub(5).max(1);
    let off = cur.saturating_sub(rows / 2).min(n.saturating_sub(rows));
    let mut lines = vec![Line::raw("")];
    for (i, t) in theme::all().iter().enumerate().skip(off).take(rows) {
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
        Span::styled(format!("  {}/{n} · ↑↓ preview · ↵ keep · esc cancel · b background ", cur + 1), Style::new().fg(theme::dim())),
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
    let r = centered(area, 52, signals().len() as u16 + 5);
    f.render_widget(Clear, r);
    let block = panel(format!("send signal → {name} ({pid})"), theme::red());
    let mut lines = vec![Line::raw("")];
    for (i, (sname, desc, _)) in signals().iter().enumerate() {
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

/// Global search (F): live results from every view.
fn draw_search(f: &mut Frame, app: &App, body: Rect) {
    let w = body.width.saturating_sub(8).clamp(30, 130).min(body.width);
    let h = body.height.saturating_sub(4).clamp(5, 24).min(body.height);
    let r = Rect { x: body.x + (body.width - w) / 2, y: body.y + u16::from(body.height > h), width: w, height: h };
    f.render_widget(Clear, r);
    let mut lines = vec![Line::from(vec![
        Span::styled(" find ", Style::new().fg(theme::header_bg()).bg(theme::cyan()).bold()),
        Span::raw(" "),
        Span::styled(app.input.clone(), Style::new().fg(theme::fg()).bold()),
        Span::styled("█", Style::new().fg(theme::cyan())),
    ])];
    if app.input.is_empty() {
        lines.push(Line::styled(" processes, ports, addresses, services, containers, routes, MACs, users, rules, probes", Style::new().fg(theme::dim())));
    } else if app.search_hits.is_empty() {
        lines.push(Line::styled(" no matches", Style::new().fg(theme::dim())));
    }
    let rows = h.saturating_sub(4) as usize;
    let off = app.search_sel.saturating_sub(rows.saturating_sub(1));
    for (i, hit) in app.search_hits.iter().enumerate().skip(off).take(rows) {
        let sel = i == app.search_sel;
        let style = if sel { Style::new().fg(theme::fg()).bg(theme::sel_bg()).bold() } else { Style::new().fg(theme::fg()) };
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<10}", hit.kind), Style::new().fg(theme::purple()).bg(if sel { theme::sel_bg() } else { theme::bg() })),
            Span::styled(crate::util::truncate(&hit.text, w.saturating_sub(16) as usize), style),
        ]));
    }
    let total = app.search_hits.len();
    f.render_widget(
        Paragraph::new(lines).style(Style::new().bg(theme::bg())).block(
            panel("search", theme::cyan())
                .title_bottom(Line::styled(format!(" {}{} · ↑↓ choose · ↵ jump · esc close ", total, if total >= 200 { "+" } else { "" }), Style::new().fg(theme::dim())).right_aligned()),
        ),
        r,
    );
}

/// Explain mode: a panel over the bottom of the view about the selected item.
fn draw_explain(f: &mut Frame, app: &App, body: Rect) {
    let term = app.explain_term();
    let entry = term.as_deref().and_then(crate::explain::lookup);
    let mut lines = Vec::new();
    let title = match entry {
        Some(e) => {
            lines.push(Line::styled(format!(" {}", e.text), Style::new().fg(theme::fg())));
            if !e.next.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled(" next ", Style::new().fg(theme::header_bg()).bg(theme::cyan()).bold()),
                    Span::styled(format!(" {}", e.next), Style::new().fg(theme::cyan())),
                ]));
            }
            format!("explain · {}", e.title)
        }
        None => {
            lines.push(Line::styled(
                match term {
                    Some(t) if !t.is_empty() => format!(" Nothing to explain for “{t}” yet. Move the selection to a state, event, route, rule or check."),
                    _ => " Select a row: socket states, process states, routes, neighbour states, kernel events, firewall verdicts, probes and doctor checks are explained here.".to_string(),
                },
                Style::new().fg(theme::muted()),
            ));
            "explain".to_string()
        }
    };
    let w = body.width.saturating_sub(4).max(20) as usize;
    let text_rows: usize = lines.iter().map(|l| l.width().div_ceil(w).max(1)).sum();
    let h = (text_rows as u16 + 2).clamp(3, body.height.saturating_sub(2).max(3)).min(body.height);
    let r = Rect { x: body.x, y: body.bottom().saturating_sub(h), width: body.width, height: h };
    f.render_widget(Clear, r);
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(widgets::panel(title, theme::cyan()).title_bottom(Line::styled(" h closes ", Style::new().fg(theme::dim())).right_aligned())),
        r,
    );
}

fn draw_help(f: &mut Frame, area: Rect) {
    let r = centered(area, 104, 49);
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
        row("1-9 0 S U / ←→", "switch view (0 containers, S system, U users) · mouse: click tabs, rows, headers"),
        row("↵ on a process", "inspector: identity, history graphs, sockets, files, journal, environment"),
        row("y / E", "copy the selected value (clipboard, works over SSH) / export the view as CSV"),
        row("↑↓ j k pgup pgdn", "move selection (g / G = top / bottom)"),
        row("/", "filter current list (esc clears)"),
        row(":", "lsof query: 1234 · :443 · tcp:22 · /var/log/x · -u root -i"),
        row("space", "pause / resume sampling"),
        row("+ / -", "refresh interval ±250ms"),
        row("T", "theme picker (live preview, b = background on/off)"),
        row("R", "write a Markdown report to ./vigil-report-<time>.md"),
        row("F", "find anything: processes, ports, IPs, MACs, services, containers, routes, users; ↵ jumps there"),
        row("h", "explain the selected item: what it means and what to run next (Junos / Cisco too)"),
        row("W", "troubleshoot: doctor (L1→L7), subnet calc, path MTU, DNS per resolver, throughput, capture"),
        row("? / q", "help / quit"),
        sec("Processes"),
        row("c m p n u i o w e", "sort cpu · mem · pid · name · user · io · conns · net/s · fds"),
        row("r / t", "reverse sort / toggle process tree"),
        row("↵ or f", "open files of process (lsof -p)"),
        row("x / K / del", "send signal (TERM, KILL, HUP, STOP, …)"),
        sec("Sockets (lsof -i)"),
        row("l", "listening sockets only"),
        row("s", "sort: process · port · state · proto · remote · rtt · traffic"),
        row("C / D", "capture this connection (tcpdump) / close it (sock_diag)"),
        row("N", "reverse DNS names on/off (any view)"),
        row("↵ / P", "open files of owner / everything on this port"),
        row("x", "signal the owning process"),
        sec("Probes · Firewall"),
        row("a / d / t", "add a probe (1.1.1.1, tcp:host:port, dns:name, https://url) / delete / trace path"),
        row("0 / S", "containers / system: services, journal, kernel events (e switches pane)"),
        row("z / s", "firewall: hide zero-hit rules / sort by packets per second"),
        sec("Open Files"),
        row("↵", "who else has this file / port open"),
        row("p / r", "files of this pid / rerun query"),
        sec("Notes"),
        Line::styled(
            if cfg!(windows) { "   Run as administrator to see the event log and every process." } else { "   Run with sudo to see sockets & files of all users." },
            Style::new().fg(theme::muted()),
        ),
        Line::styled(format!("   {}", crate::platform::get().summary()), Style::new().fg(theme::dim())),
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
            s.entries = std::sync::Arc::new(e);
            s.took = took;
            s.updated = Some(std::time::Instant::now());
        }
        // VIGIL_SNAP_LIVE=1 starts the real network collectors (routes, probes).
        let net = if std::env::var_os("VIGIL_SNAP_LIVE").is_some() {
            crate::app::NetHandles::start(&Default::default()).0
        } else {
            crate::app::NetHandles::idle()
        };
        let mut app = App::new(Sampler::new(), sockets, files.clone(), Duration::from_secs(1), Tab::Overview, Default::default(), net);
        if std::env::var_os("VIGIL_SNAP_LIVE").is_some() {
            std::thread::sleep(Duration::from_secs(7));
        }
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
            // Explain mode over every view.
            app.explain = true;
            for tab in Tab::ALL {
                app.tab = tab;
                term.draw(|f| super::draw(f, &mut app)).unwrap();
                if let (Some(d), 180, Tab::Processes) = (&dir, w, tab) {
                    std::fs::write(format!("{d}/explain-{:?}.txt", tab), dump(&term)).unwrap();
                }
            }
            app.explain = false;
            // Global search finds this test process by name and jumps to it.
            app.input = "vigil".into();
            app.search_hits = app.search("vigil");
            assert!(app.search_hits.iter().any(|h| h.kind == "proc"), "own process not found");
            app.mode = crate::app::Mode::Search;
            term.draw(|f| super::draw(f, &mut app)).unwrap();
            if let (Some(d), 180) = (&dir, w) {
                std::fs::write(format!("{d}/search.txt"), dump(&term)).unwrap();
            }
            app.mode = crate::app::Mode::Normal;
            app.input.clear();
            app.show_help = true;
            term.draw(|f| super::draw(f, &mut app)).unwrap();
            app.show_help = false;
            // The inspector, on our own process, at every size.
            app.open_inspector(std::process::id());
            std::thread::sleep(Duration::from_millis(300));
            term.draw(|f| super::draw(f, &mut app)).unwrap();
            if let (Some(d), 180) = (&dir, w) {
                std::fs::write(format!("{d}/Inspector.txt"), dump(&term)).unwrap();
            }
            app.inspect_env = true;
            term.draw(|f| super::draw(f, &mut app)).unwrap();
            app.inspect = None;
            app.mode = crate::app::Mode::Theme;
            for i in 0..crate::theme::all().len() {
                crate::theme::set(i);
                term.draw(|f| super::draw(f, &mut app)).unwrap();
                if let (Some(d), 180) = (&dir, w) {
                    std::fs::write(format!("{d}/theme-{}.txt", crate::theme::all()[i].name), dump(&term)).unwrap();
                }
            }
            crate::theme::set(0);
            app.mode = crate::app::Mode::Normal;
        }
    }

    #[test]
    fn tab_row_never_overlaps_badges() {
        assert_eq!(super::short_badge("LOSS gateway fc00:d264:c6f5:748:: 100%"), "LOSS gateway fc00:d264:c6f5:748:: 100%");
        assert_eq!(super::short_badge("LOSS gateway 2001:db8:aaaa:bbbb:cccc:dddd:eeee:1 100%"), "LOSS gateway 2001:db8:aaaa:bbbb:cc… 100%");
        assert_eq!(super::short_badge("MEM 96%"), "MEM 96%");
        let alerts: Vec<(String, ratatui::style::Color)> = vec![("MEM 96%".into(), crate::theme::red()), ("LOSS gateway fc00:d264:c6f5:748:: 100%".into(), crate::theme::red()), ("LOAD 2.1/core".into(), crate::theme::orange())];
        let w = |v: &[ratatui::text::Span]| v.iter().map(|s| s.width()).sum::<usize>();
        assert!(w(&super::fit_badges(&alerts, 200)) <= 200);
        let some = super::fit_badges(&alerts, 20);
        assert!(w(&some) <= 20, "{some:?}");
        assert!(some.iter().any(|s| s.content.contains('+')), "overflow badge expected: {some:?}");

        // Thresholds low enough that several badges show on any machine.
        let mut cfg = crate::config::Config::default();
        cfg.alerts.mem_pct = 0.01;
        cfg.alerts.disk_pct = 0.01;
        cfg.alerts.load_per_core = 0.0001;
        let sockets = Arc::new(Mutex::new(SocketStore::default()));
        let files = Arc::new(Mutex::new(FilesStore::default()));
        let mut app = App::new(Sampler::new(), sockets, files, Duration::from_secs(1), Tab::Users, cfg, crate::app::NetHandles::idle());
        app.tick();
        assert!(app.alerts().len() >= 2);
        for width in [200u16, 160, 120, 100, 80] {
            let mut term = Terminal::new(TestBackend::new(width, 20)).unwrap();
            term.draw(|f| super::draw(f, &mut app)).unwrap();
            let screen = dump(&term);
            let row: String = screen.lines().nth(1).unwrap().to_string();
            let alerts: String = screen.lines().nth(2).unwrap().to_string();
            if std::env::var_os("VIGIL_SHOW_TABROW").is_some() {
                eprintln!("{width:>3} |{}|\n    |{}|", row.trim_end(), alerts.trim_end());
            }
            // Alerts live on their own row, so on a wide screen every tab keeps its name.
            if width >= 160 {
                assert!(row.contains("Troubleshoot") && row.contains("Overview"), "width {width}: {row:?}");
            }
            assert!(alerts.contains("MEM") || alerts.contains('+'), "width {width}: no badges in {alerts:?}");
            // Every tab key is still on the row, and the active tab keeps its name.
            for t in Tab::ALL {
                assert!(row.contains(&format!(" {} ", t.key())), "width {width}: tab {:?} missing in {row:?}", t);
            }
            assert!(row.contains("Users"), "width {width}: {row:?}");
        }
    }

    #[test]
    fn renders_troubleshoot_output_and_link_layer() {
        use crate::tools::{Line, Tone};
        let net = crate::app::NetHandles::idle();
        {
            let mut t = net.tools.lock().unwrap();
            t.kind = Some(crate::tools::Kind::Doctor);
            if std::env::var_os("VIGIL_SNAP_LIVE").is_some() {
                let lines = std::sync::Mutex::new(Vec::new());
                t.checks = crate::tools::doctor::run(&crate::tools::Settings::from(&crate::config::Troubleshoot::default()), &|tone, text| lines.lock().unwrap().push(Line { tone, text }));
                t.lines = lines.into_inner().unwrap();
            } else {
                for (tone, text) in [(Tone::Head, "L1 · Physical"), (Tone::Warn, "  ▲ NIC errors         eth0: 1234 CRC, 2 frame"), (Tone::Dim, "      → CRC/frame errors are damage on the wire: bad cable, dirty fibre or SFP, EMI, or a duplex mismatch. Missed/overrun = the host is too slow to drain the NIC ring (ethtool -G). Switch side: show interfaces IF extensive (Junos)")] {
                    t.lines.push(Line { tone, text: text.into() });
                }
                t.checks.push(crate::tools::doctor::Check { layer: 1, name: "NIC errors", status: crate::tools::doctor::Status::Warn, detail: String::new(), hint: String::new() });
            }
        }
        {
            let mut l = net.l2.lock().unwrap();
            l.nics.push(crate::collect::l2::NicStats { name: "eth0".into(), carrier: Some(true), speed_mbps: Some(1000), duplex: Some("full".into()), rx_packets: 10, rx_crc: 1234, rx_errors: 1236, carrier_changes: Some(4), ..Default::default() });
            l.lldp.push(crate::collect::l2::Lldp { local_port: "eth0".into(), chassis: "sw-core-1".into(), port: "ge-0/0/12".into(), vlan: "10".into(), mgmt_ip: "10.0.0.2".into(), sys_descr: "Juniper Networks, Inc. ex4300-48t".into(), ..Default::default() });
        }
        let sockets = Arc::new(Mutex::new(SocketStore::default()));
        let files = Arc::new(Mutex::new(FilesStore::default()));
        let mut app = App::new(Sampler::new(), sockets, files, Duration::from_secs(1), Tab::Troubleshoot, Default::default(), net);
        let dir = std::env::var("VIGIL_SNAP_DIR").ok();
        for (w, h) in [(180u16, 50u16), (100, 30), (60, 15), (20, 6)] {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| super::draw(f, &mut app)).unwrap();
            let out = dump(&term);
            if w >= 100 && std::env::var_os("VIGIL_SNAP_LIVE").is_none() {
                assert!(out.contains("NIC errors"), "{out}");
                assert!(out.contains("sw-core-1"), "{out}");
            }
            if let (Some(d), 180) = (&dir, w) {
                std::fs::write(format!("{d}/Troubleshoot.txt"), out).unwrap();
            }
        }
        app.net.tools.lock().unwrap().lines.clear();
        let mut term = Terminal::new(TestBackend::new(140, 30)).unwrap();
        term.draw(|f| super::draw(f, &mut app)).unwrap();
        assert!(dump(&term).contains("subnet calculator"));
    }
}

#[cfg(test)]
mod mouse_tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use crate::app::{App, NetHandles, Tab};
    use crate::collect::lsof::{FilesStore, SocketStore};
    use crate::collect::system::Sampler;

    fn click(app: &mut App, x: u16, y: u16) {
        app.on_mouse(MouseEvent { kind: MouseEventKind::Down(MouseButton::Left), column: x, row: y, modifiers: KeyModifiers::NONE });
    }

    /// Clicks land where the frame was drawn: tab bar, table rows, headers.
    #[test]
    fn clicks_switch_tabs_select_rows_and_sort() {
        let mut app = App::new(
            Sampler::new(),
            Arc::new(Mutex::new(SocketStore::default())),
            Arc::new(Mutex::new(FilesStore::default())),
            Duration::from_secs(1),
            Tab::Overview,
            Default::default(),
            NetHandles::idle(),
        );
        let mut term = Terminal::new(TestBackend::new(180, 50)).unwrap();
        term.draw(|f| super::draw(f, &mut app)).unwrap();

        // Find "Procs" in the rendered tab row and click it.
        let buf = term.backend().buffer().clone();
        let row: String = (0..180).map(|x| buf[(x, 1)].symbol().to_string()).collect();
        let col = row.find("Procs").expect("tab bar shows Procs") as u16;
        click(&mut app, col + 1, 1);
        assert_eq!(app.tab, Tab::Processes);

        // Click the third process row.
        term.draw(|f| super::draw(f, &mut app)).unwrap();
        let (area, off) = app.hits.table.expect("process table registered");
        click(&mut app, area.x + 10, area.y + 2 + 2);
        assert_eq!(app.proc_state.selected(), Some(off + 2));

        // Click the MEM header to sort by memory.
        let (x0, _, _) = *app.hits.proc_headers.iter().find(|(_, _, s)| *s == crate::app::ProcSort::Mem).unwrap();
        click(&mut app, x0 + 1, area.y + 1);
        assert_eq!(app.proc_sort, crate::app::ProcSort::Mem);
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
        sockets.lock().unwrap().entries = std::sync::Arc::new(e);

        let mut app = App::new(Sampler::new(), sockets, files, Duration::from_secs(1), Tab::Overview, Default::default(), crate::app::NetHandles::idle());
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
