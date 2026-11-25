use std::collections::BTreeMap;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table, TableState, Wrap,
};
use ratatui::Frame;

use super::widgets::{frame, kv, meter, panel, AreaGraph, GraphColor};
use crate::app::{App, ProcSort};
use crate::theme;
use crate::util::{fmt_bytes, fmt_duration, fmt_rate, truncate};

fn header(cols: &[&str]) -> Row<'static> {
    Row::new(cols.iter().map(|c| Cell::from(c.to_string())).collect::<Vec<_>>())
        .style(Style::new().fg(theme::BLUE).bold())
        .bottom_margin(0)
}

fn sel_style() -> Style {
    Style::new().bg(theme::SEL_BG).bold()
}

fn scrollbar(f: &mut Frame, area: Rect, len: usize, state: &TableState) {
    if len as u16 <= area.height.saturating_sub(3) {
        return;
    }
    let mut ss = ScrollbarState::new(len).position(state.selected().unwrap_or(0));
    f.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .track_symbol(Some("│"))
            .thumb_symbol("┃")
            .style(Style::new().fg(theme::BORDER))
            .thumb_style(Style::new().fg(theme::BLUE)),
        area.inner(ratatui::layout::Margin { vertical: 1, horizontal: 0 }),
        &mut ss,
    );
}

/// Keep the selection on screen and return the visible window `(offset, rows)`.
/// Only that window gets turned into table rows, so a 50 000-line lsof result
/// costs the same to draw as a 50-line one.
fn window(state: &mut TableState, len: usize, area: Rect) -> (usize, usize) {
    let h = area.height.saturating_sub(3).max(1) as usize; // borders + header
    let sel = state.selected().unwrap_or(0).min(len.saturating_sub(1));
    state.select(Some(sel));
    let mut off = state.offset();
    if sel < off {
        off = sel;
    }
    if sel >= off + h {
        off = sel + 1 - h;
    }
    off = off.min(len.saturating_sub(h));
    *state.offset_mut() = off;
    (off, h)
}

/// Table state relative to the visible window.
fn local_state(state: &TableState, off: usize) -> TableState {
    TableState::default().with_selected(state.selected().map(|s| s - off))
}

fn status_code(s: &str) -> (char, ratatui::style::Color) {
    match s {
        "Running" => ('R', theme::GREEN),
        "Sleeping" => ('S', theme::DIM),
        "Idle" => ('I', theme::DIM),
        "Stopped" => ('T', theme::YELLOW),
        "Tracing" => ('t', theme::YELLOW),
        "Zombie" => ('Z', theme::RED),
        "Dead" => ('X', theme::RED),
        "Disk sleep" => ('D', theme::ORANGE),
        "LockBlocked" => ('L', theme::ORANGE),
        _ => ('?', theme::MUTED),
    }
}

fn filter_title(filter: &str) -> Vec<Span<'static>> {
    if filter.is_empty() {
        vec![]
    } else {
        vec![
            Span::styled(" filter ", Style::new().fg(theme::DIM)),
            Span::styled(format!("“{filter}” "), Style::new().fg(theme::YELLOW).bold()),
        ]
    }
}

// ─────────────────────────────── processes ───────────────────────────────

pub fn processes(f: &mut Frame, app: &mut App, area: Rect) {
    let [table_area, detail] =
        Layout::vertical([Constraint::Min(5), Constraint::Length(6)]).areas(area);

    let arrow = if app.proc_desc { "▼" } else { "▲" };
    let cols: [(&str, Option<ProcSort>); 11] = [
        ("PID", Some(ProcSort::Pid)),
        ("USER", Some(ProcSort::User)),
        ("CPU%", Some(ProcSort::Cpu)),
        ("", None),
        ("MEM", Some(ProcSort::Mem)),
        ("MEM%", None),
        ("IO R/W", Some(ProcSort::Io)),
        ("CONN", Some(ProcSort::Conn)),
        ("ST", None),
        ("TIME", None),
        ("COMMAND", Some(ProcSort::Name)),
    ];
    let head: Vec<Cell> = cols
        .iter()
        .map(|(name, s)| {
            if *s == Some(app.proc_sort) {
                Cell::from(format!("{name}{arrow}")).style(Style::new().fg(theme::YELLOW).bold())
            } else {
                Cell::from(name.to_string()).style(Style::new().fg(theme::BLUE).bold())
            }
        })
        .collect();

    let (off, h) = window(&mut app.proc_state, app.proc_rows.len(), table_area);
    let procs = &app.sampler.procs;
    let conns = &app.conn_counts;
    let mem_total = app.sampler.mem_total.max(1) as f64;
    let ncores = app.sampler.ncores().max(1) as f32;

    let end = (off + h).min(app.proc_rows.len());
    let rows: Vec<Row> = app.proc_rows[off..end]
        .iter()
        .map(|r| {
            let p = &procs[r.idx];
            let mem_pct = p.mem as f64 / mem_total * 100.0;
            let io = p.read_rate + p.write_rate;
            let (st, st_color) = status_code(p.status);
            let conn = conns.get(&p.pid).copied().unwrap_or(0);
            let cmd = if p.cmd.is_empty() { String::new() } else { format!(" {}", p.cmd) };
            Row::new(vec![
                Cell::from(p.pid.to_string()).style(Style::new().fg(theme::MUTED)),
                Cell::from(truncate(&p.user, 10)).style(Style::new().fg(if &*p.user == "root" {
                    theme::RED
                } else {
                    theme::TEAL
                })),
                Cell::from(format!("{:5.1}", p.cpu)).style(Style::new().fg(theme::heat(p.cpu as f64 / ncores.min(4.0) as f64))),
                Cell::from(Line::from(meter((p.cpu / ncores.min(4.0)) as f64, 5))),
                Cell::from(fmt_bytes(p.mem)).style(Style::new().fg(theme::PURPLE)),
                Cell::from(format!("{mem_pct:4.1}")).style(Style::new().fg(theme::heat(mem_pct * 3.0))),
                Cell::from(if io > 0.0 {
                    format!("{}/{}", fmt_bytes(p.read_rate as u64), fmt_bytes(p.write_rate as u64))
                } else {
                    "·".into()
                })
                .style(Style::new().fg(if io > 0.0 { theme::YELLOW } else { theme::DIM })),
                Cell::from(if conn > 0 { conn.to_string() } else { "·".into() })
                    .style(Style::new().fg(if conn > 0 { theme::CYAN } else { theme::DIM })),
                Cell::from(st.to_string()).style(Style::new().fg(st_color)),
                Cell::from(fmt_duration(p.run_time)).style(Style::new().fg(theme::DIM)),
                Cell::from(Line::from(vec![
                    Span::styled(r.prefix.clone(), Style::new().fg(theme::BORDER)),
                    Span::styled(p.name.to_string(), Style::new().fg(theme::FG).bold()),
                    Span::styled(cmd, Style::new().fg(theme::DIM)),
                ])),
            ])
        })
        .collect();

    let mut title = vec![Span::styled(
        format!(" processes ({}) ", app.proc_rows.len()),
        Style::new().fg(theme::GREEN).bold(),
    )];
    if app.proc_tree {
        title.push(Span::styled(" tree ", Style::new().fg(theme::HEADER_BG).bg(theme::PURPLE)));
    }
    title.extend(filter_title(&app.proc_filter));
    let block = frame().title(Line::from(title));

    let len = app.proc_rows.len();
    let t = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(10),
            Constraint::Length(6),
            Constraint::Length(5),
            Constraint::Length(7),
            Constraint::Length(5),
            Constraint::Length(13),
            Constraint::Length(5),
            Constraint::Length(2),
            Constraint::Length(10),
            Constraint::Min(20),
        ],
    )
    .header(Row::new(head))
    .block(block)
    .row_highlight_style(sel_style())
    .highlight_symbol("▌");
    f.render_stateful_widget(t, table_area, &mut local_state(&app.proc_state, off));
    scrollbar(f, table_area, len, &app.proc_state);

    // Detail pane for the selected process.
    let block = panel("details", theme::BLUE);
    let lines = match app.selected_proc() {
        Some(p) => {
            let conn = app.conn_counts.get(&p.pid).copied().unwrap_or(0);
            vec![
                Line::from(
                    [
                        kv(" pid", p.pid.to_string(), theme::FG),
                        kv("ppid", p.ppid.map(|x| x.to_string()).unwrap_or("-".into()), theme::FG),
                        kv("user", p.user.to_string(), theme::TEAL),
                        kv("status", p.status, theme::GREEN),
                        kv("uptime", fmt_duration(p.run_time), theme::FG),
                        kv("rss", fmt_bytes(p.mem), theme::PURPLE),
                        kv("virt", fmt_bytes(p.virt), theme::PURPLE),
                        kv("sockets", conn.to_string(), theme::CYAN),
                    ]
                    .concat(),
                ),
                Line::from(
                    [
                        kv(" disk read", format!("{} ({})", fmt_rate(p.read_rate), fmt_bytes(p.read_total)), theme::YELLOW),
                        kv("written", format!("{} ({})", fmt_rate(p.write_rate), fmt_bytes(p.write_total)), theme::ORANGE),
                        kv("exe", p.exe.to_string(), theme::MUTED),
                    ]
                    .concat(),
                ),
                Line::from(vec![
                    Span::styled(" cmd ", Style::new().fg(theme::DIM)),
                    Span::styled(p.cmd.to_string(), Style::new().fg(theme::FG)),
                ]),
            ]
        }
        None => vec![Line::styled(" no process selected", Style::new().fg(theme::DIM))],
    };
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(block), detail);
}

// ─────────────────────────────── network ───────────────────────────────

pub fn network(f: &mut Frame, app: &mut App, area: Rect) {
    let ifaces = app.sampler.ifaces.clone();
    let h = (ifaces.len() as u16 + 3).min((area.height / 2).max(5));
    let [table_area, bottom] = Layout::vertical([Constraint::Length(h), Constraint::Min(6)]).areas(area);

    let rows: Vec<Row> = ifaces
        .iter()
        .map(|i| {
            let active = i.rx_rate + i.tx_rate > 0.0;
            Row::new(vec![
                Cell::from(i.name.clone()).style(Style::new().fg(if active { theme::CYAN } else { theme::MUTED }).bold()),
                Cell::from(fmt_rate(i.rx_rate)).style(Style::new().fg(theme::GREEN)),
                Cell::from(fmt_rate(i.tx_rate)).style(Style::new().fg(theme::ORANGE)),
                Cell::from(fmt_bytes(i.rx_total)).style(Style::new().fg(theme::FG)),
                Cell::from(fmt_bytes(i.tx_total)).style(Style::new().fg(theme::FG)),
                Cell::from(format!("{}/{}", i.rx_packets, i.tx_packets)).style(Style::new().fg(theme::DIM)),
                Cell::from(format!("{}/{}", i.rx_errors, i.tx_errors)).style(Style::new().fg(
                    if i.rx_errors + i.tx_errors > 0 { theme::RED } else { theme::DIM },
                )),
                Cell::from(i.mac.clone()).style(Style::new().fg(theme::DIM)),
                Cell::from(i.addrs.join("  ")).style(Style::new().fg(theme::TEAL)),
            ])
        })
        .collect();
    let t = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(11),
            Constraint::Length(11),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(19),
            Constraint::Length(9),
            Constraint::Length(18),
            Constraint::Min(10),
        ],
    )
    .header(header(&["IFACE", "RX/s", "TX/s", "RX TOTAL", "TX TOTAL", "PACKETS RX/TX", "ERR", "MAC", "ADDRESSES"]))
    .block(panel(format!("interfaces ({})", ifaces.len()), theme::CYAN))
    .row_highlight_style(sel_style())
    .highlight_symbol("▌");
    f.render_stateful_widget(t, table_area, &mut app.net_state);

    let [graphs, side] = Layout::horizontal([Constraint::Min(30), Constraint::Length(34)]).areas(bottom);

    let sel = app.net_state.selected().and_then(|i| ifaces.get(i));
    if let Some(iface) = sel {
        let (rxh, txh) = &app.sampler.iface_hist[&iface.name];
        let w = graphs.width.saturating_sub(2) as usize;
        let rx = rxh.tail(w);
        let tx = txh.tail(w);
        let max = rx.iter().chain(tx.iter()).copied().fold(1024.0, f64::max) * 1.1;
        let block = panel(format!("{}  traffic", iface.name), theme::CYAN).title(
            Line::from(vec![
                Span::styled("▼ ", Style::new().fg(theme::GREEN)),
                Span::styled(format!("{}  ", fmt_rate(iface.rx_rate)), Style::new().fg(theme::FG)),
                Span::styled("▲ ", Style::new().fg(theme::ORANGE)),
                Span::styled(format!("{}  ", fmt_rate(iface.tx_rate)), Style::new().fg(theme::FG)),
                Span::styled(format!("scale {} ", fmt_rate(max)), Style::new().fg(theme::DIM)),
            ])
            .right_aligned(),
        );
        let inner = block.inner(graphs);
        f.render_widget(block, graphs);
        let [d, u] = Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(inner);
        f.render_widget(
            AreaGraph { data: &rx, max, color: GraphColor::Gradient(theme::TEAL, theme::GREEN), inverted: false },
            d,
        );
        f.render_widget(
            AreaGraph { data: &tx, max, color: GraphColor::Gradient(theme::YELLOW, theme::ORANGE), inverted: true },
            u,
        );
    }

    // Remote hosts with the most connections (from lsof).
    let mut remotes: BTreeMap<String, usize> = BTreeMap::new();
    if let Ok(st) = app.sockets.lock() {
        for e in &st.entries {
            let r = e.endpoints().1;
            if !r.is_empty() {
                let host = r.rsplit_once(':').map(|(h, _)| h).unwrap_or(r);
                *remotes.entry(host.to_string()).or_default() += 1;
            }
        }
    }
    let mut v: Vec<_> = remotes.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    let rows: Vec<Row> = v
        .iter()
        .take(side.height as usize)
        .map(|(h, n)| {
            Row::new(vec![
                Cell::from(truncate(h, 24)).style(Style::new().fg(theme::TEAL)),
                Cell::from(n.to_string()).style(Style::new().fg(theme::FG).bold()),
            ])
        })
        .collect();
    f.render_widget(
        Table::new(rows, [Constraint::Min(10), Constraint::Length(5)])
            .header(header(&["REMOTE HOST", "CONN"]))
            .block(panel("top peers", theme::PURPLE)),
        side,
    );
}

// ─────────────────────────────── sockets ───────────────────────────────

pub fn sockets(f: &mut Frame, app: &mut App, area: Rect) {
    let (updated, took, err, total, backend) = match app.sockets.lock() {
        Ok(s) => (s.updated, s.took, s.error.clone(), s.entries.len(), s.backend.label()),
        Err(_) => (None, Default::default(), None, 0, ""),
    };
    let rows_data = app.socket_rows();

    let [summary, table_area] = Layout::vertical([Constraint::Length(3), Constraint::Min(5)]).areas(area);

    // Summary chips: count by state / protocol.
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for e in rows_data {
        let k = if e.state.is_empty() { format!("{} (no state)", e.proto) } else { e.state.clone() };
        *counts.entry(k).or_default() += 1;
    }
    let mut chips = vec![Span::raw(" ")];
    for (k, n) in &counts {
        chips.push(Span::styled(format!(" {k} "), Style::new().fg(theme::HEADER_BG).bg(theme::tcp_state(k))));
        chips.push(Span::styled(format!(" {n}  "), Style::new().fg(theme::FG).bold()));
    }
    if !app.is_root {
        chips.push(Span::styled("  ⚠ not root: only your own processes are visible", Style::new().fg(theme::YELLOW)));
    }
    let age = updated.map(|u| format!("{:.1}s ago", u.elapsed().as_secs_f64())).unwrap_or("pending".into());
    let block = panel(backend, theme::PURPLE).title(
        Line::styled(format!(" updated {age} · {}ms ", took.as_millis()), Style::new().fg(theme::DIM)).right_aligned(),
    );
    f.render_widget(Paragraph::new(Line::from(chips)).block(block), summary);

    if let Some(e) = err {
        f.render_widget(
            Paragraph::new(Line::styled(format!(" lsof error: {e}"), Style::new().fg(theme::RED)))
                .block(panel("sockets", theme::RED)),
            table_area,
        );
        return;
    }

    let n_rows = rows_data.len();
    let (off, h) = window(&mut app.sock_state, n_rows, table_area);
    let rows_data = app.socket_rows();
    let rows: Vec<Row> = rows_data[off..(off + h).min(n_rows)]
        .iter()
        .map(|e| {
            let (l, r) = e.endpoints();
            Row::new(vec![
                Cell::from(format!("{} {}", e.proto, e.ftype.trim_start_matches("IP"))).style(Style::new().fg(theme::CYAN)),
                Cell::from(l.to_string()).style(Style::new().fg(if e.is_listening() { theme::GREEN } else { theme::FG })),
                Cell::from(if r.is_empty() { "·".to_string() } else { r.to_string() }).style(Style::new().fg(theme::TEAL)),
                Cell::from(e.state.clone()).style(Style::new().fg(theme::tcp_state(&e.state)).bold()),
                Cell::from(e.pid.to_string()).style(Style::new().fg(theme::MUTED)),
                Cell::from(e.command.clone()).style(Style::new().fg(theme::FG).bold()),
                Cell::from(e.user.clone()).style(Style::new().fg(if e.user == "root" { theme::RED } else { theme::TEAL })),
                Cell::from(e.fd_display()).style(Style::new().fg(theme::DIM)),
            ])
        })
        .collect();

    let mut title = vec![Span::styled(
        format!(" sockets ({}/{total}) ", rows_data.len()),
        Style::new().fg(theme::CYAN).bold(),
    )];
    if app.sock_listen_only {
        title.push(Span::styled(" LISTEN only ", Style::new().fg(theme::HEADER_BG).bg(theme::GREEN)));
    }
    title.push(Span::styled(format!("  sort {} ", app.sock_sort.label()), Style::new().fg(theme::DIM)));
    title.extend(filter_title(&app.sock_filter));

    let len = n_rows;
    let t = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Length(12),
            Constraint::Length(7),
            Constraint::Min(12),
            Constraint::Length(10),
            Constraint::Length(5),
        ],
    )
    .header(header(&["PROTO", "LOCAL", "REMOTE", "STATE", "PID", "PROCESS", "USER", "FD"]))
    .block(frame().title(Line::from(title)))
    .row_highlight_style(sel_style())
    .highlight_symbol("▌");
    f.render_stateful_widget(t, table_area, &mut local_state(&app.sock_state, off));
    scrollbar(f, table_area, len, &app.sock_state);
}

// ─────────────────────────────── files ───────────────────────────────

pub fn files(f: &mut Frame, app: &mut App, area: Rect) {
    let (query, loading, err, took, total) = match app.files.lock() {
        Ok(s) => (s.query.clone(), s.loading, s.error.clone(), s.took, s.entries.len()),
        Err(_) => (None, false, None, Default::default(), 0),
    };
    let [summary, table_area] = Layout::vertical([Constraint::Length(3), Constraint::Min(5)]).areas(area);

    let Some(query) = query else {
        let lines = vec![
            Line::raw(""),
            Line::styled("  No lsof query yet.", Style::new().fg(theme::FG).bold()),
            Line::raw(""),
            Line::from(vec![
                Span::styled("  Press ", Style::new().fg(theme::DIM)),
                Span::styled(":", Style::new().fg(theme::BLUE).bold()),
                Span::styled(" and type one of:", Style::new().fg(theme::DIM)),
            ]),
            Line::styled("     1234              files opened by pid 1234", Style::new().fg(theme::MUTED)),
            Line::styled("     :8080             who is using port 8080", Style::new().fg(theme::MUTED)),
            Line::styled("     tcp:443           TCP sockets on port 443", Style::new().fg(theme::MUTED)),
            Line::styled("     /var/log/syslog   who has this file open", Style::new().fg(theme::MUTED)),
            Line::styled("     -u www-data       raw lsof arguments", Style::new().fg(theme::MUTED)),
            Line::raw(""),
            Line::from(vec![
                Span::styled("  Or press ", Style::new().fg(theme::DIM)),
                Span::styled("↵", Style::new().fg(theme::BLUE).bold()),
                Span::styled(" on a process in the Processes or Sockets view.", Style::new().fg(theme::DIM)),
            ]),
        ];
        f.render_widget(Paragraph::new(lines).block(panel("open files", theme::PURPLE)), area);
        return;
    };

    let rows_data = app.file_rows();
    // Type breakdown.
    let mut types: BTreeMap<String, usize> = BTreeMap::new();
    for e in rows_data {
        *types.entry(e.ftype.clone()).or_default() += 1;
    }
    let mut v: Vec<_> = types.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    let mut chips = vec![Span::raw(" ")];
    if loading {
        chips.push(Span::styled(" ⟳ running… ", Style::new().fg(theme::HEADER_BG).bg(theme::YELLOW).bold()));
        chips.push(Span::raw("  "));
    }
    for (k, n) in v.iter().take(10) {
        chips.push(Span::styled(format!("{k} "), Style::new().fg(theme::file_type(k)).bold()));
        chips.push(Span::styled(format!("{n}  "), Style::new().fg(theme::FG)));
    }
    let block = panel(query.label(), theme::PURPLE).title(
        Line::styled(format!(" {} entries · {}ms ", total, took.as_millis()), Style::new().fg(theme::DIM)).right_aligned(),
    );
    f.render_widget(Paragraph::new(Line::from(chips)).block(block), summary);

    if let Some(e) = err {
        f.render_widget(
            Paragraph::new(Line::styled(format!(" {e}"), Style::new().fg(theme::RED)))
                .block(panel("error", theme::RED)),
            table_area,
        );
        return;
    }

    let n_rows = rows_data.len();
    let (off, h) = window(&mut app.files_state, n_rows, table_area);
    let rows_data = app.file_rows();
    let rows: Vec<Row> = rows_data[off..(off + h).min(n_rows)]
        .iter()
        .map(|e| {
            Row::new(vec![
                Cell::from(e.pid.to_string()).style(Style::new().fg(theme::MUTED)),
                Cell::from(truncate(&e.command, 15)).style(Style::new().fg(theme::FG).bold()),
                Cell::from(truncate(&e.user, 10)).style(Style::new().fg(theme::TEAL)),
                Cell::from(e.fd_display()).style(Style::new().fg(theme::YELLOW)),
                Cell::from(e.ftype.clone()).style(Style::new().fg(theme::file_type(&e.ftype))),
                Cell::from(e.size_off()).style(Style::new().fg(theme::DIM)),
                Cell::from(e.node.clone()).style(Style::new().fg(theme::DIM)),
                Cell::from(Line::from(vec![
                    Span::styled(e.name.clone(), Style::new().fg(theme::file_type(&e.ftype))),
                    Span::styled(
                        if e.state.is_empty() { String::new() } else { format!("  ({})", e.state) },
                        Style::new().fg(theme::tcp_state(&e.state)),
                    ),
                ])),
            ])
        })
        .collect();

    let mut title = vec![Span::styled(
        format!(" files ({}/{total}) ", rows_data.len()),
        Style::new().fg(theme::PURPLE).bold(),
    )];
    title.extend(filter_title(&app.files_filter));
    let len = n_rows;
    let t = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(15),
            Constraint::Length(10),
            Constraint::Length(6),
            Constraint::Length(7),
            Constraint::Length(9),
            Constraint::Length(10),
            Constraint::Min(20),
        ],
    )
    .header(header(&["PID", "COMMAND", "USER", "FD", "TYPE", "SIZE/OFF", "NODE", "NAME"]))
    .block(frame().title(Line::from(title)))
    .row_highlight_style(sel_style())
    .highlight_symbol("▌");
    f.render_stateful_widget(t, table_area, &mut local_state(&app.files_state, off));
    scrollbar(f, table_area, len, &app.files_state);
}

// ─────────────────────────────── storage ───────────────────────────────

pub fn storage(f: &mut Frame, app: &mut App, area: Rect) {
    let s = &app.sampler;
    let h = (s.disks_info.len() as u16 + 3).min((area.height / 2).max(5));
    let [disks, bottom] = Layout::vertical([Constraint::Length(h), Constraint::Min(6)]).areas(area);

    let bar_w = 20;
    let rows: Vec<Row> = s
        .disks_info
        .iter()
        .map(|d| {
            let pct = d.pct();
            Row::new(vec![
                Cell::from(d.mount.clone()).style(Style::new().fg(theme::FG).bold()),
                Cell::from(truncate(&d.name, 20)).style(Style::new().fg(theme::MUTED)),
                Cell::from(d.fs.clone()).style(Style::new().fg(theme::CYAN)),
                Cell::from(format!("{}{}", d.kind, if d.removable { " ⏏" } else { "" })).style(Style::new().fg(theme::DIM)),
                Cell::from(fmt_bytes(d.total)).style(Style::new().fg(theme::FG)),
                Cell::from(fmt_bytes(d.used())).style(Style::new().fg(theme::YELLOW)),
                Cell::from(fmt_bytes(d.avail)).style(Style::new().fg(theme::GREEN)),
                Cell::from(Line::from(meter(pct, bar_w))),
                Cell::from(format!("{pct:5.1}%")).style(Style::new().fg(theme::heat(pct)).bold()),
            ])
        })
        .collect();
    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Min(16),
                Constraint::Length(20),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(bar_w as u16),
                Constraint::Length(7),
            ],
        )
        .header(header(&["MOUNT", "DEVICE", "FS", "KIND", "SIZE", "USED", "AVAIL", "USAGE", ""]))
        .block(panel(format!("filesystems ({})", s.disks_info.len()), theme::YELLOW)),
        disks,
    );

    let [io, temps] = Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)]).areas(bottom);

    let mut procs: Vec<_> = s.procs.iter().filter(|p| p.read_rate + p.write_rate > 0.0).collect();
    procs.sort_by(|a, b| {
        (b.read_rate + b.write_rate)
            .partial_cmp(&(a.read_rate + a.write_rate))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let rows: Vec<Row> = procs
        .iter()
        .take(io.height as usize)
        .map(|p| {
            Row::new(vec![
                Cell::from(p.pid.to_string()).style(Style::new().fg(theme::MUTED)),
                Cell::from(truncate(&p.name, 24)).style(Style::new().fg(theme::FG).bold()),
                Cell::from(fmt_rate(p.read_rate)).style(Style::new().fg(theme::GREEN)),
                Cell::from(fmt_rate(p.write_rate)).style(Style::new().fg(theme::ORANGE)),
                Cell::from(fmt_bytes(p.read_total)).style(Style::new().fg(theme::DIM)),
                Cell::from(fmt_bytes(p.write_total)).style(Style::new().fg(theme::DIM)),
            ])
        })
        .collect();
    let io_block = panel("disk i/o by process", theme::ORANGE).title(
        Line::from(vec![
            Span::styled("read ", Style::new().fg(theme::DIM)),
            Span::styled(format!("{}  ", fmt_rate(s.io_read_rate)), Style::new().fg(theme::GREEN)),
            Span::styled("write ", Style::new().fg(theme::DIM)),
            Span::styled(format!("{} ", fmt_rate(s.io_write_rate)), Style::new().fg(theme::ORANGE)),
        ])
        .right_aligned(),
    );
    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(7),
                Constraint::Min(12),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Length(9),
                Constraint::Length(9),
            ],
        )
        .header(header(&["PID", "PROCESS", "READ/s", "WRITE/s", "READ Σ", "WRITE Σ"]))
        .block(io_block),
        io,
    );

    let block = panel(format!("sensors ({})", s.temps.len()), theme::RED);
    if s.temps.is_empty() {
        f.render_widget(
            Paragraph::new(Line::styled(" no temperature sensors exposed", Style::new().fg(theme::DIM))).block(block),
            temps,
        );
        return;
    }
    let bw = (temps.width as usize).saturating_sub(34).max(4);
    let lines: Vec<Line> = s
        .temps
        .iter()
        .take(temps.height.saturating_sub(2) as usize)
        .map(|t| {
            let crit = t.critical.filter(|c| *c > 0.0).unwrap_or(100.0);
            let pct = (t.temp / crit * 100.0) as f64;
            let mut sp = vec![Span::styled(
                format!(" {:<20}", truncate(&t.label, 20)),
                Style::new().fg(theme::MUTED),
            )];
            sp.extend(meter(pct, bw));
            sp.push(Span::styled(format!(" {:5.1}°C", t.temp), Style::new().fg(theme::heat(pct)).bold()));
            Line::from(sp)
        })
        .collect();
    f.render_widget(Paragraph::new(lines).block(block), temps);
}
