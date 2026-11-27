use std::collections::{BTreeMap, HashMap};

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
use crate::util::{fmt_bytes, fmt_duration, fmt_rate, spark, truncate};

/// Column headings. Headings of numeric columns are right-aligned so they sit
/// above their numbers: anything that measures (%, /s, ms, sizes, counts).
pub(super) fn header(cols: &[&str]) -> Row<'static> {
    Row::new(cols.iter().map(|c| head_cell(c, is_numeric_col(c), false)).collect::<Vec<_>>())
        .style(Style::new().fg(theme::blue()).bold())
        .bottom_margin(0)
}

pub(super) fn is_numeric_col(name: &str) -> bool {
    let n = name.trim_end_matches(['▼', '▲']);
    const EXACT: &[&str] = &[
        "PID", "CPU%", "MEM", "MEM%", "IO R/W", "CONN", "NET/s", "FDS", "TIME", "RTT ms", "RETR", "RECV/SEND Q",
        "↓ RX/s", "↑ TX/s", "RX/s", "TX/s", "UTIL", "DROPS", "ERR", "RX Σ", "TX Σ", "MTU", "LINK", "SIZE", "USED",
        "AVAIL", "INODES", "READ/s", "WRITE/s", "TOTAL R", "TOTAL W", "SIZE/OFF", "NODE", "PORT", "LAST ms", "MIN",
        "AVG", "MAX", "JITTER", "LOSS", "PACKETS", "BYTES", "PKT/s", "BYTES/s", "METRIC", "CPU", "THROTTLED",
        "PIDS", "IO R/s", "IO W/s", "NET ↓/s", "NET ↑/s", "OOM", "RESTARTS", "MEMORY", "R IOPS", "W IOPS",
        "AWAIT ms", "QUEUE", "R/s", "W/s", "STATUS", "CERT", "HOP", "SENT", "BEST", "WORST", "CPU%/LIM", "MEM%",
        "CPU%", "CONN", "LOSS%", "%", "ATTEMPTS", "IDLE", "MOS",
    ];
    EXACT.contains(&n)
}

fn head_cell(name: &str, right: bool, active: bool) -> Cell<'static> {
    let style = if active { Style::new().fg(theme::yellow()).bold() } else { Style::new().fg(theme::blue()).bold() };
    let line = Line::from(name.to_string());
    Cell::from(if right { line.right_aligned() } else { line }).style(style)
}

/// A right-aligned (numeric) cell.
pub(super) fn num(text: impl Into<String>, style: Style) -> Cell<'static> {
    Cell::from(Line::from(text.into()).right_aligned()).style(style)
}

/// Placeholder for "no value", right-aligned and dimmed.
pub(super) fn none() -> Cell<'static> {
    num("·", Style::new().fg(theme::dim()))
}

pub(super) fn sel_style() -> Style {
    Style::new().bg(theme::sel_bg()).bold()
}

pub(super) fn scrollbar(f: &mut Frame, area: Rect, len: usize, state: &TableState) {
    if len as u16 <= area.height.saturating_sub(3) {
        return;
    }
    let mut ss = ScrollbarState::new(len).position(state.selected().unwrap_or(0));
    f.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .track_symbol(Some(theme::glyphs().track))
            .thumb_symbol(theme::glyphs().thumb)
            .style(Style::new().fg(theme::border()))
            .thumb_style(Style::new().fg(theme::blue())),
        area.inner(ratatui::layout::Margin { vertical: 1, horizontal: 0 }),
        &mut ss,
    );
}

/// Keep the selection on screen and return the visible window `(offset, rows)`.
/// Only that window gets turned into table rows, so a 50 000-line lsof result
/// costs the same to draw as a 50-line one.
pub(super) fn window(state: &mut TableState, len: usize, area: Rect) -> (usize, usize) {
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
pub(super) fn local_state(state: &TableState, off: usize) -> TableState {
    TableState::default().with_selected(state.selected().map(|s| s - off))
}

fn status_code(s: &str) -> (char, ratatui::style::Color) {
    match s {
        "Running" => ('R', theme::green()),
        "Sleeping" => ('S', theme::dim()),
        "Idle" => ('I', theme::dim()),
        "Stopped" => ('T', theme::yellow()),
        "Tracing" => ('t', theme::yellow()),
        "Zombie" => ('Z', theme::red()),
        "Dead" => ('X', theme::red()),
        "Disk sleep" => ('D', theme::orange()),
        "LockBlocked" => ('L', theme::orange()),
        _ => ('?', theme::muted()),
    }
}

pub(super) fn filter_title(filter: &str) -> Vec<Span<'static>> {
    if filter.is_empty() {
        vec![]
    } else {
        vec![
            Span::styled(" filter ", Style::new().fg(theme::dim())),
            Span::styled(format!("“{filter}” "), Style::new().fg(theme::yellow()).bold()),
        ]
    }
}

// ─────────────────────────────── processes ───────────────────────────────

pub fn processes(f: &mut Frame, app: &mut App, area: Rect) {
    let [table_area, detail] =
        Layout::vertical([Constraint::Min(5), Constraint::Length(6)]).areas(area);

    let arrow = if app.proc_desc { "▼" } else { "▲" };
    let cols: [(&str, Option<ProcSort>); 13] = [
        ("PID", Some(ProcSort::Pid)),
        ("USER", Some(ProcSort::User)),
        ("CPU%", Some(ProcSort::Cpu)),
        ("", None),
        ("MEM", Some(ProcSort::Mem)),
        ("MEM%", None),
        ("IO R/W", Some(ProcSort::Io)),
        ("CONN", Some(ProcSort::Conn)),
        ("NET/s", Some(ProcSort::Net)),
        ("FDS", Some(ProcSort::Fds)),
        ("ST", None),
        ("TIME", None),
        ("COMMAND", Some(ProcSort::Name)),
    ];
    let head: Vec<Cell> = cols
        .iter()
        .map(|(name, s)| {
            let active = *s == Some(app.proc_sort);
            let label = if active { format!("{name}{arrow}") } else { name.to_string() };
            head_cell(&label, is_numeric_col(name), active)
        })
        .collect();
    let fds = app.net.limits.try_lock().map(|l| l.fds.clone()).unwrap_or_default();

    let (off, h) = window(&mut app.proc_state, app.proc_rows.len(), table_area);
    let proc_widths = [
        Constraint::Length(7),
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Length(5),
        Constraint::Length(7),
        Constraint::Length(5),
        Constraint::Length(13),
        Constraint::Length(5),
        Constraint::Length(7),
        Constraint::Length(5),
        Constraint::Length(2),
        Constraint::Length(10),
        Constraint::Min(20),
    ];
    app.hits.table = Some((table_area, off));
    {
        // Same geometry as the Table: inside the border, after the 1-column
        // selection marker, columns separated by one space.
        let inner = table_area.inner(ratatui::layout::Margin { vertical: 1, horizontal: 1 });
        let cols_area = Rect { x: inner.x + 1, width: inner.width.saturating_sub(1), ..inner };
        let rects = Layout::horizontal(proc_widths).spacing(1).split(cols_area);
        for (r, (_, sort)) in rects.iter().zip(cols.iter()) {
            if let Some(sort) = sort {
                app.hits.proc_headers.push((r.x, r.x + r.width, *sort));
            }
        }
    }
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
            let net = app.proc_net.get(&p.pid).map(|(t, r)| t + r).unwrap_or(0.0);
            let fd = fds.get(&p.pid).copied();
            let fd_pct = fd.and_then(|(n, l)| l.filter(|l| *l > 0).map(|l| n as f64 / l as f64 * 100.0));
            Row::new(vec![
                num(p.pid.to_string(), Style::new().fg(theme::muted())),
                Cell::from(truncate(&p.user, 10)).style(Style::new().fg(if &*p.user == "root" {
                    theme::red()
                } else {
                    theme::teal()
                })),
                num(format!("{:.1}", p.cpu), Style::new().fg(theme::heat(p.cpu as f64 / ncores.min(4.0) as f64))),
                Cell::from(Line::from(meter((p.cpu / ncores.min(4.0)) as f64, 5))),
                num(fmt_bytes(p.mem), Style::new().fg(theme::purple())),
                num(format!("{mem_pct:.1}"), Style::new().fg(theme::heat(mem_pct * 3.0))),
                if io > 0.0 {
                    num(format!("{}/{}", fmt_bytes(p.read_rate as u64), fmt_bytes(p.write_rate as u64)), Style::new().fg(theme::yellow()))
                } else {
                    none()
                },
                if conn > 0 { num(conn.to_string(), Style::new().fg(theme::cyan())) } else { none() },
                if net >= 1.0 { num(fmt_bytes(net as u64), Style::new().fg(theme::teal())) } else { none() },
                match fd {
                    Some((n, _)) => num(n.to_string(), Style::new().fg(match fd_pct {
                        Some(p) if p >= 90.0 => theme::red(),
                        Some(p) if p >= 70.0 => theme::orange(),
                        _ => theme::muted(),
                    })),
                    None => none(),
                },
                Cell::from(st.to_string()).style(Style::new().fg(st_color)),
                num(fmt_duration(p.run_time), Style::new().fg(theme::dim())),
                Cell::from(Line::from(vec![
                    Span::styled(r.prefix.clone(), Style::new().fg(theme::border())),
                    Span::styled(p.name.to_string(), Style::new().fg(theme::fg()).bold()),
                    Span::styled(cmd, Style::new().fg(theme::dim())),
                ])),
            ])
        })
        .collect();

    let mut title = vec![Span::styled(
        format!(" processes ({}) ", app.proc_rows.len()),
        Style::new().fg(theme::green()).bold(),
    )];
    if app.proc_tree {
        title.push(Span::styled(" tree ", Style::new().fg(theme::header_bg()).bg(theme::purple())));
    }
    title.extend(filter_title(&app.proc_filter));
    let block = frame().title(Line::from(title));

    let len = app.proc_rows.len();
    let t = Table::new(rows, proc_widths)
    .column_spacing(1)
    .header(Row::new(head))
    .block(block)
    .row_highlight_style(sel_style())
    .highlight_symbol(theme::glyphs().select);
    f.render_stateful_widget(t, table_area, &mut local_state(&app.proc_state, off));
    scrollbar(f, table_area, len, &app.proc_state);

    // Detail pane for the selected process.
    let block = panel("details", theme::blue());
    let lines = match app.selected_proc() {
        Some(p) => {
            let conn = app.conn_counts.get(&p.pid).copied().unwrap_or(0);
            vec![
                Line::from(
                    [
                        kv(" pid", p.pid.to_string(), theme::fg()),
                        kv("ppid", p.ppid.map(|x| x.to_string()).unwrap_or("-".into()), theme::fg()),
                        kv("user", p.user.to_string(), theme::teal()),
                        kv("status", p.status, theme::green()),
                        kv("uptime", fmt_duration(p.run_time), theme::fg()),
                        kv("rss", fmt_bytes(p.mem), theme::purple()),
                        kv("virt", fmt_bytes(p.virt), theme::purple()),
                        kv("sockets", conn.to_string(), theme::cyan()),
                        kv(
                            "fds",
                            match app.fd_info(p.pid) {
                                Some((n, Some(l))) => format!("{n}/{l} ({:.0}%)", n as f64 / l.max(1) as f64 * 100.0),
                                Some((n, None)) => n.to_string(),
                                None => "·".into(),
                            },
                            theme::fg(),
                        ),
                        kv(
                            "net",
                            app.proc_net
                                .get(&p.pid)
                                .map(|(t, r)| format!("↓{} ↑{}", fmt_rate(*r), fmt_rate(*t)))
                                .unwrap_or_else(|| "·".into()),
                            theme::teal(),
                        ),
                    ]
                    .concat(),
                ),
                Line::from(
                    [
                        kv(" disk read", format!("{} ({})", fmt_rate(p.read_rate), fmt_bytes(p.read_total)), theme::yellow()),
                        kv("written", format!("{} ({})", fmt_rate(p.write_rate), fmt_bytes(p.write_total)), theme::orange()),
                        kv("exe", p.exe.to_string(), theme::muted()),
                    ]
                    .concat(),
                ),
                Line::from(vec![
                    Span::styled(" cmd ", Style::new().fg(theme::dim())),
                    Span::styled(p.cmd.to_string(), Style::new().fg(theme::fg())),
                ]),
            ]
        }
        None => vec![Line::styled(" no process selected", Style::new().fg(theme::dim()))],
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
            let oper = i.oper.clone().unwrap_or_default();
            let ocol = match oper.as_str() {
                "up" => theme::green(),
                "down" | "lowerlayerdown" => theme::red(),
                "dormant" => theme::yellow(),
                _ => theme::dim(),
            };
            let util = i.util_pct();
            let kind = match (&i.kind, &i.master) {
                (Some(k), Some(m)) => format!("{k}→{m}"),
                (Some(k), None) => k.clone(),
                (None, Some(m)) => format!("→{m}"),
                _ => String::new(),
            };
            let speed = match (i.speed_mbps, &i.duplex) {
                (Some(s), Some(d)) if s >= 1000 => format!("{}G {}", s / 1000, &d[..1.min(d.len())]),
                (Some(s), Some(d)) => format!("{s}M {}", &d[..1.min(d.len())]),
                (Some(s), None) if s >= 1000 => format!("{}G", s / 1000),
                (Some(s), None) => format!("{s}M"),
                _ => "·".into(),
            };
            let errs = i.rx_errors + i.tx_errors;
            Row::new(vec![
                Cell::from(i.name.clone()).style(Style::new().fg(if active { theme::cyan() } else { theme::muted() }).bold()),
                Cell::from(if oper.is_empty() { "·".into() } else { oper.clone() }).style(Style::new().fg(ocol)),
                Cell::from(kind).style(Style::new().fg(theme::purple())),
                if speed == "·" { none() } else { num(speed, Style::new().fg(theme::fg())) },
                if i.mtu > 0 {
                    num(i.mtu.to_string(), Style::new().fg(if i.mtu != 1500 { theme::yellow() } else { theme::dim() }))
                } else {
                    none()
                },
                num(fmt_rate(i.rx_rate), Style::new().fg(theme::green())),
                num(fmt_rate(i.tx_rate), Style::new().fg(theme::orange())),
                match util {
                    Some(u) => num(format!("{u:.0}%"), Style::new().fg(theme::heat(u)).bold()),
                    None => none(),
                },
                if i.drop_rate > 0.0 {
                    num(format!("{:.0}/s", i.drop_rate), Style::new().fg(theme::red()))
                } else if i.rx_dropped + i.tx_dropped > 0 {
                    num(format!("Σ{}", i.rx_dropped + i.tx_dropped), Style::new().fg(theme::dim()))
                } else {
                    none()
                },
                if errs > 0 { num(format!("{}/{}", i.rx_errors, i.tx_errors), Style::new().fg(theme::red())) } else { none() },
                num(fmt_bytes(i.rx_total), Style::new().fg(theme::fg())),
                num(fmt_bytes(i.tx_total), Style::new().fg(theme::fg())),
                Cell::from(i.addrs.join("  ")).style(Style::new().fg(theme::teal())),
            ])
        })
        .collect();
    let t = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(6),
            Constraint::Length(12),
            Constraint::Length(7),
            Constraint::Length(5),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(5),
            Constraint::Length(8),
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Min(10),
        ],
    )
    .column_spacing(2)
    .header(header(&["IFACE", "STATE", "KIND", "LINK", "MTU", "RX/s", "TX/s", "UTIL", "DROPS", "ERR", "RX Σ", "TX Σ", "ADDRESSES"]))
    .block(panel(format!("interfaces ({})", ifaces.len()), theme::cyan()))
    .row_highlight_style(sel_style())
    .highlight_symbol(theme::glyphs().select);
    app.hits.table = Some((table_area, app.net_state.offset()));
    f.render_stateful_widget(t, table_area, &mut app.net_state);

    let [graphs, side] = Layout::horizontal([Constraint::Min(30), Constraint::Length(42)]).areas(bottom);

    let sel = app.net_state.selected().and_then(|i| ifaces.get(i));
    if let Some(iface) = sel {
        let (rxh, txh) = &app.sampler.iface_hist[&iface.name];
        let w = graphs.width.saturating_sub(2) as usize;
        let rx = rxh.tail(w);
        let tx = txh.tail(w);
        let max = rx.iter().chain(tx.iter()).copied().fold(1024.0, f64::max) * 1.1;
        let block = panel(format!("{}  {}", iface.name, iface.mac), theme::cyan()).title(
            Line::from(vec![
                Span::styled("▼ ", Style::new().fg(theme::green())),
                Span::styled(format!("{}  ", fmt_rate(iface.rx_rate)), Style::new().fg(theme::fg())),
                Span::styled("▲ ", Style::new().fg(theme::orange())),
                Span::styled(format!("{}  ", fmt_rate(iface.tx_rate)), Style::new().fg(theme::fg())),
                Span::styled(format!("scale {} ", fmt_rate(max)), Style::new().fg(theme::dim())),
            ])
            .right_aligned(),
        );
        let inner = block.inner(graphs);
        f.render_widget(block, graphs);
        let [d, u] = Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(inner);
        f.render_widget(
            AreaGraph { data: &rx, max, color: GraphColor::Gradient(theme::teal(), theme::green()), inverted: false },
            d,
        );
        f.render_widget(
            AreaGraph { data: &tx, max, color: GraphColor::Gradient(theme::yellow(), theme::orange()), inverted: true },
            u,
        );
    }

    let [kpanel, talkers, peers] =
        Layout::vertical([Constraint::Length(17), Constraint::Percentage(50), Constraint::Min(4)]).areas(side);

    // Kernel TCP/UDP health.
    let mut lines = match &app.sampler.knet.counters {
        Some(c) => {
            let row = |k: &str, v: String, col| {
                Line::from(vec![
                    Span::styled(format!(" {k:<17}"), Style::new().fg(theme::muted())),
                    Span::styled(format!("{v:>20}"), Style::new().fg(col).bold()),
                ])
            };
            let warn = |v: f64| if v > 0.0 { theme::orange() } else { theme::dim() };
            vec![
                row("retransmits", format!("{:.0}/s  {:.2}%", c.retrans_rate, c.retrans_pct), theme::heat(c.retrans_pct * 20.0)),
                row("segments out", format!("{:.0}/s", c.out_segs_rate), theme::fg()),
                row("listen overflows", format!("{:.1}/s", c.listen_overflow_rate.max(c.listen_drop_rate)), warn(c.listen_overflow_rate + c.listen_drop_rate)),
                row("udp buffer drops", format!("{:.1}/s", c.udp_rcvbuf_err_rate + c.udp_sndbuf_err_rate), warn(c.udp_rcvbuf_err_rate + c.udp_sndbuf_err_rate)),
                row("udp in errors", format!("{:.1}/s", c.udp_in_err_rate), warn(c.udp_in_err_rate)),
                row("tcp timeouts", format!("{:.1}/s", c.tcp_timeout_rate), warn(c.tcp_timeout_rate)),
                row("syn retransmits", format!("{:.1}/s", c.syn_retrans_rate), warn(c.syn_retrans_rate)),
                row("resets sent", format!("{:.1}/s", c.resets_out_rate), theme::fg()),
                row("estab. resets", format!("{:.1}/s", c.est_resets_rate), warn(c.est_resets_rate)),
                row("opens act/pass", format!("{:.0}/{:.0} /s", c.active_opens_rate, c.passive_opens_rate), theme::fg()),
                row("established", c.curr_estab.to_string(), theme::cyan()),
                row(
                    "conntrack",
                    c.conntrack.map(|(n, m)| format!("{n}/{m} ({:.0}%)", c.conntrack_pct().unwrap_or(0.0))).unwrap_or_else(|| "n/a".into()),
                    theme::heat(c.conntrack_pct().unwrap_or(0.0)),
                ),
                Line::from(vec![
                    Span::styled(" retrans% ", Style::new().fg(theme::dim())),
                    Span::styled(spark(&app.sampler.knet.retrans_hist.tail(28), 5.0), Style::new().fg(theme::orange())),
                ]),
            ]
        }
        None => vec![Line::styled(if cfg!(target_os = "macos") { " kernel counters: collecting…" } else { " kernel counters: not available here" }, Style::new().fg(theme::dim()))],
    };
    if app.sampler.knet.tcp_hidden {
        lines.insert(0, Line::styled(" TCP counters need sudo on macOS (UDP shown)", Style::new().fg(theme::yellow())));
    }
    if let Ok(l) = app.net.limits.try_lock() {
        let mut x = crate::app::ExtraHealth::default();
        x.fill_limits(&l, &app.sampler, app.socket_snapshot());
        let row = |k: &str, v: String, pct: Option<f64>| {
            Line::from(vec![
                Span::styled(format!(" {k:<17}"), Style::new().fg(theme::muted())),
                Span::styled(format!("{v:>20}"), Style::new().fg(theme::heat(pct.unwrap_or(0.0))).bold()),
            ])
        };
        if let (Some((lo, hi)), Some(p)) = (l.ephemeral, x.ephemeral_pct) {
            lines.push(row("ephemeral ports", format!("{p:.1}% of {lo}-{hi}"), Some(p)));
        }
        if let (Some((n, m)), Some(p)) = (l.files, x.files_pct) {
            lines.push(row("open files (sys)", format!("{n}/{m}"), Some(p)));
        } else if let Some((n, _)) = l.files {
            lines.push(row("open files (sys)", n.to_string(), None));
        }
    }
    f.render_widget(Paragraph::new(lines).block(panel("tcp / udp health", theme::orange())), kpanel);

    // Top talkers: bandwidth per process from tcp_info deltas.
    let mut tk: Vec<(u32, f64, f64)> = app.proc_net.iter().map(|(p, (t, r))| (*p, *t, *r)).collect();
    tk.sort_by(|a, b| (b.1 + b.2).total_cmp(&(a.1 + a.2)));
    let names: HashMap<u32, &str> = app.sampler.procs.iter().map(|p| (p.pid, &*p.name)).collect();
    let rows: Vec<Row> = tk
        .iter()
        .take(talkers.height.saturating_sub(3) as usize)
        .map(|(pid, tx, rx)| {
            Row::new(vec![
                Cell::from(truncate(names.get(pid).copied().unwrap_or("?"), 16)).style(Style::new().fg(theme::fg())),
                num(fmt_rate(*rx), Style::new().fg(theme::green())),
                num(fmt_rate(*tx), Style::new().fg(theme::orange())),
            ])
        })
        .collect();
    let talk_block = panel("top talkers", theme::green());
    if tk.is_empty() {
        let msg = if cfg!(target_os = "linux") || crate::platform::get().tools.nettop { " no traffic measured yet" } else { " per-process bandwidth: Linux and macOS" };
        f.render_widget(Paragraph::new(Line::styled(msg, Style::new().fg(theme::dim()))).block(talk_block), talkers);
    } else {
        f.render_widget(
            Table::new(rows, [Constraint::Min(10), Constraint::Length(11), Constraint::Length(11)])
                .header(header(&["PROCESS", "↓ RX/s", "↑ TX/s"]))
                .block(talk_block),
            talkers,
        );
    }

    // Remote hosts with the most connections.
    let mut remotes: BTreeMap<String, usize> = BTreeMap::new();
    if let Ok(st) = app.sockets.lock() {
        for e in st.entries.iter() {
            let r = e.endpoints().1;
            if !r.is_empty() {
                let host = r.rsplit_once(':').map(|(h, _)| h).unwrap_or(r);
                *remotes.entry(host.to_string()).or_default() += 1;
            }
        }
    }
    let mut v: Vec<_> = remotes.into_iter().collect();
    v.sort_by_key(|e| std::cmp::Reverse(e.1));
    let rows: Vec<Row> = v
        .iter()
        .take(peers.height.saturating_sub(3) as usize)
        .map(|(h, n)| {
            let ip = h.trim_matches(['[', ']']).parse().ok();
            let sc = ip.as_ref().map(crate::collect::ipinfo::scope).unwrap_or("");
            let label = match (app.show_names, &app.resolver, ip) {
                (true, Some(r), Some(ip)) => r.lookup(ip).unwrap_or_else(|| h.clone()),
                _ => h.clone(),
            };
            Row::new(vec![
                Cell::from(truncate(&label, 26)).style(Style::new().fg(theme::teal())),
                Cell::from(sc).style(Style::new().fg(theme::dim())),
                num(n.to_string(), Style::new().fg(theme::fg()).bold()),
            ])
        })
        .collect();
    f.render_widget(
        Table::new(rows, [Constraint::Min(10), Constraint::Length(8), Constraint::Length(5)])
            .header(header(&["REMOTE HOST", "SCOPE", "CONN"]))
            .block(panel("top peers", theme::purple())),
        peers,
    );
}

// ─────────────────────────────── sockets ───────────────────────────────

pub fn sockets(f: &mut Frame, app: &mut App, area: Rect) {
    let (updated, took, err, total, backend) = match app.sockets.lock() {
        Ok(s) => (s.updated, s.took, s.error.clone(), s.entries.len(), s.backend.label()),
        Err(_) => (None, Default::default(), None, 0, ""),
    };
    let rows_data = app.socket_rows();

    let sel_tcp = app
        .sock_state
        .selected()
        .and_then(|i| app.socket_rows().get(i))
        .and_then(|e| e.net.as_ref().and_then(|n| n.tcp.map(|t| (e.name.clone(), t, n.rx_queue, n.tx_queue))));
    let detail_h = if sel_tcp.is_some() { 3 } else { 0 };
    let [summary, table_area, detail] =
        Layout::vertical([Constraint::Length(3), Constraint::Min(5), Constraint::Length(detail_h)]).areas(area);

    // Summary chips: count by state / protocol.
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for e in rows_data.iter() {
        let k = if e.state.is_empty() { format!("{} (no state)", e.proto) } else { e.state.clone() };
        *counts.entry(k).or_default() += 1;
    }
    let mut chips = vec![Span::raw(" ")];
    for (k, n) in &counts {
        chips.push(Span::styled(format!(" {k} "), Style::new().fg(theme::header_bg()).bg(theme::tcp_state(k))));
        chips.push(Span::styled(format!(" {n}  "), Style::new().fg(theme::fg()).bold()));
    }
    if !app.is_root {
        chips.push(Span::styled("  ⚠ not root: only your own processes are visible", Style::new().fg(theme::yellow())));
    }
    let age = updated.map(|u| format!("{:.1}s ago", u.elapsed().as_secs_f64())).unwrap_or("pending".into());
    let block = panel(backend, theme::purple()).title(
        Line::styled(format!(" updated {age} · {}ms ", took.as_millis()), Style::new().fg(theme::dim())).right_aligned(),
    );
    f.render_widget(Paragraph::new(Line::from(chips)).block(block), summary);

    if let Some(e) = err {
        f.render_widget(
            Paragraph::new(Line::styled(format!(" lsof error: {e}"), Style::new().fg(theme::red())))
                .block(panel("sockets", theme::red())),
            table_area,
        );
        return;
    }

    let n_rows = rows_data.len();
    let (off, h) = window(&mut app.sock_state, n_rows, table_area);
    app.hits.table = Some((table_area, off));
    let rows_data = app.socket_rows();
    // Extra columns only when the data exists (Linux scanner / containers).
    let has_tcp = rows_data.range(off, off + h).any(|e| e.net.as_ref().is_some_and(|n| n.tcp.is_some()));
    let has_ns = rows_data.range(off, off + h).any(|e| e.net.as_ref().is_some_and(|n| n.netns.is_some()));
    let dim = |s: String| if s.is_empty() { "·".to_string() } else { s };
    let rows: Vec<Row> = rows_data
        .range(off, off + h)
        .map(|e| {
            let (l, r) = e.endpoints();
            let udp = e.proto == "UDP";
            let scope = crate::collect::ipinfo::endpoint_ip(r).map(|ip| crate::collect::ipinfo::scope(&ip)).unwrap_or("");
            let rcol = match scope {
                "public" => theme::teal(),
                "cgnat" => theme::purple(),
                "loopback" | "link-local" => theme::dim(),
                _ => theme::fg(),
            };
            let n = e.net.as_deref();
            let t = n.and_then(|n| n.tcp);
            let mut cells = vec![
                Cell::from(format!("{} {}", e.proto, e.ftype.trim_start_matches("IP"))).style(Style::new().fg(theme::cyan())),
                Cell::from(app.endpoint_label(l, udp)).style(Style::new().fg(if e.is_listening() { theme::green() } else { theme::fg() })),
                Cell::from(dim(app.endpoint_label(r, udp))).style(Style::new().fg(rcol)),
                Cell::from(e.state.clone()).style(Style::new().fg(theme::tcp_state(&e.state)).bold()),
            ];
            if has_tcp {
                let rtt_ms = t.map(|t| t.rtt_us as f64 / 1000.0);
                cells.push(match rtt_ms.filter(|v| *v > 0.0) {
                    Some(v) => num(
                        format!("{v:.1}"),
                        Style::new().fg(if v >= 100.0 {
                            theme::red()
                        } else if v >= 30.0 {
                            theme::yellow()
                        } else {
                            theme::green()
                        }),
                    ),
                    None => none(),
                });
                let retr = t.map(|t| t.total_retrans).unwrap_or(0);
                cells.push(if retr > 0 { num(retr.to_string(), Style::new().fg(theme::orange())) } else { none() });
                let (rq, sq) = n.map(|n| (n.rx_queue, n.tx_queue)).unwrap_or((0, 0));
                cells.push(if rq + sq > 0 {
                    num(format!("{}/{}", fmt_bytes(rq as u64), fmt_bytes(sq as u64)), Style::new().fg(theme::yellow()))
                } else {
                    none()
                });
                let (tx, rx) = n.map(|n| (n.tx_rate, n.rx_rate)).unwrap_or((0.0, 0.0));
                cells.push(if rx >= 1.0 { num(fmt_rate(rx), Style::new().fg(theme::green())) } else { none() });
                cells.push(if tx >= 1.0 { num(fmt_rate(tx), Style::new().fg(theme::orange())) } else { none() });
            }
            cells.push(num(if e.pid == 0 { "-".into() } else { e.pid.to_string() }, Style::new().fg(theme::muted())));
            cells.push(Cell::from(e.command.clone()).style(Style::new().fg(theme::fg()).bold()));
            if has_ns {
                cells.push(Cell::from(n.and_then(|n| n.netns.as_deref()).unwrap_or("host").to_string()).style(Style::new().fg(theme::purple())));
            }
            cells.push(Cell::from(e.user.clone()).style(Style::new().fg(if e.user == "root" { theme::red() } else { theme::teal() })));
            Row::new(cells)
        })
        .collect();

    let mut title = vec![Span::styled(
        format!(" sockets ({}/{total}) ", rows_data.len()),
        Style::new().fg(theme::cyan()).bold(),
    )];
    if app.sock_listen_only {
        title.push(Span::styled(" LISTEN only ", Style::new().fg(theme::header_bg()).bg(theme::green())));
    }
    title.push(Span::styled(format!("  sort {} ", app.sock_sort.label()), Style::new().fg(theme::dim())));
    title.extend(filter_title(&app.sock_filter));

    if app.show_names {
        title.push(Span::styled(" names ", Style::new().fg(theme::header_bg()).bg(theme::cyan())));
    }
    let len = n_rows;
    let mut widths = vec![Constraint::Length(8), Constraint::Percentage(20), Constraint::Percentage(24), Constraint::Length(12)];
    let mut heads = vec!["PROTO", "LOCAL", "REMOTE", "STATE"];
    if has_tcp {
        widths.extend([Constraint::Length(7), Constraint::Length(5), Constraint::Length(11), Constraint::Length(10), Constraint::Length(10)]);
        heads.extend(["RTT ms", "RETR", "RECV/SEND Q", "↓ RX/s", "↑ TX/s"]);
    }
    widths.extend([Constraint::Length(7), Constraint::Min(10)]);
    heads.extend(["PID", "PROCESS"]);
    if has_ns {
        widths.push(Constraint::Length(17));
        heads.push("NAMESPACE");
    }
    widths.push(Constraint::Length(9));
    heads.push("USER");
    let t = Table::new(rows, widths)
    .column_spacing(1)
    .header(header(&heads))
    .block(frame().title(Line::from(title)))
    .row_highlight_style(sel_style())
    .highlight_symbol(theme::glyphs().select);
    f.render_stateful_widget(t, table_area, &mut local_state(&app.sock_state, off));
    scrollbar(f, table_area, len, &app.sock_state);

    // `ss -ti` for the selected connection.
    if let Some((name, t, rq, sq)) = sel_tcp {
        let ms = |us: u32| format!("{:.1}", us as f64 / 1000.0);
        let line = Line::from(
            [
                vec![Span::raw(" ")],
                kv("rtt", format!("{}±{} ms (min {})", ms(t.rtt_us), ms(t.rttvar_us), ms(t.min_rtt_us)), theme::green()),
                kv("cwnd", t.snd_cwnd.to_string(), theme::cyan()),
                kv("mss", t.snd_mss.to_string(), theme::fg()),
                kv("pmtu", t.pmtu.to_string(), theme::fg()),
                kv("unacked", t.unacked.to_string(), theme::fg()),
                kv("lost", t.lost.to_string(), if t.lost > 0 { theme::red() } else { theme::fg() }),
                kv("retrans now/total", format!("{}/{}", t.retransmits, t.total_retrans), if t.total_retrans > 0 { theme::orange() } else { theme::fg() }),
                kv("delivery", fmt_rate(t.delivery_rate as f64), theme::teal()),
                kv("queues r/s", format!("{}/{}", fmt_bytes(rq as u64), fmt_bytes(sq as u64)), theme::yellow()),
                kv("sent/recv", format!("{}/{}", fmt_bytes(t.bytes_acked), fmt_bytes(t.bytes_received)), theme::muted()),
            ]
            .concat(),
        );
        f.render_widget(Paragraph::new(line).wrap(Wrap { trim: true }).block(panel(format!("tcp_info  {name}"), theme::green())), detail);
    }
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
            Line::styled("  No lsof query yet.", Style::new().fg(theme::fg()).bold()),
            Line::raw(""),
            Line::from(vec![
                Span::styled("  Press ", Style::new().fg(theme::dim())),
                Span::styled(":", Style::new().fg(theme::blue()).bold()),
                Span::styled(" and type one of:", Style::new().fg(theme::dim())),
            ]),
            Line::styled("     1234              files opened by pid 1234", Style::new().fg(theme::muted())),
            Line::styled("     :8080             who is using port 8080", Style::new().fg(theme::muted())),
            Line::styled("     tcp:443           TCP sockets on port 443", Style::new().fg(theme::muted())),
            Line::styled("     /var/log/syslog   who has this file open", Style::new().fg(theme::muted())),
            Line::styled("     -u www-data       raw lsof arguments", Style::new().fg(theme::muted())),
            Line::raw(""),
            Line::from(vec![
                Span::styled("  Or press ", Style::new().fg(theme::dim())),
                Span::styled("↵", Style::new().fg(theme::blue()).bold()),
                Span::styled(" on a process in the Processes or Sockets view.", Style::new().fg(theme::dim())),
            ]),
        ];
        f.render_widget(Paragraph::new(lines).block(panel("open files", theme::purple())), area);
        return;
    };

    let rows_data = app.file_rows();
    // Type breakdown.
    let mut types: BTreeMap<String, usize> = BTreeMap::new();
    for e in rows_data.iter() {
        *types.entry(e.ftype.clone()).or_default() += 1;
    }
    let mut v: Vec<_> = types.into_iter().collect();
    v.sort_by_key(|e| std::cmp::Reverse(e.1));
    let mut chips = vec![Span::raw(" ")];
    if loading {
        chips.push(Span::styled(" ⟳ running… ", Style::new().fg(theme::header_bg()).bg(theme::yellow()).bold()));
        chips.push(Span::raw("  "));
    }
    for (k, n) in v.iter().take(10) {
        chips.push(Span::styled(format!("{k} "), Style::new().fg(theme::file_type(k)).bold()));
        chips.push(Span::styled(format!("{n}  "), Style::new().fg(theme::fg())));
    }
    let block = panel(query.label(), theme::purple()).title(
        Line::styled(format!(" {} entries · {}ms ", total, took.as_millis()), Style::new().fg(theme::dim())).right_aligned(),
    );
    f.render_widget(Paragraph::new(Line::from(chips)).block(block), summary);

    if let Some(e) = err {
        f.render_widget(
            Paragraph::new(Line::styled(format!(" {e}"), Style::new().fg(theme::red())))
                .block(panel("error", theme::red())),
            table_area,
        );
        return;
    }

    let n_rows = rows_data.len();
    let (off, h) = window(&mut app.files_state, n_rows, table_area);
    app.hits.table = Some((table_area, off));
    let rows_data = app.file_rows();
    let rows: Vec<Row> = rows_data
        .range(off, off + h)
        .map(|e| {
            Row::new(vec![
                num(e.pid.to_string(), Style::new().fg(theme::muted())),
                Cell::from(truncate(&e.command, 15)).style(Style::new().fg(theme::fg()).bold()),
                Cell::from(truncate(&e.user, 10)).style(Style::new().fg(theme::teal())),
                Cell::from(e.fd_display()).style(Style::new().fg(theme::yellow())),
                Cell::from(e.ftype.clone()).style(Style::new().fg(theme::file_type(&e.ftype))),
                num(e.size_off(), Style::new().fg(theme::dim())),
                num(e.node.clone(), Style::new().fg(theme::dim())),
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
        Style::new().fg(theme::purple()).bold(),
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
    .highlight_symbol(theme::glyphs().select);
    f.render_stateful_widget(t, table_area, &mut local_state(&app.files_state, off));
    scrollbar(f, table_area, len, &app.files_state);
}

// ─────────────────────────────── storage ───────────────────────────────

pub fn storage(f: &mut Frame, app: &mut App, area: Rect) {
    let s = &app.sampler;
    let fs_h = (s.disks_info.len() as u16 + 3).min((area.height / 3).max(5));
    let dev_h = if s.diskio.devices.is_empty() { 0 } else { (s.diskio.devices.len() as u16 + 3).min(area.height / 4).max(4) };
    let [disks, devices, bottom] =
        Layout::vertical([Constraint::Length(fs_h), Constraint::Length(dev_h), Constraint::Min(6)]).areas(area);

    // Filesystems: space and inodes.
    let bar_w = 20;
    let rows: Vec<Row> = s
        .disks_info
        .iter()
        .map(|d| {
            let pct = d.pct();
            let ino = d.inode_pct();
            Row::new(vec![
                Cell::from(d.mount.clone()).style(Style::new().fg(theme::fg()).bold()),
                Cell::from(truncate(&d.name, 20)).style(Style::new().fg(theme::muted())),
                Cell::from(d.fs.clone()).style(Style::new().fg(theme::cyan())),
                Cell::from(format!("{}{}", d.kind, if d.removable { " ⏏" } else { "" })).style(Style::new().fg(theme::dim())),
                num(fmt_bytes(d.total), Style::new().fg(theme::fg())),
                num(fmt_bytes(d.used()), Style::new().fg(theme::yellow())),
                num(fmt_bytes(d.avail), Style::new().fg(theme::green())),
                Cell::from(Line::from(meter(pct, bar_w))),
                num(format!("{pct:.1}%"), Style::new().fg(theme::heat(pct)).bold()),
                match ino {
                    Some(p) => num(format!("{p:.1}%"), Style::new().fg(theme::heat(p))),
                    None => none(),
                },
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
                Constraint::Length(6),
                Constraint::Length(7),
            ],
        )
        .column_spacing(2)
        .header(header(&["MOUNT", "DEVICE", "FS", "KIND", "SIZE", "USED", "AVAIL", "USAGE", "%", "INODES"]))
        .block(panel(format!("filesystems ({})", s.disks_info.len()), theme::yellow())),
        disks,
    );

    // Block devices: iostat -x.
    if dev_h > 0 {
        let rows: Vec<Row> = s
            .diskio
            .devices
            .iter()
            .map(|d| {
                let busy = d.r_iops + d.w_iops >= 1.0;
                Row::new(vec![
                    Cell::from(d.name.clone()).style(Style::new().fg(theme::fg()).bold()),
                    num(format!("{:.0}", d.r_iops), Style::new().fg(theme::green())),
                    num(format!("{:.0}", d.w_iops), Style::new().fg(theme::orange())),
                    num(fmt_rate(d.r_bps), Style::new().fg(theme::green())),
                    num(fmt_rate(d.w_bps), Style::new().fg(theme::orange())),
                    if busy {
                        num(format!("{:.1}", d.await_ms), Style::new().fg(theme::heat(d.await_ms)).bold())
                    } else {
                        none()
                    },
                    num(format!("{:.0}%", d.util_pct), Style::new().fg(theme::heat(d.util_pct))),
                    num(format!("{:.2}", d.queue), Style::new().fg(theme::muted())),
                    Cell::from(Line::from(meter(d.util_pct, 16))),
                ])
            })
            .collect();
        f.render_widget(
            Table::new(
                rows,
                [
                    Constraint::Min(10),
                    Constraint::Length(7),
                    Constraint::Length(7),
                    Constraint::Length(10),
                    Constraint::Length(10),
                    Constraint::Length(9),
                    Constraint::Length(6),
                    Constraint::Length(6),
                    Constraint::Length(16),
                ],
            )
            .column_spacing(2)
            .header(header(&["DEVICE", "R/s", "W/s", "READ/s", "WRITE/s", "AWAIT ms", "UTIL", "QUEUE", ""]))
            .block(panel("devices (iostat)", theme::orange())),
            devices,
        );
    }

    let [io, temps] = Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)]).areas(bottom);

    let mut procs: Vec<_> = s.procs.iter().filter(|p| p.read_rate + p.write_rate > 0.0).collect();
    procs.sort_by(|a, b| (b.read_rate + b.write_rate).total_cmp(&(a.read_rate + a.write_rate)));
    let rows: Vec<Row> = procs
        .iter()
        .take(io.height as usize)
        .map(|p| {
            Row::new(vec![
                num(p.pid.to_string(), Style::new().fg(theme::muted())),
                Cell::from(truncate(&p.name, 24)).style(Style::new().fg(theme::fg()).bold()),
                num(fmt_rate(p.read_rate), Style::new().fg(theme::green())),
                num(fmt_rate(p.write_rate), Style::new().fg(theme::orange())),
                num(fmt_bytes(p.read_total), Style::new().fg(theme::dim())),
                num(fmt_bytes(p.write_total), Style::new().fg(theme::dim())),
            ])
        })
        .collect();
    let io_block = panel("disk i/o by process", theme::orange()).title(
        Line::from(vec![
            Span::styled("read ", Style::new().fg(theme::dim())),
            Span::styled(format!("{}  ", fmt_rate(s.io_read_rate)), Style::new().fg(theme::green())),
            Span::styled("write ", Style::new().fg(theme::dim())),
            Span::styled(format!("{} ", fmt_rate(s.io_write_rate)), Style::new().fg(theme::orange())),
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
        .column_spacing(2)
        .header(header(&["PID", "PROCESS", "READ/s", "WRITE/s", "TOTAL R", "TOTAL W"]))
        .block(io_block),
        io,
    );

    let block = panel(format!("sensors ({})", s.temps.len()), theme::red());
    if s.temps.is_empty() {
        f.render_widget(
            Paragraph::new(Line::styled(" no temperature sensors exposed", Style::new().fg(theme::dim()))).block(block),
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
            let mut sp = vec![Span::styled(format!(" {:<20}", truncate(&t.label, 20)), Style::new().fg(theme::muted()))];
            sp.extend(meter(pct, bw));
            sp.push(Span::styled(format!(" {:>6.1}°C", t.temp), Style::new().fg(theme::heat(pct)).bold()));
            Line::from(sp)
        })
        .collect();
    f.render_widget(Paragraph::new(lines).block(block), temps);
}
