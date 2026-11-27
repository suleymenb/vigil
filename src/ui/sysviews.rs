//! Containers (cgroup v2) and System (services, journal, kernel events).

use std::time::SystemTime;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use super::views::{header, local_state, none, num, scrollbar, sel_style, window};
use super::widgets::{frame, meter, panel};
use crate::app::App;
use crate::theme;
use crate::util::{fmt_bytes, fmt_rate, truncate};

fn ago(t: SystemTime) -> String {
    let s = SystemTime::now().duration_since(t).map(|d| d.as_secs()).unwrap_or(0);
    match s {
        0..=59 => format!("{s}s ago"),
        60..=3599 => format!("{}m ago", s / 60),
        3600..=86_399 => format!("{}h ago", s / 3600),
        _ => format!("{}d ago", s / 86_400),
    }
}

// ─────────────────────────────── containers ───────────────────────────────

pub fn containers(f: &mut Frame, app: &mut App, area: Rect) {
    let store = app.net.containers.clone();
    let Ok(st) = store.lock() else { return };
    if st.containers.is_empty() {
        let msg = st.error.clone().unwrap_or_else(|| {
            if st.version == 0 { "reading cgroups…".into() } else { "no containers running".into() }
        });
        let lines = vec![
            Line::raw(""),
            Line::styled(format!("  {msg}"), Style::new().fg(theme::fg())),
            Line::raw(""),
            Line::styled("  Docker, containerd / Kubernetes, CRI-O and Podman are found through cgroup v2;", Style::new().fg(theme::dim())),
            Line::styled("  no daemon or socket access is needed. Run as root to see every container.", Style::new().fg(theme::dim())),
        ];
        f.render_widget(Paragraph::new(lines).block(panel("containers", theme::cyan())), area);
        return;
    }
    let n = st.containers.len();
    let [table_area, detail] = Layout::vertical([Constraint::Min(5), Constraint::Length(5)]).areas(area);
    let (off, h) = window(&mut app.ctr_state, n, table_area);
    app.hits.table = Some((table_area, off));
    let rows: Vec<Row> = st.containers[off..(off + h).min(n)]
        .iter()
        .map(|c| {
            let cpu_limit_pct = c.cpu_limit.map(|l| c.cpu_pct / (l * 100.0) * 100.0);
            let mem_pct = c.mem_pct();
            Row::new(vec![
                Cell::from(truncate(&c.name, 32)).style(Style::new().fg(theme::fg()).bold()),
                Cell::from(c.runtime).style(Style::new().fg(theme::dim())),
                num(format!("{:.1}", c.cpu_pct), Style::new().fg(theme::heat(cpu_limit_pct.unwrap_or(c.cpu_pct / 4.0)))),
                Cell::from(c.cpu_limit.map(|l| format!("{l:.1} cpu")).unwrap_or_else(|| "·".into())).style(Style::new().fg(theme::muted())),
                if c.throttled_pct > 0.0 {
                    num(format!("{:.0}%", c.throttled_pct), Style::new().fg(theme::heat(c.throttled_pct * 2.0)).bold())
                } else {
                    none()
                },
                num(fmt_bytes(c.mem), Style::new().fg(theme::purple())),
                match mem_pct {
                    Some(p) => num(format!("{p:.0}%"), Style::new().fg(theme::heat(p))),
                    None => none(),
                },
                if c.oom_kills > 0 {
                    num(c.oom_kills.to_string(), Style::new().fg(if c.new_ooms > 0 { theme::red() } else { theme::orange() }).bold())
                } else {
                    none()
                },
                num(fmt_rate(c.io_read_bps), Style::new().fg(theme::green())),
                num(fmt_rate(c.io_write_bps), Style::new().fg(theme::orange())),
                num(fmt_rate(c.net_rx_bps), Style::new().fg(theme::green())),
                num(fmt_rate(c.net_tx_bps), Style::new().fg(theme::orange())),
                num(c.pids.to_string(), Style::new().fg(theme::muted())),
            ])
        })
        .collect();
    let throttled = st.containers.iter().filter(|c| c.throttled_pct > 0.0).count();
    let mut title = vec![Span::styled(format!(" containers ({n}) "), Style::new().fg(theme::cyan()).bold())];
    if throttled > 0 {
        title.push(Span::styled(format!(" {throttled} throttled "), Style::new().fg(theme::header_bg()).bg(theme::orange())));
    }
    let t = Table::new(
        rows,
        [
            Constraint::Min(18),
            Constraint::Length(10),
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Length(5),
            Constraint::Length(4),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(5),
        ],
    )
    .column_spacing(2)
    .header(header(&["CONTAINER", "RUNTIME", "CPU%", "LIMIT", "THROTTLED", "MEM", "MEM%", "OOM", "IO R/s", "IO W/s", "NET ↓/s", "NET ↑/s", "PIDS"]))
    .block(frame().title(Line::from(title)))
    .row_highlight_style(sel_style())
    .highlight_symbol(theme::glyphs().select);
    f.render_stateful_widget(t, table_area, &mut local_state(&app.ctr_state, off));
    scrollbar(f, table_area, n, &app.ctr_state);

    if let Some(c) = app.ctr_state.selected().and_then(|i| st.containers.get(i)) {
        let mem_line = match (c.mem_max, c.mem_pct()) {
            (Some(m), Some(p)) => {
                let mut v = vec![Span::styled(" memory  ", Style::new().fg(theme::dim()))];
                v.extend(meter(p, 30));
                v.push(Span::styled(format!("  {} of {}", fmt_bytes(c.mem), fmt_bytes(m)), Style::new().fg(theme::fg())));
                Line::from(v)
            }
            _ => Line::styled(format!(" memory  {} (no limit)", fmt_bytes(c.mem)), Style::new().fg(theme::fg())),
        };
        let lines = vec![
            Line::from(vec![
                Span::styled(" id ", Style::new().fg(theme::dim())),
                Span::styled(c.id.clone(), Style::new().fg(theme::muted())),
            ]),
            Line::from(vec![
                Span::styled(" cgroup ", Style::new().fg(theme::dim())),
                Span::styled(c.path.clone(), Style::new().fg(theme::muted())),
            ]),
            mem_line,
        ];
        f.render_widget(Paragraph::new(lines).block(panel(c.name.clone(), theme::blue())), detail);
    }
}

// ─────────────────────────────── system ───────────────────────────────

pub fn system(f: &mut Frame, app: &mut App, area: Rect) {
    let [top, events] = Layout::vertical([Constraint::Percentage(58), Constraint::Min(6)]).areas(area);
    let [units_area, journal_area] = Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(top);

    // Keep the journal pane in sync with the selected unit.
    if !app.sys_events_focus {
        app.load_selected_journal(false);
    }

    let store = app.net.services.clone();
    let Ok(st) = store.lock() else { return };
    let n = st.units.len();
    let failed = st.units.iter().filter(|u| u.failed()).count();
    let (off, h) = window(&mut app.svc_state, n, units_area);
    if !app.sys_events_focus {
        app.hits.table = Some((units_area, off));
    }
    let rows: Vec<Row> = st.units[off.min(n)..(off + h).min(n)]
        .iter()
        .map(|u| {
            let col = if u.failed() {
                theme::red()
            } else if u.active == "active" {
                theme::green()
            } else if u.active == "activating" || u.active == "reloading" {
                theme::yellow()
            } else {
                theme::dim()
            };
            Row::new(vec![
                Cell::from(truncate(u.name.trim_end_matches(".service"), 64)).style(Style::new().fg(theme::fg()).bold()),
                Cell::from(format!("{}/{}", u.active, u.sub)).style(Style::new().fg(col)),
                if u.restarts > 0 {
                    num(u.restarts.to_string(), Style::new().fg(if u.restarts >= 5 { theme::red() } else { theme::orange() }).bold())
                } else {
                    none()
                },
                if u.main_pid > 0 { num(u.main_pid.to_string(), Style::new().fg(theme::muted())) } else { none() },
                match u.memory {
                    Some(m) => num(fmt_bytes(m), Style::new().fg(theme::purple())),
                    None => match u.exit_status {
                        Some(s) if s != 0 => num(format!("exit {s}"), Style::new().fg(theme::red())),
                        _ => none(),
                    },
                },
                Cell::from(truncate(&u.description, 40)).style(Style::new().fg(theme::dim())),
            ])
        })
        .collect();
    let mut title = vec![Span::styled(format!(" {} units ({n}) ", if st.manager.is_empty() { "service" } else { st.manager }), Style::new().fg(theme::green()).bold())];
    if failed > 0 {
        title.push(Span::styled(format!(" {failed} failed "), Style::new().fg(theme::header_bg()).bg(theme::red())));
    }
    if !app.sys_events_focus {
        title.push(Span::styled(" ◀ ", Style::new().fg(theme::blue())));
    }
    let mut block = frame().title(Line::from(title));
    if let Some(e) = &st.error {
        block = block.title_bottom(Line::styled(format!(" {e} "), Style::new().fg(theme::orange())));
    }
    let t = Table::new(
        rows,
        [Constraint::Percentage(45), Constraint::Length(16), Constraint::Length(8), Constraint::Length(7), Constraint::Length(9), Constraint::Min(0)],
    )
    .column_spacing(2)
    .header(header(&["UNIT", "STATE", "RESTARTS", "PID", "MEMORY", "DESCRIPTION"]))
    .block(block)
    .row_highlight_style(sel_style())
    .highlight_symbol(theme::glyphs().select);
    f.render_stateful_widget(t, units_area, &mut local_state(&app.svc_state, off));
    scrollbar(f, units_area, n, &app.svc_state);

    // Journal of the selected unit (newest at the bottom).
    let jt = st.journal_unit.clone().unwrap_or_else(|| "journal".into());
    let inner_h = journal_area.height.saturating_sub(2) as usize;
    let lines: Vec<Line> = if st.journal_loading {
        vec![Line::styled(" loading…", Style::new().fg(theme::dim()))]
    } else {
        let skip = st.journal.len().saturating_sub(inner_h);
        st.journal
            .iter()
            .skip(skip)
            .map(|l| {
                let low = l.to_ascii_lowercase();
                let col = if low.contains("error") || low.contains("fail") || low.contains("fatal") || low.contains("panic") {
                    theme::red()
                } else if low.contains("warn") {
                    theme::yellow()
                } else {
                    theme::fg()
                };
                // Dim the timestamp + host part of `short-iso` lines.
                match l.split_once(": ") {
                    Some((head, msg)) if head.len() < 80 => Line::from(vec![
                        Span::styled(format!("{head}: "), Style::new().fg(theme::dim())),
                        Span::styled(msg.to_string(), Style::new().fg(col)),
                    ]),
                    _ => Line::styled(l.clone(), Style::new().fg(col)),
                }
            })
            .collect()
    };
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(panel(format!("{} · {jt}", if cfg!(windows) { "SCM events" } else { "journal" }), theme::purple())),
        journal_area,
    );
    drop(st);

    // Kernel events (newest first).
    let k = app.net.kmsg.clone();
    let Ok(ks) = k.lock() else { return };
    let ev: Vec<_> = ks.events.iter().rev().collect();
    let n = ev.len();
    let (off, h) = window(&mut app.ev_state, n, events);
    if app.sys_events_focus {
        app.hits.table = Some((events, off));
    }
    let rows: Vec<Row> = ev[off.min(n)..(off + h).min(n)]
        .iter()
        .map(|e| {
            let col = match e.kind {
                "OOM" | "HUNG" | "HW" | "FS" | "IO" | "CONNTRACK" | "POWER" | "CRASH" => theme::red(),
                "LINK" | "NIC" | "SYNFLOOD" | "SEGV" => theme::orange(),
                _ if e.level <= 3 => theme::red(),
                _ => theme::yellow(),
            };
            Row::new(vec![
                num(ago(e.at), Style::new().fg(theme::dim())),
                Cell::from(e.kind).style(Style::new().fg(col).bold()),
                Cell::from(e.text.clone()).style(Style::new().fg(theme::fg())),
            ])
        })
        .collect();
    let what = if cfg!(windows) { "event log" } else { "kernel events" };
    let mut title = vec![Span::styled(format!(" {what} ({n}) "), Style::new().fg(theme::red()).bold())];
    if app.sys_events_focus {
        title.push(Span::styled(" ◀ ", Style::new().fg(theme::blue())));
    }
    let mut block = frame().title(Line::from(title)).title(
        Line::styled(
            if cfg!(windows) { " POWER · CRASH · LINK · IO · FS · HW · OOM " } else { " OOM · LINK · NIC · SEGV · IO · FS · SYNFLOOD · HUNG " },
            Style::new().fg(theme::dim()),
        )
        .right_aligned(),
    );
    if let Some(e) = &ks.error {
        block = block.title_bottom(Line::styled(format!(" {e} "), Style::new().fg(theme::orange())));
    }
    if n == 0 {
        let msg = if ks.error.is_some() { "" } else if cfg!(windows) { " no warnings or errors in the recent System log" } else { " no notable kernel events since boot" };
        f.render_widget(Paragraph::new(Line::styled(msg, Style::new().fg(theme::dim()))).block(block), events);
        return;
    }
    let t = Table::new(rows, [Constraint::Length(9), Constraint::Length(10), Constraint::Min(20)])
        .column_spacing(2)
        .header(header(&["WHEN", "KIND", "MESSAGE"]))
        .block(block)
        .row_highlight_style(sel_style())
        .highlight_symbol(theme::glyphs().select);
    f.render_stateful_widget(t, events, &mut local_state(&app.ev_state, off));
}

// ─────────────────────────────── users ───────────────────────────────

pub fn users(f: &mut Frame, app: &mut App, area: Rect) {
    let store = app.net.sessions.clone();
    let Ok(st) = store.lock() else { return };
    let sh = (st.sessions.len() as u16 + 3).min((area.height / 2).max(5));
    let [top, bottom] = Layout::vertical([Constraint::Length(sh), Constraint::Min(6)]).areas(area);
    let [failed_area, acc_area] = Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(bottom);

    let n = st.sessions.len();
    let (off, h) = window(&mut app.users_state, n, top);
    app.hits.table = Some((top, off));
    let rows: Vec<Row> = st.sessions[off.min(n)..(off + h).min(n)]
        .iter()
        .map(|s| {
            let scope = s.from.parse().map(|ip| crate::collect::ipinfo::scope(&ip)).unwrap_or("");
            Row::new(vec![
                Cell::from(s.user.clone()).style(Style::new().fg(if s.user == "root" { theme::red() } else { theme::teal() }).bold()),
                Cell::from(s.tty.clone()).style(Style::new().fg(theme::muted())),
                Cell::from(if s.from.is_empty() { "local".into() } else { s.from.clone() })
                    .style(Style::new().fg(if scope == "public" { theme::orange() } else { theme::fg() })),
                Cell::from(scope).style(Style::new().fg(theme::dim())),
                Cell::from(s.login.clone()).style(Style::new().fg(theme::muted())),
                if s.idle.is_empty() { none() } else { num(s.idle.clone(), Style::new().fg(theme::dim())) },
                Cell::from(s.what.clone()).style(Style::new().fg(theme::fg())),
            ])
        })
        .collect();
    let t = Table::new(
        rows,
        [Constraint::Length(12), Constraint::Length(9), Constraint::Length(18), Constraint::Length(9), Constraint::Length(7), Constraint::Length(7), Constraint::Min(10)],
    )
    .column_spacing(2)
    .header(header(&["USER", "TTY", "FROM", "SCOPE", "LOGIN", "IDLE", "RUNNING"]))
    .block(panel(format!("logged in ({n})"), theme::teal()))
    .row_highlight_style(sel_style())
    .highlight_symbol(theme::glyphs().select);
    f.render_stateful_widget(t, top, &mut local_state(&app.users_state, off));

    // Failed SSH logins in the last hour, by source address.
    let rows: Vec<Row> = st
        .failed
        .iter()
        .take(failed_area.height.saturating_sub(3) as usize)
        .map(|fs| {
            let scope = fs.ip.parse().map(|ip| crate::collect::ipinfo::scope(&ip)).unwrap_or("");
            Row::new(vec![
                Cell::from(fs.ip.clone()).style(Style::new().fg(theme::fg()).bold()),
                Cell::from(scope).style(Style::new().fg(theme::dim())),
                num(fs.attempts.to_string(), Style::new().fg(theme::heat((fs.attempts as f64).min(100.0))).bold()),
                Cell::from(fs.users.join(", ")).style(Style::new().fg(theme::muted())),
            ])
        })
        .collect();
    let title = format!("failed ssh logins · last hour ({} from {} addresses)", st.failed_total, st.failed.len());
    let mut block = panel(title, theme::red());
    if let Some(note) = &st.ssh_note {
        block = block.title_bottom(Line::styled(format!(" {note} "), Style::new().fg(theme::dim())));
    }
    if st.failed.is_empty() {
        let msg = if st.ssh_note.is_some() { "" } else { " none" };
        f.render_widget(Paragraph::new(Line::styled(msg, Style::new().fg(theme::green()))).block(block), failed_area);
    } else {
        f.render_widget(
            Table::new(rows, [Constraint::Length(18), Constraint::Length(9), Constraint::Length(8), Constraint::Min(10)])
                .column_spacing(2)
                .header(header(&["SOURCE", "SCOPE", "ATTEMPTS", "USERS TRIED"]))
                .block(block),
            failed_area,
        );
    }

    let rows: Vec<Row> = st
        .accepted
        .iter()
        .take(acc_area.height.saturating_sub(3) as usize)
        .map(|a| {
            Row::new(vec![
                Cell::from(a.user.clone()).style(Style::new().fg(if a.user == "root" { theme::red() } else { theme::teal() })),
                Cell::from(a.ip.clone()).style(Style::new().fg(theme::fg())),
                Cell::from(a.method.clone()).style(Style::new().fg(if a.method == "password" { theme::yellow() } else { theme::green() })),
            ])
        })
        .collect();
    f.render_widget(
        Table::new(rows, [Constraint::Length(12), Constraint::Min(14), Constraint::Length(10)])
            .column_spacing(2)
            .header(header(&["USER", "FROM", "METHOD"]))
            .block(panel("accepted ssh logins · last hour", theme::green())),
        acc_area,
    );
}
