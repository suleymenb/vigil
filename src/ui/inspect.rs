//! Process inspector: everything about one process on one screen.

use std::collections::BTreeMap;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use super::views::{header, none, num};
use super::widgets::{kv, panel, AreaGraph, GraphColor};
use crate::app::App;
use crate::collect::system::is_secret_env;
use crate::theme;
use crate::util::{fmt_bytes, fmt_duration, fmt_rate, truncate, truncate_left};

/// Describe a trend over the history window: "+38 % in 2 min".
fn trend(first: f32, last: f32, samples: usize, secs_per_sample: usize) -> Option<(String, bool)> {
    if samples < 10 || first <= 0.0 {
        return None;
    }
    let pct = (last - first) / first * 100.0;
    if pct.abs() < 5.0 {
        return None;
    }
    let mins = (samples * secs_per_sample).div_ceil(60);
    Some((format!("{}{:.0} % in {} min", if pct > 0.0 { "+" } else { "" }, pct, mins), pct > 20.0))
}

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let Some(pid) = app.inspect else { return };
    let Some(p) = app.sampler.procs.iter().find(|p| p.pid == pid).cloned() else {
        f.render_widget(
            Paragraph::new(Line::styled(format!(" process {pid} has exited · Esc to close"), Style::new().fg(theme::yellow())))
                .block(panel("inspector", theme::blue())),
            area,
        );
        return;
    };
    let deep = app.inspect_info.clone().unwrap_or_default();
    let [left, right] = Layout::horizontal([Constraint::Percentage(48), Constraint::Percentage(52)]).areas(area);

    // ── Left: identity + resources with history
    let [ident, res] = Layout::vertical([Constraint::Length(15), Constraint::Min(8)]).areas(left);
    let procs = &app.sampler.procs;
    let mut chain = Vec::new();
    let mut cur = p.ppid;
    while let Some(pp) = cur {
        match procs.iter().find(|x| x.pid == pp) {
            Some(x) if chain.len() < 6 => {
                chain.push(format!("{} ({})", x.name, x.pid));
                cur = x.ppid;
            }
            _ => break,
        }
    }
    let children: Vec<String> = procs.iter().filter(|x| x.ppid == Some(pid)).map(|x| x.name.to_string()).collect();
    let mut kids: BTreeMap<String, usize> = BTreeMap::new();
    for c in &children {
        *kids.entry(c.clone()).or_default() += 1;
    }
    let kid_text = kids.iter().map(|(n, c)| if *c > 1 { format!("{n} ×{c}") } else { n.clone() }).collect::<Vec<_>>().join(", ");
    let label = |k: &str| Span::styled(format!(" {k:<10}"), Style::new().fg(theme::dim()));
    let vw = ident.width.saturating_sub(14) as usize;
    let mut lines = vec![
        Line::from([vec![label("pid")], kv("", p.pid.to_string(), theme::fg()), kv("user", p.user.to_string(), theme::teal()), kv("status", p.status, theme::green())].concat()),
        Line::from([vec![label("uptime")], kv("", fmt_duration(p.run_time), theme::fg()), kv("threads", deep.threads.map(|t| t.to_string()).unwrap_or_else(|| "·".into()), theme::fg())].concat()),
        Line::from(vec![label("exe"), Span::styled(truncate_left(&p.exe, vw), Style::new().fg(theme::fg()))]),
        Line::from(vec![label("cwd"), Span::styled(truncate_left(&deep.cwd, vw), Style::new().fg(theme::fg()))]),
        Line::from(vec![
            label("root"),
            Span::styled(
                if deep.root.is_empty() || deep.root == "/" { "/".to_string() } else { format!("{} (chroot / container)", deep.root) },
                Style::new().fg(if deep.root.is_empty() || deep.root == "/" { theme::dim() } else { theme::purple() }),
            ),
        ]),
        Line::from(vec![label("command"), Span::styled(truncate(&p.cmd, vw), Style::new().fg(theme::cyan()))]),
        Line::from(vec![label("parents"), Span::styled(if chain.is_empty() { "·".into() } else { truncate(&chain.join(" ← "), vw) }, Style::new().fg(theme::muted()))]),
        Line::from(vec![label("children"), Span::styled(if children.is_empty() { "·".into() } else { truncate(&format!("{}: {kid_text}", children.len()), vw) }, Style::new().fg(theme::muted()))]),
    ];
    if let Some(u) = &deep.unit {
        lines.push(Line::from(vec![label("unit"), Span::styled(u.clone(), Style::new().fg(theme::green()).bold())]));
    }
    if let Some(c) = &deep.container {
        let name = app
            .net
            .containers
            .try_lock()
            .ok()
            .and_then(|s| s.containers.iter().find(|x| c.ends_with(&x.id[..12.min(x.id.len())])).map(|x| x.name.clone()));
        lines.push(Line::from(vec![label("container"), Span::styled(name.unwrap_or_else(|| c.clone()), Style::new().fg(theme::purple()).bold())]));
    }
    if !deep.cgroup.is_empty() {
        lines.push(Line::from(vec![label("cgroup"), Span::styled(truncate_left(&deep.cgroup, vw), Style::new().fg(theme::dim()))]));
    }
    if let Some((_, why)) = app.net.limits.try_lock().ok().and_then(|l| l.needs_restart.iter().find(|(x, _)| *x == pid).cloned()) {
        lines.push(Line::from(vec![label("restart"), Span::styled(format!("needed: {why}"), Style::new().fg(theme::orange()).bold())]));
    }
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(panel(format!("{}  ({})", p.name, p.pid), theme::blue())),
        ident,
    );

    // Resources: three small history graphs (cpu, memory, fds) + current I/O.
    let block = panel("resources · last 2 min", theme::green());
    let inner = block.inner(res);
    f.render_widget(block, res);
    let [g_cpu, g_mem, g_fd, io] =
        Layout::vertical([Constraint::Ratio(1, 3), Constraint::Ratio(1, 3), Constraint::Ratio(1, 3), Constraint::Length(2)]).areas(inner);
    let (cpu_h, mem_h) = app.sampler.proc_hist.get(&pid).cloned().unwrap_or_default();
    let fd_h = app.net.limits.try_lock().ok().and_then(|l| l.fd_hist.get(&pid).cloned()).unwrap_or_default();
    let fd_now = app.fd_info(pid);
    let ncores = app.sampler.ncores().max(1) as f64;
    let graph = |f: &mut Frame, a: Rect, title: Line, data: Vec<f64>, max: f64, c1, c2| {
        let [t, g] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(a);
        f.render_widget(Paragraph::new(title), t);
        f.render_widget(AreaGraph { data: &data, max, color: GraphColor::Gradient(c1, c2), inverted: false }, g);
    };
    let w = inner.width as usize;
    let trend_span = |first: f32, last: f32, n: usize, secs: usize| match trend(first, last, n, secs) {
        Some((t, warn)) => Span::styled(format!("  {t}"), Style::new().fg(if warn { theme::orange() } else { theme::muted() }).bold()),
        None => Span::raw(""),
    };
    graph(
        f,
        g_cpu,
        Line::from(vec![
            Span::styled(" cpu  ", Style::new().fg(theme::dim())),
            Span::styled(format!("{:.1} %", p.cpu), Style::new().fg(theme::heat(p.cpu as f64 / ncores.min(4.0))).bold()),
        ]),
        cpu_h.tail(w),
        (cpu_h.max() as f64).max(10.0) * 1.1,
        theme::green(),
        theme::yellow(),
    );
    let mt = trend_span(mem_h.first(), mem_h.last(), mem_h.len(), 1);
    graph(
        f,
        g_mem,
        Line::from(vec![
            Span::styled(" memory  ", Style::new().fg(theme::dim())),
            Span::styled(fmt_bytes(p.mem), Style::new().fg(theme::purple()).bold()),
            Span::styled(format!("  virt {}", fmt_bytes(p.virt)), Style::new().fg(theme::dim())),
            mt,
        ]),
        mem_h.tail(w),
        (mem_h.max() as f64).max(1.0) * 1.1,
        theme::purple(),
        theme::pink(),
    );
    let ft = trend_span(fd_h.first(), fd_h.last(), fd_h.len(), 5);
    graph(
        f,
        g_fd,
        Line::from(vec![
            Span::styled(" open fds  ", Style::new().fg(theme::dim())),
            Span::styled(
                match fd_now {
                    Some((n, Some(l))) => format!("{n} / {l} ({:.0} %)", n as f64 / l.max(1) as f64 * 100.0),
                    Some((n, None)) => n.to_string(),
                    None => "·".into(),
                },
                Style::new().fg(theme::cyan()).bold(),
            ),
            ft,
        ]),
        fd_h.tail(w),
        (fd_h.max() as f64).max(1.0) * 1.1,
        theme::teal(),
        theme::cyan(),
    );
    let net = app.proc_net.get(&pid).copied().unwrap_or((0.0, 0.0));
    f.render_widget(
        Paragraph::new(Line::from(
            [
                vec![Span::raw(" ")],
                kv("disk r/w", format!("{} / {}", fmt_rate(p.read_rate), fmt_rate(p.write_rate)), theme::yellow()),
                kv("net ↓/↑", format!("{} / {}", fmt_rate(net.1), fmt_rate(net.0)), theme::teal()),
            ]
            .concat(),
        )),
        io,
    );

    // ── Right: sockets, open files, journal or environment
    let [socks, files, bottom] = Layout::vertical([Constraint::Percentage(34), Constraint::Percentage(30), Constraint::Min(6)]).areas(right);
    let snap = app.socket_snapshot().unwrap_or_default();
    let mine: Vec<_> = snap.iter().filter(|e| e.pid == pid).collect();
    let rows: Vec<Row> = mine
        .iter()
        .take(socks.height.saturating_sub(3) as usize)
        .map(|e| {
            let (l, r) = e.endpoints();
            let t = e.net.as_ref().and_then(|n| n.tcp);
            Row::new(vec![
                Cell::from(e.proto.clone()).style(Style::new().fg(theme::cyan())),
                Cell::from(l.to_string()).style(Style::new().fg(if e.is_listening() { theme::green() } else { theme::fg() })),
                Cell::from(if r.is_empty() { "·".into() } else { r.to_string() }).style(Style::new().fg(theme::teal())),
                Cell::from(e.state.clone()).style(Style::new().fg(theme::tcp_state(&e.state))),
                match t.filter(|t| t.rtt_us > 0) {
                    Some(t) => num(format!("{:.1}", t.rtt_us as f64 / 1000.0), Style::new().fg(theme::green())),
                    None => none(),
                },
            ])
        })
        .collect();
    f.render_widget(
        Table::new(rows, [Constraint::Length(4), Constraint::Percentage(36), Constraint::Percentage(36), Constraint::Length(11), Constraint::Length(7)])
            .column_spacing(1)
            .header(header(&["", "LOCAL", "REMOTE", "STATE", "RTT ms"]))
            .block(panel(format!("sockets ({})", mine.len()), theme::cyan())),
        socks,
    );

    let (fl, loading) = app.inspect_files.try_lock().map(|s| (s.entries.clone(), s.loading)).unwrap_or_default();
    let mut types: BTreeMap<&str, usize> = BTreeMap::new();
    for e in fl.iter() {
        *types.entry(e.ftype.as_str()).or_default() += 1;
    }
    let mut lines = vec![Line::from(
        types
            .iter()
            .flat_map(|(t, n)| {
                vec![
                    Span::styled(format!(" {t} "), Style::new().fg(theme::file_type(t)).bold()),
                    Span::styled(n.to_string(), Style::new().fg(theme::fg())),
                ]
            })
            .collect::<Vec<_>>(),
    )];
    for e in fl.iter().filter(|e| e.ftype == "REG" || e.ftype == "DIR").take(files.height.saturating_sub(3) as usize) {
        lines.push(Line::from(vec![
            Span::styled(format!(" {:>5} ", e.fd_display()), Style::new().fg(theme::yellow())),
            Span::styled(truncate(&e.name, files.width.saturating_sub(10) as usize), Style::new().fg(theme::file_type(&e.ftype))),
        ]));
    }
    if loading {
        lines = vec![Line::styled(" running lsof…", Style::new().fg(theme::dim()))];
    }
    f.render_widget(Paragraph::new(lines).block(panel(format!("open files ({}) · f for all", fl.len()), theme::purple())), files);

    if app.inspect_env {
        let lines: Vec<Line> = deep
            .environ
            .iter()
            .map(|(k, v)| {
                let shown = if is_secret_env(k) { "•••••• (hidden)".to_string() } else { v.clone() };
                Line::from(vec![
                    Span::styled(format!(" {k}="), Style::new().fg(theme::blue())),
                    Span::styled(shown, Style::new().fg(if is_secret_env(k) { theme::dim() } else { theme::fg() })),
                ])
            })
            .collect();
        let title = if deep.environ.is_empty() { "environment (not readable: run as root)".to_string() } else { format!("environment ({}) · v journal", deep.environ.len()) };
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(panel(title, theme::yellow())), bottom);
    } else {
        let (unit, journal) = app
            .net
            .services
            .try_lock()
            .map(|s| (s.journal_unit.clone(), s.journal.clone()))
            .unwrap_or_default();
        let lines: Vec<Line> = match (&deep.unit, unit.as_ref() == deep.unit.as_ref()) {
            (Some(_), true) => {
                let h = bottom.height.saturating_sub(2) as usize;
                journal.iter().skip(journal.len().saturating_sub(h)).map(|l| Line::styled(format!(" {l}"), Style::new().fg(theme::fg()))).collect()
            }
            (Some(_), false) => vec![Line::styled(" loading journal…", Style::new().fg(theme::dim()))],
            (None, _) => vec![Line::styled(" not a systemd service · v shows the environment", Style::new().fg(theme::dim()))],
        };
        f.render_widget(
            Paragraph::new(lines).wrap(Wrap { trim: false }).block(panel(format!("journal · {} · v environment", deep.unit.clone().unwrap_or_else(|| "-".into())), theme::yellow())),
            bottom,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::trend;

    #[test]
    fn trends() {
        assert_eq!(trend(100.0, 150.0, 120, 1), Some(("+50 % in 2 min".into(), true)));
        assert_eq!(trend(100.0, 102.0, 120, 1), None);
        assert_eq!(trend(100.0, 150.0, 3, 1), None);
    }
}
