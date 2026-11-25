use std::collections::BTreeMap;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};
use ratatui::Frame;

use super::widgets::{kv, meter, meter_solid, panel, AreaGraph, GraphColor};
use crate::app::App;
use crate::theme;
use crate::util::{fmt_bytes, fmt_rate, spark, truncate};

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let [cpu, mid, bottom] = Layout::vertical([
        Constraint::Percentage(38),
        Constraint::Percentage(30),
        Constraint::Min(8),
    ])
    .areas(area);
    draw_cpu(f, app, cpu);

    let [mem, net] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(mid);
    draw_mem(f, app, mem);
    draw_net(f, app, net);

    let [procs, listen, side] = Layout::horizontal([
        Constraint::Percentage(42),
        Constraint::Percentage(33),
        Constraint::Percentage(25),
    ])
    .areas(bottom);
    draw_top_procs(f, app, procs);
    draw_listening(f, app, listen);
    draw_side(f, app, side);
}

fn draw_cpu(f: &mut Frame, app: &App, area: Rect) {
    let s = &app.sampler;
    let total = s.cpu_total.last();
    let mut title = format!("cpu  {}  {}c/{}t", s.host.cpu_brand, s.host.physical_cores, s.ncores());
    if let Some(t) = s.temps.iter().find(|t| {
        let l = t.label.to_lowercase();
        l.contains("cpu") || l.contains("package") || l.contains("tdie") || l.contains("tctl")
    }) {
        title.push_str(&format!("  {:.0}°C", t.temp));
    }
    let mut block = panel(title, theme::blue());
    if s.cpu_freq > 0 {
        block = block.title_bottom(
            Line::from(vec![
                Span::styled(" freq ", Style::new().fg(theme::dim())),
                Span::styled(format!("{:.2} GHz ", s.cpu_freq as f64 / 1000.0), Style::new().fg(theme::cyan())),
            ])
            .right_aligned(),
        );
    }
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Per-core column layout: as many columns as needed to fit all cores.
    let n = s.ncores();
    let rows = inner.height.max(1) as usize;
    let cols = n.div_ceil(rows).max(1);
    let col_w = 30usize;
    let cores_w = (cols * col_w) as u16;
    let cores_w = cores_w.min(inner.width / 2);
    let [graph_area, cores_area] =
        Layout::horizontal([Constraint::Min(20), Constraint::Length(cores_w)]).areas(inner);

    let [label, graph] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(graph_area);
    let l = Line::from(vec![
        Span::styled(" total ", Style::new().fg(theme::dim())),
        Span::styled(format!("{total:5.1}%"), Style::new().fg(theme::heat(total)).bold()),
        Span::raw("  "),
    ]);
    let mut l = l;
    l.spans.extend(meter(total, (graph_area.width as usize).saturating_sub(18).min(40)));
    f.render_widget(Paragraph::new(l), label);
    let data = s.cpu_total.tail(graph.width as usize);
    f.render_widget(
        AreaGraph { data: &data, max: 100.0, color: GraphColor::Heat, inverted: false },
        graph,
    );

    // Per-core meters.
    let col_w = (cores_area.width as usize / cols).max(1);
    let col_areas = Layout::horizontal(vec![Constraint::Length(col_w as u16); cols]).split(cores_area);
    for (c, ca) in col_areas.iter().enumerate() {
        let mut lines = Vec::new();
        for (i, h) in s.cpu_cores.iter().enumerate().skip(c * rows).take(rows) {
            let v = h.last();
            let spark_w = col_w.saturating_sub(20).min(10);
            let bar_w = col_w.saturating_sub(13 + spark_w).max(3);
            let mut spans = vec![Span::styled(format!(" C{i:<3}"), Style::new().fg(theme::muted()))];
            spans.extend(meter(v, bar_w));
            spans.push(Span::styled(format!("{v:4.0}% "), Style::new().fg(theme::heat(v))));
            spans.push(Span::styled(spark(&h.tail(spark_w), 100.0), Style::new().fg(theme::heat(v))));
            lines.push(Line::from(spans));
        }
        f.render_widget(Paragraph::new(lines), *ca);
    }
}

fn draw_mem(f: &mut Frame, app: &App, area: Rect) {
    let s = &app.sampler;
    let block = panel("memory", theme::purple());
    let inner = block.inner(area);
    f.render_widget(block, area);
    let mem_pct = s.mem_hist.last();
    let swap_pct = s.swap_hist.last();
    let bw = (inner.width as usize).saturating_sub(26).max(5);

    let line = |name: &str, used: u64, total: u64, pct: f64| {
        let mut sp = vec![Span::styled(format!(" {name:<5}"), Style::new().fg(theme::muted()))];
        sp.extend(meter(pct, bw));
        sp.push(Span::styled(format!(" {pct:3.0}% "), Style::new().fg(theme::heat(pct)).bold()));
        sp.push(Span::styled(
            format!("{}/{}", fmt_bytes(used), fmt_bytes(total)),
            Style::new().fg(theme::fg()),
        ));
        Line::from(sp)
    };
    let [text, graph] = Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).areas(inner);
    let lines = vec![
        line("ram", s.mem_used, s.mem_total, mem_pct),
        line("swap", s.swap_used, s.swap_total, swap_pct),
        Line::from(
            [vec![Span::raw(" ")], kv("available", fmt_bytes(s.mem_avail), theme::green())].concat(),
        ),
    ];
    f.render_widget(Paragraph::new(lines), text);
    let data = s.mem_hist.tail(graph.width as usize);
    f.render_widget(
        AreaGraph {
            data: &data,
            max: 100.0,
            color: GraphColor::Gradient(theme::purple(), theme::pink()),
            inverted: false,
        },
        graph,
    );
}

fn draw_net(f: &mut Frame, app: &App, area: Rect) {
    let s = &app.sampler;
    let w = area.width.saturating_sub(2) as usize;
    let rx = s.rx_hist.tail(w);
    let tx = s.tx_hist.tail(w);
    let max = rx.iter().chain(tx.iter()).copied().fold(1024.0, f64::max) * 1.1;
    let block = panel("network", theme::cyan()).title(
        Line::from(vec![
            Span::styled("scale ", Style::new().fg(theme::dim())),
            Span::styled(format!("{} ", fmt_rate(max)), Style::new().fg(theme::muted())),
        ])
        .right_aligned(),
    );
    let inner = block.inner(area);
    f.render_widget(block, area);
    let [lbl, down, up] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Percentage(50),
        Constraint::Percentage(50),
    ])
    .areas(inner);
    let l = Line::from(vec![
        Span::styled(" ▼ rx ", Style::new().fg(theme::green()).bold()),
        Span::styled(format!("{:<12}", fmt_rate(s.rx_rate)), Style::new().fg(theme::fg())),
        Span::styled(" ▲ tx ", Style::new().fg(theme::orange()).bold()),
        Span::styled(format!("{:<12}", fmt_rate(s.tx_rate)), Style::new().fg(theme::fg())),
        Span::styled(" peak ", Style::new().fg(theme::dim())),
        Span::styled(
            format!("{} / {}", fmt_rate(s.rx_hist.max()), fmt_rate(s.tx_hist.max())),
            Style::new().fg(theme::muted()),
        ),
    ]);
    f.render_widget(Paragraph::new(l), lbl);
    f.render_widget(
        AreaGraph { data: &rx, max, color: GraphColor::Gradient(theme::teal(), theme::green()), inverted: false },
        down,
    );
    f.render_widget(
        AreaGraph { data: &tx, max, color: GraphColor::Gradient(theme::yellow(), theme::orange()), inverted: true },
        up,
    );
}

fn draw_top_procs(f: &mut Frame, app: &App, area: Rect) {
    let s = &app.sampler;
    // Partial selection: O(n) to find the top-N, then sort only those.
    let n = area.height.saturating_sub(3) as usize;
    let mut procs: Vec<_> = s.procs.iter().collect();
    let by_cpu = |a: &&crate::collect::system::ProcInfo, b: &&crate::collect::system::ProcInfo| b.cpu.total_cmp(&a.cpu);
    if n > 0 && procs.len() > n {
        procs.select_nth_unstable_by(n - 1, by_cpu);
        procs.truncate(n);
    }
    procs.sort_by(by_cpu);
    let ncores = s.ncores().max(1) as f64;
    let rows: Vec<Row> = procs
        .iter()
        .take(n)
        .map(|p| {
            let norm = p.cpu as f64 / ncores;
            Row::new(vec![
                Cell::from(p.pid.to_string()).style(Style::new().fg(theme::dim())),
                Cell::from(truncate(&p.name, 32)).style(Style::new().fg(theme::fg())),
                Cell::from(truncate(&p.user, 10)).style(Style::new().fg(theme::muted())),
                Cell::from(Line::from(meter(norm.max(p.cpu as f64 / 4.0), 5))),
                Cell::from(format!("{:5.1}", p.cpu)).style(Style::new().fg(theme::heat(p.cpu as f64))),
                Cell::from(fmt_bytes(p.mem)).style(Style::new().fg(theme::purple())),
            ])
        })
        .collect();
    let t = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Min(10),
            Constraint::Length(10),
            Constraint::Length(5),
            Constraint::Length(6),
            Constraint::Length(7),
        ],
    )
    .header(
        Row::new(["PID", "NAME", "USER", "", "CPU%", "MEM"])
            .style(Style::new().fg(theme::blue()).bold()),
    )
    .block(panel("top processes", theme::green()));
    f.render_widget(t, area);
}

fn draw_listening(f: &mut Frame, app: &App, area: Rect) {
    let store = app.sockets.lock();
    let mut ports: BTreeMap<(u16, String), (String, u32)> = BTreeMap::new();
    let mut err = None;
    if let Ok(st) = &store {
        err = st.error.clone();
        for e in st.entries.iter().filter(|e| e.is_listening()) {
            if let Some(p) = e.local_port() {
                ports.entry((p, e.proto.clone())).or_insert((e.command.clone(), e.pid));
            }
        }
    }
    drop(store);
    let title = format!("listening ports ({})", ports.len());
    let block = panel(title, theme::green()).title_bottom(
        Line::styled(" lsof -i ", Style::new().fg(theme::dim())).right_aligned(),
    );
    if let Some(e) = err {
        f.render_widget(Paragraph::new(Line::styled(format!(" {e}"), Style::new().fg(theme::red()))).block(block), area);
        return;
    }
    let rows: Vec<Row> = ports
        .iter()
        .map(|((port, proto), (cmd, pid))| {
            Row::new(vec![
                Cell::from(port.to_string()).style(Style::new().fg(theme::green()).bold()),
                Cell::from(proto.clone()).style(Style::new().fg(theme::cyan())),
                Cell::from(truncate(cmd, 18)).style(Style::new().fg(theme::fg())),
                Cell::from(pid.to_string()).style(Style::new().fg(theme::dim())),
            ])
        })
        .collect();
    let t = Table::new(
        rows,
        [Constraint::Length(6), Constraint::Length(5), Constraint::Min(8), Constraint::Length(7)],
    )
    .header(Row::new(["PORT", "PROTO", "PROCESS", "PID"]).style(Style::new().fg(theme::blue()).bold()))
    .block(block);
    f.render_widget(t, area);
}

fn draw_side(f: &mut Frame, app: &App, area: Rect) {
    let s = &app.sampler;
    let [conns, disks] = Layout::vertical([Constraint::Length(8), Constraint::Min(3)]).areas(area);

    // Connection state summary.
    let mut states: BTreeMap<String, usize> = BTreeMap::new();
    if let Ok(st) = app.sockets.lock() {
        for e in &st.entries {
            let k = if e.state.is_empty() { e.proto.clone() } else { e.state.clone() };
            *states.entry(k).or_default() += 1;
        }
    }
    let mut v: Vec<_> = states.into_iter().collect();
    v.sort_by_key(|e| std::cmp::Reverse(e.1));
    let lines: Vec<Line> = v
        .iter()
        .take(6)
        .map(|(k, n)| {
            Line::from(vec![
                Span::styled(format!(" {k:<12}"), Style::new().fg(theme::tcp_state(k))),
                Span::styled(format!("{n:>5}"), Style::new().fg(theme::fg()).bold()),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(lines).block(panel("connections", theme::cyan())), conns);

    // Disks.
    let block = panel("disks", theme::yellow());
    let inner = block.inner(disks);
    f.render_widget(block, disks);
    let bw = (inner.width as usize).saturating_sub(14).max(3);
    let mut lines = Vec::new();
    for d in s.disks_info.iter().filter(|d| d.total > 0) {
        lines.push(Line::from(vec![
            Span::styled(format!(" {}", truncate(&d.mount, (inner.width as usize).saturating_sub(8))), Style::new().fg(theme::fg())),
            Span::styled(format!(" {}", fmt_bytes(d.total)), Style::new().fg(theme::dim())),
        ]));
        let mut sp = vec![Span::raw(" ")];
        sp.extend(meter_solid(d.pct(), bw, theme::heat(d.pct())));
        sp.push(Span::styled(format!(" {:3.0}%", d.pct()), Style::new().fg(theme::heat(d.pct()))));
        lines.push(Line::from(sp));
    }
    f.render_widget(Paragraph::new(lines), inner);
}
