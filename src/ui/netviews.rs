//! Network-engineering views: Routes (routes, neighbours, DNS), Probes
//! (latency monitor) and Firewall (rule hit counters).

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use super::views::{filter_title, header, local_state, none, num, scrollbar, sel_style, window};
use super::widgets::{frame, panel, AreaGraph, GraphColor};
use crate::app::App;
use crate::collect::ipinfo;
use crate::theme;
use crate::util::{fmt_bytes, fmt_rate, spark, truncate};

fn neigh_color(state: &str) -> ratatui::style::Color {
    if state.contains("FAILED") || state.contains("INCOMPLETE") {
        theme::red()
    } else if state.contains("REACHABLE") || state.contains("PERMANENT") || state.contains("NOARP") {
        theme::green()
    } else if state.contains("DELAY") || state.contains("PROBE") {
        theme::yellow()
    } else {
        theme::dim() // STALE, NONE
    }
}

fn scope_color(scope: &str) -> ratatui::style::Color {
    match scope {
        "public" => theme::teal(),
        "private" => theme::fg(),
        "cgnat" => theme::purple(),
        "loopback" | "link-local" | "any" => theme::dim(),
        "multicast" | "broadcast" => theme::yellow(),
        _ => theme::muted(),
    }
}

// ─────────────────────────────── routes ───────────────────────────────

pub fn routes(f: &mut Frame, app: &mut App, area: Rect) {
    let ni = app.net.netinfo.clone();
    let Ok(ni) = ni.lock() else { return };
    let [left, right] = Layout::horizontal([Constraint::Min(60), Constraint::Length(42)]).areas(area);
    let rh = (ni.routes.len() as u16 + 3).min((left.height * 3 / 5).max(6));
    let [rt, nb] = Layout::vertical([Constraint::Length(rh), Constraint::Min(5)]).areas(left);

    let gws = ni.default_gateways();
    let (off, h) = window(&mut app.route_state, ni.routes.len(), rt);
    app.hits.table = Some((rt, off));
    let rows: Vec<Row> = ni.routes[off.min(ni.routes.len())..(off + h).min(ni.routes.len())]
        .iter()
        .map(|r| {
            let default = r.dst == "default";
            Row::new(vec![
                Cell::from(r.family).style(Style::new().fg(theme::dim())),
                Cell::from(r.dst.clone()).style(Style::new().fg(if default { theme::yellow() } else { theme::fg() }).bold()),
                Cell::from(if r.gateway.is_empty() { "·".into() } else { r.gateway.clone() })
                    .style(Style::new().fg(theme::cyan())),
                Cell::from(r.dev.clone()).style(Style::new().fg(theme::teal())),
                Cell::from(r.proto.clone()).style(Style::new().fg(theme::muted())),
                num(r.metric.clone(), Style::new().fg(theme::dim())),
                Cell::from(r.src.clone()).style(Style::new().fg(theme::dim())),
            ])
        })
        .collect();
    let title = format!("routes ({})", ni.routes.len());
    let mut block = panel(title, theme::yellow());
    if let Some(e) = &ni.error {
        block = block.title_bottom(Line::styled(format!(" {e} "), Style::new().fg(theme::orange())).right_aligned());
    }
    let t = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Min(18),
            Constraint::Length(26),
            Constraint::Length(12),
            Constraint::Length(9),
            Constraint::Length(7),
            Constraint::Length(16),
        ],
    )
    .header(header(&["FAM", "DESTINATION", "GATEWAY", "DEV", "PROTO", "METRIC", "SRC"]))
    .block(block)
    .row_highlight_style(sel_style())
    .highlight_symbol(theme::glyphs().select);
    f.render_stateful_widget(t, rt, &mut local_state(&app.route_state, off));
    scrollbar(f, rt, ni.routes.len(), &app.route_state);

    // Neighbours: problems first.
    let mut neigh: Vec<_> = ni.neighbors.iter().collect();
    neigh.sort_by_key(|n| (!(n.state.contains("FAILED") || n.state.contains("INCOMPLETE")), n.dev.clone(), n.ip.clone()));
    let bad = neigh.iter().filter(|n| n.state.contains("FAILED") || n.state.contains("INCOMPLETE")).count();
    let rows: Vec<Row> = neigh
        .iter()
        .take(nb.height.saturating_sub(3) as usize)
        .map(|n| {
            let ip = n.ip.parse().ok();
            let sc = ip.as_ref().map(ipinfo::scope).unwrap_or("");
            Row::new(vec![
                Cell::from(n.ip.clone()).style(Style::new().fg(scope_color(sc))),
                Cell::from(if n.mac.is_empty() { "·".into() } else { n.mac.clone() }).style(Style::new().fg(theme::muted())),
                Cell::from(n.dev.clone()).style(Style::new().fg(theme::teal())),
                Cell::from(n.state.clone()).style(Style::new().fg(neigh_color(&n.state)).bold()),
                Cell::from(if gws.contains(&n.ip) { "gateway" } else { "" }).style(Style::new().fg(theme::yellow())),
            ])
        })
        .collect();
    let mut title = vec![Span::styled(format!(" neighbours ({}) ", ni.neighbors.len()), Style::new().fg(theme::cyan()).bold())];
    if bad > 0 {
        title.push(Span::styled(format!(" {bad} failed/incomplete "), Style::new().fg(theme::header_bg()).bg(theme::red())));
    }
    f.render_widget(
        Table::new(rows, [Constraint::Min(18), Constraint::Length(19), Constraint::Length(12), Constraint::Length(12), Constraint::Length(8)])
            .header(header(&["ADDRESS", "LINK-LAYER", "DEV", "STATE", ""]))
            .block(frame().title(Line::from(title))),
        nb,
    );

    // DNS + gateways + probe summary.
    let loaded = ni.updated.is_some();
    let mut lines = vec![Line::styled(" default gateway", Style::new().fg(theme::dim()))];
    if !loaded {
        lines.push(Line::styled("   loading…", Style::new().fg(theme::dim())));
    } else if gws.is_empty() {
        lines.push(Line::styled("   none: no default route", Style::new().fg(theme::red()).bold()));
    }
    for g in &gws {
        lines.push(Line::styled(format!("   {g}"), Style::new().fg(theme::yellow()).bold()));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(" nameservers", Style::new().fg(theme::dim())));
    if loaded && ni.dns.servers.is_empty() {
        lines.push(Line::styled("   none configured", Style::new().fg(theme::red())));
    }
    for d in &ni.dns.servers {
        lines.push(Line::styled(format!("   {d}"), Style::new().fg(theme::cyan())));
    }
    if !ni.dns.search.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled(" search domains", Style::new().fg(theme::dim())));
        for d in &ni.dns.search {
            lines.push(Line::styled(format!("   {d}"), Style::new().fg(theme::fg())));
        }
    }
    if let Some(n) = &ni.dns.note {
        lines.push(Line::raw(""));
        lines.push(Line::styled(format!(" {n}"), Style::new().fg(theme::muted())));
    }
    if let Ok(p) = app.net.probes.try_lock() {
        let autos: Vec<_> = p.probes.iter().filter(|p| p.auto).collect();
        if !autos.is_empty() {
            lines.push(Line::raw(""));
            lines.push(Line::styled(" reachability (auto probes)", Style::new().fg(theme::dim())));
            for pr in autos {
                let (txt, col) = match pr.last_ms {
                    Some(ms) => (format!("{ms:.1} ms"), theme::green()),
                    None => (pr.last_err.clone().unwrap_or_else(|| "pending".into()), theme::red()),
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("   {:<22}", truncate(&pr.name, 22)), Style::new().fg(theme::fg())),
                    Span::styled(truncate(&txt, 16), Style::new().fg(col)),
                ]));
            }
        }
    }
    let age = ni.updated.map(|u| format!(" updated {:.0}s ago ", u.elapsed().as_secs_f64())).unwrap_or_default();
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel("dns & gateway", theme::purple()).title_bottom(Line::styled(age, Style::new().fg(theme::dim())).right_aligned())),
        right,
    );
}

// ─────────────────────────────── probes ───────────────────────────────

pub fn probes(f: &mut Frame, app: &mut App, area: Rect) {
    let store = app.net.probes.clone();
    let Ok(st) = store.lock() else { return };
    let n = st.probes.len();
    let th = (n as u16 + 3).min((area.height / 2).max(6));
    let [top, bottom] = Layout::vertical([Constraint::Length(th), Constraint::Min(6)]).areas(area);

    if n == 0 {
        let lines = vec![
            Line::raw(""),
            Line::styled("  No probes yet.", Style::new().fg(theme::fg()).bold()),
            Line::raw(""),
            Line::from(vec![
                Span::styled("  Press ", Style::new().fg(theme::dim())),
                Span::styled("a", Style::new().fg(theme::blue()).bold()),
                Span::styled(" and enter a target:", Style::new().fg(theme::dim())),
            ]),
            Line::styled("     1.1.1.1                 ICMP echo (ping)", Style::new().fg(theme::muted())),
            Line::styled("     tcp:db.internal:5432    TCP connect time", Style::new().fg(theme::muted())),
            Line::styled("     dns:github.com          resolver lookup time", Style::new().fg(theme::muted())),
            Line::raw(""),
            Line::styled("  Gateway and DNS servers are probed automatically once the routing table is read.", Style::new().fg(theme::dim())),
        ];
        f.render_widget(Paragraph::new(lines).block(panel("latency probes", theme::cyan())), area);
        return;
    }

    let (off, h) = window(&mut app.probe_state, n, top);
    app.hits.table = Some((top, off));
    let w = 24usize;
    let rows: Vec<Row> = st.probes[off..(off + h).min(n)]
        .iter()
        .map(|p| {
            let loss = p.loss_pct();
            let stats = p.stats();
            let ms = |v: Option<f64>, st: Style| match v {
                Some(x) => num(format!("{x:.1}"), st),
                None => none(),
            };
            let tail: Vec<f64> = p.hist.tail(w).into_iter().map(|x| if x.is_finite() { x } else { 0.0 }).collect();
            let max = stats.map(|s| s.2).unwrap_or(1.0).max(1.0);
            let last_col = match p.last_ms {
                Some(v) if v > 100.0 => theme::orange(),
                Some(_) => theme::green(),
                None => theme::red(),
            };
            Row::new(vec![
                Cell::from(truncate(&p.name, 28)).style(Style::new().fg(theme::fg()).bold()),
                Cell::from(p.target.kind()).style(Style::new().fg(if p.auto { theme::dim() } else { theme::cyan() })),
                match (&p.last_ms, &p.last_err) {
                    _ if p.silent() => num("no reply", Style::new().fg(theme::dim())),
                    (Some(v), _) => num(format!("{v:.1}"), Style::new().fg(last_col)),
                    (None, Some(e)) => num(truncate(e, 14), Style::new().fg(last_col)),
                    _ => none(),
                },
                ms(stats.map(|s| s.0), Style::new().fg(theme::muted())),
                ms(stats.map(|s| s.1), Style::new().fg(theme::fg())),
                ms(stats.map(|s| s.2), Style::new().fg(theme::muted())),
                ms(stats.map(|s| s.3), Style::new().fg(theme::purple())),
                if p.silent() {
                    num("·", Style::new().fg(theme::dim()))
                } else {
                    num(format!("{loss:.0}%"), Style::new().fg(theme::heat(loss * 2.0)).bold())
                },
                match p.http_status {
                    Some(st) => num(
                        st.to_string(),
                        Style::new().fg(match st {
                            200..=299 => theme::green(),
                            300..=399 => theme::cyan(),
                            400..=499 => theme::yellow(),
                            _ => theme::red(),
                        }),
                    ),
                    None => none(),
                },
                match p.mos() {
                    Some(m) => num(format!("{m:.1}"), Style::new().fg(if m >= 4.0 { theme::green() } else if m >= 3.6 { theme::yellow() } else { theme::red() })),
                    None => none(),
                },
                match p.cert_days {
                    Some(d) => num(
                        format!("{d}d"),
                        Style::new().fg(if d < 7 {
                            theme::red()
                        } else if d < 21 {
                            theme::orange()
                        } else {
                            theme::green()
                        }),
                    ),
                    None => none(),
                },
                Cell::from(spark(&tail, max)).style(Style::new().fg(theme::teal())),
            ])
        })
        .collect();
    let t = Table::new(
        rows,
        [
            Constraint::Min(16),
            Constraint::Length(5),
            Constraint::Length(14),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(4),
            Constraint::Length(6),
            Constraint::Length(w as u16),
        ],
    )
    .column_spacing(2)
    .header(header(&["TARGET", "TYPE", "LAST ms", "MIN", "AVG", "MAX", "JITTER", "LOSS", "STATUS", "MOS", "CERT", "HISTORY"]))
    .block(panel(format!("latency probes ({n})"), theme::cyan()))
    .row_highlight_style(sel_style())
    .highlight_symbol(theme::glyphs().select);
    f.render_stateful_widget(t, top, &mut local_state(&app.probe_state, off));

    // Path trace (t) for the selected probe, if one was run for it.
    let Some(p) = app.probe_state.selected().and_then(|i| st.probes.get(i)) else { return };
    let host = match &p.target {
        crate::collect::probes::Target::Icmp(ip) => ip.to_string(),
        crate::collect::probes::Target::Tcp(h, _) | crate::collect::probes::Target::Dns(h) => h.clone(),
        crate::collect::probes::Target::Http(u) => u.split("://").nth(1).unwrap_or(u).split(['/', ':']).next().unwrap_or("").to_string(),
    };
    let trace = app.net.trace.try_lock().ok().and_then(|t| t.current.clone()).filter(|t| t.target == host);
    if let Some(tr) = trace {
        let title = if tr.running {
            format!("path to {} ({})  tracing…", tr.target, tr.mode.label())
        } else {
            format!("path to {}  ({}, {}, {} hops)", tr.target, tr.mode.label(), tr.tool, tr.hops.len())
        };
        let mut block = panel(title, theme::cyan());
        if let Some(e) = &tr.error {
            block = block.title_bottom(Line::styled(format!(" {e} "), Style::new().fg(theme::orange())));
        }
        let rows: Vec<Row> = tr
            .hops
            .iter()
            .take(bottom.height.saturating_sub(3) as usize)
            .map(|hp| {
                let silent = hp.host == "*" || hp.host == "???";
                Row::new(vec![
                    num(hp.n.to_string(), Style::new().fg(theme::dim())),
                    Cell::from(hp.host.clone()).style(Style::new().fg(if silent { theme::dim() } else { theme::fg() }).bold()),
                    num(format!("{:.0}%", hp.loss_pct), Style::new().fg(theme::heat(hp.loss_pct * 2.0)).bold()),
                    num(hp.sent.to_string(), Style::new().fg(theme::dim())),
                    if silent { none() } else { num(format!("{:.1}", hp.last), Style::new().fg(theme::fg())) },
                    if silent { none() } else { num(format!("{:.1}", hp.avg), Style::new().fg(theme::green())) },
                    if silent { none() } else { num(format!("{:.1}", hp.best), Style::new().fg(theme::muted())) },
                    if silent { none() } else { num(format!("{:.1}", hp.worst), Style::new().fg(theme::orange())) },
                ])
            })
            .collect();
        f.render_widget(
            Table::new(
                rows,
                [
                    Constraint::Length(4),
                    Constraint::Min(16),
                    Constraint::Length(6),
                    Constraint::Length(5),
                    Constraint::Length(8),
                    Constraint::Length(8),
                    Constraint::Length(8),
                    Constraint::Length(8),
                ],
            )
            .column_spacing(2)
            .header(header(&["HOP", "HOST", "LOSS%", "SENT", "LAST ms", "AVG", "BEST", "WORST"]))
            .block(block),
            bottom,
        );
        return;
    }

    // Big graph of the selected probe, losses drawn as red marks underneath.
    let gw = bottom.width.saturating_sub(2) as usize;
    let raw = p.hist.tail(gw);
    let data: Vec<f64> = raw.iter().map(|x| if x.is_finite() { *x } else { 0.0 }).collect();
    let max = data.iter().copied().fold(1.0, f64::max) * 1.15;
    let block = panel(format!("{}  {}", p.name, p.target.spec()), theme::cyan()).title(
        Line::styled(format!(" scale {max:.1} ms · loss {:.0}% of {} ", p.loss_pct(), p.sent()), Style::new().fg(theme::dim())).right_aligned(),
    );
    let inner = block.inner(bottom);
    f.render_widget(block, bottom);
    let [g, lossrow] = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(inner);
    f.render_widget(AreaGraph { data: &data, max, color: GraphColor::Gradient(theme::teal(), theme::cyan()), inverted: false }, g);
    let pad = gw.saturating_sub(raw.len());
    let marks: String = " ".repeat(pad) + &raw.iter().map(|x| if x.is_finite() { ' ' } else { 'x' }).collect::<String>();
    f.render_widget(Paragraph::new(Line::styled(marks, Style::new().fg(theme::red()))), lossrow);
}

// ─────────────────────────────── firewall ───────────────────────────────

pub fn firewall(f: &mut Frame, app: &mut App, area: Rect) {
    let rows_data = app.fw_rows();
    let (source, err, total, age) = match app.net.fw.try_lock() {
        Ok(s) => (s.source, s.error.clone(), s.rules.len(), s.updated.map(|u| u.elapsed().as_secs_f64())),
        Err(_) => ("", None, 0, None),
    };
    if total == 0 {
        let msg = match (&err, age) {
            (Some(e), _) => e.clone(),
            (None, None) => "reading the ruleset…".into(),
            (None, Some(_)) => "no rules loaded".into(),
        };
        let lines = vec![
            Line::raw(""),
            Line::styled(format!("  {msg}"), Style::new().fg(if err.is_some() { theme::orange() } else { theme::fg() })),
            Line::raw(""),
            Line::styled("  Linux: nftables (nft -j) or iptables-save -c · macOS: pfctl -s rules -v", Style::new().fg(theme::dim())),
            Line::styled("  Run vigil with sudo to read rule counters.", Style::new().fg(theme::dim())),
        ];
        f.render_widget(Paragraph::new(lines).block(panel("firewall", theme::red())), area);
        return;
    }
    let n = rows_data.len();
    let (off, h) = window(&mut app.fw_state, n, area);
    app.hits.table = Some((area, off));
    let rows: Vec<Row> = rows_data[off.min(n)..(off + h).min(n)]
        .iter()
        .map(|r| {
            let vcol = match r.verdict.as_str() {
                v if v.starts_with("drop") || v.starts_with("reject") || v.starts_with("block") => theme::red(),
                v if v.starts_with("accept") || v.starts_with("pass") => theme::green(),
                v if v.starts_with("jump") || v.starts_with("goto") => theme::purple(),
                v if v.contains("nat") || v.starts_with("masq") => theme::yellow(),
                _ => theme::muted(),
            };
            let active = r.pps > 0.0;
            Row::new(vec![
                Cell::from(format!("{} {}", r.family, r.table)).style(Style::new().fg(theme::dim())),
                Cell::from(r.chain.clone()).style(Style::new().fg(theme::cyan())),
                Cell::from(r.rule.clone()).style(Style::new().fg(theme::fg())),
                Cell::from(r.verdict.clone()).style(Style::new().fg(vcol).bold()),
                num(r.packets.to_string(), Style::new().fg(if r.packets > 0 { theme::fg() } else { theme::dim() })),
                num(fmt_bytes(r.bytes), Style::new().fg(theme::muted())),
                if active { num(format!("{:.0}", r.pps), Style::new().fg(theme::yellow()).bold()) } else { none() },
                if active { num(fmt_rate(r.bps), Style::new().fg(theme::orange())) } else { none() },
            ])
        })
        .collect();
    let mut title = vec![Span::styled(format!(" rules ({n}/{total}) "), Style::new().fg(theme::red()).bold())];
    if app.fw_hide_zero {
        title.push(Span::styled(" hits only ", Style::new().fg(theme::header_bg()).bg(theme::yellow())));
    }
    if app.fw_by_rate {
        title.push(Span::styled("  sort pkt/s ", Style::new().fg(theme::dim())));
    }
    title.extend(filter_title(&app.fw_filter));
    let mut block = frame().title(Line::from(title)).title(Line::styled(format!(" {source} "), Style::new().fg(theme::dim())).right_aligned());
    if let Some(e) = err {
        block = block.title_bottom(Line::styled(format!(" {e} "), Style::new().fg(theme::orange())));
    }
    let t = Table::new(
        rows,
        [
            Constraint::Length(14),
            Constraint::Length(14),
            Constraint::Min(30),
            Constraint::Length(14),
            Constraint::Length(11),
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Length(10),
        ],
    )
    .header(header(&["TABLE", "CHAIN", "RULE", "VERDICT", "PACKETS", "BYTES", "PKT/s", "BYTES/s"]))
    .block(block)
    .row_highlight_style(sel_style())
    .highlight_symbol(theme::glyphs().select);
    f.render_stateful_widget(t, area, &mut local_state(&app.fw_state, off));
    scrollbar(f, area, n, &app.fw_state);
}
