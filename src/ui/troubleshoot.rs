//! Troubleshoot view (W): tool output on the left, link layer on the right.

use std::time::SystemTime;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::widgets::{frame, panel};
use crate::app::App;
use crate::collect::l2;
use crate::theme;
use crate::tools::{doctor, Kind, Tone};

fn tone_style(t: Tone) -> Style {
    match t {
        Tone::Head => Style::new().fg(theme::blue()).bold(),
        Tone::Good => Style::new().fg(theme::green()),
        Tone::Warn => Style::new().fg(theme::yellow()),
        Tone::Bad => Style::new().fg(theme::red()).bold(),
        Tone::Dim => Style::new().fg(theme::muted()),
        Tone::Normal => Style::new().fg(theme::fg()),
    }
}

/// Word-wrap with a hanging indent, so long hints stay readable. Runs of
/// spaces (column alignment) are kept on the first row.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(20);
    if text.chars().count() <= width {
        return vec![text.to_string()];
    }
    let lead = text.chars().take_while(|c| *c == ' ').count();
    let hang = (lead + 2).min(width / 2);
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut indent = lead;
    for w in text[lead..].split(' ') {
        let wl = w.chars().count();
        if !cur.is_empty() && indent + cur.chars().count() + 1 + wl > width {
            out.push(format!("{}{}", " ".repeat(indent), cur.trim_end()));
            cur.clear();
            indent = hang;
        }
        if cur.is_empty() && w.is_empty() && indent == hang {
            continue; // no leading spaces on continuation rows
        }
        if !cur.is_empty() || (w.is_empty() && indent != hang) {
            cur.push(' ');
        }
        cur.push_str(w);
    }
    if !cur.trim().is_empty() {
        out.push(format!("{}{}", " ".repeat(indent), cur.trim_end()));
    }
    out
}

const MENU: [(&str, &str, &str); 5] = [
    ("d", "doctor", "walk L1 → L7: link, NIC errors, ARP, IP, gateway, internet, MTU, TCP, clock, TLS, DNS, HTTP"),
    ("c", "calc", "subnet calculator: 10.0.0.0/22 /24 · 10.1.2.3 255.255.252.0 · 10.0.0.0/22 10.0.4.1 · 2001:db8::/48"),
    ("m", "mtu", "path MTU with don't-fragment pings; finds PPPoE, tunnels and PMTU black holes"),
    ("n", "dns", "ask every resolver directly: github.com MX · 8.8.8.8 (PTR) · name @10.0.0.53"),
    ("p", "perf", "throughput to a host running `vigil perf --server` (blank: HTTP download test)"),
];

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let wide = area.width >= 120;
    let [out_area, l2_area] = if wide {
        Layout::horizontal([Constraint::Min(60), Constraint::Length((area.width * 36 / 100).clamp(44, 64))]).areas(area)
    } else {
        Layout::vertical([Constraint::Min(8), Constraint::Length(12.min(area.height / 2))]).areas(area)
    };
    output(f, app, out_area);
    link_layer(f, app, l2_area);
    app.hits.table = None;
}

fn output(f: &mut Frame, app: &mut App, area: Rect) {
    let store = app.net.tools.clone();
    let Ok(st) = store.lock() else { return };
    let inner_w = area.width.saturating_sub(4) as usize;
    let h = area.height.saturating_sub(2) as usize;

    let mut title = vec![Span::styled(" troubleshoot ", Style::new().fg(theme::green()).bold())];
    if let Some(k) = st.kind {
        title.push(Span::styled(format!("· {}{} ", k.title(), if st.arg.is_empty() { String::new() } else { format!(" {}", st.arg) }), Style::new().fg(theme::fg())));
    }
    if st.running {
        title.push(Span::styled(" running… ", Style::new().fg(theme::header_bg()).bg(theme::cyan()).bold()));
    }
    let mut block = frame().title(Line::from(title));

    // Layer ladder after a doctor run: the worst status per layer.
    if st.kind == Some(Kind::Doctor) && !st.checks.is_empty() {
        let mut spans = vec![Span::raw(" ")];
        for layer in 1..=7u8 {
            let worst = st.checks.iter().filter(|c| c.layer == layer).map(|c| c.status).max_by_key(|s| match s {
                doctor::Status::Fail => 4,
                doctor::Status::Warn => 3,
                doctor::Status::Pass => 2,
                doctor::Status::Info => 1,
                doctor::Status::Skip => 0,
            });
            let Some(w) = worst else { continue };
            let col = match w {
                doctor::Status::Fail => theme::red(),
                doctor::Status::Warn => theme::yellow(),
                doctor::Status::Pass => theme::green(),
                _ => theme::dim(),
            };
            spans.push(Span::styled(format!(" L{layer} {} ", doctor::LAYERS[layer as usize]), Style::new().fg(theme::header_bg()).bg(col).bold()));
            spans.push(Span::raw(" "));
        }
        block = block.title_bottom(Line::from(spans));
    }

    if st.lines.is_empty() && !st.running {
        let mut lines = vec![Line::styled(" Run a tool:", Style::new().fg(theme::muted())), Line::raw("")];
        for (k, name, desc) in MENU {
            lines.push(Line::from(vec![
                Span::styled(format!("   {k}  "), Style::new().fg(theme::blue()).bold()),
                Span::styled(format!("{name:<8}"), Style::new().fg(theme::fg()).bold()),
                Span::styled(desc, Style::new().fg(theme::muted())),
            ]));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled("   The same tools on the command line: vigil doctor · vigil calc · vigil dns · vigil mtu · vigil perf", Style::new().fg(theme::dim())));
        lines.push(Line::styled("   Targets live in [troubleshoot] in the config file; nothing is contacted until you run a tool.", Style::new().fg(theme::dim())));
        f.render_widget(Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: false }).block(block), area);
        return;
    }

    // Wrapped display rows, each tagged with its source line.
    let mut rows: Vec<(usize, Tone, String)> = Vec::new();
    let mut first_row = Vec::with_capacity(st.lines.len());
    for (i, l) in st.lines.iter().enumerate() {
        first_row.push(rows.len());
        for r in wrap(&l.text, inner_w) {
            rows.push((i, l.tone, r));
        }
    }
    let total = rows.len();
    let sel = app.tool_state.selected().filter(|s| *s < st.lines.len());
    let mut off = app.tool_state.offset();
    match sel {
        None => off = total.saturating_sub(h), // follow the output
        Some(s) => {
            let a = first_row[s];
            let b = first_row.get(s + 1).copied().unwrap_or(total).saturating_sub(1);
            if a < off {
                off = a;
            }
            if b >= off + h {
                off = (b + 1).saturating_sub(h);
            }
        }
    }
    off = off.min(total.saturating_sub(h));
    *app.tool_state.offset_mut() = off;
    let lines: Vec<Line> = rows[off..(off + h).min(total)]
        .iter()
        .map(|(src, tone, text)| {
            let mut style = tone_style(*tone);
            if Some(*src) == sel {
                style = style.bg(theme::sel_bg());
            }
            Line::styled(format!(" {text}"), style)
        })
        .collect();
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn link_layer(f: &mut Frame, app: &mut App, area: Rect) {
    let store = app.net.l2.clone();
    let Ok(st) = store.lock() else { return };
    let w = area.width.saturating_sub(4) as usize;
    let dim = Style::new().fg(theme::dim());
    let mut lines: Vec<Line> = Vec::new();
    let sec = |t: &str| Line::styled(format!(" {t}"), Style::new().fg(theme::purple()).bold());

    lines.push(sec("Interfaces"));
    lines.push(Line::styled(format!(" {:<10} {:<13} {:>6} {:>7} {:>7} {:>5}", "IFACE", "LINK", "ERR/s", "ERRORS", "CRC/FR", "FLAPS"), Style::new().fg(theme::blue()).bold()));
    let mut nics: Vec<&l2::NicStats> = st.nics.iter().filter(|n| l2::is_physical(&n.name) && n.rx_packets + n.tx_packets > 0).collect();
    nics.sort_by(|a, b| (b.rx_errors + b.tx_errors + b.rx_crc).cmp(&(a.rx_errors + a.tx_errors + a.rx_crc)).then(a.name.cmp(&b.name)));
    if nics.is_empty() {
        lines.push(Line::styled(" collecting…", dim));
    }
    for n in nics.iter().take(8) {
        let link = match (n.carrier, n.speed_mbps, n.duplex.as_deref()) {
            (Some(false), _, _) => "no carrier".to_string(),
            (_, Some(s), Some(d)) => format!("{} {d}", if s >= 1000 { format!("{}G", s / 1000) } else { format!("{s}M") }),
            (_, Some(s), None) => format!("{s} Mb/s"),
            (Some(true), None, _) => "up".into(),
            _ => n.oper.clone().unwrap_or_else(|| "·".into()),
        };
        let rate = st.err_rate.get(&n.name).copied().unwrap_or(0.0);
        let errs = n.rx_errors + n.tx_errors;
        let phys = n.rx_crc + n.rx_frame;
        let flaps = n.carrier_changes.map(|c| (c / 2).to_string()).unwrap_or_else(|| "·".into());
        let col = if rate > 0.0 || phys > 0 {
            theme::red()
        } else if errs > 0 || n.carrier_changes.unwrap_or(0) > 10 {
            theme::yellow()
        } else {
            theme::fg()
        };
        lines.push(Line::styled(
            format!(" {:<10} {:<13} {:>6} {:>7} {:>7} {:>5}", crate::util::truncate(&n.name, 10), crate::util::truncate(&link, 13), if rate > 0.0 { format!("{rate:.1}") } else { "0".into() }, errs, if cfg!(target_os = "linux") { phys.to_string() } else { "·".into() }, flaps),
            Style::new().fg(col),
        ));
    }

    lines.push(Line::raw(""));
    lines.push(sec("LLDP neighbours"));
    if st.lldp.is_empty() {
        lines.push(Line::styled(format!(" {}", st.lldp_note.clone().unwrap_or_else(|| "none".into())), dim));
    }
    for n in &st.lldp {
        lines.push(Line::from(vec![
            Span::styled(format!(" {} ", n.local_port), Style::new().fg(theme::fg()).bold()),
            Span::styled("↔ ", dim),
            Span::styled(format!("{} {}", n.chassis, n.port), Style::new().fg(theme::cyan())),
            Span::styled(
                format!("{}{}", if n.vlan.is_empty() { String::new() } else { format!(" vlan {}", n.vlan) }, if n.mgmt_ip.is_empty() { String::new() } else { format!(" · {}", n.mgmt_ip) }),
                Style::new().fg(theme::muted()),
            ),
        ]));
        if !n.sys_descr.is_empty() {
            lines.push(Line::styled(format!("   {}", crate::util::truncate(&n.sys_descr, w.saturating_sub(3))), dim));
        }
    }

    lines.push(Line::raw(""));
    lines.push(sec("ARP watch"));
    let changes: Vec<_> = st.arp.changes.iter().rev().take(6).collect();
    if changes.is_empty() {
        lines.push(Line::styled(" no MAC address changes since start", dim));
    }
    for c in changes {
        let ago = SystemTime::now().duration_since(c.at).map(|d| d.as_secs()).unwrap_or(0);
        let when = if ago < 60 { format!("{ago}s") } else if ago < 3600 { format!("{}m", ago / 60) } else { format!("{}h", ago / 3600) };
        lines.push(Line::from(vec![
            Span::styled(format!(" {when:>4} "), dim),
            Span::styled(format!("{} ", c.ip), Style::new().fg(if c.gateway { theme::red() } else { theme::yellow() }).bold()),
            Span::styled(format!("{} → {}", c.old_mac, c.new_mac), Style::new().fg(theme::fg())),
            Span::styled(if c.dev.is_empty() { String::new() } else { format!(" {}", c.dev) }, dim),
            Span::styled(if c.gateway { "  GATEWAY" } else { "" }, Style::new().fg(theme::red()).bold()),
        ]));
    }
    for (mac, ips) in st.arp.shared_macs().into_iter().take(3) {
        lines.push(Line::styled(format!(" shared {mac}: {}", ips.join(" ")), Style::new().fg(theme::muted())));
    }
    if st.gateway_changes() > 0 {
        lines.push(Line::styled(" gateway MAC changed: VRRP/HSRP failover, a replaced router, or ARP spoofing", Style::new().fg(theme::red())));
    }
    f.render_widget(Paragraph::new(lines).block(panel("link layer", theme::purple())), area);
}

#[cfg(test)]
mod tests {
    use super::wrap;

    #[test]
    fn wraps_with_hanging_indent() {
        let w = wrap("      → CRC/frame errors are damage on the wire: bad cable, dirty fibre or SFP, EMI, or a duplex mismatch", 40);
        assert!(w.len() > 1);
        assert!(w.iter().all(|l| l.chars().count() <= 40), "{w:?}");
        assert!(w[1].starts_with("        "));
        assert_eq!(wrap("short", 40), vec!["short".to_string()]);
    }
}
