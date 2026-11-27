//! The help screen (`?`): every key, grouped by view, the current view first.
//!
//! Laid out in two columns when the window is wide enough, keys drawn as
//! keycaps, descriptions wrapped under themselves. It scrolls and searches
//! from the keyboard like every other part of vigil.

use ratatui::layout::Rect;
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState};
use ratatui::Frame;

use super::widgets::panel;
use crate::app::{App, Tab};
use crate::theme;

pub struct Section {
    pub title: &'static str,
    /// The view these keys belong to; `None` for keys that work everywhere.
    pub tab: Option<Tab>,
    /// (keys separated by spaces, what they do). A `·` between keys is a
    /// separator, not a key.
    pub rows: &'static [(&'static str, &'static str)],
}

pub static SECTIONS: &[Section] = &[
    Section {
        title: "Move around",
        tab: None,
        rows: &[
            ("1-9 0 S U W", "jump to a view: the number or letter shown in the tab bar"),
            ("← → · Tab", "previous / next view (also H and L, Shift-Tab)"),
            ("↑ ↓ · j k", "move the selection"),
            ("PgUp PgDn", "move a page"),
            ("g G · Home End", "first / last row"),
            ("/", "filter the list while you type; Esc clears it"),
            ("F", "find anything: process, port, IP, MAC, service, container, route, user. Enter jumps to it"),
            ("Esc", "close a dialog, clear a filter"),
        ],
    },
    Section {
        title: "Everywhere",
        tab: None,
        rows: &[
            ("h", "explain the selected item: what it means and what to run next"),
            ("y", "copy the selected value (works over SSH)"),
            ("E", "export the view as CSV"),
            ("R", "write a Markdown report to ./vigil-report-<time>.md"),
            (":", "lsof query: 1234 · :443 · tcp:22 · /var/log/x · -u root -i"),
            ("N", "reverse DNS names on / off"),
            ("T", "theme picker with live preview (b: background on / off)"),
            ("Space", "pause / resume sampling"),
            ("+ -", "refresh interval ±250 ms"),
            ("? · F1", "this help"),
            ("q · Ctrl-C", "quit"),
        ],
    },
    Section {
        title: "Processes",
        tab: Some(Tab::Processes),
        rows: &[
            ("Enter · I", "inspector: identity, history, sockets, files, journal, environment"),
            ("f", "open files of the process"),
            ("x K Del", "send a signal: TERM, KILL, HUP, STOP, …"),
            ("t", "process tree on / off"),
            ("c m p n u", "sort by CPU · memory · pid · name · user"),
            ("i o w e", "sort by disk I/O · connections · network/s · open files"),
            ("r", "reverse the sort"),
        ],
    },
    Section {
        title: "Inspector (Enter on a process)",
        tab: Some(Tab::Processes),
        rows: &[
            ("v", "switch between journal and environment"),
            ("f", "all open files"),
            ("x", "send a signal"),
            ("r", "read again"),
            ("y", "copy the command line"),
            ("Esc", "back to the list"),
        ],
    },
    Section {
        title: "Network",
        tab: Some(Tab::Network),
        rows: &[("↑ ↓", "choose an interface"), ("C", "capture on it: a pcap file Wireshark opens")],
    },
    Section {
        title: "Sockets",
        tab: Some(Tab::Sockets),
        rows: &[
            ("l", "listening sockets only"),
            ("s", "next sort: process · port · state · proto · remote · rtt · traffic"),
            ("Enter · f", "open files of the owning process"),
            ("i", "inspect the owning process"),
            ("P", "everything on this port"),
            ("C", "capture this connection (tcpdump)"),
            ("D", "close this connection (needs root)"),
            ("x K Del", "signal the owning process"),
        ],
    },
    Section {
        title: "Open files",
        tab: Some(Tab::Files),
        rows: &[
            ("Enter", "who else has this file or port open"),
            ("p", "all files of this process"),
            ("r", "run the query again"),
            ("x K", "signal the process"),
        ],
    },
    Section {
        title: "Probes",
        tab: Some(Tab::Probes),
        rows: &[
            ("a", "add a probe: 1.1.1.1 · tcp:host:port · dns:name · https://url"),
            ("d · Del", "delete the selected probe"),
            ("t", "trace the path to it"),
        ],
    },
    Section {
        title: "Firewall",
        tab: Some(Tab::Firewall),
        rows: &[("z", "hide rules that never matched"), ("s", "sort by packets per second")],
    },
    Section {
        title: "System",
        tab: Some(Tab::System),
        rows: &[("e", "switch between services and kernel events"), ("Enter · l", "load the journal of the selected service")],
    },
    Section {
        title: "Troubleshoot",
        tab: Some(Tab::Troubleshoot),
        rows: &[
            ("d", "doctor: walks the network layer by layer"),
            ("c", "subnet calculator"),
            ("m", "path MTU"),
            ("n", "DNS lookup"),
            ("r", "port reachability: open, refused or filtered"),
            ("e", "traceroute over ICMP, TCP or UDP"),
            ("s", "SNMP: interfaces and errors of a switch or router"),
            ("l", "syslog receiver"),
            ("o", "rogue DHCP server check"),
            ("w", "Wi-Fi details"),
            ("p", "throughput test"),
            ("t", "packet capture for Wireshark"),
            ("x", "stop the running tool"),
        ],
    },
    Section {
        title: "Dialogs",
        tab: None,
        rows: &[
            ("Enter · Esc", "apply / cancel what you typed"),
            ("↑ ↓ · Enter", "signal and theme pickers: choose, confirm"),
        ],
    },
];

/// Arrows and other symbols a plain console font may lack, spelled out.
fn plain(token: &str) -> &str {
    match token {
        "↑" => "Up",
        "↓" => "Down",
        "←" => "Left",
        "→" => "Right",
        t => t,
    }
}

fn plain_text(text: &str) -> String {
    text.replace('±', "+/-").replace('…', "...").replace('·', "|")
}

fn width(s: &str) -> usize {
    s.chars().count()
}

/// The keycaps of a row and their total width.
fn keycaps(keys: &str, ascii: bool) -> (Vec<Span<'static>>, usize) {
    let cap = Style::new().fg(theme::blue()).bg(theme::sel_bg()).bold();
    let mut spans = Vec::new();
    let mut w = 0;
    for (i, tok) in keys.split(' ').enumerate() {
        if i > 0 {
            spans.push(Span::raw(" "));
            w += 1;
        }
        if tok == "·" {
            spans.push(Span::styled(if ascii { "|" } else { "·" }, Style::new().fg(theme::dim())));
            w += 1;
        } else {
            let t = if ascii { plain(tok) } else { tok };
            spans.push(Span::styled(format!(" {t} "), cap));
            w += width(t) + 2;
        }
    }
    (spans, w)
}

/// Word wrap to `max` columns (a word longer than that is cut).
fn wrap(text: &str, max: usize) -> Vec<String> {
    let max = max.max(8);
    let mut out = vec![String::new()];
    for word in text.split(' ') {
        let mut word = word.to_string();
        loop {
            let cur = out.last_mut().unwrap();
            let need = width(&word) + usize::from(!cur.is_empty());
            if width(cur) + need <= max {
                if !cur.is_empty() {
                    cur.push(' ');
                }
                cur.push_str(&word);
                break;
            }
            if cur.is_empty() {
                // Longer than a whole line: cut it.
                let head: String = word.chars().take(max).collect();
                word = word.chars().skip(max).collect();
                cur.push_str(&head);
            }
            out.push(String::new());
        }
    }
    out
}

/// One section as lines `w` columns wide, or None when nothing matches `filter`.
fn section_lines(s: &Section, here: bool, w: usize, filter: &str, ascii: bool) -> Option<Vec<Line<'static>>> {
    let needle = filter.to_lowercase();
    let title_hit = s.title.to_lowercase().contains(&needle);
    let rows: Vec<&(&str, &str)> = s.rows.iter().filter(|(k, d)| needle.is_empty() || title_hit || k.to_lowercase().contains(&needle) || d.to_lowercase().contains(&needle)).collect();
    if rows.is_empty() {
        return None;
    }
    let caps: Vec<(Vec<Span<'static>>, usize)> = rows.iter().map(|(k, _)| keycaps(k, ascii)).collect();
    // Descriptions start in one column per section, however wide its keys are.
    let key_w = caps.iter().map(|c| c.1).max().unwrap_or(0).min(w / 2);
    let desc_w = w.saturating_sub(key_w + 2);

    let accent = if here { theme::green() } else { theme::purple() };
    let mut title = vec![Span::styled(s.title.to_string(), Style::new().fg(accent).bold())];
    let mut used = width(s.title);
    if here {
        title.push(Span::styled("  this view", Style::new().fg(theme::dim())));
        used += 11;
    }
    let rule = if ascii { "-" } else { "─" };
    title.push(Span::styled(format!(" {}", rule.repeat(w.saturating_sub(used + 1))), Style::new().fg(theme::border())));
    let mut lines = vec![Line::from(title)];
    for ((_, desc), (cap, cap_w)) in rows.iter().zip(caps) {
        let desc = if ascii { plain_text(desc) } else { desc.to_string() };
        let mut cap = Some(cap);
        if cap_w > key_w {
            // Keys wider than the key column (a very narrow window): on a line of their own.
            lines.push(Line::from(cap.take().unwrap_or_default()));
        }
        for part in wrap(&desc, desc_w) {
            let mut spans = match cap.take() {
                Some(mut v) => {
                    v.push(Span::raw(" ".repeat(key_w - cap_w + 2)));
                    v
                }
                None => vec![Span::raw(" ".repeat(key_w + 2))],
            };
            spans.push(Span::styled(part, Style::new().fg(theme::fg())));
            lines.push(Line::from(spans));
        }
    }
    lines.push(Line::raw(""));
    Some(lines)
}

/// The sections in reading order: the current view's first.
fn ordered(tab: Tab) -> Vec<(&'static Section, bool)> {
    let here = |s: &Section| s.tab == Some(tab);
    SECTIONS.iter().filter(|s| here(s)).map(|s| (s, true)).chain(SECTIONS.iter().filter(|s| !here(s)).map(|s| (s, false))).collect()
}

/// Lines of padding between two columns.
const GAP: usize = 3;

/// Columns that fit in `width`: each needs room for keys and a readable description.
fn columns(width: usize) -> usize {
    match width {
        w if w >= 3 * 54 + 2 * GAP => 3,
        w if w >= 2 * 46 + GAP => 2,
        _ => 1,
    }
}

/// Sections into `n` columns of about the same height, in reading order.
fn distribute(blocks: Vec<Vec<Line<'static>>>, n: usize) -> Vec<Vec<Line<'static>>> {
    let total: usize = blocks.iter().map(Vec::len).sum();
    let target = total.div_ceil(n.max(1));
    let mut cols: Vec<Vec<Line<'static>>> = vec![Vec::new(); n.max(1)];
    let mut c = 0;
    for b in blocks {
        // The next column, once more than half of this section would hang below the target.
        if !cols[c].is_empty() && cols[c].len() + b.len() / 2 > target && c + 1 < cols.len() {
            c += 1;
        }
        cols[c].extend(b);
    }
    cols
}

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let ascii = theme::is_ascii();
    // Wide enough for three columns when the window is; otherwise two that
    // stay readable, or the whole window when it is small.
    let avail = area.width.saturating_sub(2);
    let w = if columns(avail.saturating_sub(4) as usize) == 3 { avail.min(176) } else { avail.min(124) };
    let w = w.max(area.width.min(40));
    // Borders and one column of padding each side (the right one is the scrollbar's).
    let body_w = (w as usize).saturating_sub(4);
    if body_w < 16 || area.height < 5 {
        app.help_scroll = 0;
        return;
    }
    let n = columns(body_w);
    let col_w = (body_w - (n - 1) * GAP) / n;
    let blocks: Vec<Vec<Line<'static>>> = ordered(app.tab).into_iter().filter_map(|(s, here)| section_lines(s, here, col_w, &app.help_filter, ascii)).collect();
    let mut cols = distribute(blocks, n);
    if cols.iter().all(Vec::is_empty) {
        cols[0].push(Line::styled(format!("nothing matches \"{}\"", app.help_filter), Style::new().fg(theme::muted())));
    }
    if app.help_filter.is_empty() {
        let note = if cfg!(windows) { "Run as administrator to see the event log and every process." } else { "Run with sudo to see the sockets and files of every user." };
        let last = cols.iter().rposition(|c| !c.is_empty()).unwrap_or(0);
        for part in wrap(note, col_w) {
            cols[last].push(Line::styled(part, Style::new().fg(theme::muted())));
        }
        for part in wrap(&crate::platform::get().summary(), col_w) {
            cols[last].push(Line::styled(part, Style::new().fg(theme::dim())));
        }
    }
    for c in &mut cols {
        while c.last().is_some_and(|l| l.width() == 0) {
            c.pop();
        }
    }
    let height = cols.iter().map(Vec::len).max().unwrap_or(0);

    // As tall as the content, up to the window.
    let r = super::centered(area, w, (height as u16 + 2).min(area.height.saturating_sub(2).max(area.height.min(8))));
    f.render_widget(Clear, r);
    let footer = if app.help_typing || !app.help_filter.is_empty() {
        Line::from(vec![
            Span::styled(" search ", Style::new().fg(theme::header_bg()).bg(theme::yellow()).bold()),
            Span::styled(format!(" {}", app.help_filter), Style::new().fg(theme::fg())),
            Span::styled(if app.help_typing { "_ " } else { " " }, Style::new().fg(theme::yellow())),
            Span::styled(if app.help_typing { " Enter keep · Esc clear " } else { " / edit · Esc clear " }.replace('·', if ascii { "|" } else { "·" }), Style::new().fg(theme::dim())),
        ])
    } else {
        let keys = if ascii { " Up/Down scroll | PgUp/PgDn page | / search | Esc close " } else { " ↑↓ scroll · PgUp PgDn page · / search · Esc close " };
        Line::styled(keys, Style::new().fg(theme::dim()))
    };
    let block = panel(format!("keys {} {}", if ascii { "|" } else { "·" }, app.tab.title()), theme::blue()).title_bottom(footer);
    let inner = block.inner(r);
    f.render_widget(block, r);
    let body = Rect { x: inner.x + 1, width: inner.width.saturating_sub(2), ..inner };
    let max_scroll = height.saturating_sub(body.height as usize);
    app.help_scroll = app.help_scroll.min(max_scroll as u16);
    app.help_page = body.height.saturating_sub(2).max(1);
    for (i, lines) in cols.into_iter().enumerate() {
        let rect = Rect { x: body.x + (i * (col_w + GAP)) as u16, width: col_w as u16, ..body };
        f.render_widget(Paragraph::new(lines).scroll((app.help_scroll, 0)), rect);
    }
    if max_scroll > 0 {
        let mut ss = ScrollbarState::new(max_scroll + 1).position(app.help_scroll as usize);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .track_symbol(Some(theme::glyphs().track))
                .thumb_symbol(theme::glyphs().thumb)
                .style(Style::new().fg(theme::border()))
                .thumb_style(Style::new().fg(theme::blue())),
            inner,
            &mut ss,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_on_words() {
        assert_eq!(wrap("move the selection", 40), ["move the selection"]);
        assert_eq!(wrap("sort by CPU · memory · pid · name", 14), ["sort by CPU ·", "memory · pid ·", "name"]);
        // A word longer than the line is cut, never dropped.
        assert_eq!(wrap("./vigil-report-<time>.md now", 10), ["./vigil-re", "port-<time", ">.md now"]);
        assert!(wrap("a b c d e f g h i j k l m n o p", 9).iter().all(|l| l.chars().count() <= 9));
    }

    #[test]
    fn keycaps_have_the_width_they_report() {
        for s in SECTIONS {
            for (keys, _) in s.rows {
                for ascii in [false, true] {
                    let (spans, w) = keycaps(keys, ascii);
                    assert_eq!(spans.iter().map(|s| s.content.chars().count()).sum::<usize>(), w, "{keys}");
                    assert!(w <= 30, "{keys} is too wide for a key column");
                }
            }
        }
    }

    #[test]
    fn columns_follow_the_window_and_stay_balanced() {
        assert_eq!((columns(60), columns(95), columns(120), columns(167), columns(168)), (1, 2, 2, 2, 3));
        let block = |n: usize| vec![Line::raw(""); n];
        // Reading order is kept and no column is much taller than a third.
        let cols = distribute(vec![block(10), block(12), block(8), block(9), block(11), block(10)], 3);
        assert_eq!(cols.iter().map(Vec::len).collect::<Vec<_>>(), [22, 17, 21]);
        assert_eq!(distribute(vec![block(5), block(7)], 1)[0].len(), 12);
        // More columns than sections: the rest stay empty.
        assert_eq!(distribute(vec![block(4)], 3).iter().map(Vec::len).collect::<Vec<_>>(), [4, 0, 0]);
    }

    #[test]
    fn current_view_comes_first_and_every_view_with_keys_has_a_section() {
        let first = ordered(Tab::Sockets);
        assert_eq!((first[0].0.title, first[0].1), ("Sockets", true));
        assert_eq!(first.len(), SECTIONS.len());
        assert!(!ordered(Tab::Overview)[0].1);
        for tab in [Tab::Processes, Tab::Network, Tab::Sockets, Tab::Files, Tab::Probes, Tab::Firewall, Tab::System, Tab::Troubleshoot] {
            assert!(SECTIONS.iter().any(|s| s.tab == Some(tab)), "{tab:?}");
        }
    }

    #[test]
    fn search_narrows_rows_and_keeps_whole_sections_by_title() {
        let s = SECTIONS.iter().find(|s| s.title == "Sockets").unwrap();
        let all = section_lines(s, false, 60, "", false).unwrap().len();
        let some = section_lines(s, false, 60, "capture", false).unwrap().len();
        assert!(some < all && some >= 3, "{some} of {all}");
        assert_eq!(section_lines(s, false, 60, "SOCK", false).unwrap().len(), all);
        assert!(section_lines(s, false, 60, "no such thing", false).is_none());
        // Plain consoles: no arrows or dots that the font may lack.
        for s in SECTIONS {
            for l in section_lines(s, true, 50, "", true).unwrap() {
                let text: String = l.spans.iter().map(|s| s.content.as_ref()).collect();
                assert!(text.is_ascii(), "{text}");
                assert!(text.chars().count() <= 50, "{text}");
            }
        }
    }
}
