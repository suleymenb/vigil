//! Custom widgets: gradient area graphs and meters.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::Span;
use ratatui::widgets::{Block, BorderType, Widget};
use ratatui::text::Line;

use crate::theme;

const BLOCKS: [char; 9] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

#[derive(Clone, Copy)]
pub enum GraphColor {
    /// Colour each row by its height (green → red).
    Heat,
    /// Gradient from bottom colour to top colour.
    Gradient(Color, Color),
}

/// Filled area graph, newest sample on the right, 1/8 cell vertical resolution.
pub struct AreaGraph<'a> {
    pub data: &'a [f64],
    pub max: f64,
    pub color: GraphColor,
    /// Grow downward from the top edge (used for upload under download).
    pub inverted: bool,
}

impl Widget for AreaGraph<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let (w, h) = (area.width as usize, area.height as usize);
        if w == 0 || h == 0 {
            return;
        }
        let max = if self.max <= 0.0 { 1.0 } else { self.max };
        let start = self.data.len().saturating_sub(w);
        let slice = &self.data[start..];
        let offset = w - slice.len();

        for (i, &v) in slice.iter().enumerate() {
            let x = area.x + (offset + i) as u16;
            let frac = (v / max).clamp(0.0, 1.0);
            let mut eighths = (frac * (h * 8) as f64).round() as usize;
            if v > 0.0 && eighths == 0 {
                eighths = 1; // keep non-zero activity visible
            }
            for row in 0..h {
                let filled = eighths.saturating_sub(row * 8).min(8);
                if filled == 0 {
                    break;
                }
                let t = (row as f64 + 0.5) / h as f64;
                let color = match self.color {
                    GraphColor::Heat => theme::heat(t * 100.0),
                    GraphColor::Gradient(a, b) => theme::lerp(a, b, t),
                };
                let (y, ch) = if self.inverted {
                    let ch = match filled {
                        8 => '█',
                        4..=7 => '▀',
                        _ => '▔',
                    };
                    (area.y + row as u16, ch)
                } else {
                    (area.y + (h - 1 - row) as u16, BLOCKS[filled])
                };
                if let Some(cell) = buf.cell_mut((x, y)) {
                    cell.set_char(ch).set_fg(color);
                }
            }
        }
    }
}

/// btop-style meter where every filled cell gets its own heat colour.
pub fn meter(pct: f64, width: usize) -> Vec<Span<'static>> {
    let pct = pct.clamp(0.0, 100.0);
    let filled_f = pct / 100.0 * width as f64;
    let full = filled_f.floor() as usize;
    let mut spans = Vec::with_capacity(width);
    for i in 0..width {
        let cell_pct = (i as f64 + 0.5) / width.max(1) as f64 * 100.0;
        if i < full {
            spans.push(Span::styled("■", Style::new().fg(theme::heat(cell_pct))));
        } else {
            spans.push(Span::styled("■", Style::new().fg(theme::border())));
        }
    }
    spans
}

/// Meter with a fixed accent colour instead of heat.
pub fn meter_solid(pct: f64, width: usize, color: Color) -> Vec<Span<'static>> {
    let full = (pct.clamp(0.0, 100.0) / 100.0 * width as f64).round() as usize;
    vec![
        Span::styled("■".repeat(full), Style::new().fg(color)),
        Span::styled("■".repeat(width.saturating_sub(full)), Style::new().fg(theme::border())),
    ]
}

pub fn panel(title: impl Into<String>, accent: Color) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(theme::border()))
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled(title.into(), Style::new().fg(accent).bold()),
            Span::raw(" "),
        ]))
}

/// Rounded frame without a default title.
pub fn frame() -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(theme::border()))
}

pub fn kv(key: &str, val: impl Into<String>, color: Color) -> Vec<Span<'static>> {
    vec![
        Span::styled(format!("{key} "), Style::new().fg(theme::dim())),
        Span::styled(val.into(), Style::new().fg(color)),
        Span::raw("  "),
    ]
}
