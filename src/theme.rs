//! Runtime-switchable colour palettes.
//!
//! The active palette is a single atomic index into a static table, so a colour
//! lookup is one relaxed load + an array index: no locks, no allocation.

use std::sync::atomic::{AtomicUsize, Ordering};

use ratatui::style::Color;
use ratatui::symbols::border;

/// Characters a theme draws with. Colours alone can't make a CRT feel like a CRT.
pub struct Glyphs {
    pub border: border::Set,
    pub meter_on: &'static str,
    pub meter_off: &'static str,
    /// Area graph, 0..=8 eighths filled.
    pub graph: [char; 9],
    /// Downward graph: full, more than half, less than half.
    pub graph_down: [char; 3],
    pub spark: [char; 8],
    pub select: &'static str,
    pub divider: &'static str,
    pub track: &'static str,
    pub thumb: &'static str,
}

pub const MODERN: Glyphs = Glyphs {
    border: border::ROUNDED,
    meter_on: "■",
    meter_off: "■",
    graph: [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'],
    graph_down: ['█', '▀', '▔'],
    spark: ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'],
    select: "▌",
    divider: "│",
    track: "│",
    thumb: "┃",
};

pub const NEON: Glyphs = Glyphs {
    border: border::THICK,
    meter_on: "▰",
    meter_off: "▱",
    graph: [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'],
    graph_down: ['█', '▀', '▔'],
    spark: ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'],
    select: "▶",
    divider: "┃",
    track: "┃",
    thumb: "█",
};

/// Pure 7-bit ASCII, as on a VT100 / serial console.
pub const ASCII: Glyphs = Glyphs {
    border: border::Set {
        top_left: "+",
        top_right: "+",
        bottom_left: "+",
        bottom_right: "+",
        vertical_left: "|",
        vertical_right: "|",
        horizontal_top: "-",
        horizontal_bottom: "-",
    },
    meter_on: "#",
    meter_off: ".",
    graph: [' ', '_', '_', '.', '.', ':', ':', '#', '#'],
    graph_down: ['#', ':', '\''],
    spark: ['_', '.', '-', '~', '=', '+', '*', '#'],
    select: ">",
    divider: "|",
    track: "|",
    thumb: "#",
};

pub struct Palette {
    pub name: &'static str,
    pub glyphs: &'static Glyphs,
    /// Background painted behind the whole UI (`Color::Reset` = terminal's own).
    pub bg: Color,
    pub fg: Color,
    pub dim: Color,
    pub muted: Color,
    pub border: Color,
    pub sel_bg: Color,
    pub header_bg: Color,
    pub blue: Color,
    pub purple: Color,
    pub cyan: Color,
    pub teal: Color,
    pub green: Color,
    pub yellow: Color,
    pub orange: Color,
    pub red: Color,
    pub pink: Color,
}

const fn rgb(hex: u32) -> Color {
    Color::Rgb((hex >> 16) as u8, ((hex >> 8) & 0xff) as u8, (hex & 0xff) as u8)
}

pub const THEMES: &[Palette] = &[
    Palette {
        name: "tokyo-night",
        glyphs: &MODERN,
        bg: rgb(0x1a1b26), fg: rgb(0xc0caf5), dim: rgb(0x565f89), muted: rgb(0x7a84b2),
        border: rgb(0x3b4261), sel_bg: rgb(0x292e42), header_bg: rgb(0x16161e),
        blue: rgb(0x7aa2f7), purple: rgb(0xbb9af7), cyan: rgb(0x7dcfff), teal: rgb(0x73daca),
        green: rgb(0x9ece6a), yellow: rgb(0xe0af68), orange: rgb(0xff9e64), red: rgb(0xf7768e),
        pink: rgb(0xff75b5),
    },
    Palette {
        name: "catppuccin-mocha",
        glyphs: &MODERN,
        bg: rgb(0x1e1e2e), fg: rgb(0xcdd6f4), dim: rgb(0x6c7086), muted: rgb(0x9399b2),
        border: rgb(0x45475a), sel_bg: rgb(0x313244), header_bg: rgb(0x181825),
        blue: rgb(0x89b4fa), purple: rgb(0xcba6f7), cyan: rgb(0x89dceb), teal: rgb(0x94e2d5),
        green: rgb(0xa6e3a1), yellow: rgb(0xf9e2af), orange: rgb(0xfab387), red: rgb(0xf38ba8),
        pink: rgb(0xf5c2e7),
    },
    Palette {
        name: "gruvbox",
        glyphs: &MODERN,
        bg: rgb(0x282828), fg: rgb(0xebdbb2), dim: rgb(0x665c54), muted: rgb(0xa89984),
        border: rgb(0x504945), sel_bg: rgb(0x3c3836), header_bg: rgb(0x1d2021),
        blue: rgb(0x83a598), purple: rgb(0xd3869b), cyan: rgb(0x8ec07c), teal: rgb(0x689d6a),
        green: rgb(0xb8bb26), yellow: rgb(0xfabd2f), orange: rgb(0xfe8019), red: rgb(0xfb4934),
        pink: rgb(0xd3869b),
    },
    Palette {
        name: "nord",
        glyphs: &MODERN,
        bg: rgb(0x2e3440), fg: rgb(0xd8dee9), dim: rgb(0x616e88), muted: rgb(0x8a96ad),
        border: rgb(0x434c5e), sel_bg: rgb(0x3b4252), header_bg: rgb(0x242933),
        blue: rgb(0x81a1c1), purple: rgb(0xb48ead), cyan: rgb(0x88c0d0), teal: rgb(0x8fbcbb),
        green: rgb(0xa3be8c), yellow: rgb(0xebcb8b), orange: rgb(0xd08770), red: rgb(0xbf616a),
        pink: rgb(0xc895bf),
    },
    Palette {
        name: "dracula",
        glyphs: &MODERN,
        bg: rgb(0x282a36), fg: rgb(0xf8f8f2), dim: rgb(0x6272a4), muted: rgb(0x9aa2c8),
        border: rgb(0x44475a), sel_bg: rgb(0x383a4a), header_bg: rgb(0x21222c),
        blue: rgb(0xbd93f9), purple: rgb(0xff79c6), cyan: rgb(0x8be9fd), teal: rgb(0x6be5c8),
        green: rgb(0x50fa7b), yellow: rgb(0xf1fa8c), orange: rgb(0xffb86c), red: rgb(0xff5555),
        pink: rgb(0xff92df),
    },
    Palette {
        name: "rose-pine",
        glyphs: &MODERN,
        bg: rgb(0x191724), fg: rgb(0xe0def4), dim: rgb(0x6e6a86), muted: rgb(0x908caa),
        border: rgb(0x403d52), sel_bg: rgb(0x26233a), header_bg: rgb(0x1f1d2e),
        blue: rgb(0x9ccfd8), purple: rgb(0xc4a7e7), cyan: rgb(0x9ccfd8), teal: rgb(0x31748f),
        green: rgb(0x8fbf9f), yellow: rgb(0xf6c177), orange: rgb(0xea9a97), red: rgb(0xeb6f92),
        pink: rgb(0xebbcba),
    },
    Palette {
        name: "solarized-light",
        glyphs: &MODERN,
        bg: rgb(0xfdf6e3), fg: rgb(0x073642), dim: rgb(0x93a1a1), muted: rgb(0x657b83),
        border: rgb(0xc9c2ac), sel_bg: rgb(0xeee8d5), header_bg: rgb(0xeee8d5),
        blue: rgb(0x268bd2), purple: rgb(0x6c71c4), cyan: rgb(0x2aa198), teal: rgb(0x2aa198),
        green: rgb(0x859900), yellow: rgb(0xb58900), orange: rgb(0xcb4b16), red: rgb(0xdc322f),
        pink: rgb(0xd33682),
    },
    // Night City: neon on near-black, thick frames, ▰▱ meters.
    Palette {
        name: "cyberpunk",
        glyphs: &NEON,
        bg: rgb(0x0a0a12), fg: rgb(0xe6f7ff), dim: rgb(0x3d4a6b), muted: rgb(0x7f8fb8),
        border: rgb(0x00b3c4), sel_bg: rgb(0x2a0f3d), header_bg: rgb(0x07070d),
        blue: rgb(0x00f0ff), purple: rgb(0xff2a6d), cyan: rgb(0x05d9e8), teal: rgb(0x01ffc3),
        green: rgb(0x39ff14), yellow: rgb(0xfcee0a), orange: rgb(0xff9f1c), red: rgb(0xff003c),
        pink: rgb(0xff00e6),
    },
    // Green phosphor CRT (P1). Monochrome: severity is brightness, not hue.
    Palette {
        name: "phosphor",
        glyphs: &ASCII,
        bg: rgb(0x040a04), fg: rgb(0x33ff33), dim: rgb(0x146614), muted: rgb(0x1f9a1f),
        border: rgb(0x1a801a), sel_bg: rgb(0x0f3d0f), header_bg: rgb(0x020502),
        blue: rgb(0x33ff33), purple: rgb(0x29cc29), cyan: rgb(0x4dff4d), teal: rgb(0x29cc29),
        green: rgb(0x1fb31f), yellow: rgb(0x66ff66), orange: rgb(0x99ff99), red: rgb(0xd9ffd9),
        pink: rgb(0x66ff66),
    },
    // Uses the terminal's own 16 colours: works over plain SSH, tmux without
    // truecolor, serial consoles, and follows whatever scheme the terminal has.
    Palette {
        name: "ansi",
        glyphs: &MODERN,
        bg: Color::Reset, fg: Color::Reset, dim: Color::DarkGray, muted: Color::Gray,
        border: Color::DarkGray, sel_bg: Color::DarkGray, header_bg: Color::Black,
        blue: Color::Blue, purple: Color::Magenta, cyan: Color::Cyan, teal: Color::LightCyan,
        green: Color::Green, yellow: Color::Yellow, orange: Color::LightRed, red: Color::Red,
        pink: Color::LightMagenta,
    },
];

static CURRENT: AtomicUsize = AtomicUsize::new(0);

#[inline]
pub fn pal() -> &'static Palette {
    &THEMES[CURRENT.load(Ordering::Relaxed)]
}

#[inline]
pub fn glyphs() -> &'static Glyphs {
    pal().glyphs
}

/// True for themes that must stay within 7-bit ASCII.
pub fn is_ascii() -> bool {
    std::ptr::eq(glyphs(), &ASCII)
}

/// Tree connectors: (middle child, last child, continue below middle, continue below last).
pub fn tree() -> (&'static str, &'static str, &'static str, &'static str) {
    if is_ascii() {
        ("|- ", "`- ", "|  ", "   ")
    } else {
        ("├─ ", "└─ ", "│  ", "   ")
    }
}

pub fn index() -> usize {
    CURRENT.load(Ordering::Relaxed)
}

pub fn set(i: usize) {
    CURRENT.store(i.min(THEMES.len() - 1), Ordering::Relaxed);
}

pub fn by_name(name: &str) -> Option<usize> {
    THEMES.iter().position(|t| t.name.eq_ignore_ascii_case(name))
}

/// Pick a sensible default: plain 16 colours when the terminal can't do truecolor.
pub fn auto_default() -> usize {
    let ct = std::env::var("COLORTERM").unwrap_or_default();
    // iTerm2, WezTerm, VS Code, Ghostty… set TERM_PROGRAM and all do truecolor.
    let truecolor = ct.contains("truecolor")
        || ct.contains("24bit")
        || std::env::var("TERM_PROGRAM").is_ok_and(|t| t != "Apple_Terminal");
    if truecolor {
        0
    } else {
        by_name("ansi").unwrap_or(0)
    }
}

macro_rules! accessors {
    ($($f:ident),*) => { $( #[inline] pub fn $f() -> Color { pal().$f } )* };
}
accessors!(bg, fg, dim, muted, border, sel_bg, header_bg, blue, purple, cyan, teal, green, yellow, orange, red, pink);

fn rgb_of(c: Color) -> Option<(f64, f64, f64)> {
    match c {
        Color::Rgb(r, g, b) => Some((r as f64, g as f64, b as f64)),
        _ => None,
    }
}

pub fn lerp(a: Color, b: Color, t: f64) -> Color {
    let t = t.clamp(0.0, 1.0);
    match (rgb_of(a), rgb_of(b)) {
        (Some((ar, ag, ab)), Some((br, bg, bb))) => Color::Rgb(
            (ar + (br - ar) * t) as u8,
            (ag + (bg - ag) * t) as u8,
            (ab + (bb - ab) * t) as u8,
        ),
        // 16-colour palettes can't blend: step instead.
        _ => {
            if t < 0.5 {
                a
            } else {
                b
            }
        }
    }
}

/// Green → yellow → red for a 0..100 percentage.
pub fn heat(pct: f64) -> Color {
    let p = pct.clamp(0.0, 100.0) / 100.0;
    if p < 0.5 {
        lerp(green(), yellow(), p * 2.0)
    } else {
        lerp(yellow(), red(), (p - 0.5) * 2.0)
    }
}

pub fn tcp_state(state: &str) -> Color {
    match state {
        "LISTEN" => green(),
        "ESTABLISHED" => cyan(),
        "TIME_WAIT" | "FIN_WAIT1" | "FIN_WAIT_1" | "FIN_WAIT2" | "FIN_WAIT_2" => yellow(),
        "CLOSE_WAIT" | "LAST_ACK" | "CLOSING" => orange(),
        "SYN_SENT" | "SYN_RECV" | "SYN_RECEIVED" | "NEW_SYN_RECV" => purple(),
        "CLOSED" => red(),
        _ => muted(),
    }
}

pub fn file_type(t: &str) -> Color {
    match t {
        "REG" => fg(),
        "DIR" => blue(),
        "IPv4" | "IPv6" => cyan(),
        "unix" => purple(),
        "PIPE" | "FIFO" => yellow(),
        "CHR" => teal(),
        "KQUEUE" | "a_inode" => muted(),
        _ => dim(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_names_unique_and_resolvable() {
        for (i, t) in THEMES.iter().enumerate() {
            assert_eq!(by_name(t.name), Some(i));
        }
    }

    #[test]
    fn ansi_heat_does_not_panic() {
        set(by_name("ansi").unwrap());
        for p in [0.0, 25.0, 50.0, 75.0, 100.0] {
            let _ = heat(p);
        }
        set(0);
    }
}
