//! Runtime-switchable colour palettes.
//!
//! The active palette is a single atomic index into a table fixed at startup
//! (built-in themes plus `[[custom_themes]]`), so a colour lookup is two
//! relaxed loads + an array index: no locks, no allocation.

use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::OnceLock;

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

pub static MODERN: Glyphs = Glyphs {
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

pub static NEON: Glyphs = Glyphs {
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

/// For consoles whose font is small: the classic Windows console window
/// (Consolas, Lucida Console) and the Linux text console (`TERM=linux`, a
/// 256- or 512-glyph font). Every character here is in WGL4 and in the Linux
/// console fonts: plain box corners, half and full blocks. The finer blocks
/// of the other sets (▁▂▃▅▆▇ ▔), rounded corners and heavy lines show up
/// there as empty boxes or question marks.
pub static SAFE: Glyphs = Glyphs {
    border: border::PLAIN,
    meter_on: "■",
    meter_off: "■",
    graph: [' ', '_', '▄', '▄', '▄', '▄', '█', '█', '█'],
    graph_down: ['█', '▀', '¯'],
    spark: ['_', '_', '▄', '▄', '▄', '▄', '█', '█'],
    select: "▌",
    divider: "│",
    track: "│",
    thumb: "█",
};

/// Pure 7-bit ASCII, as on a VT100 / serial console.
pub static ASCII: Glyphs = Glyphs {
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

#[derive(Clone, Copy)]
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

static BUILTIN: &[Palette] = &[
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
    // Kanagawa (wave): ink and woodblock-print colours.
    Palette {
        name: "kanagawa",
        glyphs: &MODERN,
        bg: rgb(0x1f1f28), fg: rgb(0xdcd7ba), dim: rgb(0x54546d), muted: rgb(0x727169),
        border: rgb(0x363646), sel_bg: rgb(0x2d4f67), header_bg: rgb(0x16161d),
        blue: rgb(0x7e9cd8), purple: rgb(0x957fb8), cyan: rgb(0x7fb4ca), teal: rgb(0x6a9589),
        green: rgb(0x98bb6c), yellow: rgb(0xe6c384), orange: rgb(0xffa066), red: rgb(0xe46876),
        pink: rgb(0xd27e99),
    },
    // Everforest (dark, medium): soft greens, easy on the eyes for long shifts.
    Palette {
        name: "everforest",
        glyphs: &MODERN,
        bg: rgb(0x2d353b), fg: rgb(0xd3c6aa), dim: rgb(0x7a8478), muted: rgb(0x9da9a0),
        border: rgb(0x475258), sel_bg: rgb(0x3d484d), header_bg: rgb(0x232a2e),
        blue: rgb(0x7fbbb3), purple: rgb(0xd699b6), cyan: rgb(0x83c092), teal: rgb(0x83c092),
        green: rgb(0xa7c080), yellow: rgb(0xdbbc7f), orange: rgb(0xe69875), red: rgb(0xe67e80),
        pink: rgb(0xd699b6),
    },
    Palette {
        name: "one-dark",
        glyphs: &MODERN,
        bg: rgb(0x282c34), fg: rgb(0xabb2bf), dim: rgb(0x5c6370), muted: rgb(0x7f848e),
        border: rgb(0x3e4451), sel_bg: rgb(0x2c313a), header_bg: rgb(0x21252b),
        blue: rgb(0x61afef), purple: rgb(0xc678dd), cyan: rgb(0x56b6c2), teal: rgb(0x56b6c2),
        green: rgb(0x98c379), yellow: rgb(0xe5c07b), orange: rgb(0xd19a66), red: rgb(0xe06c75),
        pink: rgb(0xc678dd),
    },
    Palette {
        name: "monokai",
        glyphs: &MODERN,
        bg: rgb(0x272822), fg: rgb(0xf8f8f2), dim: rgb(0x75715e), muted: rgb(0xa59f85),
        border: rgb(0x49483e), sel_bg: rgb(0x3e3d32), header_bg: rgb(0x1e1f1c),
        blue: rgb(0x66d9ef), purple: rgb(0xae81ff), cyan: rgb(0x66d9ef), teal: rgb(0xa6e22e),
        green: rgb(0xa6e22e), yellow: rgb(0xe6db74), orange: rgb(0xfd971f), red: rgb(0xf92672),
        pink: rgb(0xf92672),
    },
    Palette {
        name: "github-dark",
        glyphs: &MODERN,
        bg: rgb(0x0d1117), fg: rgb(0xc9d1d9), dim: rgb(0x6e7681), muted: rgb(0x8b949e),
        border: rgb(0x30363d), sel_bg: rgb(0x161b22), header_bg: rgb(0x010409),
        blue: rgb(0x58a6ff), purple: rgb(0xbc8cff), cyan: rgb(0x39c5cf), teal: rgb(0x56d4dd),
        green: rgb(0x3fb950), yellow: rgb(0xd29922), orange: rgb(0xdb6d28), red: rgb(0xf85149),
        pink: rgb(0xdb61a2),
    },
    Palette {
        name: "solarized-dark",
        glyphs: &MODERN,
        bg: rgb(0x002b36), fg: rgb(0x93a1a1), dim: rgb(0x586e75), muted: rgb(0x839496),
        border: rgb(0x2b4c55), sel_bg: rgb(0x073642), header_bg: rgb(0x00212b),
        blue: rgb(0x268bd2), purple: rgb(0x6c71c4), cyan: rgb(0x2aa198), teal: rgb(0x2aa198),
        green: rgb(0x859900), yellow: rgb(0xb58900), orange: rgb(0xcb4b16), red: rgb(0xdc322f),
        pink: rgb(0xd33682),
    },
    // A light theme for bright rooms and projectors.
    Palette {
        name: "catppuccin-latte",
        glyphs: &MODERN,
        bg: rgb(0xeff1f5), fg: rgb(0x4c4f69), dim: rgb(0x9ca0b0), muted: rgb(0x6c6f85),
        border: rgb(0xccd0da), sel_bg: rgb(0xdce0e8), header_bg: rgb(0xe6e9ef),
        blue: rgb(0x1e66f5), purple: rgb(0x8839ef), cyan: rgb(0x04a5e5), teal: rgb(0x179299),
        green: rgb(0x40a02b), yellow: rgb(0xdf8e1d), orange: rgb(0xfe640b), red: rgb(0xd20f39),
        pink: rgb(0xea76cb),
    },
    // Amber CRT (P3), like phosphor: monochrome, ASCII, severity by brightness.
    Palette {
        name: "amber",
        glyphs: &ASCII,
        bg: rgb(0x0f0a00), fg: rgb(0xffb000), dim: rgb(0x6b4a00), muted: rgb(0xa87400),
        border: rgb(0x7a5300), sel_bg: rgb(0x3a2800), header_bg: rgb(0x080500),
        blue: rgb(0xffb000), purple: rgb(0xe09a00), cyan: rgb(0xffc233), teal: rgb(0xe09a00),
        green: rgb(0xcc8c00), yellow: rgb(0xffd066), orange: rgb(0xffe099), red: rgb(0xfff0cc),
        pink: rgb(0xffd066),
    },
    // Okabe-Ito: distinguishable with every common form of colour blindness
    // (no red/green pair carries meaning on its own).
    Palette {
        name: "okabe-ito",
        glyphs: &MODERN,
        bg: rgb(0x111418), fg: rgb(0xe8e8e8), dim: rgb(0x6b7280), muted: rgb(0x9ca3af),
        border: rgb(0x3a4150), sel_bg: rgb(0x243041), header_bg: rgb(0x0b0d10),
        blue: rgb(0x56b4e9), purple: rgb(0xcc79a7), cyan: rgb(0x56b4e9), teal: rgb(0x009e73),
        green: rgb(0x009e73), yellow: rgb(0xf0e442), orange: rgb(0xe69f00), red: rgb(0xd55e00),
        pink: rgb(0xcc79a7),
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
    // The 16 terminal colours with 7-bit ASCII glyphs: raster fonts, serial
    // lines and anything else without box-drawing or block characters.
    Palette {
        name: "classic",
        glyphs: &ASCII,
        bg: Color::Reset, fg: Color::Reset, dim: Color::DarkGray, muted: Color::Gray,
        border: Color::DarkGray, sel_bg: Color::DarkGray, header_bg: Color::Black,
        blue: Color::Blue, purple: Color::Magenta, cyan: Color::Cyan, teal: Color::LightCyan,
        green: Color::Green, yellow: Color::Yellow, orange: Color::LightRed, red: Color::Red,
        pink: Color::LightMagenta,
    },
];

static CURRENT: AtomicUsize = AtomicUsize::new(0);
/// Built-in themes plus `[[custom_themes]]` from the config, fixed at startup.
static ALL: OnceLock<Vec<Palette>> = OnceLock::new();

/// Every theme, built-in first.
pub fn all() -> &'static [Palette] {
    ALL.get().map(|v| v.as_slice()).unwrap_or(BUILTIN)
}

#[inline]
pub fn pal() -> &'static Palette {
    let a = all();
    &a[CURRENT.load(Ordering::Relaxed).min(a.len() - 1)]
}

/// `#rrggbb`, `reset`, an ANSI colour name (`red`, `light-blue`, `dark-gray`)
/// or `ansi:N` for one of the 256 indexed colours.
pub fn parse_color(s: &str) -> Option<Color> {
    let t = s.trim().to_ascii_lowercase().replace(['_', ' '], "-");
    if let Some(h) = t.strip_prefix('#') {
        return (h.len() == 6).then(|| u32::from_str_radix(h, 16).ok()).flatten().map(rgb);
    }
    if let Some(n) = t.strip_prefix("ansi:") {
        return n.parse::<u8>().ok().map(Color::Indexed);
    }
    Some(match t.as_str() {
        "reset" | "default" | "none" => Color::Reset,
        "black" => Color::Black,
        "red" => Color::Red,
        "green" => Color::Green,
        "yellow" => Color::Yellow,
        "blue" => Color::Blue,
        "magenta" => Color::Magenta,
        "cyan" => Color::Cyan,
        "gray" | "grey" => Color::Gray,
        "dark-gray" | "dark-grey" => Color::DarkGray,
        "light-red" => Color::LightRed,
        "light-green" => Color::LightGreen,
        "light-yellow" => Color::LightYellow,
        "light-blue" => Color::LightBlue,
        "light-magenta" => Color::LightMagenta,
        "light-cyan" => Color::LightCyan,
        "white" => Color::White,
        _ => return None,
    })
}

/// Register `[[custom_themes]]`. Call once, before the first `set`.
/// Returns warnings for unknown bases, glyph sets or colours.
pub fn install_custom(custom: &[crate::config::CustomTheme]) -> Vec<String> {
    let (v, warnings) = build(custom);
    let _ = ALL.set(v);
    warnings
}

fn build(custom: &[crate::config::CustomTheme]) -> (Vec<Palette>, Vec<String>) {
    let mut warnings = Vec::new();
    let mut v: Vec<Palette> = BUILTIN.to_vec();
    for c in custom {
        if c.name.trim().is_empty() {
            warnings.push("custom theme without a name skipped".into());
            continue;
        }
        let base = if c.base.is_empty() {
            0
        } else {
            match v.iter().position(|t| t.name.eq_ignore_ascii_case(&c.base)) {
                Some(i) => i,
                None => {
                    warnings.push(format!("theme {}: unknown base \"{}\", using {}", c.name, c.base, BUILTIN[0].name));
                    0
                }
            }
        };
        let mut p = v[base];
        p.name = Box::leak(c.name.trim().to_string().into_boxed_str());
        match c.glyphs.to_ascii_lowercase().as_str() {
            "" => {}
            "modern" => p.glyphs = &MODERN,
            "neon" => p.glyphs = &NEON,
            "ascii" => p.glyphs = &ASCII,
            g => warnings.push(format!("theme {}: unknown glyphs \"{g}\" (modern, neon, ascii)", c.name)),
        }
        for (k, val) in &c.colors {
            let Some(col) = parse_color(val) else {
                warnings.push(format!("theme {}: bad colour {k} = \"{val}\"", c.name));
                continue;
            };
            let slot = match k.as_str() {
                "bg" => &mut p.bg,
                "fg" => &mut p.fg,
                "dim" => &mut p.dim,
                "muted" => &mut p.muted,
                "border" => &mut p.border,
                "sel_bg" => &mut p.sel_bg,
                "header_bg" => &mut p.header_bg,
                "blue" => &mut p.blue,
                "purple" => &mut p.purple,
                "cyan" => &mut p.cyan,
                "teal" => &mut p.teal,
                "green" => &mut p.green,
                "yellow" => &mut p.yellow,
                "orange" => &mut p.orange,
                "red" => &mut p.red,
                "pink" => &mut p.pink,
                other => {
                    warnings.push(format!("theme {}: unknown colour slot {other}", c.name));
                    continue;
                }
            };
            *slot = col;
        }
        // A custom theme with a built-in's name replaces it.
        match v.iter().position(|t| t.name.eq_ignore_ascii_case(p.name)) {
            Some(i) => v[i] = p,
            None => v.push(p),
        }
    }
    (v, warnings)
}

/// Which characters to draw with: `glyphs = …` in the config, `--glyphs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GlyphMode {
    /// Whatever the theme asks for.
    Theme,
    /// `SAFE` for every theme (ASCII themes stay ASCII).
    Safe,
    /// `ASCII` for every theme.
    Ascii,
}

static GLYPH_MODE: AtomicU8 = AtomicU8::new(0);

pub fn set_glyph_mode(m: GlyphMode) {
    GLYPH_MODE.store(m as u8, Ordering::Relaxed);
}

/// `auto`, `theme`, `safe` or `ascii` (None for anything else). `auto` looks
/// at the console vigil runs in.
pub fn parse_glyph_mode(s: &str) -> Option<GlyphMode> {
    match s.trim().to_ascii_lowercase().as_str() {
        "auto" | "" => Some(auto_glyph_mode(cfg!(windows), |k| std::env::var(k).ok().filter(|v| !v.is_empty()))),
        "theme" | "modern" | "full" => Some(GlyphMode::Theme),
        "safe" | "basic" => Some(GlyphMode::Safe),
        "ascii" => Some(GlyphMode::Ascii),
        _ => None,
    }
}

/// The consoles with a small font announce themselves: on Windows it is the
/// classic console window unless a modern terminal set its variable (Windows
/// Terminal, VS Code, WezTerm, Alacritty; over SSH the font is the client's).
/// On Linux it is the text console of a server or VM, `TERM=linux`.
pub fn auto_glyph_mode(windows: bool, env: impl Fn(&str) -> Option<String>) -> GlyphMode {
    let small_font = if windows {
        !["WT_SESSION", "TERM_PROGRAM", "WEZTERM_EXECUTABLE", "ALACRITTY_WINDOW_ID", "SSH_CONNECTION", "SSH_CLIENT"].iter().any(|k| env(k).is_some())
    } else {
        env("TERM").as_deref() == Some("linux")
    };
    if small_font {
        GlyphMode::Safe
    } else {
        GlyphMode::Theme
    }
}

#[inline]
pub fn glyphs() -> &'static Glyphs {
    let own = pal().glyphs;
    match GLYPH_MODE.load(Ordering::Relaxed) {
        2 => &ASCII,
        1 if !std::ptr::eq(own, &ASCII) => &SAFE,
        _ => own,
    }
}

/// True for themes that must stay within 7-bit ASCII.
pub fn is_ascii() -> bool {
    std::ptr::eq(glyphs(), &ASCII)
}

/// True when symbols beyond the basic console fonts must be avoided.
pub fn plain_symbols() -> bool {
    is_ascii() || std::ptr::eq(glyphs(), &SAFE)
}

/// A symbol in three grades: any Unicode font, the basic console fonts
/// (WGL4), 7-bit ASCII.
pub fn sym3(full: &'static str, safe: &'static str, ascii: &'static str) -> &'static str {
    if is_ascii() {
        ascii
    } else if plain_symbols() {
        safe
    } else {
        full
    }
}

/// `full` where the font has it, `plain` (ASCII) elsewhere.
pub fn sym(full: &'static str, plain: &'static str) -> &'static str {
    sym3(full, plain, plain)
}

/// The Enter key in hints.
pub fn enter() -> &'static str {
    sym("↵", "enter")
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
    CURRENT.store(i.min(all().len() - 1), Ordering::Relaxed);
}

pub fn by_name(name: &str) -> Option<usize> {
    all().iter().position(|t| t.name.eq_ignore_ascii_case(name))
}

/// Pick a sensible default: plain 16 colours when the terminal can't do truecolor.
pub fn names() -> Vec<&'static str> {
    all().iter().map(|t| t.name).collect()
}

pub fn auto_default() -> usize {
    let env = |k: &str| std::env::var(k).unwrap_or_default();
    let p = crate::platform::get();
    let truecolor = if p.os == crate::platform::Os::Windows {
        // Windows Terminal / VS Code / ConEmu, or Windows 10 1703+ conhost.
        std::env::var_os("WT_SESSION").is_some()
            || !env("TERM_PROGRAM").is_empty()
            || env("ConEmuANSI") == "ON"
            || p.windows_build.is_some_and(|b| b >= 15_063)
    } else {
        supports_truecolor(&env("COLORTERM"), &env("TERM"), &env("TERM_PROGRAM"))
    };
    if truecolor {
        0
    } else {
        by_name("ansi").unwrap_or(0)
    }
}

/// Decide whether the terminal can show 24-bit colour.
///
/// `COLORTERM` is the proper signal, but `sudo` strips it (env_reset keeps only
/// TERM, PATH, HOME, …). So we fall back to TERM: every modern terminal
/// emulator does truecolor, and the ones that don't announce themselves with a
/// basic TERM such as `linux` (the VT console), `vt100`, `screen` or `dumb`.
pub fn supports_truecolor(colorterm: &str, term: &str, term_program: &str) -> bool {
    if colorterm.contains("truecolor") || colorterm.contains("24bit") {
        return true;
    }
    if term_program == "Apple_Terminal" {
        return false; // Terminal.app before macOS 26 maps RGB to wrong colours
    }
    let t = term.to_ascii_lowercase();
    !(t.is_empty()
        || matches!(
            t.as_str(),
            "linux" | "dumb" | "ansi" | "vt100" | "vt102" | "vt220" | "xterm" | "screen" | "cons25"
        ))
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
    fn custom_themes() {
        let c = crate::config::CustomTheme {
            name: "noc".into(),
            base: "nord".into(),
            glyphs: "ascii".into(),
            colors: [("bg".to_string(), "#000000".to_string()), ("red".into(), "light-red".into()), ("blue".into(), "ansi:33".into()), ("nope".into(), "#fff".into())].into_iter().collect(),
        };
        let (v, w) = build(&[c, crate::config::CustomTheme { name: "x".into(), base: "missing".into(), ..Default::default() }]);
        let t = v.iter().find(|t| t.name == "noc").unwrap();
        assert_eq!(t.bg, Color::Rgb(0, 0, 0));
        assert_eq!(t.red, Color::LightRed);
        assert_eq!(t.blue, Color::Indexed(33));
        assert!(std::ptr::eq(t.glyphs, &ASCII));
        assert_eq!(v.len(), BUILTIN.len() + 2);
        assert_eq!(w.len(), 2, "{w:?}"); // "nope" slot (and bad #fff) + unknown base
        assert_eq!(parse_color("#12ab3C"), Some(Color::Rgb(0x12, 0xab, 0x3c)));
        assert_eq!(parse_color("Dark Gray"), Some(Color::DarkGray));
        assert_eq!(parse_color("#fff"), None);
    }

    #[test]
    fn theme_names_unique_and_resolvable() {
        for (i, t) in all().iter().enumerate() {
            assert_eq!(by_name(t.name), Some(i));
        }
    }

    #[test]
    fn small_console_fonts_get_the_safe_glyphs() {
        let env = |pairs: &'static [(&'static str, &'static str)]| move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string());
        // Windows: the classic console window, unless a modern terminal says otherwise.
        assert_eq!(auto_glyph_mode(true, env(&[])), GlyphMode::Safe);
        assert_eq!(auto_glyph_mode(true, env(&[("ConEmuPID", "4242")])), GlyphMode::Safe);
        for var in ["WT_SESSION", "TERM_PROGRAM", "WEZTERM_EXECUTABLE", "ALACRITTY_WINDOW_ID", "SSH_CONNECTION"] {
            let pairs: &'static [(&'static str, &'static str)] = Box::leak(vec![(var, "x")].into_boxed_slice());
            assert_eq!(auto_glyph_mode(true, env(pairs)), GlyphMode::Theme, "{var}");
        }
        // Linux and macOS: only the text console of a server or VM.
        assert_eq!(auto_glyph_mode(false, env(&[("TERM", "linux")])), GlyphMode::Safe);
        assert_eq!(auto_glyph_mode(false, env(&[("TERM", "xterm-256color")])), GlyphMode::Theme);
        assert_eq!(auto_glyph_mode(false, env(&[])), GlyphMode::Theme);
        assert_eq!(parse_glyph_mode("Safe"), Some(GlyphMode::Safe));
        assert_eq!(parse_glyph_mode("ascii"), Some(GlyphMode::Ascii));
        assert_eq!(parse_glyph_mode("theme"), Some(GlyphMode::Theme));
        assert_eq!(parse_glyph_mode("sparkles"), None);
    }

    /// WGL4 block elements and box drawing, plus Latin-1: what Consolas,
    /// Lucida Console and the Linux console fonts all have.
    #[test]
    fn safe_glyphs_stay_within_basic_console_fonts() {
        let ok = |c: char| c.is_ascii() || matches!(c, '─' | '│' | '┌' | '┐' | '└' | '┘' | '▀' | '▄' | '█' | '▌' | '▐' | '■' | '¯');
        let g = &SAFE;
        let b = &g.border;
        let strs = [b.top_left, b.top_right, b.bottom_left, b.bottom_right, b.vertical_left, b.vertical_right, b.horizontal_top, b.horizontal_bottom, g.meter_on, g.meter_off, g.select, g.divider, g.track, g.thumb];
        for c in strs.iter().flat_map(|s| s.chars()).chain(g.graph).chain(g.graph_down).chain(g.spark) {
            assert!(ok(c), "U+{:04X} {c} is not in the basic console fonts", c as u32);
        }
        // Graph levels still rise with the value.
        let rank = |c: char| [' ', '_', '▄', '█'].iter().position(|x| *x == c).unwrap();
        assert!(g.graph.windows(2).all(|w| rank(w[0]) <= rank(w[1])) && g.spark.windows(2).all(|w| rank(w[0]) <= rank(w[1])));
    }

    #[test]
    fn truecolor_detection() {
        // sudo on Ubuntu: COLORTERM stripped, TERM kept.
        assert!(supports_truecolor("", "xterm-256color", ""));
        assert!(supports_truecolor("", "xterm-kitty", ""));
        assert!(supports_truecolor("truecolor", "screen", ""));
        assert!(!supports_truecolor("", "linux", ""));
        assert!(!supports_truecolor("", "vt100", ""));
        assert!(!supports_truecolor("", "", ""));
        assert!(!supports_truecolor("", "xterm-256color", "Apple_Terminal"));
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
