//! Tokyo-night inspired palette with gradient helpers.

use ratatui::style::Color;

pub const FG: Color = Color::Rgb(192, 202, 245);
pub const DIM: Color = Color::Rgb(86, 95, 137);
pub const MUTED: Color = Color::Rgb(122, 132, 178);
pub const BORDER: Color = Color::Rgb(59, 66, 97);
pub const SEL_BG: Color = Color::Rgb(41, 46, 66);
pub const HEADER_BG: Color = Color::Rgb(26, 27, 38);

pub const BLUE: Color = Color::Rgb(122, 162, 247);
pub const PURPLE: Color = Color::Rgb(187, 154, 247);
pub const CYAN: Color = Color::Rgb(125, 207, 255);
pub const TEAL: Color = Color::Rgb(115, 218, 202);
pub const GREEN: Color = Color::Rgb(158, 206, 106);
pub const YELLOW: Color = Color::Rgb(224, 175, 104);
pub const ORANGE: Color = Color::Rgb(255, 158, 100);
pub const RED: Color = Color::Rgb(247, 118, 142);
pub const PINK: Color = Color::Rgb(255, 117, 181);

fn rgb(c: Color) -> (f64, f64, f64) {
    match c {
        Color::Rgb(r, g, b) => (r as f64, g as f64, b as f64),
        _ => (255.0, 255.0, 255.0),
    }
}

pub fn lerp(a: Color, b: Color, t: f64) -> Color {
    let t = t.clamp(0.0, 1.0);
    let (ar, ag, ab) = rgb(a);
    let (br, bg, bb) = rgb(b);
    Color::Rgb(
        (ar + (br - ar) * t) as u8,
        (ag + (bg - ag) * t) as u8,
        (ab + (bb - ab) * t) as u8,
    )
}

/// Green → yellow → red for a 0..100 percentage.
pub fn heat(pct: f64) -> Color {
    let p = pct.clamp(0.0, 100.0) / 100.0;
    if p < 0.5 {
        lerp(GREEN, YELLOW, p * 2.0)
    } else {
        lerp(YELLOW, RED, (p - 0.5) * 2.0)
    }
}

pub fn tcp_state(state: &str) -> Color {
    match state {
        "LISTEN" => GREEN,
        "ESTABLISHED" => CYAN,
        "TIME_WAIT" | "FIN_WAIT1" | "FIN_WAIT_1" | "FIN_WAIT2" | "FIN_WAIT_2" => YELLOW,
        "CLOSE_WAIT" | "LAST_ACK" | "CLOSING" => ORANGE,
        "SYN_SENT" | "SYN_RECV" | "SYN_RECEIVED" => PURPLE,
        "CLOSED" => RED,
        _ => MUTED,
    }
}

pub fn file_type(t: &str) -> Color {
    match t {
        "REG" => FG,
        "DIR" => BLUE,
        "IPv4" | "IPv6" => CYAN,
        "unix" => PURPLE,
        "PIPE" | "FIFO" => YELLOW,
        "CHR" => TEAL,
        "KQUEUE" | "a_inode" => MUTED,
        _ => DIM,
    }
}
