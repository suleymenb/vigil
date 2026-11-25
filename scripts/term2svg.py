#!/usr/bin/env python3
"""Render the terminal mockups in docs/handbook.html to SVG screenshots.

The mockups use fictional server data, so the README never shows anything
from a real machine. Usage:

    python3 scripts/term2svg.py            # writes docs/img/*.svg
"""
import html
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "handbook.html"
OUT = ROOT / "docs" / "img"

# tokyo-night, same values as src/theme.rs
BG, FG = "#1a1b26", "#c0caf5"
COLORS = {
    "b": "#7aa2f7", "p": "#bb9af7", "c": "#7dcfff", "te": "#73daca", "g": "#9ece6a",
    "y": "#e0af68", "o": "#ff9e64", "r": "#f7768e", "d": "#565f89", "m": "#7a84b2",
    "bd": "#4a5378", "w": FG,
}
# classes that paint a background (fg becomes the terminal background)
BACKGROUNDS = {
    "badge": "#7aa2f7", "chip-l": "#9ece6a", "chip-e": "#7dcfff", "chip-t": "#e0af68",
    "chip-c": "#ff9e64", "chip-s": "#bb9af7", "sig": "#f7768e", "sel": "#292e42",
}
CW, LH, FS, PAD, TOP = 7.8, 18, 13, 18, 40

TOKEN = re.compile(r'<span class="([^"]+)">|</span>|<u>|</u>|[^<]+')


def runs(line):
    """Yield (text, fg, bg, bold, underline) runs for one line of mockup HTML."""
    stack = []
    under = False
    for m in TOKEN.finditer(line):
        t = m.group(0)
        if m.group(1):
            stack.append(m.group(1).split())
        elif t == "</span>":
            if stack:
                stack.pop()
        elif t == "<u>":
            under = True
        elif t == "</u>":
            under = False
        else:
            fg, bg, bold = FG, None, False
            for classes in stack:
                for c in classes:
                    if c in COLORS:
                        fg = COLORS[c]
                    if c == "w":
                        bold = True
                    if c in BACKGROUNDS:
                        bg = BACKGROUNDS[c]
                        if c != "sel":
                            fg, bold = BG, True
            yield html.unescape(t), fg, bg, bold, under


def render(pre, title):
    lines = pre.split("\n")
    width_cols = max(len(html.unescape(re.sub(r"<[^>]+>", "", l))) for l in lines)
    w = int(width_cols * CW + 2 * PAD)
    h = int(len(lines) * LH + TOP + PAD)
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="{html.escape(title)}">',
        f'<rect width="{w}" height="{h}" rx="10" fill="{BG}"/>',
        '<circle cx="20" cy="18" r="6" fill="#f7768e"/><circle cx="40" cy="18" r="6" fill="#e0af68"/><circle cx="60" cy="18" r="6" fill="#9ece6a"/>',
        f'<text x="{w / 2:.0f}" y="22" fill="#565f89" font-family="ui-monospace,Menlo,Consolas,monospace" font-size="12" text-anchor="middle">{html.escape(title)}</text>',
        f'<g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,DejaVu Sans Mono,monospace" font-size="{FS}" xml:space="preserve">',
    ]
    for i, line in enumerate(lines):
        y = TOP + i * LH
        col = 0
        for text, fg, bg, bold, under in runs(line):
            n = len(text)
            x = PAD + col * CW
            if bg:
                out.append(f'<rect x="{x:.1f}" y="{y - 1}" width="{n * CW:.1f}" height="{LH}" fill="{bg}"/>')
            # Place every word at its exact column so fonts with slightly
            # different advance widths can't drift or stretch spaces.
            for w in re.finditer(r"\S+", text):
                chunk = w.group(0)
                wx = x + w.start() * CW
                attrs = f'x="{wx:.1f}" y="{y + 13}" fill="{fg}" textLength="{len(chunk) * CW:.1f}" lengthAdjust="spacingAndGlyphs"'
                if bold:
                    attrs += ' font-weight="700"'
                if under:
                    attrs += ' text-decoration="underline"'
                out.append(f"<text {attrs}>{html.escape(chunk)}</text>")
            col += n
    out.append("</g></svg>")
    return "\n".join(out)


def main():
    src = SRC.read_text(encoding="utf-8")
    pres = re.findall(r"<pre>(.*?)</pre>", src, re.S)
    if len(pres) < 3:
        sys.exit("expected three <pre> mockups in docs/handbook.html")
    OUT.mkdir(parents=True, exist_ok=True)
    for name, pre, title in [
        ("overview.svg", pres[0], "sudo vigil"),
        ("probes.svg", pres[1], "sudo vigil -t probes"),
        ("sockets.svg", pres[2], "sudo vigil -t sockets"),
    ]:
        (OUT / name).write_text(render(pre, title), encoding="utf-8")
        print("wrote", OUT / name)


if __name__ == "__main__":
    main()
