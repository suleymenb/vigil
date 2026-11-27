#!/usr/bin/env python3
"""Build the Overview mockup in docs/handbook.html with exact column widths.

The mockup shows a fictional server (nothing from a real machine). Every
panel is assembled from fixed-width pieces, so borders always line up; run
scripts/term2svg.py afterwards to refresh docs/img/overview.svg.

    python3 scripts/overview_mockup.py && python3 scripts/term2svg.py
"""
import html
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HANDBOOK = ROOT / "docs" / "handbook.html"
W = 136  # total columns

# A line is a list of (text, css classes or "") runs.


def width(line):
    return sum(len(t) for t, _ in line)


def pad(line, n):
    w = width(line)
    assert w <= n, (w, n, "".join(t for t, _ in line))
    return line + [(" " * (n - w), "")]


def to_html(line):
    out = []
    for text, cls in line:
        t = html.escape(text, quote=False)
        if " u" in cls:  # underline: <u> inside the span, as the handbook CSS expects
            cls, t = cls.replace(" u", ""), f"<u>{t}</u>"
        out.append(f'<span class="{cls}">{t}</span>' if cls else t)
    return "".join(out)


def box(title, w, body, right=None):
    """A rounded panel `w` columns wide around `body` lines."""
    top = [("╭", "bd"), (" ", "")] + title + [(" ", "")]
    if right:
        fill = w - width(top) - width(right) - 2
        top += [("─" * fill, "bd")] + right + [(" ", ""), ("╮", "bd")]
    else:
        top += [("─" * (w - width(top) - 1), "bd"), ("╮", "bd")]
    lines = [top]
    for b in body:
        lines.append([("│", "bd")] + pad(b, w - 2) + [("│", "bd")])
    lines.append([("╰" + "─" * (w - 2) + "╯", "bd")])
    assert all(width(l) == w for l in lines), [width(l) for l in lines]
    return lines


def hstack(*blocks):
    assert len({len(b) for b in blocks}) == 1
    return [sum(rows, []) for rows in zip(*blocks)]


def heat(v):
    return "g" if v < 50 else "y" if v < 75 else "o"


def meter(pct, n):
    on = round(pct / 100 * n)
    runs = []
    for i in range(on):
        runs.append(("■", heat((i + 1) / n * 100)))
    runs.append(("■" * (n - on), "bd"))
    return merge(runs)


def merge(runs):
    out = []
    for t, c in runs:
        if out and out[-1][1] == c:
            out[-1] = (out[-1][0] + t, c)
        else:
            out.append((t, c))
    return out


SPARK = " ▁▂▃▄▅▆▇█"


def series(n, points):
    """`n` values through evenly spaced control `points` (linear)."""
    out = []
    for i in range(n):
        x = i / max(1, n - 1) * (len(points) - 1)
        a = int(x)
        b = min(a + 1, len(points) - 1)
        out.append(points[a] + (points[b] - points[a]) * (x - a))
    return out


def spark(vals, cls):
    return [("".join(SPARK[max(1, min(8, round(v / 100 * 8)))] for v in vals), cls)]


def area(vals, rows, cls_of):
    """Area graph: `rows` lines, bottom-up fill with eighth blocks."""
    out = []
    for r in range(rows - 1, -1, -1):
        runs = []
        for v in vals:
            fill = max(0, min(8, round(v / 100 * rows * 8 - r * 8)))
            runs.append((SPARK[fill], cls_of(v) if fill else ""))
        out.append(merge(runs))
    return out


def tab_row(active="Overview"):
    """The tab row exactly as vigil draws it at this width (inactive tabs
    shrink to their key, longest names first, until the row fits)."""
    tabs = [("1", "Overview"), ("2", "Procs"), ("3", "Network"), ("4", "Sockets"), ("5", "Files"), ("6", "Storage"),
            ("7", "Routes"), ("8", "Probes"), ("9", "Firewall"), ("0", "Containers"), ("S", "System"), ("U", "Users"),
            ("W", "Troubleshoot")]
    short = [False] * len(tabs)
    total = lambda: sum((1 if s else len(k) + 1 + len(t)) + 2 for (k, t), s in zip(tabs, short)) + len(tabs) - 1
    for i in sorted((i for i, (_, t) in enumerate(tabs) if t != active), key=lambda i: -len(tabs[i][1])):
        if total() <= W:
            break
        short[i] = True
    line = []
    for n, ((k, t), s) in enumerate(zip(tabs, short)):
        if n:
            line.append(("│", "bd"))
        line.append((" ", ""))
        line.append((k, "d"))
        if not s:
            line.append((" ", ""))
            line.append((t, "b w u" if t == active else "m"))
        line.append((" ", ""))
    return line


def build():
    left = [(" ◆ vigil ", "badge"), (" ", ""), ("prod-web-01", "c w"), ("  Ubuntu 24.04.1 LTS", "m"), ("  6.8.0-45-generic x86_64", "d"),
            ("  up ", "d"), ("41d 06:12", "g"), ("  load ", "d"), ("1.84", "g"), (" ", ""), ("1.62", "g"), (" ", ""), ("1.40", "g"),
            ("  procs ", "d"), ("214", "p")]
    right = [("● live", "g"), ("  1000ms ", "d"), (" root ", "sig")]
    head = pad(left, W - width(right)) + right
    tabs = pad(tab_row(), W)
    alerts = pad([(" ", ""), ("✓ healthy ", "g"), ("no thresholds crossed", "d")], W)

    # cpu: total meter + area graph on the left, cores on the right
    left_w = W - 2 - 2 * 28
    cpu_vals = series(left_w - 2, [10, 14, 12, 20, 26, 18, 31, 36, 27, 42, 51, 44, 37, 45, 60, 66, 50, 47, 61, 78, 84, 71, 59, 52, 48, 53, 47, 42])
    graph = area(cpu_vals, 4, heat)
    cpu_left = [[(" total ", "d"), ("38.2%", "y w"), ("  ", "")] + meter(38, left_w - 16) + [(" ", "")]]
    cpu_left += [[(" ", "")] + g + [(" ", "")] for g in graph]
    cores = [(0, 44, [52, 58, 61, 66, 70, 62, 58, 63]), (1, 33, [36, 40, 41, 48, 41, 40, 42, 47]), (2, 71, [60, 66, 74, 82, 83, 76, 69, 84]),
             (3, 24, [24, 25, 32, 33, 26, 31, 27, 30]), (4, 47, [51, 50, 57, 58, 52, 57, 58, 57])]
    cores2 = [(8, 21, [22, 23, 30, 24, 22, 30, 24, 23]), (9, 29, [26, 34, 27, 35, 36, 33, 27, 34]), (10, 18, [12, 22, 21, 23, 13, 21, 20, 22]),
              (11, 31, [33, 34, 25, 33, 43, 34, 33, 33]), (12, 22, [21, 22, 24, 30, 23, 22, 31, 23])]

    def core(n, pct, hist):
        return [(f"C{n:<3}", "m")] + meter(pct, 8) + [(f" {pct:>3}% ", heat(pct))] + spark(hist, heat(pct)) + [("  ", "")]

    cpu_body = [pad(l, left_w) + core(*a) + core(*b) for l, a, b in zip(cpu_left, cores, cores2)]
    cpu = box([("cpu", "b w"), ("  AMD EPYC 7763  8c/16t  54°C", "w")], W, cpu_body)

    mem_body = [
        [(" ram  ", "m")] + meter(64, 26) + [("  64% ", "y w"), ("20.1G/31.3G", "")],
        [(" swap ", "m")] + meter(3, 26) + [("   3% ", "g w"), ("128M/4.00G", "")],
        [(" available ", "d"), ("11.2G", "g")],
        [(" " * 13, "")] + spark(series(36, [20, 38, 48, 56, 64, 70, 73, 75, 76, 76]), "p"),
    ]
    mem = box([("memory", "p w")], 52, mem_body)
    rx = series(78, [30, 52, 30, 52, 44, 60, 76, 58, 76, 68, 80, 70, 84, 70, 86, 76, 88, 80, 88, 78])
    net_rows = area(rx, 2, lambda v: "te" if v < 60 else "g")
    tx = "".join("█" if (i // 5) % 3 == 1 else "▀" for i in range(len(rx)))
    net_body = [
        [(" ", ""), ("▼ rx", "g w"), (" 41.7M/s      ", ""), ("▲ tx", "o w"), (" 12.3M/s      ", ""), ("peak ", "d"), ("52.9M/s / 18.0M/s", "m")],
        [(" ", "")] + net_rows[0],
        [(" ", "")] + net_rows[1],
        [(" ", ""), (tx, "y")],
    ]
    net = box([("network", "c w")], W - 52, net_body, right=[(" scale ", "d"), ("58.2M/s", "m")])

    procs_body = [[(" PID     NAME            USER         CPU%   MEM", "b w")]]
    for pid, name, user, cpuv, memv, ucls in [("4121", "nginx", "www-data", 71.4, "212M", "te"), ("2290", "postgres", "postgres", 38.0, "4.1G", "te"),
                                             ("3307", "node", "deploy", 22.6, "880M", "te"), ("1877", "redis-server", "redis", 4.1, "96M", "te"),
                                             ("612", "containerd", "root", 1.2, "74M", "r")]:
        procs_body.append([(" ", ""), (f"{pid:<8}", "d"), (f"{name:<16}", ""), (f"{user:<12}", ucls), (f"{cpuv:>5.1f}", heat(cpuv)), (f"  {memv:>4}", "p")])
    procs = box([("top processes", "g w")], 50, procs_body)
    ports_body = [[(" PORT  PROTO PROCESS            PID", "b w")]]
    for port, proc, pid in [("22", "sshd", "912"), ("80", "nginx", "4120"), ("443", "nginx", "4120"), ("3000", "node", "3307"), ("5432", "postgres", "2290")]:
        ports_body.append([(" ", ""), (f"{port:<6}", "g w"), ("TCP   ", "c"), (f"{proc:<18}", ""), (f"{pid:>4}", "d")])
    ports = box([("listening ports (6)", "g w")], 42, ports_body)
    conn_body = [[(" ", "")]]
    for state, n, cls in [("ESTABLISHED", "1 284", "c"), ("TIME_WAIT", "611", "y"), ("LISTEN", "6", "g"), ("CLOSE_WAIT", "14", "o"), ("SYN_SENT", "2", "p")]:
        conn_body.append([(" ", ""), (f"{state:<16}", cls), (f"{n:>12}", "w")])
    conn_body = conn_body[1:] + [[(" ", ""), (f"{'UDP':<16}", "m"), (f"{'9':>12}", "w")]]
    conns = box([("connections", "c w")], W - 50 - 42, conn_body)

    foot = []
    for k, label in [("F", "find"), ("h", "explain"), (":", "lsof query"), ("R", "report"), ("T", "theme"), ("space", "pause"), ("?", "help"), ("q", "quit")]:
        foot += [(" ", ""), (k, "b w"), (" ", ""), (label, "d"), (" ", "")]

    lines = [head, tabs, alerts] + cpu + hstack(mem, net) + hstack(procs, ports, conns) + [foot]
    for l in lines[:-1]:
        assert width(l) == W, (width(l), "".join(t for t, _ in l))
    return "\n".join(to_html(l) for l in lines)


def main():
    src = HANDBOOK.read_text(encoding="utf-8")
    first = re.search(r"<pre>.*?</pre>", src, re.S)
    src = src[: first.start()] + "<pre>" + build() + "</pre>" + src[first.end():]
    HANDBOOK.write_text(src, encoding="utf-8")
    print("updated the Overview mockup in", HANDBOOK)


if __name__ == "__main__":
    main()
