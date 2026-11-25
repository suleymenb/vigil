# vigil ◆

A modern terminal system monitor written in Rust, built for DevOps, networking and Linux
administration. Inspired by btop, with **lsof** as a first-class citizen.

Runs on **Linux** and **macOS**. Single static binary, ~1.5 MB, ~2.5 % of one core at a 1 s refresh.

📖 **[Handbook with playbooks and diagrams](docs/handbook.html)**

## Views

| # | View | What you get |
|---|------|--------------|
| 1 | **Overview** | Gradient CPU graph, per-core meters + sparklines, RAM/swap, rx/tx graphs, top processes, **listening ports**, TCP state counts, disks |
| 2 | **Processes** | Sortable table with CPU, memory, disk I/O per second, **sockets per process**, state, uptime, full command line. Tree view, filter, send signals, detail pane |
| 3 | **Network** | Every interface: rates, totals, packets, errors, MAC, addresses. Per-interface traffic graph, top remote peers |
| 4 | **Sockets** | Live socket table: proto, local/remote, colour-coded TCP state, pid, process, user, fd. Listening-only mode |
| 5 | **Open Files** | On-demand lsof queries: by pid, port, path ("who has this file open?") or raw lsof arguments |
| 6 | **Storage** | Filesystem usage, disk I/O per process, temperature sensors |

`vigil report` prints a **point-in-time report** (Markdown or JSON) for tickets, cron jobs and
post-mortems; `R` writes the same report from inside the TUI.

The header shows **health badges** on every view (memory, swap, disk, load, CLOSE_WAIT,
TIME_WAIT, temperature and, on Linux, PSI pressure) as soon as a threshold is crossed.

## Install

Pre-built binaries for Linux (x86_64, aarch64, static musl) and macOS (Apple Silicon, Intel)
are attached to every [GitHub release](https://github.com/suleymenb/vigil/releases).

```bash
tar xzf vigil-*-x86_64-unknown-linux-musl.tar.gz && sudo mv vigil /usr/local/bin/
```

Or build from source:

```bash
cargo install --git https://github.com/suleymenb/vigil
```

Requires `lsof` for the Open Files view (preinstalled on macOS; `apt install lsof` / `dnf install lsof`).

> **Tip:** run `sudo vigil` to see sockets and open files of **all** users.
> Without root, lsof only shows your own processes.

## Usage

```
vigil [OPTIONS]
vigil report [-f md|json] [-o FILE] [--top N] [--sample-ms MS] [--fail-on-alert]

  -i, --interval <ms>         sampling interval (default 1000)
      --lsof-interval <sec>   socket scan interval (default 3)
  -t, --tab <name>            start view: overview, processes, network, sockets, files, storage
  -q, --query <query>         run an lsof query at startup, e.g. ":443" or "1234"
      --theme <name>          colour theme, or "auto"
      --list-themes           list themes and exit
      --config <path>         use a different config file
      --no-save               don't write settings back on quit
      --no-mouse              disable mouse support
      --lsof-sockets          use lsof -i instead of /proc/net (Linux)
```

```bash
sudo vigil -t sockets           # straight to the socket table
sudo vigil -q :5432             # who is using the postgres port?
vigil -q /var/log/syslog        # who has this log file open?
vigil --theme ansi              # 16-colour mode for plain SSH / tmux sessions
sudo vigil report > incident.md # snapshot for a ticket
vigil report -f json | jq .health
```

### Reports

`vigil report` samples the system for one second and prints: health, system info, CPU and
load, memory and swap, PSI, top processes by CPU and memory (with socket counts), listening
ports with an **exposed** flag for services bound to every interface, connection states, top
remote peers, interfaces, filesystems and temperatures.

```bash
# cron: mail a report only when something is wrong
*/5 * * * * vigil report --fail-on-alert -o /tmp/vigil.md || mail -s "vigil: $(hostname)" ops@example.com < /tmp/vigil.md
```

`--fail-on-alert` exits with code 2 when any `[alerts]` threshold is exceeded.

## Keys

**Global**

| Key | Action |
|-----|--------|
| `1`–`6`, `Tab`, `←` `→` | switch view |
| `↑` `↓` `j` `k` `PgUp` `PgDn` `g` `G` | navigate (mouse wheel works too) |
| `/` | filter the current list (`Esc` clears) |
| `:` | lsof query (see below) |
| `T` | theme picker with live preview (`b` toggles the background) |
| `R` | write a Markdown report to `./vigil-report-<time>.md` |
| `space` | pause / resume |
| `+` / `-` | refresh interval ±250 ms |
| `?` | help |
| `q`, `Ctrl-C` | quit |

**Processes**: `c` `m` `p` `n` `u` `i` `o` sort by cpu / mem / pid / name / user / io / connections
(press again to reverse), `r` reverse, `t` process tree, `Enter`/`f` open files of the process
(`lsof -p`), `x`/`K`/`Del` send a signal (TERM, KILL, HUP, INT, QUIT, STOP, CONT, USR1, USR2).

**Sockets**: `l` listening only, `s` cycle sort (process / port / state / proto / remote),
`Enter` open files of the owner, `P` everything on this port, `x` signal the owner.

**Open Files**: `Enter` who else has this file / port open, `p` all files of this pid,
`r` rerun the query, `x` signal.

### lsof query syntax (`:`)

| Input | Runs |
|-------|------|
| `1234` | `lsof -nP -p 1234` |
| `:8080` | `lsof -nP -i :8080` |
| `tcp:443`, `udp`, `@10.0.0.5` | `lsof -nP -i <input>` |
| `/var/lib/docker` | `lsof -nP /var/lib/docker` |
| `+L1` | deleted files that are still open (the classic "disk full but `du` disagrees") |
| `-u www-data -i` | raw arguments: `lsof -nP -u www-data -i` |

## Themes

`tokyo-night` · `catppuccin-mocha` · `gruvbox` · `nord` · `dracula` · `rose-pine` ·
`solarized-light` · `cyberpunk` · `phosphor` · `ansi`

Themes change glyphs as well as colours:

- **cyberpunk**: neon cyan, magenta and yellow on near-black, thick frames and `▰▱` meters.
- **phosphor**: a green P1 phosphor CRT. Pure 7-bit ASCII (`+--+`, `###...`, `|-` trees),
  monochrome green, and severity shown only by brightness, like a VT100.

`ansi` uses your terminal's own 16 colours, so it works over plain SSH, in tmux without
truecolor and on serial consoles. With `theme = "auto"` (the default), vigil picks `ansi` only
on terminals that can't show 24-bit colour (the Linux VT console, `vt100`, `screen`, `dumb`);
everything else gets `tokyo-night`. A theme is only written to the config when you pick it
with `T` and confirm with Enter.

## Configuration

Settings live in `~/.config/vigil/config.toml` (or `$XDG_CONFIG_HOME/vigil/config.toml`), on
macOS too. Under `sudo`, vigil uses the config of the user who ran sudo (not root's), so
`vigil` and `sudo vigil` share one set of settings. Theme, interval, sort order and tree mode are saved on quit. Precedence is
command-line flags, then the config file, then defaults. A broken config never stops vigil:
it falls back to defaults and shows a warning.

```toml
theme = "nord"
background = true          # false = keep the terminal's own (transparent) background
interval_ms = 1000
lsof_interval_s = 3
start_tab = "overview"
proc_sort = "cpu"
proc_desc = true
proc_tree = false
mouse = true

[alerts]                   # 0 disables a check
mem_pct = 90.0
swap_pct = 50.0
disk_pct = 90.0
load_per_core = 1.5        # 1-minute load / logical cores
close_wait = 100
time_wait = 20000
temp_c = 90.0
psi_pct = 20.0             # Linux PSI "some avg10" for cpu / memory / io
```

## Architecture

```
src/
├── main.rs            CLI (clap), config precedence, terminal setup, event loop
├── app.rs             state, sorting, process tree, caches, alerts, key handling
├── config.rs          TOML config, atomic save
├── theme.rs           10 palettes + glyph sets behind one atomic index
├── report.rs          `vigil report` / `R`: Markdown and JSON snapshots
├── util.rs            formatting, ring-buffer history, sparklines
├── collect/
│   ├── system.rs      sysinfo sampler + slow thread for disks/sensors, PSI
│   ├── procnet.rs     native Linux /proc/net socket reader
│   └── lsof.rs        lsof -F parser, socket worker, async queries
└── ui/
    ├── mod.rs         header, health badges, footer, help, dialogs
    ├── overview.rs    dashboard
    ├── views.rs       processes, network, sockets, files, storage
    └── widgets.rs     gradient area graph (1/8 cell resolution), meters
```

Performance choices, all measured (see the handbook for numbers):

- Collectors run on background threads; the UI thread only handles input and drawing.
- On Linux, sockets come straight from `/proc/net/{tcp,udp}[6]` (including TIME_WAIT,
  which lsof can't show). The inode-to-pid map is cached. `--lsof-sockets` forces lsof.
- Sensors are refreshed one by one instead of re-enumerated (108 ms → ~1 ms each on macOS).
- sysinfo runs single-threaded: waking a rayon pool per tick cost more than it saved.
- The screen is only redrawn when something changed (input, tick, or new background data).
- Socket and file lists are re-filtered only when their inputs change; tables only build
  the visible rows.
- Per-process strings (name, cmd, exe, user) are cached per pid as `Arc<str>`.

## Development

```bash
cargo test                                            # unit + render tests (all views, all themes, many sizes)
cargo clippy --all-targets
cargo run --release --example prof                    # collector micro-profile
cargo test --release bench_ -- --ignored --nocapture  # hot-path benchmark
```

Releases are built by GitHub Actions when a `v*` tag is pushed.

## License

MIT
