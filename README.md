# vigil ◆

Een moderne terminal-monitoringtool in Rust voor DevOps, networking en Linux-beheer.
Geïnspireerd op btop, met **lsof** als volwaardig onderdeel.

Werkt op **Linux** en **macOS**.

## Views

| # | View | Wat je ziet |
|---|------|-------------|
| 1 | **Overview** | CPU-grafiek (gradient), per-core meters + sparklines, RAM/swap, rx/tx-grafieken, top-processen, **luisterende poorten** (via lsof), verbindingsstatussen, disks |
| 2 | **Processes** | Sorteerbare tabel met CPU, MEM, disk-I/O per seconde, **aantal sockets per proces**, status, uptime, volledig commando. Boomweergave, filter, signalen sturen, detailpaneel |
| 3 | **Network** | Alle interfaces: rates, totalen, pakketten, errors, MAC, IP-adressen. Traffic-grafiek per interface, top remote peers |
| 4 | **Sockets** | `lsof -nP -i` live (achtergrond-thread): proto, local/remote, TCP-state (kleurgecodeerd), proces, user, fd. Alleen-LISTEN-modus |
| 5 | **Open Files** | Ad-hoc lsof-queries: per pid, per poort, per pad ("wie heeft dit bestand open?") of ruwe lsof-argumenten |
| 6 | **Storage** | Filesystems met gebruik, disk-I/O per proces, temperatuursensoren |

## Installatie

```bash
cargo install --path .
```

Of alleen bouwen:

```bash
cargo build --release && ./target/release/vigil
```

Vereist `lsof` (standaard op macOS; op Linux: `apt install lsof` / `dnf install lsof`).

> **Tip:** start met `sudo vigil` om sockets en open bestanden van **alle** gebruikers te zien.
> Zonder root toont lsof alleen je eigen processen.

## Opties

```
vigil [OPTIONS]
  -i, --interval <ms>         sample-interval (default 1000)
      --lsof-interval <sec>   interval van de lsof -i scan (default 3)
  -t, --tab <naam>            start-view: overview, processes, network, sockets, files, storage
  -q, --query <query>         lsof-query bij start, bv. ":443" of "1234"
      --no-mouse              muisondersteuning uit
      --lsof-sockets          gebruik lsof -i i.p.v. /proc/net (Linux)
```

Voorbeelden:

```bash
sudo vigil -t sockets           # direct naar sockets
sudo vigil -q :5432             # wie gebruikt postgres-poort 5432?
vigil -q /var/log/syslog        # wie heeft dit logbestand open?
```

## Toetsen

**Globaal**

| Toets | Actie |
|-------|-------|
| `1`–`6`, `Tab`, `←` `→` | view wisselen |
| `↑` `↓` `j` `k` `PgUp` `PgDn` `g` `G` | navigeren (muiswiel werkt ook) |
| `/` | filter op de huidige lijst (`Esc` wist) |
| `:` | lsof-query (zie hieronder) |
| `space` | pauzeren / hervatten |
| `+` / `-` | refresh-interval ±250 ms |
| `?` | help |
| `q`, `Ctrl-C` | afsluiten |

**Processes** — `c` `m` `p` `n` `u` `i` `o` sorteren op cpu/mem/pid/naam/user/io/connecties (nogmaals = omkeren),
`r` omkeren, `t` procesboom, `Enter`/`f` open files van het proces (`lsof -p`),
`x`/`K`/`Del` signaal sturen (TERM, KILL, HUP, INT, QUIT, STOP, CONT, USR1, USR2).

**Sockets** — `l` alleen luisterende sockets, `s` sortering wisselen (process/port/state/proto/remote),
`Enter` open files van de eigenaar, `P` alles op deze poort, `x` signaal naar eigenaar.

**Open Files** — `Enter` wie heeft dit bestand/deze poort nog meer open, `p` alle files van deze pid,
`r` query opnieuw uitvoeren, `x` signaal.

### lsof-querysyntax (`:`)

| Invoer | Wordt |
|--------|-------|
| `1234` | `lsof -nP -p 1234` |
| `:8080` | `lsof -nP -i :8080` |
| `tcp:443`, `udp`, `@10.0.0.5` | `lsof -nP -i <invoer>` |
| `/var/lib/docker` | `lsof -nP /var/lib/docker` |
| `-u www-data -i` | ruwe argumenten: `lsof -nP -u www-data -i` |

## Architectuur

```
src/
├── main.rs            CLI (clap), terminal setup, event loop
├── app.rs             state, sortering, procesboom, toetsafhandeling
├── theme.rs           kleurenpalet + heat-gradients
├── util.rs            formattering, ring-buffer history, sparklines
├── collect/
│   ├── system.rs      sysinfo: cpu, geheugen, processen, netwerk, disks, sensoren
│   └── lsof.rs        lsof -F parser, achtergrond socket-scanner, async queries
└── ui/
    ├── mod.rs         header, footer, help, signaal-dialoog
    ├── overview.rs    dashboard
    ├── views.rs       processes, network, sockets, files, storage
    └── widgets.rs     gradient area-graph (1/8-cel resolutie), meters
```

- lsof draait in achtergrond-threads, de UI blokkeert nooit.
- Op Linux worden sockets native uit `/proc/net/{tcp,udp}[6]` gelezen (incl. TIME_WAIT); `--lsof-sockets` forceert lsof.
- Disks en sensoren draaien op een eigen low-frequency thread; sensoren worden per stuk ververst i.p.v. opnieuw ge-enumereerd (108 ms → ~1 ms).
- sysinfo draait single-threaded: een rayon-pool van N threads wekken voor ~2 ms werk kost meer dan het oplevert.
- Er wordt alleen hertekend als er iets veranderd is (input, tick of nieuwe achtergronddata).
- Proces-strings (naam, cmd, exe, user) worden per pid gecached als `Arc<str>`.

Profileren: `cargo run --release --example prof` en `cargo test --release bench_ -- --ignored --nocapture`.
- lsof-output wordt geparsed via `-F` (machine-leesbaar), niet via kolommen — robuust tegen spaties in namen.
- Alleen rijen rond het zichtbare venster worden opgebouwd, dus ook duizenden processen blijven vlot.

## Tests

```bash
cargo test
```

Rendert alle views op meerdere terminalgroottes (inclusief heel kleine) om panics af te vangen,
en test de lsof-parser en query-parsing.
