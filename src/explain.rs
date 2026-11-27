//! Explain mode (h): what the selected thing means and what to do next.
//!
//! Short, practical entries for the terms vigil shows: TCP and neighbour
//! states, process states, kernel events, counters, routes, firewall verdicts
//! and the doctor's checks. Where it helps, the "next" line has the Linux
//! command and the Junos / Cisco equivalent on the network side.

pub struct Entry {
    pub key: &'static str,
    pub title: &'static str,
    pub text: &'static str,
    pub next: &'static str,
}

const fn e(key: &'static str, title: &'static str, text: &'static str, next: &'static str) -> Entry {
    Entry { key, title, text, next }
}

pub const ENTRIES: &[Entry] = &[
    // ── TCP states
    e("LISTEN", "TCP LISTEN", "A server socket waiting for connections. Bound to 0.0.0.0 / [::] / * it accepts on every interface; bound to 127.0.0.1 only local clients can reach it.", "who owns it: P (all users of the port) · reachable from outside? check the Firewall view · Linux: ss -ltnp"),
    e("SYN_SENT", "TCP SYN_SENT", "We sent a SYN and wait for SYN-ACK. Many of these to one destination = the far side doesn't answer: host down, port filtered (silently dropped) or no route.", "test the path: probe tcp:HOST:PORT · trace (t in Probes) · Junos: show security flow session destination-prefix X"),
    e("SYN_RECV", "TCP SYN_RECV", "A client sent SYN, we answered SYN-ACK, the final ACK hasn't arrived. Lots of them = a SYN flood or clients behind a broken return path (asymmetric routing).", "Linux: nstat -az TcpExtListenOverflows · sysctl net.ipv4.tcp_syncookies · kernel events: SYNFLOOD"),
    e("ESTABLISHED", "TCP ESTABLISHED", "An open connection exchanging data. RTT, retransmits and send/receive queues (Linux) show its health: a growing send queue means the peer or the path is slow; a growing receive queue means this application doesn't read fast enough.", "D closes it (Linux, root) · C captures it (tcpdump) · Linux: ss -tinp dst IP"),
    e("FIN_WAIT1", "TCP FIN_WAIT1", "We closed and sent FIN; waiting for the peer's ACK. Lingering FIN_WAIT1 = the peer vanished or the path drops packets.", "Linux: sysctl net.ipv4.tcp_orphan_retries"),
    e("FIN_WAIT2", "TCP FIN_WAIT2", "We closed, the peer acknowledged but hasn't closed its side yet. Normal briefly; many = the peer application keeps connections half-open.", "Linux: sysctl net.ipv4.tcp_fin_timeout (default 60 s)"),
    e("CLOSE_WAIT", "TCP CLOSE_WAIT", "The PEER closed the connection but THIS application never called close(). They pile up when code leaks connections (missing close in an error path, exhausted pool). Only the application can fix it; the kernel will not time them out.", "find the owner (Enter / i) · restart or fix the app · count per process: Sockets view, filter close_wait"),
    e("CLOSING", "TCP CLOSING", "Both sides sent FIN at the same time and wait for each other's ACK. Rare and short-lived.", ""),
    e("LAST_ACK", "TCP LAST_ACK", "The peer closed first, we closed too and wait for the final ACK. Many = packets are lost on the way back.", ""),
    e("TIME_WAIT", "TCP TIME_WAIT", "The side that closed first keeps the 4-tuple for 2×MSL (60 s on Linux) so late packets can't confuse a new connection. Normal. Tens of thousands from one client to one server:port can exhaust ephemeral ports.", "reuse connections (keep-alive, pooling) · Linux: sysctl net.ipv4.tcp_tw_reuse=1 (outgoing only) · widen net.ipv4.ip_local_port_range"),
    e("CLOSED", "TCP CLOSED", "No connection; the socket is being torn down.", ""),
    e("UDP", "UDP socket", "Connectionless: no handshake, no state, no retransmits. A UDP 'listener' is just a bound port. Drops show up as receive-buffer errors in the kernel counters, not in a socket state.", "Linux: nstat -az UdpRcvbufErrors · raise SO_RCVBUF / net.core.rmem_max for busy DNS, syslog or metrics receivers"),
    // ── Process states
    e("Running", "Process state R (running)", "On a CPU or waiting in the run queue. Load average counts these (plus D).", ""),
    e("Sleeping", "Process state S (sleeping)", "Waiting for an event (socket data, timer, lock). The normal state of most processes.", ""),
    e("Disk sleep", "Process state D (uninterruptible)", "Waiting for I/O inside the kernel and cannot be killed, not even with SIGKILL. Many D processes = slow or hung storage (NFS server gone, failing disk). They raise load average without using CPU.", "Storage view: await / util · kernel events: HUNG, IO · Linux: cat /proc/PID/stack (root)"),
    e("Zombie", "Process state Z (zombie)", "Exited, but the parent hasn't collected the exit status with wait(). Uses no memory or CPU, only a pid. A growing number = a buggy parent; killing the zombie does nothing, kill or fix the parent.", "find the parent: t (tree view) · signal the parent"),
    e("Stopped", "Process state T (stopped)", "Paused by SIGSTOP / Ctrl-Z or a debugger. Resume with SIGCONT.", "x → SIGCONT"),
    e("Idle", "Process state I (idle kernel thread)", "A kernel thread with nothing to do. Ignore.", ""),
    e("Unknown", "Process state unknown", "vigil can't read this process: it belongs to another user or to the system and the OS hides its details from unprivileged users.", "run vigil with sudo (Windows: as administrator)"),
    // ── Neighbour (ARP / NDP) states
    e("REACHABLE", "Neighbour REACHABLE", "The MAC address was confirmed recently (ARP/NDP reply or upper-layer traffic).", ""),
    e("STALE", "Neighbour STALE", "Known MAC, not confirmed recently. Still used; the kernel re-checks it on the next packet. Normal.", ""),
    e("DELAY", "Neighbour DELAY / PROBE", "The kernel is re-verifying a stale entry. Short-lived.", ""),
    e("PROBE", "Neighbour PROBE", "The kernel is sending unicast ARP/NS to re-verify the address.", ""),
    e("FAILED", "Neighbour FAILED", "ARP/NDP got no answer. For the gateway this explains 'no internet': wrong VLAN, the port is down, the gateway is down, or port security / dynamic ARP inspection blocks you.", "switch: show ethernet-switching table (Junos) · show mac address-table (Cisco) · Linux: arping -I IF GW"),
    e("INCOMPLETE", "Neighbour INCOMPLETE", "An ARP request is outstanding and nothing answered yet. Same causes as FAILED.", "Linux: arping -I IF IP · tcpdump -ni IF arp"),
    e("PERMANENT", "Neighbour PERMANENT (static)", "A static entry added by hand or by the OS (broadcast/multicast). Never expires: a wrong static ARP entry silently breaks a host.", "Linux: ip neigh show nud permanent · Windows: arp -a (static)"),
    // ── Routes
    e("default", "Default route", "Where packets go when no more specific route matches: 0.0.0.0/0 (IPv4) or ::/0 (IPv6). With several, the lowest metric wins; equal metrics may load-balance (ECMP).", "Linux: ip route get 1.1.1.1 shows the route actually used · Junos: show route 0.0.0.0/0 · Cisco: show ip route 0.0.0.0"),
    e("kernel", "Route proto kernel", "Created automatically for the subnet of an address configured on an interface (a 'connected' route).", "Junos/Cisco call these Direct / connected routes"),
    e("dhcp", "Route proto dhcp", "Installed by the DHCP client (option 3 router, option 121 classless routes).", ""),
    e("static", "Route proto static", "Configured by hand or by config management. Remember it on the other side too: return traffic needs a route back.", ""),
    e("link", "Scope link", "The destination is directly on this link: no gateway, the host ARPs for the destination itself.", ""),
    e("metric", "Route metric", "Preference between routes to the same prefix: lower wins. Wi-Fi + Ethernet both up = two default routes; the metric decides which one carries traffic.", ""),
    e("on-link", "On-link route", "Directly connected; no next-hop router.", ""),
    // ── Kernel / event log kinds
    e("OOM", "Out of memory kill", "The kernel ran out of memory and killed the process with the worst oom_score. In a container it may be the cgroup's memory.max that was hit, not the host.", "Containers view: OOM column · Linux: journalctl -k | grep -i oom · raise the limit or fix the leak"),
    e("LINK", "Link up / down", "A NIC lost or regained carrier. Repeating = a flapping link: cable, SFP/optic, switch port errors, or power saving (EEE).", "Troubleshoot view: link layer (flaps, CRC) · switch: show interfaces IF extensive (Junos) · show interface IF (Cisco)"),
    e("NIC", "NIC reset / TX timeout", "The driver detected a hung transmit queue and reset the adapter: a driver or firmware bug, or flow-control storms. Traffic stalls for seconds each time.", "Linux: ethtool -i IF (driver/firmware) · ethtool -S IF · update firmware"),
    e("SEGV", "Segmentation fault", "A process accessed invalid memory and was killed by the kernel. Usually a bug, sometimes bad RAM (if many unrelated programs crash).", "coredumpctl list · check the HW kind for memory errors"),
    e("IO", "I/O error", "The block layer got an error from a disk: failing media, cable, controller, or a vanished SAN path.", "Linux: smartctl -a /dev/X · dmesg -T | grep -i error · Storage view: await"),
    e("FS", "Filesystem error", "The filesystem found corruption; ext4 may remount itself read-only to protect data.", "check the mount (Storage view) · fsck after unmounting · Windows: chkdsk"),
    e("SYNFLOOD", "SYN flood", "More half-open connections than the listen backlog: the kernel switched to SYN cookies. Either an attack or a legitimate burst bigger than the backlog.", "raise backlog + net.core.somaxconn · Linux: ss -ltn (Recv-Q of LISTEN = queue length)"),
    e("CONNTRACK", "Conntrack table full", "The netfilter connection table is full; new connections are DROPPED. Common on NAT gateways and Kubernetes nodes.", "sysctl net.netfilter.nf_conntrack_max · conntrack -S · lower timeouts for UDP"),
    e("HUNG", "Hung task / soft lockup", "A task was blocked for over 120 s (usually on I/O) or a CPU didn't schedule. Points at storage stalls or a kernel bug.", "Storage view · Linux: cat /proc/PID/stack"),
    e("HW", "Hardware error", "Machine check / EDAC / WHEA: the CPU or memory reported a hardware fault. Correctable errors that repeat predict failure.", "Linux: ras-mc-ctl --summary · edac-util · replace the DIMM"),
    e("POWER", "Unexpected shutdown", "Windows Kernel-Power 41: the system rebooted without shutting down cleanly (power loss, hard hang, PSU, overheating).", "Event Viewer → System, BugCheck 1001 next to it · check temperatures"),
    e("CRASH", "Bug check (blue screen)", "Windows stopped with a bug check. The dump in C:\\Windows\\Minidump names the driver.", "WinDbg !analyze -v on the minidump"),
    e("ERROR", "Error-level message", "A kernel or system log message at error level that vigil did not classify further.", ""),
    // ── Counters and badges
    e("retransmits", "TCP retransmits", "Segments sent again because no ACK came back in time. Above ~1-2 % something on the path loses packets (congestion, bad link, policer, Wi-Fi).", "find the connection: Sockets view, sort rtt / traffic · probe the peer · Junos: show interfaces queue (drops)"),
    e("listen drops", "Listen queue overflows / drops", "Connections the kernel dropped because the application's accept queue was full: the app accepts too slowly or the backlog is too small.", "raise listen(backlog) and net.core.somaxconn · add workers"),
    e("UDP buffer drops", "UDP receive buffer errors", "Datagrams dropped because the socket buffer was full: the receiver (DNS, syslog, statsd, VoIP) can't keep up.", "raise SO_RCVBUF / net.core.rmem_max · more receiver threads"),
    e("ephemeral", "Ephemeral ports", "Source ports for outgoing connections (Linux 32768-60999 by default). Exhausted = connect() fails with EADDRNOTAVAIL. Usually TIME_WAIT from many short connections to the same server:port.", "connection reuse · widen ip_local_port_range"),
    e("fd", "File descriptors", "Every socket and open file uses one. At the per-process limit (ulimit -n) the app gets 'Too many open files'.", "raise LimitNOFILE= (systemd) or ulimit -n · find leaks: lsof -p PID"),
    e("PSI", "Pressure stall information", "Share of time tasks were stalled waiting for CPU, memory or I/O (Linux). Better than load average: it measures lost time, not queue length.", "cat /proc/pressure/{cpu,memory,io}"),
    e("throttled", "CPU throttling", "The container used its CPU quota (cpu.max) before the period ended and was paused. Latency spikes with low average CPU are the classic symptom.", "raise the CPU limit, or drop it and keep requests"),
    // ── Interfaces / L1-L2
    e("CRC", "CRC / FCS errors", "Frames arrived damaged: the checksum didn't match. Always physical: cable, connector, dirty fibre, failing optic, EMI, or a duplex mismatch.", "replace cable/optic · Junos: show interfaces IF extensive (Input errors: CRC/Align errors) · Cisco: show interfaces IF counters errors"),
    e("duplex", "Duplex", "Full duplex sends and receives at once. Half duplex on a switched network means one side autonegotiated and the other was forced: late collisions and CRC errors follow.", "set both ends to auto · ethtool IF"),
    e("MTU", "MTU", "Largest packet an interface sends without fragmenting: 1500 on Ethernet, less inside tunnels (PPPoE 1492, GRE 1476, VXLAN 1450, WireGuard 1420), 9000 with jumbo frames.", "Troubleshoot view: m (path MTU) · Linux: ip link set IF mtu N"),
    e("drops", "Interface drops", "Packets the host discarded: ring buffer full (rx_missed), unknown protocol or VLAN, or a full qdisc on transmit.", "Linux: ethtool -S IF · ethtool -G IF rx 4096 · tc -s qdisc"),
    e("capture", "Packet capture", "Records packets to a .pcap file (Linux/macOS: tcpdump; Windows: pktmon, .pcapng) that Wireshark opens directly. Filters use BPF syntax: port 443, host 10.0.0.5, tcp and not port 22. Needs root / administrator.", "vigil capture -i en0 -t 30 port 443 · live into Wireshark: sudo vigil capture -w - port 53 | wireshark -k -i - · over SSH: ssh host sudo vigil capture -w - port 443 | wireshark -k -i -"),
    e("LLDP", "LLDP neighbour", "Link Layer Discovery Protocol: the switch announces its name, port and VLAN. Tells you exactly where a server is plugged in.", "Linux: lldpctl · Junos: show lldp neighbors · Cisco: show lldp neighbors detail (or CDP)"),
    e("ARP change", "MAC address change", "An IP is now answered by a different MAC. For the gateway: a VRRP/HSRP failover, a replaced router, or ARP spoofing (someone in the VLAN intercepts traffic).", "compare with the router's real MAC · switch: show arp / show mac address-table · enable DAI"),
    // ── Firewall
    e("ACCEPT", "Firewall ACCEPT", "Packets matching this rule are allowed.", ""),
    e("DROP", "Firewall DROP", "Packets are discarded silently: the sender only sees a timeout. Rising counters here explain 'connection timed out'.", "Junos: show security policies hit-count · Cisco: show access-lists"),
    e("REJECT", "Firewall REJECT", "Packets are refused with an ICMP error or TCP RST: the sender sees 'connection refused' immediately.", ""),
    e("policy", "Chain policy", "What happens to packets that match no rule in the chain.", ""),
    // ── Probes
    e("icmp", "ICMP probe", "Echo request/reply round-trip time. Routers deprioritise ICMP to themselves, so loss to an intermediate hop alone is not proof of loss.", "compare with a tcp: probe to a real service"),
    e("tcp", "TCP connect probe", "Time for the three-way handshake. A RST counts as reachable (the host answered, the port is closed).", ""),
    e("dns", "DNS probe", "Time for a lookup through the system resolver, including the cache.", "Troubleshoot view: n compares every resolver"),
    e("https", "HTTP probe", "Status code and time to first byte via curl, plus days until the TLS certificate expires.", ""),
    e("no reply", "Probe target never answers", "This automatic probe (your gateway or DNS server) has not answered a single ping. Many routers, firewalls and VPN gateways drop ICMP to themselves, so vigil does not raise a LOSS alarm for it. If the target used to answer and stops, the alarm comes back.", "probe a real service instead: a tcp:HOST:PORT probe, or dns:NAME for a resolver"),
    e("MOS", "MOS (call quality)", "Mean Opinion Score estimated from latency, jitter and loss with the ITU-T G.107 E-model: 4.3+ excellent, 4.0 good, 3.6 fair (calls work but people notice), below 3.6 poor. Tells you whether this path is fit for voice and video (Teams, Zoom, SIP).", "poor MOS with low latency means jitter or loss: check Wi-Fi, QoS (Junos: class-of-service; Cisco: service-policy) and congestion"),
    e("jitter", "Jitter", "How much latency varies between probes. Voice and video need low jitter; high jitter with low loss = queueing (bufferbloat).", ""),
    // ── Services
    e("failed", "Failed unit / service", "The service exited with an error or crashed and is not running. Check its log (journal pane).", "Linux: systemctl status UNIT · journalctl -u UNIT -b · Windows: sc qc NAME, Event Viewer"),
    e("activating", "Activating", "Starting up. Stuck here = a start timeout or a dependency it waits for.", "systemctl list-jobs"),
    e("restarts", "Restart loop", "systemd restarted the unit repeatedly (Restart=). It starts, crashes, starts again.", "journalctl -u UNIT -n 100"),
    // ── Health badges (Overview explains the most urgent one)
    e("healthy", "Healthy", "No threshold from [alerts] is crossed. Badges appear in the row under the tabs the moment one is: memory, disk, inodes, load, retransmits, drops, probe loss, certificates, failed services and more.", "thresholds live in [alerts] in the config; 0 turns a check off"),
    e("MEM", "Badge: memory", "Used memory (without reclaimable cache) is above the threshold. Next comes swapping, then the OOM killer.", "Procs view, sort with m · the inspector shows whether one process keeps growing (a leak)"),
    e("SWAP", "Badge: swap", "A large part of swap is in use: the machine has needed more memory than it has. Heavy swapping makes everything slow.", "Procs sorted by memory · vmstat 1 (si/so columns) · add RAM or fix the leak"),
    e("DISK", "Badge: disk full", "A filesystem is nearly full. Writes fail at 100 %, which breaks databases, logs and package updates.", "Storage view · deleted-but-open files: : then +L1 · du -xh / | sort -h | tail"),
    e("INODES", "Badge: inodes", "The filesystem ran out of inodes: no new file can be created even with free space. Usually millions of tiny files (sessions, caches, mail queues).", "find / -xdev -type d -size +1M · clean the directory, or reformat with more inodes"),
    e("LOAD", "Badge: load", "More runnable (or I/O-blocked) tasks than CPUs for a while. Check whether it is CPU (Procs) or disk (Storage await, PSI io).", "Procs sorted by cpu · Storage devices · /proc/pressure"),
    e("TEMP", "Badge: temperature", "The hottest sensor is above the threshold: the CPU will throttle, and hardware ages faster.", "Storage view shows sensors · check fans, airflow, dust"),
    e("RETRANS", "Badge: TCP retransmits", "A high share of TCP segments is sent twice: packets are lost somewhere. Find which connections in Sockets (sort rtt) and which path with probes and a trace.", "Sockets, s until rtt · Probes · W, d (doctor)"),
    e("LOSS", "Badge: probe loss", "A latency probe is losing packets. Loss to the gateway is local (cable, Wi-Fi, switch); loss only further out is the uplink or provider.", "Probes view, t to trace where it starts"),
    e("FDS", "Badge: file descriptors", "A process (or the whole system) is close to its open-file limit and will soon fail with Too many open files.", "Procs, sort with e · Enter on it to see what it holds open"),
    e("EPHEMERAL PORTS", "Badge: ephemeral ports", "Most local ports for outgoing connections are in use, usually TIME_WAIT from many short connections. New connections will fail with EADDRNOTAVAIL.", "connection pooling / keep-alive · net.ipv4.ip_local_port_range"),
    e("AWAIT", "Badge: disk latency", "Requests to this disk take long on average (queue + service time). Applications stall on I/O.", "Storage view: devices · which process writes: Storage, I/O by process"),
    e("BUSY", "Badge: disk saturated", "The disk has I/O in flight almost all the time. A single disk at ~100 % is the bottleneck.", "Storage view · spread the load or use faster storage"),
    e("CERT", "Badge: certificate expiring", "A TLS certificate checked by an HTTPS probe expires soon. Browsers and clients will refuse it after that date.", "renew it (certbot renew · your PKI) · Probes view shows days left"),
    e("HTTP error", "Badge: HTTP error", "An HTTPS probe got a server error (5xx) back: the service is up but failing.", "the service's logs (System view journal) · curl -v URL"),
    e("NEEDS RESTART", "Badge: needs restart", "Processes still run a binary or library that an update replaced. They keep the old, possibly vulnerable code until restarted.", "Enter on the process: the inspector names the unit · systemctl restart UNIT"),
    e("SSH FAILS", "Badge: failed SSH logins", "Many failed SSH logins in the last hour: password guessing.", "Users view (U) shows the sources · disable password login · fail2ban"),
    e("GATEWAY MAC CHANGED", "Badge: gateway MAC changed", "The default gateway is now answered by a different MAC address: a failover, a replaced router, or ARP spoofing.", "W: link layer, ARP watch · compare with the router's real MAC"),
    e("ERR", "Badge: NIC errors", "Error counters on an interface are rising: frames damaged on the wire (CRC), missed by the NIC, or a duplex problem.", "W: link layer · ethtool -S IF · check the switch port"),
    // ── Files (lsof types)
    e("REG", "Regular file", "An ordinary file the process has open. FD shows how: r read, w write, u both.", "Enter: who else has it open"),
    e("DIR", "Directory", "A directory the process has open (often its working directory, or a watched folder).", ""),
    e("CHR", "Character device", "A device such as /dev/null, a terminal (tty) or /dev/urandom.", ""),
    e("FIFO", "Pipe", "An anonymous or named pipe between processes (shell pipelines, logging).", ""),
    e("unix", "Unix socket", "Local inter-process communication through the file system (Docker, databases, systemd, D-Bus).", "ss -xp shows both ends"),
    e("IPv4", "Network socket", "A TCP or UDP socket. The Sockets view (4) shows the same with RTT, queues and bandwidth.", ""),
    e("deleted", "Deleted file still open", "The file was deleted but this process keeps it open, so its space is not freed until the process closes it or exits. Classic cause of a full disk that du can't explain.", "send HUP so it reopens its logs, or restart it · : then +L1 lists them all"),
    e("txt", "Program text", "The executable file of the process itself.", ""),
    e("mem", "Memory-mapped file", "A file mapped into memory: shared libraries, databases.", ""),
    e("cwd", "Working directory", "The directory the process was started in or moved to.", ""),
    // ── Storage / Users
    e("storage", "Storage view", "Filesystems with space and inodes, disks with latency (await), utilisation and queue (like iostat -x), I/O per process and sensors. await above ~10 ms on SSD or ~50 ms on HDD means the disk is the bottleneck.", "iostat -x 1 · df -i"),
    e("sessions", "Users and sessions", "Who is logged in, from where, how long idle and what they run, plus failed SSH logins of the last hour by source.", "w · last · journalctl -u ssh"),
    // ── Network tools
    e("open", "Port open", "The TCP handshake completed: something listens and nothing on the way blocks it.", ""),
    e("refused", "Port refused", "A TCP RST came back fast: the host is reachable, but nothing listens on that port, or a firewall REJECTs (rejects actively) instead of dropping.", "on the host: ss -ltnp / netstat -ano · firewall: look for a reject rule"),
    e("filtered", "Port filtered", "No answer at all within the timeout: a firewall DROPs the packets silently, a route is missing, or the host is down. Ports that answer on the same host prove it is a firewall.", "Junos: show security policies hit-count · show security flow session destination-port N · Cisco: show access-lists · trace with e: host tcp PORT"),
    e("reach", "Port reachability", "Tries a TCP connection to each port: open, refused (RST) or filtered (silence). The quickest way to tell \"the app is down\" from \"the firewall blocks it\".", ""),
    e("trace", "Path trace", "Every router on the path, with loss and latency per hop. Loss that starts at one hop and continues to the end is real; loss at only one middle hop is that router rate-limiting replies. If ICMP is filtered, trace with TCP to the service's port.", "mtr -T -P 443 HOST · Junos: traceroute HOST · Cisco: traceroute HOST"),
    e("snmp", "SNMP device view", "Interface state, speed, traffic, errors, CRC and discards from the switch or router itself, sampled twice for rates, plus LLDP neighbours and CPU. The device side of the cable.", "Junos: show interfaces extensive · show lldp neighbors · Cisco: show interfaces · show cdp/lldp neighbors"),
    e("port down", "Port enabled but down", "The port is administratively up but has no link: unplugged cable, broken optic, the far end is off, or it was err-disabled.", "Junos: show interfaces IF · Cisco: show interface status err-disabled"),
    e("discards", "Interface discards", "The device dropped packets on purpose: output buffers full during bursts (congestion) or a QoS policy dropping a class. Not a cabling problem.", "Junos: show interfaces queue IF · Cisco: show policy-map interface IF"),
    e("syslog", "Syslog receiver", "Live log stream from network devices pointed at this host, classified: LINK flaps, ROUTING (OSPF/BGP/IS-IS neighbours), STP, ERRDISABLE, SECURITY, CONFIG commits, HW.", "Junos: set system syslog host IP any any · Cisco: logging host IP"),
    e("ROUTING", "Routing protocol event", "An OSPF, BGP or IS-IS neighbour changed state. Down/Idle means routes from that neighbour are withdrawn: traffic reroutes or blackholes.", "Junos: show ospf neighbor · show bgp summary · Cisco: show ip ospf neighbor · show ip bgp summary"),
    e("STP", "Spanning tree event", "A topology change or role change: MAC tables flush and traffic floods briefly. Frequent changes mean a flapping port or a loop.", "Junos: show spanning-tree bridge · Cisco: show spanning-tree detail | include changes"),
    e("ERRDISABLE", "Port err-disabled", "The switch shut the port down to protect the network (BPDU guard, port security, storm control, link flap). It stays down until recovered.", "Cisco: show interfaces status err-disabled · shut / no shut · Junos: clear ethernet-switching port-error"),
    e("SECURITY", "Security event", "Failed logins, port-security violations, DHCP snooping or dynamic ARP inspection drops, or a firewall screen.", "find the source address; check whether it is expected"),
    e("CONFIG", "Configuration change", "Someone committed or changed the configuration. When an outage starts right after one, this is your first suspect.", "Junos: show system commit · show | compare rollback 1 · Cisco: show archive config differences"),
    e("DUPLEX", "Duplex mismatch", "The two ends of a link negotiated different duplex: late collisions and CRC errors follow, and throughput collapses under load.", "set both ends to auto (or both to the same fixed values)"),
    e("LOGIN", "Login", "A user logged in to the device.", ""),
    e("dhcp servers", "DHCP servers", "One DISCOVER broadcast; every server that answers is listed. More than one server means a rogue DHCP server; none means no server, a missing relay or DHCP snooping dropping the request.", "find the rogue's MAC in the switch's MAC table · enable DHCP snooping (Junos: dhcp-security · Cisco: ip dhcp snooping)"),
    e("Wi-Fi", "Wi-Fi signal", "RSSI is the signal strength: -30 to -60 dBm good, -60 to -67 fine for voice, below -70 weak. SNR (signal minus noise) above 25 dB is good, below 20 dB causes retries and slow, jittery links.", "move closer, prefer 5/6 GHz, check the AP's channel and transmit power on the controller"),
    // ── Doctor checks
    e("Link", "Doctor: link", "Is any physical interface up with carrier and an address? Nothing above works without it.", "ip link · nmcli · switch: show interfaces terse"),
    e("NIC errors", "Doctor: NIC errors", "Error counters on physical interfaces. CRC/frame = the wire; missed/overrun = the host can't drain the NIC fast enough.", "ethtool -S IF"),
    e("Gateway MAC", "Doctor: gateway MAC", "Is the default gateway in the ARP table with a MAC? If not, the problem is layer 2: VLAN, port, or the gateway itself.", "arping GW · switch MAC table"),
    e("LLDP neighbour", "Doctor: LLDP", "Which switch and port you're connected to, if the switch speaks LLDP and lldpd runs here.", ""),
    e("IPv4 address", "Doctor: IPv4 address", "A usable address (not 169.254.x.x). APIPA means DHCP failed.", "dhclient -v IF · Windows: ipconfig /renew"),
    e("Default route", "Doctor: default route", "Without one only the local subnet is reachable.", "ip route · route print"),
    e("Gateway ping", "Doctor: gateway ping", "Loss or latency to the first hop is a local problem: Wi-Fi, congestion, duplex, a busy router.", ""),
    e("Internet ping", "Doctor: internet ping", "Reachability beyond the gateway. Fails while the gateway works = NAT, upstream routing, the ISP, or ICMP filtered (see the TCP check).", "trace: t in the Probes view · mtr"),
    e("Path MTU", "Doctor: path MTU", "Largest packet that crosses the path without fragmenting. A black hole (no 'fragmentation needed' replies) makes TLS and SSH hang after connecting.", "m in this view · clamp MSS on the router"),
    e("IPv6", "Doctor: IPv6", "If the host has global IPv6 but it's broken, clients wait for the IPv4 fallback on every connection.", ""),
    e("TCP connect", "Doctor: TCP connect", "Opens a TCP connection to the internet target on 443. Works while ping fails = ICMP is filtered, which is fine.", ""),
    e("TCP health", "Doctor: TCP health", "Kernel-wide retransmit rate and accept-queue drops during the run.", ""),
    e("Clock", "Doctor: clock", "Compares the local clock with the web server's Date header. TLS, Kerberos/AD and TOTP fail with skew.", "timedatectl · chronyc tracking · w32tm /query /status"),
    e("TLS", "Doctor: TLS", "Can a TLS handshake verify the certificate chain? Failing here with working TCP = an inspecting proxy, wrong clock or old CA bundle.", "curl -v URL · openssl s_client -connect HOST:443"),
    e("System resolver", "Doctor: system resolver", "A lookup through getaddrinfo, exactly as applications do it (hosts file, cache, search domains, resolvers).", "getent hosts NAME · resolvectl query NAME · nslookup NAME"),
    e("DNS servers", "Doctor: DNS servers", "Each configured resolver queried directly. One dead resolver makes every lookup wait for its timeout.", "n in this view compares them with public resolvers"),
    e("HTTP", "Doctor: HTTP", "A real HTTP request: status code, connect time and time to first byte.", ""),
    e("Proxy", "Doctor: proxy", "Proxy environment variables change how curl and many tools connect.", ""),
];

/// Look up an entry: exact key first, then case-insensitive, then prefix.
pub fn lookup(term: &str) -> Option<&'static Entry> {
    let t = term.trim();
    ENTRIES
        .iter()
        .find(|e| e.key == t)
        .or_else(|| ENTRIES.iter().find(|e| e.key.eq_ignore_ascii_case(t)))
        .or_else(|| ENTRIES.iter().find(|e| t.to_ascii_lowercase().starts_with(&e.key.to_ascii_lowercase()) && e.key.len() >= 3))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookups() {
        assert_eq!(lookup("CLOSE_WAIT").unwrap().title, "TCP CLOSE_WAIT");
        assert_eq!(lookup("stale").unwrap().key, "STALE");
        assert_eq!(lookup("https://example.com").unwrap().key, "https");
        assert!(lookup("nonsense-term").is_none());
        // Keys are unique.
        let mut keys: Vec<&str> = ENTRIES.iter().map(|e| e.key).collect();
        keys.sort();
        let n = keys.len();
        keys.dedup();
        assert_eq!(n, keys.len());
    }
}
