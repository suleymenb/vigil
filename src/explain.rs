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
    e("jitter", "Jitter", "How much latency varies between probes. Voice and video need low jitter; high jitter with low loss = queueing (bufferbloat).", ""),
    // ── Services
    e("failed", "Failed unit / service", "The service exited with an error or crashed and is not running. Check its log (journal pane).", "Linux: systemctl status UNIT · journalctl -u UNIT -b · Windows: sc qc NAME, Event Viewer"),
    e("activating", "Activating", "Starting up. Stuck here = a start timeout or a dependency it waits for.", "systemctl list-jobs"),
    e("restarts", "Restart loop", "systemd restarted the unit repeatedly (Restart=). It starts, crashes, starts again.", "journalctl -u UNIT -n 100"),
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
