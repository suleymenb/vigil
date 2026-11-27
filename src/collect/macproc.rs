//! Per-tick process numbers on macOS, straight from libproc.
//!
//! sysinfo's macOS backend runs two `sysctl(KERN_PROCARGS2)` calls for every
//! process on every refresh (the kernel copies each process's whole argument
//! and environment block), plus four `proc_pidinfo` calls, whether or not the
//! caller asked for command lines. With ~900 processes that was ~15 ms per
//! tick, three quarters of vigil's total CPU time.
//!
//! This reads what changes every tick with one call per process:
//! `PROC_PIDTASKALLINFO` returns parent, uid, start time, name, state, CPU
//! time, resident and virtual size at once. Disk I/O (`proc_pid_rusage`) is
//! read only for processes whose CPU time moved since the last tick: a
//! process that didn't run didn't do I/O. sysinfo is still used once per new
//! process for its command line and executable.
//!
//! Interface counters are one small `sysctl` per interface (see `net`).

#![cfg(target_os = "macos")]

use std::mem;
use std::sync::OnceLock;

use super::system::{NetRaw, Raw};

/// BSD process status (1 idle, 2 run, 3 sleep, 4 stopped, 5 zombie) and the
/// number of threads on a CPU right now.
fn status_str(status: u32, task: bool, running: i32) -> &'static str {
    match status {
        5 => "Zombie",
        4 => "Stopped",
        1 => "Idle",
        _ if !task => "Unknown",
        _ if running > 0 => "Running",
        _ => "Sleeping",
    }
}

/// mach time units → nanoseconds (1:1 on Intel, 125/3 on Apple Silicon).
fn timebase() -> f64 {
    static TB: OnceLock<f64> = OnceLock::new();
    *TB.get_or_init(read_timebase)
}

fn read_timebase() -> f64 {
    #[repr(C)]
    struct TimebaseInfo {
        numer: u32,
        denom: u32,
    }
    extern "C" {
        fn mach_timebase_info(info: *mut TimebaseInfo) -> libc::c_int;
    }
    let mut tb = TimebaseInfo { numer: 0, denom: 0 };
    unsafe {
        mach_timebase_info(&mut tb);
    }
    if tb.denom == 0 {
        1.0
    } else {
        tb.numer as f64 / tb.denom as f64
    }
}

/// All pids, into a reused buffer.
pub fn list_pids(buf: &mut Vec<libc::pid_t>) {
    // Sized from the last call, with room for processes that appeared since;
    // a full buffer means there may be more, so grow and ask again.
    let mut cap = (buf.len() + 64).max(256);
    loop {
        buf.clear();
        buf.resize(cap, 0);
        let n = unsafe { libc::proc_listallpids(buf.as_mut_ptr() as *mut libc::c_void, (cap * mem::size_of::<libc::pid_t>()) as libc::c_int) };
        let n = n.max(0) as usize;
        if n < cap || cap >= 1 << 20 {
            buf.truncate(n.min(cap));
            return;
        }
        cap *= 2;
    }
}

/// A NUL-terminated C name as bytes.
fn c_name(src: &[libc::c_char]) -> [u8; 32] {
    let mut name = [0u8; 32];
    for (d, c) in name.iter_mut().zip(src.iter().take_while(|c| **c != 0)) {
        *d = *c as u8;
    }
    name
}

fn named(mut r: Raw, src: &[libc::c_char]) -> Raw {
    let name = c_name(src);
    r.set_name(&name[..name.iter().position(|b| *b == 0).unwrap_or(name.len())]);
    r
}

/// One process: full task info when permitted, the BSD part otherwise.
pub fn read(pid: libc::pid_t) -> Option<Raw> {
    unsafe {
        let mut all = mem::zeroed::<libc::proc_taskallinfo>();
        let size = mem::size_of::<libc::proc_taskallinfo>() as libc::c_int;
        if libc::proc_pidinfo(pid, libc::PROC_PIDTASKALLINFO, 0, &mut all as *mut _ as *mut libc::c_void, size) == size {
            let (b, t) = (&all.pbsd, &all.ptinfo);
            let r = Raw {
                pid: pid as u32,
                ppid: b.pbi_ppid,
                uid: Some(b.pbi_uid),
                start: b.pbi_start_tvsec,
                status: status_str(b.pbi_status, true, t.pti_numrunning),
                task: true,
                cpu_ns: (t.pti_total_user.saturating_add(t.pti_total_system) as f64 * timebase()) as u64,
                rss: t.pti_resident_size,
                virt: t.pti_virtual_size,
                ..Default::default()
            };
            return Some(named(r, if b.pbi_name[0] != 0 { &b.pbi_name[..] } else { &b.pbi_comm[..] }));
        }
        // Other users' processes without root: the short form is always allowed
        // (parent, owner, state, 16-byte name; no start time, see `start_time`).
        let mut short = mem::zeroed::<BsdShortInfo>();
        let size = mem::size_of::<BsdShortInfo>() as libc::c_int;
        if libc::proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &mut short as *mut _ as *mut libc::c_void, size) == size {
            let r = Raw { pid: pid as u32, ppid: short.ppid, uid: Some(short.uid), status: status_str(short.status, false, 0), ..Default::default() };
            return Some(named(r, &short.comm[..]));
        }
        None
    }
}

/// How long the process has run.
pub fn run_time(start: u64, now_s: u64, _uptime_s: u64) -> u64 {
    now_s.saturating_sub(start)
}

const PROC_PIDT_SHORTBSDINFO: libc::c_int = 13;

/// `struct proc_bsdshortinfo` from <sys/proc_info.h>.
#[repr(C)]
struct BsdShortInfo {
    pid: u32,
    ppid: u32,
    pgid: u32,
    status: u32,
    comm: [libc::c_char; 16],
    flags: u32,
    uid: u32,
    gid: u32,
    ruid: u32,
    rgid: u32,
    svuid: u32,
    svgid: u32,
    rfu: u32,
}

/// Start time (seconds since the epoch) of any process, via
/// `sysctl kern.proc.pid` like `ps` does. For processes whose task info is
/// not readable; called once per process, not per tick.
pub fn start_time(pid: u32) -> Option<u64> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid as libc::c_int];
    // struct kinfo_proc is 648 bytes on 64-bit macOS and starts with the
    // process's start time (extern_proc.p_un.__p_starttime, a timeval).
    let mut buf = [0u8; 1024];
    let mut len = buf.len();
    let r = unsafe { libc::sysctl(mib.as_mut_ptr(), mib.len() as libc::c_uint, buf.as_mut_ptr() as *mut libc::c_void, &mut len, std::ptr::null_mut(), 0) };
    if r != 0 || len < 16 {
        return None;
    }
    let secs = i64::from_ne_bytes(buf[..8].try_into().ok()?);
    (secs > 0).then_some(secs as u64)
}

/// Cumulative disk bytes (read, written) of a process.
pub fn disk(pid: u32) -> Option<(u64, u64)> {
    unsafe {
        let mut ru = mem::MaybeUninit::<libc::rusage_info_v2>::uninit();
        if libc::proc_pid_rusage(pid as libc::c_int, libc::RUSAGE_INFO_V2, ru.as_mut_ptr() as _) < 0 {
            return None;
        }
        let ru = ru.assume_init();
        Some((ru.ri_diskio_bytesread, ru.ri_diskio_byteswritten))
    }
}

/// What the interface reader keeps between ticks.
#[derive(Default)]
pub struct NetState {
    buf: Vec<u8>,
    /// (kernel index, name) of every interface at the last listing.
    list: Vec<(libc::c_int, String)>,
}

/// Counters of every interface, into a reused list.
///
/// sysinfo lists all interfaces on every refresh and then asks
/// `if_indextoname` for each one, which lists them all again (two more
/// sysctls per interface): ~1 ms a tick. Here the listing only runs when
/// `relist` is set (every couple of seconds; its link-level addresses carry
/// the names), and a tick costs one small sysctl per interface.
pub fn net(st: &mut NetState, relist: bool, out: &mut Vec<NetRaw>) {
    if relist || st.list.is_empty() {
        list_interfaces(st);
    }
    let (mut n, mut stale) = (0, false);
    for (index, name) in &st.list {
        // Gone, or its index now belongs to another interface.
        let Some(d) = counters(*index).filter(|d| c_name(&d.ifmd_name).starts_with(name.as_bytes()) && d.ifmd_name.get(name.len()).is_none_or(|c| *c == 0)) else {
            stale = true;
            continue;
        };
        let d = d.ifmd_data;
        let r = NetRaw::slot(out, n, name);
        (r.rx, r.tx, r.rx_errors, r.tx_errors, r.rx_dropped, r.tx_dropped, r.mtu) = (d.ifi_ibytes, d.ifi_obytes, d.ifi_ierrors, d.ifi_oerrors, 0, 0, d.ifi_mtu as u64);
        n += 1;
    }
    out.truncate(n);
    if stale {
        st.list.clear(); // list again on the next tick
    }
}

/// One interface's counters. The listing below has them too, but capped at
/// 32 bits: a busy interface would wrap every 4 GB.
fn counters(index: libc::c_int) -> Option<libc::ifmibdata> {
    let mut mib = [libc::CTL_NET, libc::PF_LINK, libc::NETLINK_GENERIC, libc::IFMIB_IFDATA, index, libc::IFDATA_GENERAL];
    let mut data = mem::MaybeUninit::<libc::ifmibdata>::uninit();
    let mut len = mem::size_of::<libc::ifmibdata>();
    let r = unsafe { libc::sysctl(mib.as_mut_ptr(), mib.len() as libc::c_uint, data.as_mut_ptr() as *mut libc::c_void, &mut len, std::ptr::null_mut(), 0) };
    (r == 0).then(|| unsafe { data.assume_init() })
}

/// Index and name of every interface, from `NET_RT_IFLIST2`.
fn list_interfaces(st: &mut NetState) {
    let mut mib = [libc::CTL_NET, libc::PF_ROUTE, 0, 0, libc::NET_RT_IFLIST2, 0];
    if st.buf.len() < 16 * 1024 {
        st.buf.resize(32 * 1024, 0);
    }
    st.list.clear();
    let len = loop {
        let mut len = st.buf.len();
        let r = unsafe { libc::sysctl(mib.as_mut_ptr(), mib.len() as libc::c_uint, st.buf.as_mut_ptr() as *mut libc::c_void, &mut len, std::ptr::null_mut(), 0) };
        if r == 0 {
            break len;
        }
        // Too small for this many interfaces and addresses: grow and ask again.
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOMEM) || st.buf.len() >= 8 << 20 {
            return;
        }
        let bigger = st.buf.len() * 2;
        st.buf.resize(bigger, 0);
    };
    parse_iflist2(&st.buf[..len], &mut st.list);
}

/// Routing-socket messages: each `RTM_IFINFO2` is an `if_msghdr2` followed
/// by the interface's link-level address, which starts with its name.
fn parse_iflist2(data: &[u8], out: &mut Vec<(libc::c_int, String)>) {
    const HDR: usize = mem::size_of::<libc::if_msghdr2>();
    let mut off = 0;
    while off + 4 <= data.len() {
        let msglen = u16::from_ne_bytes([data[off], data[off + 1]]) as usize;
        if msglen < 4 || off + msglen > data.len() {
            break;
        }
        let msg = &data[off..off + msglen];
        off += msglen;
        if msg[3] as libc::c_int != libc::RTM_IFINFO2 || msglen < HDR + 8 {
            continue;
        }
        let hdr: libc::if_msghdr2 = unsafe { std::ptr::read_unaligned(msg.as_ptr() as *const libc::if_msghdr2) };
        // struct sockaddr_dl: length, family, index (2 bytes), type, name
        // length, address length, selector length, then the name.
        let sdl = &msg[HDR..];
        if sdl[1] as libc::c_int != libc::AF_LINK {
            continue;
        }
        if let Some(name) = sdl.get(8..8 + sdl[5] as usize).and_then(|b| std::str::from_utf8(b).ok()).filter(|s| !s.is_empty()) {
            out.push((hdr.ifm_index as libc::c_int, name.to_string()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_own_process() {
        let mut pids = Vec::new();
        list_pids(&mut pids);
        let me = std::process::id() as libc::pid_t;
        assert!(pids.contains(&me) && pids.len() > 20, "{} pids", pids.len());
        let r = read(me).expect("own process");
        assert!(r.task && !r.kernel && r.rss > 0 && r.virt > r.rss && r.cpu_ns > 0);
        assert_eq!(r.uid, Some(unsafe { libc::getuid() }));
        assert!(r.start > 1_600_000_000);
        assert!(String::from_utf8_lossy(r.name()).starts_with("vigil"), "{:?}", String::from_utf8_lossy(r.name()));
        assert!(matches!(r.status, "Running" | "Sleeping"));
        // CPU time is in nanoseconds: this test has run for milliseconds, not hours.
        assert!(r.cpu_ns > 100_000 && r.cpu_ns < 600 * 1_000_000_000, "{}", r.cpu_ns);
        assert!(disk(me as u32).is_some());
        assert!(timebase() > 0.0);
        assert_eq!(run_time(r.start, r.start + 90, 0), 90);
        // pid 1 (launchd) always exists; as a normal user only its identity is readable.
        let l = read(1).expect("launchd");
        assert_eq!(String::from_utf8_lossy(l.name()), "launchd");
        assert_eq!((l.uid, l.ppid), (Some(0), 0));
        assert!(l.task == (unsafe { libc::geteuid() } == 0));
        let boot = start_time(1).expect("launchd start time");
        assert!(boot > 1_600_000_000 && boot <= start_time(me as u32).unwrap());
        assert_eq!(start_time(me as u32), Some(r.start));
    }

    #[test]
    fn interface_counters_match_sysinfo() {
        let (mut st, mut out) = (NetState::default(), Vec::new());
        net(&mut st, false, &mut out);
        let sys = sysinfo::Networks::new_with_refreshed_list();
        let mut ours: Vec<&str> = out.iter().map(|r| r.name.as_str()).collect();
        let mut theirs: Vec<&str> = sys.keys().map(String::as_str).collect();
        ours.sort();
        theirs.sort();
        assert_eq!(ours, theirs);
        let lo = out.iter().find(|r| r.name == "lo0").expect("lo0");
        assert_eq!(lo.mtu, sys["lo0"].mtu());
        for r in &out {
            // Counters only grow, and sysinfo read them a moment later.
            let s = &sys[&r.name];
            assert!(r.rx <= s.total_received() && s.total_received() - r.rx < 1 << 30, "{} rx {} vs {}", r.name, r.rx, s.total_received());
            assert!(r.tx <= s.total_transmitted(), "{} tx", r.name);
            assert_eq!(r.rx_errors, s.total_errors_on_received(), "{}", r.name);
        }
        // Later reads reuse the buffers and give the same list, with or
        // without listing the interfaces again.
        let names: Vec<String> = out.iter().map(|r| r.name.clone()).collect();
        for relist in [false, true] {
            net(&mut st, relist, &mut out);
            assert_eq!(names, out.iter().map(|r| r.name.clone()).collect::<Vec<_>>());
        }
        // An index that no longer answers drops out and forces a new listing.
        st.list.push((60_000, "gone0".into()));
        net(&mut st, false, &mut out);
        assert!(st.list.is_empty() && names == out.iter().map(|r| r.name.clone()).collect::<Vec<_>>());
        net(&mut st, false, &mut out);
        assert_eq!(st.list.len(), names.len());
    }
}
