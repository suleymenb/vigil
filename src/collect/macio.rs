//! Block-device statistics on macOS, read from the I/O Registry directly.
//!
//! This used to run `ioreg -c IOBlockStorageDriver -r -l` every two seconds:
//! a 19 ms child process, about 1 % of a core that never showed up in
//! vigil's own CPU figure. The same numbers are one property read per disk:
//! each `IOBlockStorageDriver` has a "Statistics" dictionary (operations,
//! bytes and total time in ns per direction) and its child is the whole-disk
//! `IOMedia` with the "BSD Name".

#![cfg(target_os = "macos")]

use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr};

use super::diskio::Raw;

type CfRef = *const c_void;
type IoObject = u32;

const UTF8: u32 = 0x0800_0100; // kCFStringEncodingUTF8
const SINT64: isize = 4; // kCFNumberSInt64Type

#[link(name = "IOKit", kind = "framework")]
extern "C" {
    fn IOServiceMatching(name: *const c_char) -> CfRef;
    fn IOServiceGetMatchingServices(main_port: u32, matching: CfRef, existing: *mut IoObject) -> i32;
    fn IOIteratorNext(iterator: IoObject) -> IoObject;
    fn IOObjectRelease(object: IoObject) -> i32;
    fn IORegistryEntryCreateCFProperty(entry: IoObject, key: CfRef, allocator: CfRef, options: u32) -> CfRef;
    fn IORegistryEntryGetChildEntry(entry: IoObject, plane: *const c_char, child: *mut IoObject) -> i32;
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFStringCreateWithCString(alloc: CfRef, c_str: *const c_char, encoding: u32) -> CfRef;
    fn CFStringGetCString(s: CfRef, buffer: *mut c_char, size: isize, encoding: u32) -> u8;
    fn CFDictionaryGetValue(dict: CfRef, key: CfRef) -> CfRef;
    fn CFNumberGetValue(number: CfRef, the_type: isize, value: *mut c_void) -> u8;
    fn CFGetTypeID(cf: CfRef) -> usize;
    fn CFDictionaryGetTypeID() -> usize;
    fn CFStringGetTypeID() -> usize;
    fn CFNumberGetTypeID() -> usize;
    fn CFRelease(cf: CfRef);
}

/// An owned CoreFoundation object, released on drop.
struct Cf(CfRef);

impl Cf {
    fn string(s: &CStr) -> Option<Cf> {
        let r = unsafe { CFStringCreateWithCString(std::ptr::null(), s.as_ptr(), UTF8) };
        (!r.is_null()).then_some(Cf(r))
    }

    /// A property of a registry entry, when it has the expected type.
    fn property(entry: IoObject, key: &CStr, type_id: usize) -> Option<Cf> {
        let key = Cf::string(key)?;
        let r = unsafe { IORegistryEntryCreateCFProperty(entry, key.0, std::ptr::null(), 0) };
        if r.is_null() {
            return None;
        }
        let v = Cf(r);
        (unsafe { CFGetTypeID(v.0) } == type_id).then_some(v)
    }

    /// A 64-bit number from a dictionary (0 when missing).
    fn number(&self, key: &CStr) -> u64 {
        let Some(key) = Cf::string(key) else { return 0 };
        let mut out: i64 = 0;
        unsafe {
            let v = CFDictionaryGetValue(self.0, key.0);
            if v.is_null() || CFGetTypeID(v) != CFNumberGetTypeID() {
                return 0;
            }
            CFNumberGetValue(v, SINT64, &mut out as *mut i64 as *mut c_void);
        }
        out.max(0) as u64
    }
}

impl Drop for Cf {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0) }
    }
}

/// An I/O Registry object, released on drop.
struct Io(IoObject);

impl Drop for Io {
    fn drop(&mut self) {
        unsafe {
            IOObjectRelease(self.0);
        }
    }
}

/// Cumulative statistics per whole disk ("disk0", "disk4", …). Disks that
/// have done no I/O at all (empty card readers) are left out.
pub fn read() -> HashMap<String, Raw> {
    let mut m = HashMap::new();
    unsafe {
        // The matching dictionary is consumed by the call below.
        let matching = IOServiceMatching(c"IOBlockStorageDriver".as_ptr());
        if matching.is_null() {
            return m;
        }
        let mut iter: IoObject = 0;
        if IOServiceGetMatchingServices(0, matching, &mut iter) != 0 || iter == 0 {
            return m;
        }
        let iter = Io(iter);
        loop {
            let driver = IOIteratorNext(iter.0);
            if driver == 0 {
                break;
            }
            let driver = Io(driver);
            let Some(stats) = Cf::property(driver.0, c"Statistics", CFDictionaryGetTypeID()) else { continue };
            let mut child: IoObject = 0;
            if IORegistryEntryGetChildEntry(driver.0, c"IOService".as_ptr(), &mut child) != 0 || child == 0 {
                continue;
            }
            let child = Io(child);
            let Some(bsd) = Cf::property(child.0, c"BSD Name", CFStringGetTypeID()) else { continue };
            let mut buf = [0 as c_char; 64];
            if CFStringGetCString(bsd.0, buf.as_mut_ptr(), buf.len() as isize, UTF8) == 0 {
                continue;
            }
            let name = CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned();
            let (rt, wt) = (stats.number(c"Total Time (Read)") / 1_000_000, stats.number(c"Total Time (Write)") / 1_000_000);
            let raw = Raw {
                reads: stats.number(c"Operations (Read)"),
                read_sectors: stats.number(c"Bytes (Read)") / 512,
                read_ms: rt,
                writes: stats.number(c"Operations (Write)"),
                write_sectors: stats.number(c"Bytes (Write)") / 512,
                write_ms: wt,
                io_ms: rt + wt,
                weighted_ms: rt + wt,
            };
            if raw.reads + raw.writes > 0 {
                m.insert(name, raw);
            }
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry must give what `ioreg` prints (the old source).
    #[test]
    fn matches_ioreg() {
        let ours = read();
        let Ok(out) = std::process::Command::new("ioreg").args(["-c", "IOBlockStorageDriver", "-r", "-w0", "-l"]).output() else { return };
        let theirs = super::super::diskio::parse_ioreg(&String::from_utf8_lossy(&out.stdout));
        if theirs.is_empty() {
            return; // no ioreg output here (sandbox): nothing to compare with
        }
        let mut a: Vec<&String> = ours.keys().collect();
        let mut b: Vec<&String> = theirs.keys().collect();
        a.sort();
        b.sort();
        assert_eq!(a, b);
        for (name, t) in &theirs {
            let o = &ours[name];
            // Read a moment earlier: never ahead, and close.
            assert!(o.reads <= t.reads && t.reads - o.reads < 100_000, "{name}: {o:?} vs {t:?}");
            assert!(o.writes <= t.writes && o.read_sectors <= t.read_sectors && o.write_ms <= t.write_ms, "{name}: {o:?} vs {t:?}");
            assert!(o.reads > 0 && o.read_sectors > 0, "{name}: {o:?}");
        }
    }
}
