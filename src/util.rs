#![allow(non_snake_case)]

use std::ffi::CStr;
use std::fs::File;
use std::io::Read;
use std::mem::{offset_of, size_of};
use std::os::raw::{c_char, c_int};
use std::str::from_utf8;

use crate::all_addr::{AllAddr, RrData};
use crate::config::DhcpConfig;
use crate::daemon::Daemon;

pub(crate) const MAXDNAME: usize = 256;
pub(crate) const MAXLABEL: usize = 63;
pub(crate) const EC_MISC: i32 = 1;
pub(crate) const RANDFILE: &str = "/path/to/random/file"; // Placeholder path

pub(crate) static mut SEED: [u32; 32] = [0; 32];
pub(crate) static mut IN: [u32; 12] = [0; 12];
pub(crate) static mut OUT: [u32; 8] = [0; 8];
pub(crate) static mut OUTLEFT: i32 = 0;

extern "C" {
    pub(crate) fn die(msg: *const c_char, arg: *const c_char, code: c_int) -> !;
    pub(crate) fn my_syslog(priority: c_int, fmt: *const c_char, ...);
}

pub(crate) fn rand_init() {
    let mut fd = File::open(RANDFILE).unwrap_or_else(|_| unsafe {
        die(
            CStr::from_bytes_with_nul(b"failed to seed the random number generator\0")
                .unwrap()
                .as_ptr(),
            std::ptr::null(),
            EC_MISC,
        );
    });

    let mut seed_buffer = [0u8; 32 * 4]; // 32 u32s
    let mut in_buffer = [0u8; 12 * 4]; // 12 u32s

    if fd.read_exact(&mut seed_buffer).is_err() || fd.read_exact(&mut in_buffer).is_err() {
        unsafe {
            die(
                CStr::from_bytes_with_nul(b"failed to seed the random number generator\0")
                    .unwrap()
                    .as_ptr(),
                std::ptr::null(),
                EC_MISC,
            );
        }
    }

    unsafe {
        SEED.copy_from_slice(std::slice::from_raw_parts(
            seed_buffer.as_ptr() as *const u32,
            32,
        ));
        IN.copy_from_slice(std::slice::from_raw_parts(
            in_buffer.as_ptr() as *const u32,
            12,
        ));
    }
}

pub(crate) const fn rotate(x: u32, b: u32) -> u32 {
    (x << b) | (x >> (32 - b))
}

macro_rules! MUSH {
    ($t:expr, $seed:expr, $x:expr, $sum:expr, $i:expr, $b:expr) => {
        $x = $t[$i] += (($x ^ $seed[$i]) + $sum) ^ rotate($x, $b);
    };
}

pub(crate) fn surf() {
    let mut t = [0u32; 12];
    let mut x;
    let mut sum = 0u32;
    unsafe {
        for i in 0..12 {
            t[i] = IN[i] ^ SEED[12 + i];
        }
        for i in 0..8 {
            OUT[i] = SEED[24 + i];
        }
    }
    x = t[11];
    for _loop in 0..2 {
        for _r in 0..16 {
            sum = sum.wrapping_add(0x9e3779b9);
            MUSH!(t, unsafe { SEED }, x, sum, 0, 5);
            MUSH!(t, unsafe { SEED }, x, sum, 1, 7);
            MUSH!(t, unsafe { SEED }, x, sum, 2, 9);
            MUSH!(t, unsafe { SEED }, x, sum, 3, 13);
            MUSH!(t, unsafe { SEED }, x, sum, 4, 5);
            MUSH!(t, unsafe { SEED }, x, sum, 5, 7);
            MUSH!(t, unsafe { SEED }, x, sum, 6, 9);
            MUSH!(t, unsafe { SEED }, x, sum, 7, 13);
            MUSH!(t, unsafe { SEED }, x, sum, 8, 5);
            MUSH!(t, unsafe { SEED }, x, sum, 9, 7);
            MUSH!(t, unsafe { SEED }, x, sum, 10, 9);
            MUSH!(t, unsafe { SEED }, x, sum, 11, 13);
        }
        unsafe {
            for i in 0..8 {
                OUT[i] ^= t[i + 4];
            }
        }
    }
}

pub(crate) fn rand16() -> u16 {
    unsafe {
        if OUTLEFT == 0 {
            if IN[0] == u32::MAX {
                IN[0] = 0;
                if IN[1] == u32::MAX {
                    IN[1] = 0;
                    if IN[2] == u32::MAX {
                        IN[2] = 0;
                        IN[3] = IN[3].wrapping_add(1);
                    } else {
                        IN[2] = IN[2].wrapping_add(1);
                    }
                } else {
                    IN[1] = IN[1].wrapping_add(1);
                }
            } else {
                IN[0] = IN[0].wrapping_add(1);
            }
            surf();
            OUTLEFT = 8;
        }
        OUTLEFT -= 1;
        OUT[OUTLEFT as usize] as u16
    }
}

pub(crate) fn rand32() -> u32 {
    unsafe {
        if OUTLEFT == 0 {
            if IN[0] == u32::MAX {
                IN[0] = 0;
                if IN[1] == u32::MAX {
                    IN[1] = 0;
                    if IN[2] == u32::MAX {
                        IN[2] = 0;
                        IN[3] = IN[3].wrapping_add(1);
                    } else {
                        IN[2] = IN[2].wrapping_add(1);
                    }
                } else {
                    IN[1] = IN[1].wrapping_add(1);
                }
            } else {
                IN[0] = IN[0].wrapping_add(1);
            }
            surf();
            OUTLEFT = 8;
        }
        OUTLEFT -= 1;
        OUT[OUTLEFT as usize]
    }
}

pub(crate) fn rand64() -> u64 {
    static mut OUTLEFT: i32 = 0;
    unsafe {
        if OUTLEFT < 2 {
            if IN[0] == u32::MAX {
                IN[0] = 0;
                if IN[1] == u32::MAX {
                    IN[1] = 0;
                    if IN[2] == u32::MAX {
                        IN[2] = 0;
                        IN[3] = IN[3].wrapping_add(1);
                    } else {
                        IN[2] = IN[2].wrapping_add(1);
                    }
                } else {
                    IN[1] = IN[1].wrapping_add(1);
                }
            } else {
                IN[0] = IN[0].wrapping_add(1);
            }
            surf();
            OUTLEFT = 8;
        }
        OUTLEFT -= 2;
        (OUT[OUTLEFT as usize + 1] as u64) + ((OUT[OUTLEFT as usize] as u64) << 32)
    }
}

pub(crate) struct RRList {
    rr: u16,
    next: Option<Box<RRList>>,
}

pub(crate) fn rr_on_list(list: &Option<Box<RRList>>, rr: u16) -> bool {
    let mut current = list;
    while let Some(ref node) = current {
        if node.rr == rr {
            return true;
        }
        current = &node.next;
    }
    false
}

pub(crate) fn check_name(in_name: &mut String) -> i32 {
    // remove trailing .
    // also fail empty string and label > 63 chars
    let mut dotgap = 0usize;
    let mut l = in_name.len();
    let mut nowhite = 0;
    let mut idn_encode = 0;
    let mut hasuscore = 0;
    let mut hasucase = 0;

    if l == 0 || l > MAXDNAME {
        return 0;
    }

    if in_name.ends_with('.') {
        in_name.pop();
        l -= 1;
        nowhite = 1;
    }

    for c in in_name.bytes() {
        if c == b'.' {
            dotgap = 0;
        } else {
            dotgap += 1;
            if dotgap > MAXLABEL {
                return 0;
            }
            if c.is_ascii() && c.is_ascii_control() {
                return 0;
            }
            if !c.is_ascii() {
                #[cfg(not(any(feature = "have_idn", feature = "have_libidn2")))]
                {
                    return 0;
                }
                idn_encode = 1;
            } else if c != b' ' {
                nowhite = 1;
                #[cfg(any(feature = "have_libidn2", all(feature = "have_libidn2", not(feature = "idn2_version_number", not(idn2_version_number < 0x02000003)))))]
                {
                    if c == b'_' {
                        hasuscore = 1;
                    }
                }
            }
        }
    }
    1
}

pub(crate) fn countof<T>(array: &[T]) -> usize {
    array.len()
}

pub(crate) fn min<T: Ord>(a: T, b: T) -> T {
    if a < b {
        a
    } else {
        b
    }
}

pub(crate) const OPTION_BITS: usize = std::mem::size_of::<u32>() * 8;
pub(crate) const OPTION_SIZE: usize =
    (OPT_LAST as usize / OPTION_BITS) + ((OPT_LAST as usize % OPTION_BITS != 0) as usize);

pub(crate) fn option_var(daemon: &Daemon, x: usize) -> u32 {
    daemon.options[x / OPTION_BITS]
}

pub(crate) fn option_val(x: usize) -> u32 {
    1u32 << (x % OPTION_BITS)
}

pub(crate) fn option_bool(daemon: &Daemon, x: usize) -> bool {
    (option_var(daemon, x) & option_val(x)) != 0
}

pub(crate) fn stat_is_equal(a: u32, b: u32) -> bool {
    (a & 0xffff0000) == b
}

pub(crate) const RR_IMDATALEN: usize = size_of::<AllAddr>() - offset_of!(RrData, data);

fn have_config(config: &Option<Box<DhcpConfig>>, mask: u32) -> bool {
    if let Some(cfg) = config {
        (cfg.flags & mask) != 0
    } else {
        false
    }
}
