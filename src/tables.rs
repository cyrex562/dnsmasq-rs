use std::ffi::CString;
use std::io::{self, Error, ErrorKind};
use std::mem;
use std::os::unix::io::AsRawFd;
use std::ptr;
use std::slice;
use std::fs::OpenOptions;
use std::str::Utf8Error;
use std::fmt::Display;
use libc::{AF_INET, AF_INET6, c_char, c_int, c_void, ioctl, ESRCH, ENOENT, LOG_ERR, LOG_INFO, LOG_WARNING, O_RDWR};

const PF_DEVICE: &str = "/dev/pf";
static mut DEV: Option<std::fs::File> = None;

#[derive(Debug)]
struct PfrAddr {
    pfra_af: u8,
    pfra_net: u8,
    pfra_ip4addr: [u8; 4],   // Only for IPv4 case
    pfra_ip6addr: [u8; 16],  // Only for IPv6 case
}

#[derive(Debug)]
struct PfiocTable {
    pfrio_flags: u32,
    pfrio_buffer: *mut c_void,
    pfrio_esize: usize,
    pfrio_size: i32,
    pfrio_nadd: i32,
    pfrio_ndel: i32,
}

#[derive(Debug)]
struct PfrTable {
    pfrt_name: [c_char; 128],
    pfrt_flags: u32,
}

extern "C" {
    fn strerror(errnum: c_int) -> *const c_char;
}

fn pfr_strerror(errnum: c_int) -> &'static str {
    match errnum {
        ESRCH => "Table does not exist",
        ENOENT => "Anchor or Ruleset does not exist",
        _ => unsafe {
            let c_str = strerror(errnum);
            let c_str = c_str.as_ref().unwrap();
            let r_str = std::ffi::CStr::from_ptr(c_str).to_str().unwrap();
            r_str
        }
    }
}

fn ipset_init() -> Result<(), Error> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(PF_DEVICE)?;
    
    unsafe {
        DEV = Some(file);
    }

    Ok(())
}

fn add_to_ipset(setname: &str, ipaddr: &[u8], flags: u32, remove: bool) -> Result<i32, Error> {
    let mut table = PfrTable {
        pfrt_name: [0; 128],
        pfrt_flags: 1, // PFR_TFLAG_PERSIST
    };

    if let Err(e) = CString::new(setname)?.as_bytes_with_nul().get(..128)
        .ok_or(ErrorKind::InvalidInput)
        .and_then(|bytes| {
            for (i, &b) in bytes.iter().enumerate() {
                table.pfrt_name[i] = b as c_char;
            }
            Ok(())
        }) {
        eprintln!("error: cannot use table name {}", setname);
        return Err(Error::new(ErrorKind::Other, "ENAMETOOLONG"));
    }

    let mut io = PfiocTable {
        pfrio_flags: 0,
        pfrio_buffer: &mut table as *mut _ as *mut c_void,
        pfrio_esize: mem::size_of_val(&table),
        pfrio_size: 1,
        pfrio_nadd: 0,
        pfrio_ndel: 0,
    };

    let dev_fd = match unsafe { DEV.as_ref() } {
        Some(file) => file.as_raw_fd(),
        None => {
            eprintln!("warning: no opened pf devices {}", PF_DEVICE);
            return Err(Error::new(ErrorKind::Other, "No opened pf devices"));
        }
    };

    unsafe {
        if ioctl(dev_fd, libc::DIOCRADDTABLES, &mut io) != 0 {
            eprintln!("IPset: error: {}", pfr_strerror(*libc::__errno_location()));
            return Err(Error::last_os_error());
        }

        table.pfrt_flags &= !1;

        if io.pfrio_nadd != 0 {
            println!("info: table created");
        }

        let af = if flags & 1 != 0 { AF_INET6 } else { AF_INET };
        let mut addr = PfrAddr {
            pfra_af: af as u8,
            pfra_net: if af == AF_INET6 { 128 } else { 32 },
            pfra_ip4addr: [0; 4],
            pfra_ip6addr: [0; 16],
        };

        if af == AF_INET6 {
            addr.pfra_ip6addr.copy_from_slice(ipaddr);
        } else {
            addr.pfra_ip4addr.copy_from_slice(&ipaddr[..4]);
        }

        let mut io = PfiocTable {
            pfrio_flags: 0,
            pfrio_buffer: &mut addr as *mut _ as *mut c_void,
            pfrio_esize: mem::size_of_val(&addr),
            pfrio_size: 1,
            pfrio_nadd: 0,
            pfrio_ndel: 0,
        };

        if ioctl(dev_fd, if remove { libc::DIOCRDELADDRS } else { libc::DIOCRADDADDRS }, &mut io) != 0 {
            eprintln!("warning: DIOCR{}ADDRS: {}", if remove { "DEL" } else { "ADD" }, pfr_strerror(*libc::__errno_location()));
            return Err(Error::last_os_error());
        }

        println!("{} addresses {}", io.pfrio_nadd, if remove { "removed" } else { "added" });
        Ok(io.pfrio_nadd)
    }
}

fn main() {
    if let Err(e) = ipset_init() {
        eprintln!("Failed to initialize ipset: {}", e);
    }
}