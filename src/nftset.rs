use nftables::{nft_context, nft_ctx_new, nft_ctx_buffer_error, nft_run_cmd_from_buffer, nft_ctx_get_error_buffer};
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr::null_mut;
use libc::{AF_INET, AF_INET6};

#[cfg(target_os = "linux")]
static mut CTX: *mut nft_context = null_mut();

const CMD_ADD: &str = "add element {} {{ {} }}";
const CMD_DEL: &str = "delete element {} {{ {} }}";

unsafe fn nftset_init() {
    CTX = nft_ctx_new(0);
    if CTX.is_null() {
        eprintln!("failed to create nftset context");
        std::process::exit(libc::EXIT_FAILURE);
    }

    nft_ctx_buffer_error(CTX);
}

unsafe fn add_to_nftset(setname: &str, ipaddr: &IpAddr, flags: u32, remove: bool) -> i32 {
    let cmd = if remove { CMD_DEL } else { CMD_ADD };

    let af = if flags & libc::AF_INET as u32 != 0 { AF_INET } else { AF_INET6 };

    let addrbuff = match *ipaddr {
        IpAddr::V4(addr) => {
            if af == AF_INET {
                CString::new(addr.to_string()).unwrap()
            } else {
                return -1;
            }
        }
        IpAddr::V6(addr) => {
            if af == AF_INET6 {
                CString::new(addr.to_string()).unwrap()
            } else {
                return -1;
            }
        }
    };

    let setname_adjusted = if setname.len() > 2 && setname.chars().nth(1) == Some(' ') && (setname.chars().nth(0) == Some('4') || setname.chars().nth(0) == Some('6')) {
        if setname.starts_with('4') && (flags & libc::AF_INET as u32 == 0) {
            return -1;
        }
        if setname.starts_with('6') && (flags & libc::AF_INET6 as u32 == 0) {
            return -1;
        }
        &setname[2..]
    } else {
        setname
    };

    let mut cmd_buf = CString::new(cmd).unwrap();
    let mut cmd_buf_sz = cmd.len() + setname_adjusted.len() + addrbuff.to_bytes().len() + 10;
    cmd_buf = CString::new(format!(cmd, setname_adjusted, addrbuff.to_str().unwrap())).unwrap();

    if cmd_buf.to_bytes().len() > cmd_buf_sz {
        cmd_buf_sz = cmd_buf.to_bytes().len() + 10;
        cmd_buf = CString::new(format!(cmd, setname_adjusted, addrbuff.to_str().unwrap())).unwrap();
    }

    let ret = nft_run_cmd_from_buffer(CTX, cmd_buf.as_ptr());
    let err = CString::from_raw(nft_ctx_get_error_buffer(CTX) as *mut i8);

    if ret != 0 {
        if let Ok(err_str) = err.into_string() {
            if let Some(nl) = err_str.find('\n') {
                eprintln!("nftset {} {}", setname_adjusted, &err_str[0..nl]);
            } else {
                eprintln!("nftset {} {}", setname_adjusted, err_str);
            }
        }
    }

    ret
}

fn main() {
    unsafe {
        nftset_init();
        let ipaddr: IpAddr = "192.168.1.1".parse().unwrap();
        let flags = libc::AF_INET as u32;
        let setname = "4 example_set";
        let remove = false;
        let result = add_to_nftset(setname, &ipaddr, flags, remove);
        println!("{}", if result == 0 { "Success" } else { "Failed" });
    }
}