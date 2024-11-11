use libc::{c_int, c_void, sockaddr, sockaddr_nl, socklen_t};
use nix::sys::socket::{socket, bind, AddressFamily, SockFlag, SockProtocol, SockType};
use nix::errno::Errno;
use nix::unistd::close;
use std::ptr::null_mut;
use std::os::unix::io::RawFd;

#[allow(non_camel_case_types)]
type u32 = libc::c_uint;

const AF_NETLINK: c_int = AddressFamily::Netlink as c_int;
const SOCK_RAW: c_int = SockType::Raw as c_int;
const SOL_NETLINK: c_int = 270;
const NETLINK_ROUTE: c_int = 0;
const NLMSG_ALIGN: usize = 4;
const RTMGRP_IPV4_ROUTE: u32 = 0x40;
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV6_ROUTE: u32 = 0x400;
const RTMGRP_IPV6_IFADDR: u32 = 0x10;
const MSG_PEEK: c_int = 0x2;
const MSG_TRUNC: c_int = 0x20;

#[allow(non_camel_case_types)]
struct iovec {
    iov_base: *mut c_void,
    iov_len: usize,
}

fn safe_malloc(size: usize) -> *mut c_void {
    unsafe { libc::malloc(size) }
}

fn expand_buf(iov: &mut iovec, new_len: usize) -> bool {
    let new_base = unsafe { libc::realloc(iov.iov_base, new_len) };
    if new_base.is_null() {
        return false;
    }
    iov.iov_base = new_base;
    iov.iov_len = new_len;
    true
}

fn die(message: &str, code: c_int) {
    eprintln!("{}", message);
    std::process::exit(code);
}

unsafe fn netlink_init() -> Result<RawFd, String> {
    let mut addr = sockaddr_nl {
        nl_family: AF_NETLINK as u16,
        nl_pad: 0,
        nl_pid: 0, // Auto-bind
        nl_groups: RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR,
    };
    let mut slen: socklen_t = std::mem::size_of::<sockaddr_nl>() as socklen_t;

    let fd = socket(AddressFamily::Netlink, SockType::Raw, SockFlag::empty(), SockProtocol::NetlinkRoute)
        .map_err(|e| format!("cannot create netlink socket: {}", e))?;

    if bind(fd, &sockaddr::Netlink(addr), slen).is_err() {
        addr.nl_groups = 0;
        if let Err(e) = bind(fd, &sockaddr::Netlink(addr), slen) {
            if let Err(_) = Errno::result(Err(e)).and_then(nix::errno::errno) {
                close(fd)?;
                return Err(format!("cannot create netlink socket: {}", e));
            }
        }
    }

    let ret_addr = -1;
    if ret_addr == -1 {
        close(fd)?;
        return Err("cannot create netlink socket".to_string());
    }

    let ret_addr = libc::getsockname(fd, &mut addr as *mut sockaddr_nl as *mut sockaddr, &mut slen);
    if ret_addr == -1 {
        close(fd)?;
        return Err("cannot create netlink socket".to_string());
    }

    netlink_pid = addr.nl_pid as u32;

    iov.iov_len = 100;
    iov.iov_base = safe_malloc(iov.iov_len);

    Ok(fd)
}

unsafe fn netlink_recv(fd: RawFd, flags: c_int) -> Result<isize, String> {
    let mut msg: libc::msghdr = std::mem::zeroed();
    let mut nladdr = sockaddr_nl {
        nl_family: 0,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: 0,
    };
    let mut rc: ssize_t;

    loop {
        msg.msg_control = null_mut();
        msg.msg_controllen = 0;
        msg.msg_name = &mut nladdr as *mut sockaddr_nl as *mut c_void;
        msg.msg_namelen = std::mem::size_of::<sockaddr_nl>();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_flags = 0;

        loop {
            rc = libc::recvmsg(fd, &mut msg, flags | MSG_PEEK | MSG_TRUNC);
            if rc < 0 && Errno::last() == Errno::EINTR {
                continue;
            } else {
                break;
            }
        }

        if rc != -1 && (msg.msg_flags & MSG_TRUNC) != 0 {
            if rc as usize == iov.iov_len {
                if expand_buf(&mut iov, rc as usize + 100) {
                    continue;
                }
            } else {
                expand_buf(&mut iov, rc as usize);
            }
        }

        msg.msg_flags = 0;
        loop {
            rc = libc::recvmsg(fd, &mut msg, flags);
            if rc < 0 && Errno::last() == Errno::EINTR {
                continue;
            } else {
                break;
            }
        }

        if rc == -1 || nladdr.nl_pid == 0 {
            break;
        }
    }

    if (msg.msg_flags & MSG_TRUNC) != 0 {
        rc = -1;
        die("buffer too small", libc::ECANCELED);
    }

    Ok(rc)
}

fn main() {
    unsafe {
        match netlink_init() {
            Ok(fd) => {
                println!("Netlink socket initialized with fd: {}", fd);
                match netlink_recv(fd, 0) {
                    Ok(rc) => println!("Received netlink message with size: {}", rc),
                    Err(e) => println!("Error receiving netlink message: {}", e),
                }
            }
            Err(e) => println!("Error initializing netlink socket: {}", e),
        }
    }
}