use libc::{ioctl, AF_INET, AF_INET6, AF_UNSPEC, SIOCGIFNAME, c_int, c_char};
use nix::errno::Errno;
use std::ffi::CString;
use std::net::Ipv4Addr;
use std::ptr::null_mut;

#[cfg(target_os = "linux")]
fn indextoname(fd: c_int, index: c_int, name: &mut [c_char; libc::IF_NAMESIZE]) -> c_int {
    if index == 0 {
        return 0;
    }

    let mut ifr = libc::ifreq {
        ifr_ifindex: index,
        ..unsafe { std::mem::zeroed() }
    };

    unsafe {
        if ioctl(fd, SIOCGIFNAME, &mut ifr) == -1 {
            return 0;
        }
        std::ptr::copy_nonoverlapping(ifr.ifr_name.as_ptr(), name.as_mut_ptr(), libc::IF_NAMESIZE);
    }

    1
}

#[cfg(target_os = "solaris")]
fn indextoname(fd: c_int, index: c_int, name: &mut [c_char; libc::IF_NAMESIZE]) -> c_int {
    use libc::{AF_LOCAL, GLOBAL_ZONEID, ALL_ZERO_ZONEID, LIFN_ALLZONES, LIFC_NOXMIT, LIFC_TEMPORARY, SIOCGLIFCONF, SIOCGLIFNUM, SIOCGLIFINDEX, sa_family_t, in6_addr};

    if index == 0 {
        return 0;
    }

    if getzoneid() == GLOBAL_ZONEID {
        let interface_name = unsafe { if_indextoname(index, name.as_mut_ptr()) };
        if !interface_name.is_null() {
            return 1;
        }
        return 0;
    }

    let lifc_flags = LIFC_NOXMIT | LIFC_TEMPORARY | LIFN_ALLZONES;
    let mut lifn = libc::lifnum {
        lifn_family: AF_UNSPEC,
        lifn_flags: lifc_flags,
        lifn_count: 0,
    };

    if unsafe { ioctl(fd, SIOCGLIFNUM, &mut lifn) } < 0 {
        return 0;
    }

    let numifs = lifn.lifn_count;
    let bufsize = (numifs as usize) * std::mem::size_of::<libc::lifreq>();
    let mut lifc = libc::lifconf {
        lifc_family: AF_UNSPEC,
        lifc_flags: lifc_flags,
        lifc_len: bufsize as i32,
        lifc_buf: unsafe { libc::alloca(bufsize) as *mut libc::c_char },
    };

    if unsafe { ioctl(fd, SIOCGLIFCONF, &mut lifc) } < 0 {
        return 0;
    }

    let lifrp = lifc.lifc_req as *const libc::lifreq;
    for i in 0..(lifc.lifc_len as usize / std::mem::size_of::<libc::lifreq>()) {
        let lifr = unsafe { &*(lifrp.add(i)) };
        let mut temp_lifr = libc::lifreq {
            lifr_name: [0; libc::IF_NAMESIZE],
            ..unsafe { std::mem::zeroed() }
        };
        unsafe {
            std::ptr::copy_nonoverlapping(lifr.lifr_name.as_ptr(), temp_lifr.lifr_name.as_mut_ptr(), libc::IF_NAMESIZE);
        }
        if unsafe { ioctl(fd, SIOCGLIFINDEX, &mut temp_lifr) } < 0 {
            return 0;
        }
        
        if temp_lifr.lifr_index == index {
            unsafe {
                std::ptr::copy_nonoverlapping(temp_lifr.lifr_name.as_ptr(), name.as_mut_ptr(), libc::IF_NAMESIZE);
            }
            return 1;
        }
    }

    0
}

#[cfg(not(any(target_os = "linux", target_os = "solaris")))]
fn indextoname(fd: c_int, index: c_int, name: &mut [c_char; libc::IF_NAMESIZE]) -> c_int {
    if index == 0 || unsafe { if_indextoname(index, name.as_mut_ptr()) }.is_null() {
        return 0;
    }
    1
}

pub fn iface_check(family: c_int, addr: Option<&nix::sys::socket::SockAddr>, name: &str, auth: Option<&mut bool>) -> bool {
    let mut ret = true;
    let mut match_addr = false;

    if let Some(if_names) = daemon.if_names.as_ref() {
        ret = false;

        for tmp in if_names {
            if let Some(ref tmp_name) = tmp.name {
                if wildcard_match(tmp_name, name) {
                    tmp.flags |= INAME_USED;
                    ret = true;
                }
            }
        }

        if let Some(addr) = addr {
            for tmp in daemon.if_addrs.iter().filter(|tmp| tmp.addr.sa_family == family) {
                match family {
                    AF_INET => {
                        if let Some(ipv4_addr) = addr.as_inet() {
                            if ipv4_addr.ip() == Ipv4Addr::from(tmp.addr.in.sin_addr.s_addr) {
                                tmp.flags |= INAME_USED;
                                ret = true;
                                match_addr = true;
                            }
                        }
                    },
                    AF_INET6 => {
                        if let Some(ipv6_addr) = addr.as_inet6() {
                            if &ipv6_addr.ip().octets() == unsafe { &tmp.addr.in6.sin6_addr.s6_addr } {
                                tmp.flags |= INAME_USED;
                                ret = true;
                                match_addr = true;
                            }
                        }
                    },
                    _ => {},
                }
            }
        }
    }

    if !match_addr {
        for tmp in daemon.if_except.iter() {
            if let Some(ref tmp_name) = tmp.name {
                if wildcard_match(tmp_name, name) {
                    ret = false;
                }
            }
        }
    }

    if let Some(auth) = auth.as_deref_mut() {
        *auth = false;

        for tmp in daemon.authinterface.iter() {
            if let Some(ref tmp_name) = tmp.name {
                if tmp_name == name && (tmp.addr.sa_family == 0 || tmp.addr.sa_family == family) {
                    *auth = true;
                    break;
                }
            } else if let Some(addr) = addr {
                if tmp.addr.sa_family == AF_INET && family == AF_INET {
                    if let Some(ipv4_addr) = addr.as_inet() {
                        if ipv4_addr.ip() == Ipv4Addr::from(tmp.addr.in.sin_addr.s_addr) {
                            *auth = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    ret
}

fn main() {
    // Example usage
    let fd: c_int = 3; // Example file descriptor
    let index: c_int = 1; // Example interface index
    let mut name: [c_char; libc::IF_NAMESIZE] = [0; libc::IF_NAMESIZE];

    let result = indextoname(fd, index, &mut name);
    if result == 1 {
        println!("Interface name: {:?}", unsafe { CString::from_raw(name.as_mut_ptr()) });
    } else {
        println!("Failed to get interface name");
    }

    let auth = match iface_check(AF_INET, None, "eth0", None) {
        true => "Authorized",
        false => "Not Authorized",
    };

    println!("Interface check: {}", auth);
}