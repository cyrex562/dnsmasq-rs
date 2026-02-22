
use std::ptr;
use std::ffi::CString;
use std::os::raw::c_void;
use std::net::{Ipv4Addr, Ipv6Addr};
use libc::{AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP};
use libnetfilter_conntrack::{nfct_callback_register, nfct_close, nfct_destroy, nfct_get_attr_u32, nfct_new, nfct_open, nfct_query, nfct_set_attr, nfct_set_attr_u16, nfct_set_attr_u32, nfct_set_attr_u8, nfct_t, nfct_handle, nfct_conntrack, nfct_callback, nfct_q};

static mut GOTIT: bool = false;

extern "C" fn callback(type_: u32, ct: *mut nfct_conntrack, data: *mut c_void) -> i32 {
    unsafe {
        let ret = data as *mut u32;
        *ret = nfct_get_attr_u32(ct, libnetfilter_conntrack::ATTR_MARK);
        GOTIT = true;
    }
    0 // NFCT_CB_CONTINUE
}

pub fn get_incoming_mark(peer_addr: &mysockaddr, local_addr: &all_addr, istcp: bool, markp: &mut u32) -> bool {
    unsafe {
        GOTIT = false;
    }

    let ct = unsafe { nfct_new() };
    if ct.is_null() {
        return false;
    }

    unsafe {
        nfct_set_attr_u8(ct, libnetfilter_conntrack::ATTR_L4PROTO, if istcp { IPPROTO_TCP } else { IPPROTO_UDP });
        nfct_set_attr_u16(ct, libnetfilter_conntrack::ATTR_PORT_DST, daemon.port.to_be());

        match peer_addr.sa.sa_family as i32 {
            AF_INET6 => {
                nfct_set_attr_u8(ct, libnetfilter_conntrack::ATTR_L3PROTO, AF_INET6 as u8);
                nfct_set_attr(ct, libnetfilter_conntrack::ATTR_IPV6_SRC, peer_addr.in6.sin6_addr.s6_addr.as_ptr() as *const c_void);
                nfct_set_attr_u16(ct, libnetfilter_conntrack::ATTR_PORT_SRC, peer_addr.in6.sin6_port.to_be());
                nfct_set_attr(ct, libnetfilter_conntrack::ATTR_IPV6_DST, local_addr.addr6.s6_addr.as_ptr() as *const c_void);
            }
            AF_INET => {
                nfct_set_attr_u8(ct, libnetfilter_conntrack::ATTR_L3PROTO, AF_INET as u8);
                nfct_set_attr_u32(ct, libnetfilter_conntrack::ATTR_IPV4_SRC, u32::from(Ipv4Addr::from(peer_addr.in.sin_addr.s_addr)).to_be());
                nfct_set_attr_u16(ct, libnetfilter_conntrack::ATTR_PORT_SRC, peer_addr.in.sin_port.to_be());
                nfct_set_attr_u32(ct, libnetfilter_conntrack::ATTR_IPV4_DST, u32::from(Ipv4Addr::from(local_addr.addr4.s_addr)).to_be());
            }
            _ => {}
        }

        let h = nfct_open(libnetfilter_conntrack::CONNTRACK, 0);
        if !h.is_null() {
            nfct_callback_register(h, libnetfilter_conntrack::NFCT_T_ALL, Some(callback), markp as *mut _ as *mut c_void);
            if nfct_query(h, libnetfilter_conntrack::NFCT_Q_GET, ct) == -1 {
                static mut WARNED: bool = false;
                if !WARNED {
                    eprintln!("Conntrack connection mark retrieval failed: {}", CString::from_raw(libc::strerror(libc::errno())).into_string().unwrap());
                    WARNED = true;
                }
            }
            nfct_close(h);
        }
        nfct_destroy(ct);
    }

    unsafe { GOTIT }
}