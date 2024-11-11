
use std::time::{Duration, SystemTime};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr::null_mut;
use std::mem::size_of;
use std::ffi::c_void;
use libc::{self, AF_INET, AF_INET6};


const INTERVAL: u64 = 90;
const DHCP_CHADDR_MAX: usize = 16;
const ARP_MARK: u16 = 0;
const ARP_FOUND: u16 = 1;
const ARP_NEW: u16 = 2;
const ARP_EMPTY: u16 = 3;

#[derive(Clone, Copy)]
union AllAddr {
    addr4: Ipv4Addr,
    addr6: Ipv6Addr,
}

struct ArpRecord {
    hwlen: u16,
    status: u16,
    family: i32,
    hwaddr: [u8; DHCP_CHADDR_MAX],
    addr: AllAddr,
    next: *mut ArpRecord,
}

static mut ARPS: *mut ArpRecord = null_mut();
static mut OLD: *mut ArpRecord = null_mut();
static mut FREELIST: *mut ArpRecord = null_mut();
static mut LAST: SystemTime = SystemTime::UNIX_EPOCH;

fn filter_mac(family: i32, addrp: *const c_void, mac: &[u8], parmv: *mut c_void) -> i32 {
    unsafe {
        let mut arp = ARPS;

        if mac.len() > DHCP_CHADDR_MAX {
            return 1;
        }

        while !arp.is_null() {
            let arp_ref = &mut *arp;
            if family != arp_ref.family || arp_ref.status == ARP_NEW {
                arp = arp_ref.next;
                continue;
            }

            if family == libc::AF_INET {
                if arp_ref.addr.addr4 != *(addrp as *const Ipv4Addr) {
                    arp = arp_ref.next;
                    continue;
                }
            } else {
                if arp_ref.addr.addr6 != *(addrp as *const Ipv6Addr) {
                    arp = arp_ref.next;
                    continue;
                }
            }

            if arp_ref.status == ARP_EMPTY {
                arp_ref.status = ARP_NEW;
                arp_ref.hwlen = mac.len() as u16;
                arp_ref.hwaddr[..mac.len()].copy_from_slice(mac);
            } else if arp_ref.hwlen == mac.len() as u16 && arp_ref.hwaddr[..mac.len()] == *mac {
                arp_ref.status = ARP_FOUND;
            } else {
                arp = arp_ref.next;
                continue;
            }

            break;
        }

        if arp.is_null() {
            let new_arp = if !FREELIST.is_null() {
                let arp = FREELIST;
                FREELIST = (*FREELIST).next;
                arp
            } else {
                libc::malloc(size_of::<ArpRecord>()) as *mut ArpRecord
            };

            if new_arp.is_null() {
                return 1;
            }

            (*new_arp).next = ARPS;
            ARPS = new_arp;
            (*new_arp).status = ARP_NEW;
            (*new_arp).hwlen = mac.len() as u16;
            (*new_arp).family = family;
            (*new_arp).hwaddr[..mac.len()].copy_from_slice(mac);
            if family == libc::AF_INET {
                (*new_arp).addr.addr4 = *(addrp as *const Ipv4Addr);
            } else {
                (*new_arp).addr.addr6 = *(addrp as *const Ipv6Addr);
            }
        }

        1
    }
}

fn find_mac(addr: Option<&libc::sockaddr>, mac: &mut [u8], lazy: bool, now: SystemTime) -> i32 {
    unsafe {
        let mut arp = ARPS;
        let mut updated = false;

        loop {
            if now.duration_since(LAST).unwrap_or(Duration::new(0, 0)).as_secs() < INTERVAL {
                if addr.is_none() {
                    return 0;
                }

                while !arp.is_null() {
                    let arp_ref = &mut *arp;
                    if addr.unwrap().sa_family as i32 != arp_ref.family {
                        arp = arp_ref.next;
                        continue;
                    }

                    if arp_ref.family == libc::AF_INET && arp_ref.addr.addr4 != *(addr.unwrap() as *const _ as *const Ipv4Addr) {
                        arp = arp_ref.next;
                        continue;
                    }

                    if arp_ref.family == libc::AF_INET6 && arp_ref.addr.addr6 != *(addr.unwrap() as *const _ as *const Ipv6Addr) {
                        arp = arp_ref.next;
                        continue;
                    }

                    if arp_ref.status != ARP_EMPTY || lazy || updated {
                        if !mac.is_empty() && arp_ref.hwlen != 0 {
                            mac[..arp_ref.hwlen as usize].copy_from_slice(&arp_ref.hwaddr[..arp_ref.hwlen as usize]);
                        }
                        return arp_ref.hwlen as i32;
                    }

                    arp = arp_ref.next;
                }
            }

            if !updated {
                updated = true;
                LAST = now;

                arp = ARPS;
                while !arp.is_null() {
                    if (*arp).status != ARP_EMPTY {
                        (*arp).status = ARP_MARK;
                    }
                    arp = (*arp).next;
                }

                iface_enumerate(libc::AF_UNSPEC, null_mut(), filter_mac);

                let mut up = &mut ARPS;
                while !(*up).is_null() {
                    let tmp = (*up).next;
                    if (*up).status == ARP_MARK {
                        *up = tmp;
                        (*up).next = OLD;
                        OLD = *up;
                    } else {
                        up = &mut (*up).next;
                    }
                }

                continue;
            }

            let new_arp = if !FREELIST.is_null() {
                let arp = FREELIST;
                FREELIST = (*FREELIST).next;
                arp
            } else {
                libc::malloc(size_of::<ArpRecord>()) as *mut ArpRecord
            };

            if !new_arp.is_null() {
                (*new_arp).next = ARPS;
                ARPS = new_arp;
                (*new_arp).status = ARP_EMPTY;
                (*new_arp).family = addr.unwrap().sa_family as i32;
                (*new_arp).hwlen = 0;

                if addr.unwrap().sa_family as i32 == libc::AF_INET {
                    (*new_arp).addr.addr4 = *(addr.unwrap() as *const _ as *const Ipv4Addr);
                } else {
                    (*new_arp).addr.addr6 = *(addr.unwrap() as *const _ as *const Ipv6Addr);
                }
            }

            return 0;
        }
    }
}

fn do_arp_script_run() -> i32 {
    unsafe {
        if !OLD.is_null() {
            #[cfg(feature = "script")]
            if option_bool(OPT_SCRIPT_ARP) {
                queue_arp(ACTION_ARP_DEL, &(*OLD).hwaddr, (*OLD).hwlen, (*OLD).family, &(*OLD).addr);
            }
            let arp = OLD;
            OLD = (*OLD).next;
            (*arp).next = FREELIST;
            FREELIST = arp;
            return 1;
        }

        let mut arp = ARPS;
        while !arp.is_null() {
            if (*arp).status == ARP_NEW {
                #[cfg(feature = "script")]
                if option_bool(OPT_SCRIPT_ARP) {
                    queue_arp(ACTION_ARP, &(*arp).hwaddr, (*arp).hwlen, (*arp).family, &(*arp).addr);
                }
                (*arp).status = ARP_FOUND;
                return 1;
            }
            arp = (*arp).next;
        }

        0
    }
}