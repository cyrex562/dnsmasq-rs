
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

struct AddrList {
    flags: u32,
    prefixlen: u32,
    addr: Addr,
    next: Option<Box<AddrList>>,
}

enum Addr {
    Addr4(Ipv4Addr),
    Addr6(Ipv6Addr),
}

struct AuthZone {
    domain: String,
    subnet: Option<Box<AddrList>>,
    exclude: Option<Box<AddrList>>,
}

struct DnsHeader {
    qdcount: u16,
    hb3: u8,
    hb4: u8,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

struct Daemon {
    namebuff: String,
    auth_zones: Vec<AuthZone>,
    // ... other fields ...
}

impl Daemon {
    fn new() -> Self {
        Daemon {
            namebuff: String::new(),
            auth_zones: Vec::new(),
            // ... initialize other fields ...
        }
    }
}

fn find_addrlist(list: &AddrList, flag: u32, addr: &Addr) -> Option<&AddrList> {
    let mut current = list;
    loop {
        match (&current.addr, addr) {
            (Addr::Addr4(addr4), Addr::Addr4(addr_u4)) => {
                if flag & F_IPV4 != 0 && is_same_net(addr4, addr_u4, current.prefixlen) {
                    return Some(current);
                }
            }
            (Addr::Addr6(addr6), Addr::Addr6(addr_u6)) => {
                if is_same_net6(addr6, addr_u6, current.prefixlen) {
                    return Some(current);
                }
            }
            _ => {}
        }
        if let Some(next) = &current.next {
            current = next;
        } else {
            break;
        }
    }
    None
}

fn find_subnet(zone: &AuthZone, flag: u32, addr: &Addr) -> Option<&AddrList> {
    zone.subnet.as_ref().and_then(|subnet| find_addrlist(subnet, flag, addr))
}

fn find_exclude(zone: &AuthZone, flag: u32, addr: &Addr) -> Option<&AddrList> {
    zone.exclude.as_ref().and_then(|exclude| find_addrlist(exclude, flag, addr))
}

fn filter_zone(zone: &AuthZone, flag: u32, addr: &Addr) -> bool {
    if find_exclude(zone, flag, addr).is_some() {
        return false;
    }
    if zone.subnet.is_none() {
        return true;
    }
    find_subnet(zone, flag, addr).is_some()
}

fn in_zone(zone: &AuthZone, name: &str, cut: Option<&mut &str>) -> bool {
    let namelen = name.len();
    let domainlen = zone.domain.len();

    if let Some(cut) = cut {
        *cut = "";
    }

    if namelen >= domainlen && name.ends_with(&zone.domain) {
        if namelen == domainlen {
            return true;
        }
        if name.chars().nth(namelen - domainlen - 1) == Some('.') {
            if let Some(cut) = cut {
                *cut = &name[namelen - domainlen - 1..];
            }
            return true;
        }
    }
    false
}

fn answer_auth(header: &mut DnsHeader, limit: usize, qlen: usize, now: SystemTime, peer_addr: &Addr, local_query: bool, do_bit: bool, have_pseudoheader: bool) -> usize {
    let mut name = String::new();
    let mut ansp = 0;
    let mut qtype = 0;
    let mut qclass = 0;
    let mut rc = 0;
    let mut nameoffset = 0;
    let mut axfroffset = 0;
    let mut q = 0;
    let mut anscount = 0;
    let mut authcount = 0;
    let mut auth = !local_query;
    let mut trunc = false;
    let mut nxdomain = true;
    let mut soa = false;
    let mut ns = false;
    let mut axfr = false;
    let mut out_of_zone = false;
    let mut zone: Option<&AuthZone> = None;
    let mut subnet: Option<&AddrList> = None;
    let mut cut: Option<&str> = None;

    // ... existing code ...

    ansp
}

// ... existing code ...

fn main() {
    let daemon = Daemon::new();
    // ... existing code ...
}