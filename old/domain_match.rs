use std::cmp::Ordering;
use std::ptr;
use std::slice;

#[derive(Copy, Clone)]
struct Server {
    flags: u32,
    serial: i32,
    last_server: i32,
    arrayposn: i32,
    next: Option<Box<Server>>,
}

struct Daemon {
    servers: Option<Box<Server>>,
    local_domains: Option<Box<Server>>,
    server_has_wildcard: bool,
    serverarray: Vec<*mut Server>,
    serverarraysz: usize,
    serverarrayhwm: usize,
}

static mut DAEMON: Daemon = Daemon {
    servers: None,
    local_domains: None,
    server_has_wildcard: false,
    serverarray: Vec::new(),
    serverarraysz: 0,
    serverarrayhwm: 0,
};

const SERV_LOOP: u32 = 0x01;
const SERV_WILDCARD: u32 = 0x02;
const SERV_USE_RESOLV: u32 = 0x04;
const SERV_LITERAL_ADDRESS: u32 = 0x08;
const SERV_IS_LOCAL: u32 = SERV_USE_RESOLV | SERV_LITERAL_ADDRESS;
const F_SERVER: i32 = 0x01;
const F_DNSSECOK: i32 = 0x02;
const F_DOMAINSRV: i32 = 0x04;
const F_CONFIG: i32 = 0x08;

unsafe fn order(_qdomain: &str, _qlen: usize, _serv: *const Server) -> i32 {
    // Implement the order logic
    0
}

unsafe fn order_qsort(key: *const *mut Server) -> Ordering {
    // Implement the ordering logic for qsort
    Ordering::Equal
}

unsafe fn order_servers(s: *const Server, s2: *const Server) -> i32 {
    // Implement the order servers logic
    0
}

unsafe fn build_server_array() {
    let mut count = 0;

    let mut serv = DAEMON.servers.as_ref();
    while let Some(s) = serv {
        #[cfg(HAVE_LOOP)]
        if s.flags & SERV_LOOP == 0 {
            count += 1;
            if s.flags & SERV_WILDCARD != 0 {
                DAEMON.server_has_wildcard = true;
            }
        }
        serv = s.next.as_ref();
    }

    let mut local_serv = DAEMON.local_domains.as_ref();
    while let Some(s) = local_serv {
        count += 1;
        if s.flags & SERV_WILDCARD != 0 {
            DAEMON.server_has_wildcard = true;
        }
        local_serv = s.next.as_ref();
    }

    DAEMON.serverarraysz = count;

    if count > DAEMON.serverarrayhwm {
        count += 10; // A few extra without re-allocating.

        let new_capacity = count * std::mem::size_of::<*mut Server>();
        DAEMON.serverarray.reserve(new_capacity);

        DAEMON.serverarrayhwm = count;
    }

    count = 0;

    let mut serv = DAEMON.servers.as_ref();
    while let Some(s) = serv {
        #[cfg(HAVE_LOOP)]
        if s.flags & SERV_LOOP == 0 {
            DAEMON.serverarray.push(s as *const _ as *mut _);
            let mut s_mut = &mut *(s as *const _ as *mut Server);
            s_mut.serial = count as i32;
            s_mut.last_server = -1;
            count += 1;
        }
        serv = s.next.as_ref();
    }

    let mut local_serv = DAEMON.local_domains.as_ref();
    while let Some(s) = local_serv {
        DAEMON.serverarray.push(s as *const _ as *mut _);
        count += 1;
        local_serv = s.next.as_ref();
    }

    DAEMON.serverarray.sort_by(|a, b| order_qsort(a));
    
    for count in 0..DAEMON.serverarraysz {
        if DAEMON.serverarray[count].as_ref().map_or(false, |serv| serv.flags & SERV_IS_LOCAL == 0) {
            let server = &mut *DAEMON.serverarray[count];
            server.arrayposn = count as i32;
        }
    }
}

unsafe fn lookup_domain(domain: &str, flags: i32, lowout: &mut i32, highout: &mut i32) -> i32 {
    if DAEMON.serverarraysz == 0 {
        return 0;
    }

    let mut qdomain = String::from(domain);
    let mut crop_query;
    let mut nodots = 1;
    let mut qlen = 0;
    for c in qdomain.chars() {
        qlen += 1;
        if c == '.' {
            nodots = 0;
        }
    }

    if qlen == 0 || flags & F_DNSSECOK != 0 {
        nodots = 0;
    }

    while qlen >= 0 {
        // Implement logic to search for the server whose domain is the longest exact match to qdomain
        qlen -= 1;
    }

    0
}

fn main() {
    unsafe {
        build_server_array();
    }
}