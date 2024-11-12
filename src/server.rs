use std::time::SystemTime;

use crate::{my_sock_addr::MySockAddr, server_fd::ServerFd};
use std::net::{Ipv4Addr, Ipv6Addr};

pub(crate) struct Server {
    pub(crate) flags: u16,
    pub(crate) domain_len: u16,
    pub(crate) domain: String,
    pub(crate) next: Option<Box<Server>>,
    pub(crate) serial: i32,
    pub(crate) arrayposn: i32,
    pub(crate) last_server: i32,
    pub(crate) addr: MySockAddr,
    pub(crate) source_addr: MySockAddr,
    pub(crate) interface: [u8; IF_NAMESIZE + 1],
    pub(crate) ifindex: u32, // corresponding to interface, above
    pub(crate) sfd: Option<Box<ServerFd>>,
    pub(crate) tcpfd: i32,
    pub(crate) edns_pktsz: i32,
    pub(crate) pktsz_reduced: SystemTime,
    pub(crate) queries: u32,
    pub(crate) failed_queries: u32,
    pub(crate) nxdomain_replies: u32,
    pub(crate) retrys: u32,
    pub(crate) query_latency: u32,
    pub(crate) mma_latency: u32,
    pub(crate) forwardtime: SystemTime,
    pub(crate) forwardcount: i32,
    #[cfg(feature = "have_loop")]
    pub(crate) uid: u32,
}

pub struct ServAddr4 {
    pub flags: u16,
    pub domain_len: u16,
    pub domain: String,
    pub next: Option<Box<Server>>,
    pub addr: Ipv4Addr,
}

pub struct ServAddr6 {
    pub flags: u16,
    pub domain_len: u16,
    pub domain: String,
    pub next: Option<Box<Server>>,
    pub addr: Ipv6Addr,
}

pub struct ServLocal {
    pub flags: u16,
    pub domain_len: u16,
    pub domain: String,
    pub next: Option<Box<Server>>,
}
