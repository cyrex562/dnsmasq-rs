use libc::IF_NAMESIZE;

use crate::my_sock_addr::MySockAddr;

pub struct ServerFd {
    pub fd: i32,
    pub source_addr: MySockAddr,
    pub interface: [u8; IF_NAMESIZE + 1],
    pub ifindex: u32,
    pub used: u32,
    pub preallocated: u32,
    pub next: Option<Box<ServerFd>>,
}
