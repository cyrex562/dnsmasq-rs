use crate::server::Server;

pub struct RandFd {
    pub serv: *mut Server,
    pub fd: i32,
    pub refcount: u16, // refcount == 0xffff means overflow record
}

pub struct RandFdList {
    pub rfd: *mut RandFd,
    pub next: Option<Box<RandFdList>>,
}