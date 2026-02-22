pub struct Listener {
    pub fd: i32,
    pub tcpfd: i32,
    pub tftpfd: i32,
    pub used: i32,
    pub addr: MySockAddr,
    pub iface: Option<Box<Irec>>, // only sometimes valid for non-wildcard
    pub next: Option<Box<Listener>>,
}