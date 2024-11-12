use crate::my_sock_addr::MySockAddr;

pub struct Iname {
    pub name: String,
    pub addr: MySockAddr,
    pub flags: i32,
    pub next: Option<Box<Iname>>,
}