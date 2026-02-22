use crate::my_sock_addr::MySockAddr;

pub struct MySubnet {
    pub addr: MySockAddr,
    pub addr_used: i32,
    pub mask: i32,
}