use std::time::SystemTime;

use crate::all_addr::AllAddr;

pub struct AddrList {
    pub addr: AllAddr,
    pub flags: i32,
    pub prefixlen: i32,
    pub decline_time: SystemTime,
    pub next: Option<Box<AddrList>>,
}
