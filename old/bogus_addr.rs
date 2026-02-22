use crate::all_addr::AllAddr;

pub struct BogusAddr {
    pub is6: i32,
    pub prefix: i32,
    pub addr: AllAddr,
    pub next: *mut BogusAddr,
}