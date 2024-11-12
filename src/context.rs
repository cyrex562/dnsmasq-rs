use std::ptr::null_mut;
use std::time::SystemTime;
use crate::arp_record::ArpRecord;

pub struct Context {
    pub ARPS: *mut ArpRecord,
    pub OLD: *mut ArpRecord,
    pub FREELIST: *mut ArpRecord,
    pub LAST: SystemTime
}

impl Context {
    pub fn new() -> Self {
        let mut new_inst = Self {
            ARPS: null_mut(),
            OLD: null_mut(),
            FREELIST: null_mut(),
            LAST: SystemTime::UNIX_EPOCH
        };
        new_inst
    }
}