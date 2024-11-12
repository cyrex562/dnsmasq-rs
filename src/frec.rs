use std::time::SystemTime;

use crate::{
    all_addr::AllAddr, block_name::BlockData, my_sock_addr::MySockAddr, rand_fd::RandFdList,
    server::Server,
};

pub struct Frec {
    pub frec_src: FrecSrc,
    pub sentto: Option<Box<Server>>, // NULL means free
    pub rfds: Option<Box<RandFdList>>,
    pub new_id: u16,
    pub forwardall: i32,
    pub flags: i32,
    pub time: SystemTime,
    pub forward_timestamp: u32,
    pub forward_delay: i32,
    pub hash: [*mut u8; HASH_SIZE],
    pub stash: Option<Box<BlockData>>, // Saved reply, whilst we validate
    pub stash_len: usize,
    #[cfg(feature = "have_dnssec")]
    pub class: i32,
    #[cfg(feature = "have_dnssec")]
    pub work_counter: i32,
    #[cfg(feature = "have_dnssec")]
    pub validate_counter: i32,
    #[cfg(feature = "have_dnssec")]
    pub dependent: Option<Box<Frec>>, // Query awaiting internally-generated DNSKEY or DS query
    #[cfg(feature = "have_dnssec")]
    pub next_dependent: Option<Box<Frec>>, // list of above
    #[cfg(feature = "have_dnssec")]
    pub blocking_query: Option<Box<Frec>>, // Query which is blocking us
    pub next: Option<Box<Frec>>,
}

pub struct FrecSrc {
    pub source: MySockAddr,
    pub dest: AllAddr,
    pub iface: u32,
    pub log_id: u32,
    pub fd: i32,
    pub orig_id: u16,
    pub next: Option<Box<FrecSrc>>,
}
