const ALL_NODES: &str = "FF02::1";
const ALL_ROUTERS: &str = "FF02::2";

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
struct PingPacket {
    ptype: u8,
    code: u8,
    checksum: u16,
    identifier: u16,
    sequence_no: u16,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
struct RaPacket {
    ptype: u8,
    code: u8,
    checksum: u16,
    hop_limit: u8,
    flags: u8,
    lifetime: u16,
    reachable_time: u32,
    retrans_time: u32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
struct NeighPacket {
    ptype: u8,
    code: u8,
    checksum: u16,
    reserved: u16,
    target: libc::in6_addr,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
struct PrefixOpt {
    ptype: u8,
    len: u8,
    prefix_len: u8,
    flags: u8,
    valid_lifetime: u32,
    preferred_lifetime: u32,
    reserved: u32,
    prefix: libc::in6_addr,
}

const ICMP6_OPT_SOURCE_MAC: u8 = 1;
const ICMP6_OPT_PREFIX: u8 = 3;
const ICMP6_OPT_MTU: u8 = 5;
const ICMP6_OPT_ADV_INTERVAL: u8 = 7;
const ICMP6_OPT_RT_INFO: u8 = 24;
const ICMP6_OPT_RDNSS: u8 = 25;
const ICMP6_OPT_DNSSL: u8 = 31;