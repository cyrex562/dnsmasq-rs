/// ICMPv6 Router Advertisement protocol constants and packet structures.
/// Ported from `radv-protocol.h`.

use std::net::Ipv6Addr;

pub const ALL_NODES:   &str = "FF02::1";
pub const ALL_ROUTERS: &str = "FF02::2";

// ICMPv6 option types used in Router Advertisements
pub const ICMP6_OPT_SOURCE_MAC:   u8 = 1;
pub const ICMP6_OPT_PREFIX:       u8 = 3;
pub const ICMP6_OPT_MTU:          u8 = 5;
pub const ICMP6_OPT_ADV_INTERVAL: u8 = 7;
pub const ICMP6_OPT_RT_INFO:      u8 = 24;
pub const ICMP6_OPT_RDNSS:        u8 = 25;
pub const ICMP6_OPT_DNSSL:        u8 = 31;

/// ICMPv6 echo / ping packet header.
#[derive(Debug, Clone, Copy, Default)]
pub struct PingPacket {
    pub icmp_type:   u8,
    pub code:        u8,
    pub checksum:    u16,
    pub identifier:  u16,
    pub sequence_no: u16,
}

/// ICMPv6 Router Advertisement packet header.
#[derive(Debug, Clone, Copy, Default)]
pub struct RaPacket {
    pub icmp_type:      u8,
    pub code:           u8,
    pub checksum:       u16,
    pub hop_limit:      u8,
    pub flags:          u8,
    pub lifetime:       u16,
    pub reachable_time: u32,
    pub retrans_time:   u32,
}

/// ICMPv6 Neighbor Advertisement / Solicitation packet header.
#[derive(Debug, Clone, Copy)]
pub struct NeighPacket {
    pub icmp_type: u8,
    pub code:      u8,
    pub checksum:  u16,
    pub reserved:  u16,
    pub target:    Ipv6Addr,
}

/// ICMPv6 RA Prefix Information option.
#[derive(Debug, Clone, Copy)]
pub struct PrefixOpt {
    pub opt_type:           u8,
    pub len:                u8,
    pub prefix_len:         u8,
    pub flags:              u8,
    pub valid_lifetime:     u32,
    pub preferred_lifetime: u32,
    pub reserved:           u32,
    pub prefix:             Ipv6Addr,
}
