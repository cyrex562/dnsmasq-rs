/// Address types used throughout dnsmasq-rs.
/// Ported from the `union all_addr` and `union mysockaddr` definitions in `dnsmasq.h`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// Rust equivalent of `union all_addr` — a discriminated union covering all
/// address and record-data variants stored in the DNS cache and elsewhere.
#[derive(Debug, Clone)]
pub enum AllAddr {
    /// IPv4 address (A record).
    Addr4(Ipv4Addr),
    /// IPv6 address (AAAA record).
    Addr6(Ipv6Addr),
    /// CNAME record.
    Cname(CnameAddr),
    /// DNSKEY raw key material.
    Key(KeyAddr),
    /// DS record.
    Ds(DsAddr),
    /// Log/diagnostic data (used only for logging in forward.c).
    Log(LogAddr),
    /// Arbitrary RR stored in a blockdata chain.
    RrBlock(RrBlockAddr),
    /// Arbitrary RR small enough to store inline.
    RrData(RrDataAddr),
}

impl AllAddr {
    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        match self { Self::Addr4(a) => Some(*a), _ => None }
    }

    pub fn as_ipv6(&self) -> Option<Ipv6Addr> {
        match self { Self::Addr6(a) => Some(*a), _ => None }
    }

    pub fn as_ip(&self) -> Option<IpAddr> {
        match self {
            Self::Addr4(a) => Some(IpAddr::V4(*a)),
            Self::Addr6(a) => Some(IpAddr::V6(*a)),
            _ => None,
        }
    }
}

/// CNAME target pointer — references either a cache entry (by key) or a raw name.
#[derive(Debug, Clone)]
pub struct CnameAddr {
    /// If `is_name_ptr` is true, the target is a heap-allocated name string.
    /// Otherwise it is a reference resolved through the cache.
    pub is_name_ptr: bool,
    pub target_name: Option<String>,
    pub uid: u32,
}

/// DNSKEY record data.
#[derive(Debug, Clone)]
pub struct KeyAddr {
    pub keydata: Vec<u8>,
    pub keylen:  u16,
    pub flags:   u16,
    pub keytag:  u16,
    pub algo:    u8,
}

/// DS (Delegation Signer) record data.
#[derive(Debug, Clone)]
pub struct DsAddr {
    pub keydata: Vec<u8>,
    pub keylen:  u16,
    pub keytag:  u16,
    pub algo:    u8,
    pub digest:  u8,
}

/// Log-only diagnostic data (not stored in cache; used transiently during logging).
#[derive(Debug, Clone, Copy)]
pub struct LogAddr {
    pub keytag:  u16,
    pub algo:    u16,
    pub digest:  u16,
    pub rcode:   u16,
    pub ede:     i32,
}

/// Arbitrary RR stored as a blockdata chain.
#[derive(Debug, Clone)]
pub struct RrBlockAddr {
    pub rrtype:  u16,
    pub rrdata:  Vec<u8>,
}

/// Arbitrary RR stored inline (small records).
#[derive(Debug, Clone)]
pub struct RrDataAddr {
    pub rrtype:  u16,
    pub data:    Vec<u8>,
}

/// Rust equivalent of `union mysockaddr` — an IPv4 or IPv6 socket address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MySockAddr {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
}

impl MySockAddr {
    pub fn ip(&self) -> IpAddr {
        match self {
            Self::V4(s) => IpAddr::V4(*s.ip()),
            Self::V6(s) => IpAddr::V6(*s.ip()),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::V4(s) => s.port(),
            Self::V6(s) => s.port(),
        }
    }

    pub fn is_v4(&self) -> bool { matches!(self, Self::V4(_)) }
    pub fn is_v6(&self) -> bool { matches!(self, Self::V6(_)) }
}

impl From<SocketAddr> for MySockAddr {
    fn from(s: SocketAddr) -> Self {
        match s {
            SocketAddr::V4(a) => Self::V4(a),
            SocketAddr::V6(a) => Self::V6(a),
        }
    }
}

impl From<MySockAddr> for SocketAddr {
    fn from(s: MySockAddr) -> Self {
        match s {
            MySockAddr::V4(a) => SocketAddr::V4(a),
            MySockAddr::V6(a) => SocketAddr::V6(a),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_addr_ipv4() {
        let a = AllAddr::Addr4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(a.as_ipv4(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(a.as_ipv6().is_none());
    }

    #[test]
    fn all_addr_ipv6() {
        let a = AllAddr::Addr6(Ipv6Addr::LOCALHOST);
        assert_eq!(a.as_ipv6(), Some(Ipv6Addr::LOCALHOST));
        assert!(a.as_ipv4().is_none());
    }

    #[test]
    fn mysockaddr_from_socketaddr_v4() {
        let sa: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let msa = MySockAddr::from(sa);
        assert!(msa.is_v4());
        assert_eq!(msa.port(), 53);
    }

    #[test]
    fn mysockaddr_from_socketaddr_v6() {
        let sa: SocketAddr = "[::1]:53".parse().unwrap();
        let msa = MySockAddr::from(sa);
        assert!(msa.is_v6());
        assert_eq!(msa.port(), 53);
    }
}
