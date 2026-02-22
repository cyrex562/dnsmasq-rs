/// DNS record types for zone data and config.
/// Ported from `struct mx_srv_record`, `struct txt_record`, `struct ptr_record`,
/// `struct naptr`, `struct cname`, `struct ds_config`, `struct host_record`,
/// `struct auth_zone`, and related types in `dnsmasq.h`.

use std::net::{Ipv4Addr, Ipv6Addr};

/// MX or SRV record.
#[derive(Debug, Clone)]
pub struct MxSrvRecord {
    pub name:     String,
    pub target:   String,
    pub is_srv:   bool,
    pub srv_port: u16,
    pub priority: u32,
    pub weight:   u32,
    pub offset:   u32,
}

/// NAPTR record.
#[derive(Debug, Clone)]
pub struct Naptr {
    pub name:     String,
    pub replace:  String,
    pub regexp:   String,
    pub services: String,
    pub flags:    String,
    pub order:    u32,
    pub pref:     u32,
}

/// TXT record.
#[derive(Debug, Clone)]
pub struct TxtRecord {
    pub name:  String,
    pub txt:   Vec<u8>,
    pub class: u16,
    pub stat:  i32,
}

/// PTR record.
#[derive(Debug, Clone)]
pub struct PtrRecord {
    pub name: String,
    pub ptr:  String,
}

/// CNAME alias mapping.
#[derive(Debug, Clone)]
pub struct Cname {
    pub ttl:    i32,
    pub flag:   i32,
    pub alias:  String,
    pub target: String,
}

/// DS (Delegation Signer) configuration entry.
#[derive(Debug, Clone)]
pub struct DsConfig {
    pub name:        String,
    pub digest:      Vec<u8>,
    pub class:       i32,
    pub algo:        i32,
    pub keytag:      i32,
    pub digest_type: i32,
}

/// Addrlist flags
pub const ADDRLIST_LITERAL:  u32 = 1;
pub const ADDRLIST_IPV6:     u32 = 2;
pub const ADDRLIST_REVONLY:  u32 = 4;
pub const ADDRLIST_PREFIX:   u32 = 8;
pub const ADDRLIST_WILDCARD: u32 = 16;
pub const ADDRLIST_DECLINED: u32 = 32;

/// Generic address + flags entry, used in many config structures.
#[derive(Debug, Clone)]
pub struct Addrlist {
    pub addr:         crate::types::addr::AllAddr,
    pub flags:        u32,
    pub prefixlen:    i32,
    pub decline_time: Option<std::time::SystemTime>,
}

/// Authoritative zone definition.
#[derive(Debug, Clone)]
pub struct AuthZone {
    pub domain:          String,
    pub interface_names: Vec<AuthNameEntry>,
    pub subnet:          Vec<Addrlist>,
    pub exclude:         Vec<Addrlist>,
}

#[derive(Debug, Clone)]
pub struct AuthNameEntry {
    pub name:  String,
    pub flags: i32,
}

/// Host record — maps a set of names to IPv4/IPv6 addresses.
#[derive(Debug, Clone)]
pub struct HostRecord {
    pub ttl:   i32,
    pub flags: i32,
    pub names: Vec<String>,
    pub addr4: Option<Ipv4Addr>,
    pub addr6: Option<Ipv6Addr>,
}

/// Interface name → domain mapping.
#[derive(Debug, Clone)]
pub struct InterfaceName {
    pub name:   String,  // domain name
    pub intr:   String,  // interface name
    pub flags:  i32,
    pub proto4: Option<Ipv4Addr>,
    pub proto6: Option<Ipv6Addr>,
    pub addrs:  Vec<Addrlist>,
}

/// Bogus-address entry (addresses to block/rewrite in responses).
#[derive(Debug, Clone)]
pub struct BogusAddr {
    pub is6:    bool,
    pub prefix: i32,
    pub addr:   crate::types::addr::AllAddr,
}

/// DNS Doctor rewrite rule.
#[derive(Debug, Clone, Copy)]
pub struct Doctor {
    pub in_addr:  Ipv4Addr,
    pub end_addr: Ipv4Addr,
    pub out_addr: Ipv4Addr,
    pub mask:     Ipv4Addr,
}

/// Arbitrary RR type list (for `--cache-rr` etc.)
#[derive(Debug, Clone)]
pub struct RrList {
    pub rr:   u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mx_srv_record_clone() {
        let r = MxSrvRecord {
            name:     "example.com".into(),
            target:   "mail.example.com".into(),
            is_srv:   false,
            srv_port: 0,
            priority: 10,
            weight:   0,
            offset:   0,
        };
        let r2 = r.clone();
        assert_eq!(r2.name, r.name);
    }

    #[test]
    fn addrlist_flags() {
        assert_ne!(ADDRLIST_IPV6, ADDRLIST_LITERAL);
    }
}
