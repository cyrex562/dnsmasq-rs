//! In-memory DHCP lease database with text-format serialisation.
//! Ported from `lease.c`.

#[cfg(feature = "dhcp")]
use std::collections::HashMap;
#[cfg(feature = "dhcp")]
use std::net::Ipv4Addr;
#[cfg(feature = "dhcp")]
use std::time::{Duration, UNIX_EPOCH};

#[cfg(feature = "dhcp")]
use crate::dhcp_protocol::DHCP_CHADDR_MAX;
#[cfg(feature = "dhcp")]
use crate::types::dhcp::DhcpLease;

/// Errors that can occur during lease deserialisation.
#[cfg(feature = "dhcp")]
#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("parse error at line {0}: {1}")]
    ParseError(usize, String),
}

/// Pad or truncate a byte slice to a fixed-length 16-byte key.
#[cfg(feature = "dhcp")]
fn to_key(id: &[u8]) -> [u8; 16] {
    let mut key = [0u8; 16];
    let n = id.len().min(16);
    key[..n].copy_from_slice(&id[..n]);
    key
}

/// Build a client-id key from a `DhcpLease`, preferring the explicit client-id
/// and falling back to the hardware address bytes.
#[cfg(feature = "dhcp")]
fn lease_key(lease: &DhcpLease) -> [u8; 16] {
    if let Some(clid) = &lease.clid {
        if !clid.is_empty() {
            return to_key(clid);
        }
    }
    to_key(&lease.hwaddr[..lease.hwaddr_len.min(DHCP_CHADDR_MAX)])
}

/// In-memory DHCP lease database.
#[cfg(feature = "dhcp")]
pub struct LeaseDb {
    leases: HashMap<[u8; 16], DhcpLease>,
}

#[cfg(feature = "dhcp")]
impl LeaseDb {
    /// Create an empty lease database.
    pub fn new() -> Self {
        Self {
            leases: HashMap::new(),
        }
    }

    /// Add or renew a lease (identified by its client-id / hardware address).
    pub fn insert(&mut self, lease: DhcpLease) {
        let key = lease_key(&lease);
        self.leases.insert(key, lease);
    }

    /// Find a lease by its assigned IPv4 address.
    pub fn find_by_addr(&self, addr: Ipv4Addr) -> Option<&DhcpLease> {
        self.leases.values().find(|l| l.addr == addr)
    }

    /// Find a lease by client identifier (hardware address or option 61 bytes).
    pub fn find_by_client_id(&self, client_id: &[u8]) -> Option<&DhcpLease> {
        let key = to_key(client_id);
        self.leases.get(&key)
    }

    /// Remove leases that expired before `now_secs` (seconds since UNIX epoch).
    /// Returns the removed leases.
    pub fn prune(&mut self, now_secs: u64) -> Vec<DhcpLease> {
        let now = UNIX_EPOCH + Duration::from_secs(now_secs);
        let mut pruned = Vec::new();
        self.leases.retain(|_, lease| {
            if let Some(exp) = lease.expires {
                if exp < now {
                    pruned.push(lease.clone());
                    return false;
                }
            }
            true
        });
        pruned
    }

    /// Serialise all leases to a simple text format (one per line).
    ///
    /// Format: `<expires_unix_secs> <ip> <hwaddr_hex> <hostname|*> <clid_hex|*>`
    pub fn serialize(&self) -> String {
        let mut out = String::new();
        for lease in self.leases.values() {
            let expires = match lease.expires {
                Some(t) => t
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                None => 0,
            };
            let ip = lease.addr;
            let hw: String = lease.hwaddr[..lease.hwaddr_len.min(DHCP_CHADDR_MAX)]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":");
            let hostname = lease
                .hostname
                .as_deref()
                .unwrap_or("*")
                .to_string();
            let clid = match &lease.clid {
                Some(c) if !c.is_empty() => c
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":"),
                _ => "*".to_string(),
            };
            out.push_str(&format!(
                "{expires} {ip} {hw} {hostname} {clid}\n"
            ));
        }
        out
    }

    /// Deserialise a lease database from the text produced by [`serialize`].
    pub fn deserialize(text: &str) -> Result<Self, LeaseError> {
        let mut db = Self::new();
        for (line_no, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(5, ' ').collect();
            if parts.len() != 5 {
                return Err(LeaseError::ParseError(
                    line_no + 1,
                    format!("expected 5 fields, got {}", parts.len()),
                ));
            }
            let expires_secs: u64 = parts[0].parse().map_err(|_| {
                LeaseError::ParseError(line_no + 1, "invalid expires".into())
            })?;
            let ip: Ipv4Addr = parts[1].parse().map_err(|_| {
                LeaseError::ParseError(line_no + 1, "invalid IP address".into())
            })?;
            let hw_bytes = parse_hex_colon(parts[2]).ok_or_else(|| {
                LeaseError::ParseError(line_no + 1, "invalid hwaddr".into())
            })?;
            let hostname = if parts[3] == "*" {
                None
            } else {
                Some(parts[3].to_string())
            };
            let clid = if parts[4] == "*" {
                None
            } else {
                Some(parse_hex_colon(parts[4]).ok_or_else(|| {
                    LeaseError::ParseError(line_no + 1, "invalid client-id".into())
                })?)
            };

            let expires = if expires_secs == 0 {
                None
            } else {
                Some(UNIX_EPOCH + Duration::from_secs(expires_secs))
            };

            let hwaddr_len = hw_bytes.len().min(DHCP_CHADDR_MAX);
            let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
            hwaddr[..hwaddr_len].copy_from_slice(&hw_bytes[..hwaddr_len]);

            let lease = DhcpLease {
                clid,
                hostname,
                fqdn: None,
                old_hostname: None,
                flags: 0,
                expires,
                hwaddr,
                hwaddr_len,
                hwaddr_type: 1,
                addr: ip,
                giaddr: Ipv4Addr::UNSPECIFIED,
                extradata: Vec::new(),
                last_interface: 0,
                new_interface: 0,
                new_prefixlen: 0,
                agent_id: None,
                vendorclass: None,
                #[cfg(feature = "dhcp6")]
                addr6: std::net::Ipv6Addr::UNSPECIFIED,
                #[cfg(feature = "dhcp6")]
                iaid: 0,
                #[cfg(feature = "dhcp6")]
                slaac_address: Vec::new(),
                #[cfg(feature = "dhcp6")]
                vendorclass_count: 0,
            };
            db.insert(lease);
        }
        Ok(db)
    }
}

/// Parse a colon-separated hex string (e.g. `"de:ad:be:ef"`) into bytes.
#[cfg(feature = "dhcp")]
fn parse_hex_colon(s: &str) -> Option<Vec<u8>> {
    s.split(':')
        .map(|h| u8::from_str_radix(h, 16).ok())
        .collect()
}

#[cfg(feature = "dhcp")]
impl Default for LeaseDb {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, feature = "dhcp"))]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn make_lease(addr: Ipv4Addr, hw: [u8; 6], expires_secs: Option<u64>) -> DhcpLease {
        let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
        hwaddr[..6].copy_from_slice(&hw);
        DhcpLease {
            clid: None,
            hostname: Some("host1".into()),
            fqdn: None,
            old_hostname: None,
            flags: 0,
            expires: expires_secs.map(|s| UNIX_EPOCH + Duration::from_secs(s)),
            hwaddr,
            hwaddr_len: 6,
            hwaddr_type: 1,
            addr,
            giaddr: Ipv4Addr::UNSPECIFIED,
            extradata: Vec::new(),
            last_interface: 0,
            new_interface: 0,
            new_prefixlen: 0,
            agent_id: None,
            vendorclass: None,
            #[cfg(feature = "dhcp6")]
            addr6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            iaid: 0,
            #[cfg(feature = "dhcp6")]
            slaac_address: Vec::new(),
            #[cfg(feature = "dhcp6")]
            vendorclass_count: 0,
        }
    }

    #[test]
    fn insert_and_find_by_addr() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 5);
        db.insert(make_lease(addr, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], None));
        let found = db.find_by_addr(addr);
        assert!(found.is_some());
        assert_eq!(found.unwrap().addr, addr);
    }

    #[test]
    fn insert_and_find_by_client_id() {
        let mut db = LeaseDb::new();
        let hw = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66];
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 7), hw, None));
        let found = db.find_by_client_id(&hw);
        assert!(found.is_some());
    }

    #[test]
    fn prune_removes_expired_leaves_fresh() {
        let mut db = LeaseDb::new();
        let expired_addr = Ipv4Addr::new(10, 0, 0, 1);
        let fresh_addr = Ipv4Addr::new(10, 0, 0, 2);
        // Expired at epoch+100
        db.insert(make_lease(expired_addr, [0x01, 0, 0, 0, 0, 0], Some(100)));
        // Expires far in the future
        db.insert(make_lease(fresh_addr, [0x02, 0, 0, 0, 0, 0], Some(9_999_999_999)));

        let pruned = db.prune(200);
        assert_eq!(pruned.len(), 1);
        assert_eq!(pruned[0].addr, expired_addr);
        assert!(db.find_by_addr(fresh_addr).is_some());
        assert!(db.find_by_addr(expired_addr).is_none());
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(192, 168, 1, 50);
        db.insert(make_lease(addr, [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01], Some(1_700_000_000)));

        let text = db.serialize();
        let db2 = LeaseDb::deserialize(&text).expect("deserialize failed");
        let found = db2.find_by_addr(addr);
        assert!(found.is_some());
        assert_eq!(found.unwrap().addr, addr);
    }
}
