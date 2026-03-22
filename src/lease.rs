//! In-memory DHCP lease database with text-format serialisation.
//! Ported from `lease.c`.

#[cfg(feature = "dhcp")]
use std::collections::HashMap;
#[cfg(feature = "dhcp")]
use std::net::Ipv4Addr;
#[cfg(feature = "dhcp")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
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
    /// Maximum number of leases allowed.
    pub max_leases: usize,
    /// Set to `true` when the lease file needs rewriting.
    pub file_dirty: bool,
    /// Set to `true` when DNS records derived from leases need updating.
    pub dns_dirty: bool,
}

#[cfg(feature = "dhcp")]
impl LeaseDb {
    /// Create an empty lease database.
    pub fn new() -> Self {
        Self {
            leases: HashMap::new(),
            max_leases: 1000,
            file_dirty: false,
            dns_dirty: false,
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

    /// Allocate a new IPv4 lease. Returns `None` if `max_leases` would be exceeded.
    pub fn allocate_v4(&mut self, addr: Ipv4Addr) -> Option<&mut DhcpLease> {
        use crate::types::dhcp::LEASE_NEW;

        if self.leases.len() >= self.max_leases {
            return None;
        }

        let lease = DhcpLease {
            clid: None,
            hostname: None,
            fqdn: None,
            old_hostname: None,
            flags: LEASE_NEW,
            expires: None,
            hwaddr: [0u8; DHCP_CHADDR_MAX],
            hwaddr_len: 0,
            hwaddr_type: 0,
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
        };

        let key = lease_key(&lease);
        self.leases.insert(key, lease);
        self.file_dirty = true;
        self.dns_dirty = true;
        self.leases.get_mut(&key)
    }

    /// Set the expiry time for a lease. `0xFFFFFFFF` means infinite (no expiry).
    /// Otherwise the lease expires at `now + duration_secs`.
    pub fn set_expires(&mut self, addr: Ipv4Addr, duration_secs: u32) {
        use crate::types::dhcp::{LEASE_AUX_CHANGED, LEASE_EXP_CHANGED};

        if let Some(lease) = self.leases.values_mut().find(|l| l.addr == addr) {
            let new_expires = if duration_secs == 0xFFFF_FFFF {
                None
            } else {
                Some(SystemTime::now() + Duration::from_secs(duration_secs as u64))
            };

            if lease.expires != new_expires {
                lease.expires = new_expires;
                lease.flags |= LEASE_AUX_CHANGED | LEASE_EXP_CHANGED;
                self.file_dirty = true;
            }
        }
    }

    /// Update hardware address and optional client-id on a lease.
    pub fn set_hwaddr(&mut self, addr: Ipv4Addr, hwaddr: &[u8], hw_type: i32, clid: Option<&[u8]>) {
        use crate::types::dhcp::{LEASE_CHANGED, LEASE_AUX_CHANGED};

        // We need to find the lease, potentially remove/re-key it if clid changes.
        let key = {
            let lease = match self.leases.values().find(|l| l.addr == addr) {
                Some(l) => l,
                None => return,
            };
            lease_key(lease)
        };

        let lease = match self.leases.get_mut(&key) {
            Some(l) if l.addr == addr => l,
            _ => return,
        };

        // Check if hwaddr changed
        let hw_len = hwaddr.len().min(DHCP_CHADDR_MAX);
        let hw_changed = lease.hwaddr_len != hw_len
            || lease.hwaddr_type != hw_type
            || lease.hwaddr[..hw_len] != hwaddr[..hw_len];

        if hw_changed {
            lease.hwaddr = [0u8; DHCP_CHADDR_MAX];
            lease.hwaddr[..hw_len].copy_from_slice(&hwaddr[..hw_len]);
            lease.hwaddr_len = hw_len;
            lease.hwaddr_type = hw_type;
            lease.flags |= LEASE_CHANGED;
            self.file_dirty = true;
        }

        // Check if clid changed
        let new_clid = clid.map(|c| c.to_vec());
        let clid_changed = lease.clid != new_clid;

        if clid_changed {
            // Need to re-key: remove with old key, update clid, insert with new key
            let mut lease = self.leases.remove(&key).unwrap();
            lease.clid = new_clid;
            lease.flags |= LEASE_AUX_CHANGED;
            self.file_dirty = true;
            let new_key = lease_key(&lease);
            self.leases.insert(new_key, lease);
        }
    }

    /// Set the hostname on a lease. If `auth` is true, the `LEASE_AUTH_NAME` flag
    /// is set. If another lease already has this name, the name is removed from
    /// that lease first.
    pub fn set_hostname(&mut self, addr: Ipv4Addr, name: Option<&str>, auth: bool) {
        use crate::types::dhcp::{LEASE_AUTH_NAME, LEASE_CHANGED};

        // If a name is being set, check for duplicates and remove from other leases.
        if let Some(new_name) = name {
            // Collect addrs of leases that have the same hostname (but different addr).
            let duplicates: Vec<Ipv4Addr> = self
                .leases
                .values()
                .filter(|l| l.addr != addr)
                .filter(|l| {
                    l.hostname
                        .as_deref()
                        .map(|h| crate::util::hostname_isequal(h, new_name))
                        .unwrap_or(false)
                })
                .map(|l| l.addr)
                .collect();

            for dup_addr in duplicates {
                if let Some(dup) = self.leases.values_mut().find(|l| l.addr == dup_addr) {
                    dup.old_hostname = dup.hostname.take();
                    dup.flags |= LEASE_CHANGED;
                }
            }
        }

        // Now set the hostname on the target lease.
        if let Some(lease) = self.leases.values_mut().find(|l| l.addr == addr) {
            let name_changed = match (&lease.hostname, name) {
                (Some(old), Some(new)) => !crate::util::hostname_isequal(old, new),
                (None, None) => false,
                _ => true,
            };

            if name_changed {
                lease.old_hostname = lease.hostname.take();
                lease.hostname = name.map(|n| n.to_string());
                lease.flags |= LEASE_CHANGED;
                self.file_dirty = true;
                self.dns_dirty = true;
            }

            if auth {
                lease.flags |= LEASE_AUTH_NAME;
            } else {
                lease.flags &= !LEASE_AUTH_NAME;
            }
        }
    }

    /// Record the interface a lease is bound to.
    pub fn set_interface(&mut self, addr: Ipv4Addr, interface: i32) {
        if let Some(lease) = self.leases.values_mut().find(|l| l.addr == addr) {
            lease.last_interface = interface;
        }
    }

    /// Set the DHCP relay agent information on a lease.
    pub fn set_agent_id(&mut self, addr: Ipv4Addr, agent_id: Option<&[u8]>) {
        use crate::types::dhcp::LEASE_AUX_CHANGED;

        if let Some(lease) = self.leases.values_mut().find(|l| l.addr == addr) {
            let new_val = agent_id.map(|a| a.to_vec());
            if lease.agent_id != new_val {
                lease.agent_id = new_val;
                lease.flags |= LEASE_AUX_CHANGED;
                self.file_dirty = true;
            }
        }
    }

    /// Set the vendor class information on a lease.
    pub fn set_vendorclass(&mut self, addr: Ipv4Addr, vendorclass: Option<&[u8]>) {
        use crate::types::dhcp::LEASE_AUX_CHANGED;

        if let Some(lease) = self.leases.values_mut().find(|l| l.addr == addr) {
            let new_val = vendorclass.map(|v| v.to_vec());
            if lease.vendorclass != new_val {
                lease.vendorclass = new_val;
                lease.flags |= LEASE_AUX_CHANGED;
                self.file_dirty = true;
            }
        }
    }

    /// Find the highest allocated IPv4 address within `[start, end]`.
    /// Returns `start` if no leases exist in the range.
    pub fn find_max_addr(&self, start: Ipv4Addr, end: Ipv4Addr) -> Ipv4Addr {
        let start_u32 = u32::from(start);
        let end_u32 = u32::from(end);

        self.leases
            .values()
            .map(|l| u32::from(l.addr))
            .filter(|&a| a >= start_u32 && a <= end_u32)
            .max()
            .map(Ipv4Addr::from)
            .unwrap_or(start)
    }

    /// Mark every lease as `LEASE_CHANGED` so that helper scripts are re-run.
    pub fn rerun_scripts(&mut self) {
        use crate::types::dhcp::LEASE_CHANGED;

        for lease in self.leases.values_mut() {
            lease.flags |= LEASE_CHANGED;
        }
        self.file_dirty = true;
    }

    /// Write all leases to the given file path (using [`serialize`]).
    pub fn write_to_file(&self, path: &str) -> Result<(), LeaseError> {
        let data = self.serialize();
        std::fs::write(path, data)?;
        Ok(())
    }

    /// Load a lease database from a file (using [`deserialize`]).
    pub fn load_from_file(path: &str) -> Result<Self, LeaseError> {
        let data = std::fs::read_to_string(path)?;
        Self::deserialize(&data)
    }

    /// Return the number of active leases.
    pub fn count(&self) -> usize {
        self.leases.len()
    }

    /// Iterate over all leases.
    pub fn iter(&self) -> impl Iterator<Item = &DhcpLease> {
        self.leases.values()
    }

    /// Compute FQDNs for all leases with hostnames.
    ///
    /// Sets `lease.fqdn = hostname + "." + domain` for each lease.
    /// Port of `lease_calc_fqdns()` from lease.c:1024-1052.
    pub fn calc_fqdns(&mut self, domain: &str) {
        for lease in self.leases.values_mut() {
            if let Some(ref hostname) = lease.hostname {
                if !domain.is_empty() {
                    lease.fqdn = Some(format!("{}.{}", hostname, domain));
                } else {
                    lease.fqdn = None;
                }
            }
        }
    }

    /// Find a DHCPv6 lease by CLID, IAID, and address.
    ///
    /// Port of `lease6_find()` from lease.c:696-718.
    #[cfg(feature = "dhcp6")]
    pub fn find_v6_by_clid_iaid(
        &self,
        clid: &[u8],
        iaid: u32,
        addr: &std::net::Ipv6Addr,
    ) -> Option<&DhcpLease> {
        use crate::types::dhcp::{LEASE_TA, LEASE_NA};
        self.leases.values().find(|l| {
            (l.flags & (LEASE_TA | LEASE_NA) != 0)
                && l.iaid == iaid
                && l.addr6 == *addr
                && l.clid.as_deref() == Some(clid)
        })
    }

    /// Find a DHCPv6 lease by exact IPv6 address.
    ///
    /// Port of `lease6_find_by_plain_addr()` from lease.c:776-790.
    #[cfg(feature = "dhcp6")]
    pub fn find_v6_by_addr(&self, addr: &std::net::Ipv6Addr) -> Option<&DhcpLease> {
        use crate::types::dhcp::{LEASE_TA, LEASE_NA};
        self.leases.values().find(|l| {
            (l.flags & (LEASE_TA | LEASE_NA) != 0) && l.addr6 == *addr
        })
    }

    /// Allocate a new DHCPv6 lease.
    ///
    /// Port of `lease6_allocate()` from lease.c:873-887.
    #[cfg(feature = "dhcp6")]
    pub fn allocate_v6(
        &mut self,
        addr: std::net::Ipv6Addr,
        lease_type: u32,
    ) -> Option<&mut DhcpLease> {
        use crate::types::dhcp::LEASE_NEW;

        if self.leases.len() >= self.max_leases {
            return None;
        }

        let lease = DhcpLease {
            clid: None,
            hostname: None,
            fqdn: None,
            old_hostname: None,
            flags: LEASE_NEW | lease_type,
            expires: None,
            hwaddr: [0u8; DHCP_CHADDR_MAX],
            hwaddr_len: 0,
            hwaddr_type: 0,
            addr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            extradata: Vec::new(),
            last_interface: 0,
            new_interface: 0,
            new_prefixlen: 0,
            agent_id: None,
            vendorclass: None,
            addr6: addr,
            iaid: 0,
            slaac_address: Vec::new(),
            vendorclass_count: 0,
        };

        let key = lease_key(&lease);
        self.leases.insert(key, lease);
        self.file_dirty = true;
        self.dns_dirty = true;
        self.leases.get_mut(&key)
    }

    /// Clear LEASE_USED flags on all DHCPv6 leases.
    ///
    /// Port of `lease6_reset()` from lease.c:721-727.
    #[cfg(feature = "dhcp6")]
    pub fn reset_v6_used(&mut self) {
        use crate::types::dhcp::{LEASE_TA, LEASE_NA, LEASE_USED};
        for lease in self.leases.values_mut() {
            if lease.flags & (LEASE_TA | LEASE_NA) != 0 {
                lease.flags &= !LEASE_USED;
            }
        }
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

    #[test]
    fn find_by_addr_nonexistent() {
        let db = LeaseDb::new();
        assert!(db.find_by_addr(Ipv4Addr::new(10, 0, 0, 99)).is_none());
    }

    #[test]
    fn find_by_client_id_nonexistent() {
        let db = LeaseDb::new();
        assert!(db.find_by_client_id(&[0xaa, 0xbb]).is_none());
    }

    #[test]
    fn prune_empty_db() {
        let mut db = LeaseDb::new();
        let pruned = db.prune(1_000_000);
        assert!(pruned.is_empty());
    }

    #[test]
    fn prune_all_expired() {
        let mut db = LeaseDb::new();
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 1), [0x01, 0, 0, 0, 0, 0], Some(100)));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 2), [0x02, 0, 0, 0, 0, 0], Some(200)));
        let pruned = db.prune(300);
        assert_eq!(pruned.len(), 2);
        assert!(db.find_by_addr(Ipv4Addr::new(10, 0, 0, 1)).is_none());
        assert!(db.find_by_addr(Ipv4Addr::new(10, 0, 0, 2)).is_none());
    }

    #[test]
    fn prune_keeps_no_expiry_leases() {
        let mut db = LeaseDb::new();
        // Lease with no expiry (permanent)
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 1), [0x01, 0, 0, 0, 0, 0], None));
        let pruned = db.prune(9_999_999_999);
        assert!(pruned.is_empty());
        assert!(db.find_by_addr(Ipv4Addr::new(10, 0, 0, 1)).is_some());
    }

    #[test]
    fn deserialize_malformed_too_few_fields() {
        let result = LeaseDb::deserialize("100 10.0.0.1 aa:bb");
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_malformed_invalid_ip() {
        let result = LeaseDb::deserialize("100 not.an.ip aa:bb:cc:dd:ee:ff host1 *");
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_malformed_invalid_expires() {
        let result = LeaseDb::deserialize("notanumber 10.0.0.1 aa:bb:cc:dd:ee:ff host1 *");
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_empty_string() {
        let db = LeaseDb::deserialize("").expect("empty should be ok");
        assert!(db.find_by_addr(Ipv4Addr::new(10, 0, 0, 1)).is_none());
    }

    #[test]
    fn insert_replaces_existing_lease() {
        let mut db = LeaseDb::new();
        let hw = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 1), hw, Some(100)));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 2), hw, Some(200)));
        // Same hwaddr => same key => replaced
        assert!(db.find_by_addr(Ipv4Addr::new(10, 0, 0, 1)).is_none());
        assert!(db.find_by_addr(Ipv4Addr::new(10, 0, 0, 2)).is_some());
    }

    #[test]
    fn serialize_no_expiry_produces_zero() {
        let mut db = LeaseDb::new();
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 1), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], None));
        let text = db.serialize();
        assert!(text.starts_with("0 "));
    }

    // ── allocate_v4 tests ──

    #[test]
    fn allocate_v4_creates_lease() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 100);
        let lease = db.allocate_v4(addr);
        assert!(lease.is_some());
        let lease = lease.unwrap();
        assert_eq!(lease.addr, addr);
        assert_eq!(lease.flags, crate::types::dhcp::LEASE_NEW);
    }

    #[test]
    fn allocate_v4_sets_dirty_flags() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 100);
        db.allocate_v4(addr);
        assert!(db.file_dirty);
        assert!(db.dns_dirty);
    }

    #[test]
    fn allocate_v4_enforces_max_leases() {
        let mut db = LeaseDb::new();
        db.max_leases = 2;
        // Use insert with distinct hwaddrs to fill the db to capacity.
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 1), [0x01, 0, 0, 0, 0, 0], None));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 2), [0x02, 0, 0, 0, 0, 0], None));
        assert_eq!(db.count(), 2);
        let result = db.allocate_v4(Ipv4Addr::new(10, 0, 0, 3));
        assert!(result.is_none());
        assert_eq!(db.count(), 2);
    }

    #[test]
    fn allocate_v4_findable_by_addr() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 50);
        db.allocate_v4(addr);
        assert!(db.find_by_addr(addr).is_some());
    }

    // ── set_expires tests ──

    #[test]
    fn set_expires_infinite() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], Some(100)));
        db.set_expires(addr, 0xFFFF_FFFF);
        let lease = db.find_by_addr(addr).unwrap();
        assert!(lease.expires.is_none());
    }

    #[test]
    fn set_expires_finite() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));
        db.set_expires(addr, 3600);
        let lease = db.find_by_addr(addr).unwrap();
        assert!(lease.expires.is_some());
        // Should expire roughly 3600s from now
        let exp = lease.expires.unwrap();
        let diff = exp.duration_since(SystemTime::now()).unwrap();
        assert!(diff.as_secs() <= 3600 && diff.as_secs() >= 3598);
    }

    #[test]
    fn set_expires_sets_flags() {
        use crate::types::dhcp::{LEASE_AUX_CHANGED, LEASE_EXP_CHANGED};
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], Some(100)));
        db.set_expires(addr, 7200);
        let lease = db.find_by_addr(addr).unwrap();
        assert_ne!(lease.flags & LEASE_AUX_CHANGED, 0);
        assert_ne!(lease.flags & LEASE_EXP_CHANGED, 0);
        assert!(db.file_dirty);
    }

    #[test]
    fn set_expires_nonexistent_no_panic() {
        let mut db = LeaseDb::new();
        db.set_expires(Ipv4Addr::new(10, 0, 0, 99), 100);
        // Should not panic
    }

    // ── set_hwaddr tests ──

    #[test]
    fn set_hwaddr_updates_hardware_address() {
        use crate::types::dhcp::LEASE_CHANGED;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06], None));

        let new_hw = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        db.set_hwaddr(addr, &new_hw, 1, None);

        let lease = db.find_by_addr(addr).unwrap();
        assert_eq!(&lease.hwaddr[..6], &new_hw);
        assert_ne!(lease.flags & LEASE_CHANGED, 0);
        assert!(db.file_dirty);
    }

    #[test]
    fn set_hwaddr_same_address_no_change_flag() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let hw = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        db.insert(make_lease(addr, hw, None));
        db.file_dirty = false;

        db.set_hwaddr(addr, &hw, 1, None);
        // hwaddr didn't change, clid didn't change
        assert!(!db.file_dirty);
    }

    #[test]
    fn set_hwaddr_with_clid_rekeys() {
        use crate::types::dhcp::LEASE_AUX_CHANGED;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));

        let clid = vec![0xDE, 0xAD, 0xBE, 0xEF];
        db.set_hwaddr(addr, &[0x01, 0, 0, 0, 0, 0], 1, Some(&clid));

        let lease = db.find_by_addr(addr).unwrap();
        assert_eq!(lease.clid, Some(clid));
        assert_ne!(lease.flags & LEASE_AUX_CHANGED, 0);
    }

    #[test]
    fn set_hwaddr_nonexistent_no_panic() {
        let mut db = LeaseDb::new();
        db.set_hwaddr(Ipv4Addr::new(10, 0, 0, 99), &[0x01, 0, 0, 0, 0, 0], 1, None);
    }

    #[test]
    fn set_hwaddr_changes_hw_type() {
        use crate::types::dhcp::LEASE_CHANGED;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let hw = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        db.insert(make_lease(addr, hw, None));

        // Same hw bytes, different type
        db.set_hwaddr(addr, &hw, 6, None);
        let lease = db.find_by_addr(addr).unwrap();
        assert_eq!(lease.hwaddr_type, 6);
        assert_ne!(lease.flags & LEASE_CHANGED, 0);
    }

    // ── set_hostname tests ──

    #[test]
    fn set_hostname_basic() {
        use crate::types::dhcp::LEASE_CHANGED;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));

        db.set_hostname(addr, Some("myhost"), false);
        let lease = db.find_by_addr(addr).unwrap();
        assert_eq!(lease.hostname.as_deref(), Some("myhost"));
        assert_ne!(lease.flags & LEASE_CHANGED, 0);
        assert!(db.dns_dirty);
    }

    #[test]
    fn set_hostname_auth_flag() {
        use crate::types::dhcp::LEASE_AUTH_NAME;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));

        db.set_hostname(addr, Some("authhost"), true);
        let lease = db.find_by_addr(addr).unwrap();
        assert_ne!(lease.flags & LEASE_AUTH_NAME, 0);

        // Remove auth
        db.set_hostname(addr, Some("authhost"), false);
        let lease = db.find_by_addr(addr).unwrap();
        assert_eq!(lease.flags & LEASE_AUTH_NAME, 0);
    }

    #[test]
    fn set_hostname_removes_duplicate_from_other_lease() {
        use crate::types::dhcp::LEASE_CHANGED;
        let mut db = LeaseDb::new();
        let addr1 = Ipv4Addr::new(10, 0, 0, 1);
        let addr2 = Ipv4Addr::new(10, 0, 0, 2);

        let mut lease1 = make_lease(addr1, [0x01, 0, 0, 0, 0, 0], None);
        lease1.hostname = Some("shared-name".into());
        db.insert(lease1);

        let mut lease2 = make_lease(addr2, [0x02, 0, 0, 0, 0, 0], None);
        lease2.hostname = None;
        db.insert(lease2);

        // Set the same hostname on lease2 => should remove from lease1
        db.set_hostname(addr2, Some("shared-name"), false);

        let l1 = db.find_by_addr(addr1).unwrap();
        assert!(l1.hostname.is_none());
        assert_eq!(l1.old_hostname.as_deref(), Some("shared-name"));
        assert_ne!(l1.flags & LEASE_CHANGED, 0);

        let l2 = db.find_by_addr(addr2).unwrap();
        assert_eq!(l2.hostname.as_deref(), Some("shared-name"));
    }

    #[test]
    fn set_hostname_case_insensitive_duplicate() {
        let mut db = LeaseDb::new();
        let addr1 = Ipv4Addr::new(10, 0, 0, 1);
        let addr2 = Ipv4Addr::new(10, 0, 0, 2);

        let mut lease1 = make_lease(addr1, [0x01, 0, 0, 0, 0, 0], None);
        lease1.hostname = Some("MyHost".into());
        db.insert(lease1);

        let mut lease2 = make_lease(addr2, [0x02, 0, 0, 0, 0, 0], None);
        lease2.hostname = None;
        db.insert(lease2);

        db.set_hostname(addr2, Some("myhost"), false);

        let l1 = db.find_by_addr(addr1).unwrap();
        assert!(l1.hostname.is_none(), "duplicate should have been removed");
    }

    #[test]
    fn set_hostname_clear() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));

        db.set_hostname(addr, None, false);
        let lease = db.find_by_addr(addr).unwrap();
        assert!(lease.hostname.is_none());
        assert_eq!(lease.old_hostname.as_deref(), Some("host1")); // original was "host1"
    }

    #[test]
    fn set_hostname_same_name_no_change() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));
        db.file_dirty = false;
        db.dns_dirty = false;

        // hostname from make_lease is "host1"
        db.set_hostname(addr, Some("host1"), false);
        assert!(!db.file_dirty);
        assert!(!db.dns_dirty);
    }

    // ── set_interface tests ──

    #[test]
    fn set_interface_basic() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));

        db.set_interface(addr, 42);
        let lease = db.find_by_addr(addr).unwrap();
        assert_eq!(lease.last_interface, 42);
    }

    #[test]
    fn set_interface_nonexistent_no_panic() {
        let mut db = LeaseDb::new();
        db.set_interface(Ipv4Addr::new(10, 0, 0, 99), 5);
    }

    // ── set_agent_id tests ──

    #[test]
    fn set_agent_id_basic() {
        use crate::types::dhcp::LEASE_AUX_CHANGED;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));

        let agent = vec![0x01, 0x02, 0x03];
        db.set_agent_id(addr, Some(&agent));

        let lease = db.find_by_addr(addr).unwrap();
        assert_eq!(lease.agent_id, Some(agent));
        assert_ne!(lease.flags & LEASE_AUX_CHANGED, 0);
        assert!(db.file_dirty);
    }

    #[test]
    fn set_agent_id_clear() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let mut lease = make_lease(addr, [0x01, 0, 0, 0, 0, 0], None);
        lease.agent_id = Some(vec![0x01, 0x02]);
        db.insert(lease);

        db.set_agent_id(addr, None);
        let lease = db.find_by_addr(addr).unwrap();
        assert!(lease.agent_id.is_none());
    }

    #[test]
    fn set_agent_id_same_value_no_dirty() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let mut lease = make_lease(addr, [0x01, 0, 0, 0, 0, 0], None);
        lease.agent_id = Some(vec![0x01, 0x02]);
        db.insert(lease);
        db.file_dirty = false;

        db.set_agent_id(addr, Some(&[0x01, 0x02]));
        assert!(!db.file_dirty);
    }

    // ── set_vendorclass tests ──

    #[test]
    fn set_vendorclass_basic() {
        use crate::types::dhcp::LEASE_AUX_CHANGED;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));

        let vc = vec![0xAA, 0xBB];
        db.set_vendorclass(addr, Some(&vc));

        let lease = db.find_by_addr(addr).unwrap();
        assert_eq!(lease.vendorclass, Some(vc));
        assert_ne!(lease.flags & LEASE_AUX_CHANGED, 0);
    }

    #[test]
    fn set_vendorclass_clear() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let mut lease = make_lease(addr, [0x01, 0, 0, 0, 0, 0], None);
        lease.vendorclass = Some(vec![0xCC]);
        db.insert(lease);

        db.set_vendorclass(addr, None);
        let lease = db.find_by_addr(addr).unwrap();
        assert!(lease.vendorclass.is_none());
    }

    #[test]
    fn set_vendorclass_same_value_no_dirty() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let mut lease = make_lease(addr, [0x01, 0, 0, 0, 0, 0], None);
        lease.vendorclass = Some(vec![0xCC]);
        db.insert(lease);
        db.file_dirty = false;

        db.set_vendorclass(addr, Some(&[0xCC]));
        assert!(!db.file_dirty);
    }

    // ── find_max_addr tests ──

    #[test]
    fn find_max_addr_no_leases_returns_start() {
        let db = LeaseDb::new();
        let start = Ipv4Addr::new(10, 0, 0, 100);
        let end = Ipv4Addr::new(10, 0, 0, 200);
        assert_eq!(db.find_max_addr(start, end), start);
    }

    #[test]
    fn find_max_addr_single_lease() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 150);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));

        let result = db.find_max_addr(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 200));
        assert_eq!(result, addr);
    }

    #[test]
    fn find_max_addr_multiple_leases() {
        let mut db = LeaseDb::new();
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 110), [0x01, 0, 0, 0, 0, 0], None));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 180), [0x02, 0, 0, 0, 0, 0], None));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 150), [0x03, 0, 0, 0, 0, 0], None));

        let result = db.find_max_addr(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 200));
        assert_eq!(result, Ipv4Addr::new(10, 0, 0, 180));
    }

    #[test]
    fn find_max_addr_excludes_out_of_range() {
        let mut db = LeaseDb::new();
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 50), [0x01, 0, 0, 0, 0, 0], None));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 250), [0x02, 0, 0, 0, 0, 0], None));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 120), [0x03, 0, 0, 0, 0, 0], None));

        let result = db.find_max_addr(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 200));
        assert_eq!(result, Ipv4Addr::new(10, 0, 0, 120));
    }

    // ── rerun_scripts tests ──

    #[test]
    fn rerun_scripts_marks_all_changed() {
        use crate::types::dhcp::LEASE_CHANGED;
        let mut db = LeaseDb::new();
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 1), [0x01, 0, 0, 0, 0, 0], None));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 2), [0x02, 0, 0, 0, 0, 0], None));

        db.rerun_scripts();

        for lease in db.iter() {
            assert_ne!(lease.flags & LEASE_CHANGED, 0);
        }
        assert!(db.file_dirty);
    }

    #[test]
    fn rerun_scripts_empty_db() {
        let mut db = LeaseDb::new();
        db.rerun_scripts(); // Should not panic
        assert!(db.file_dirty);
    }

    // ── write_to_file / load_from_file tests ──

    #[test]
    fn write_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("leases.dat");
        let path_str = path.to_str().unwrap();

        let mut db = LeaseDb::new();
        let addr1 = Ipv4Addr::new(10, 0, 0, 1);
        let addr2 = Ipv4Addr::new(10, 0, 0, 2);
        db.insert(make_lease(addr1, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06], Some(1_700_000_000)));
        db.insert(make_lease(addr2, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66], None));

        db.write_to_file(path_str).unwrap();
        let loaded = LeaseDb::load_from_file(path_str).unwrap();

        assert!(loaded.find_by_addr(addr1).is_some());
        assert!(loaded.find_by_addr(addr2).is_some());
        assert_eq!(loaded.count(), 2);
    }

    #[test]
    fn load_from_file_nonexistent() {
        let result = LeaseDb::load_from_file("/tmp/nonexistent_lease_file_dnsmasq_test.dat");
        assert!(result.is_err());
    }

    #[test]
    fn write_to_file_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new_leases.dat");
        let path_str = path.to_str().unwrap();

        let db = LeaseDb::new();
        db.write_to_file(path_str).unwrap();
        assert!(path.exists());
    }

    // ── count tests ──

    #[test]
    fn count_empty() {
        let db = LeaseDb::new();
        assert_eq!(db.count(), 0);
    }

    #[test]
    fn count_after_inserts() {
        let mut db = LeaseDb::new();
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 1), [0x01, 0, 0, 0, 0, 0], None));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 2), [0x02, 0, 0, 0, 0, 0], None));
        assert_eq!(db.count(), 2);
    }

    #[test]
    fn count_after_prune() {
        let mut db = LeaseDb::new();
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 1), [0x01, 0, 0, 0, 0, 0], Some(100)));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 2), [0x02, 0, 0, 0, 0, 0], Some(9_999_999_999)));
        db.prune(200);
        assert_eq!(db.count(), 1);
    }

    // ── iter tests ──

    #[test]
    fn iter_empty() {
        let db = LeaseDb::new();
        assert_eq!(db.iter().count(), 0);
    }

    #[test]
    fn iter_returns_all_leases() {
        let mut db = LeaseDb::new();
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 1), [0x01, 0, 0, 0, 0, 0], None));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 2), [0x02, 0, 0, 0, 0, 0], None));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 3), [0x03, 0, 0, 0, 0, 0], None));

        let addrs: Vec<Ipv4Addr> = db.iter().map(|l| l.addr).collect();
        assert_eq!(addrs.len(), 3);
        assert!(addrs.contains(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(addrs.contains(&Ipv4Addr::new(10, 0, 0, 2)));
        assert!(addrs.contains(&Ipv4Addr::new(10, 0, 0, 3)));
    }

    // ── default tests ──

    #[test]
    fn default_max_leases() {
        let db = LeaseDb::new();
        assert_eq!(db.max_leases, 1000);
        assert!(!db.file_dirty);
        assert!(!db.dns_dirty);
    }

    #[test]
    fn default_trait() {
        let db = LeaseDb::default();
        assert_eq!(db.count(), 0);
        assert_eq!(db.max_leases, 1000);
    }

    // ── combined / integration-style tests ──

    #[test]
    fn allocate_then_configure_lease() {
        use crate::types::dhcp::{LEASE_NEW, LEASE_CHANGED, LEASE_AUX_CHANGED};
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(192, 168, 1, 100);

        db.allocate_v4(addr);
        db.set_hwaddr(addr, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 1, None);
        db.set_hostname(addr, Some("workstation"), true);
        db.set_expires(addr, 86400);
        db.set_interface(addr, 3);
        db.set_agent_id(addr, Some(&[0x01, 0x06, 0x00, 0x04]));
        db.set_vendorclass(addr, Some(b"MSFT 5.0"));

        let lease = db.find_by_addr(addr).unwrap();
        assert_eq!(lease.hostname.as_deref(), Some("workstation"));
        assert_eq!(&lease.hwaddr[..6], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert!(lease.expires.is_some());
        assert_eq!(lease.last_interface, 3);
        assert!(lease.agent_id.is_some());
        assert_eq!(lease.vendorclass.as_deref(), Some(b"MSFT 5.0".as_ref()));
        assert_ne!(lease.flags & LEASE_NEW, 0);
    }

    #[test]
    fn allocate_write_load_verify() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("full_test.dat");
        let path_str = path.to_str().unwrap();

        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(192, 168, 1, 50);
        db.allocate_v4(addr);
        db.set_hwaddr(addr, &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01], 1, None);
        db.set_hostname(addr, Some("testbox"), false);

        db.write_to_file(path_str).unwrap();
        let loaded = LeaseDb::load_from_file(path_str).unwrap();

        let lease = loaded.find_by_addr(addr).unwrap();
        assert_eq!(lease.hostname.as_deref(), Some("testbox"));
        assert_eq!(&lease.hwaddr[..6], &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
    }

    // ── calc_fqdns ───────────────────────────────────────────────────────────

    #[test]
    fn calc_fqdns_sets_fqdn() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.allocate_v4(addr);
        db.set_hostname(addr, Some("myhost"), true);
        db.calc_fqdns("example.com");
        let lease = db.find_by_addr(addr).unwrap();
        assert_eq!(lease.fqdn.as_deref(), Some("myhost.example.com"));
    }

    #[test]
    fn calc_fqdns_no_hostname_no_fqdn() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 2);
        db.allocate_v4(addr);
        db.calc_fqdns("example.com");
        let lease = db.find_by_addr(addr).unwrap();
        assert!(lease.fqdn.is_none());
    }

    #[test]
    fn calc_fqdns_empty_domain_no_fqdn() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 3);
        db.allocate_v4(addr);
        db.set_hostname(addr, Some("host"), true);
        db.calc_fqdns("");
        let lease = db.find_by_addr(addr).unwrap();
        assert!(lease.fqdn.is_none());
    }

    // ── DHCPv6 lease functions ───────────────────────────────────────────────

    #[cfg(feature = "dhcp6")]
    #[test]
    fn allocate_v6_basic() {
        use crate::types::dhcp::LEASE_NA;
        let mut db = LeaseDb::new();
        let addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let lease = db.allocate_v6(addr, LEASE_NA);
        assert!(lease.is_some());
        assert_eq!(db.count(), 1);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn find_v6_by_addr_found() {
        use crate::types::dhcp::LEASE_NA;
        let mut db = LeaseDb::new();
        let addr: std::net::Ipv6Addr = "2001:db8::42".parse().unwrap();
        db.allocate_v6(addr, LEASE_NA);
        assert!(db.find_v6_by_addr(&addr).is_some());
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn find_v6_by_addr_not_found() {
        let db = LeaseDb::new();
        let addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(db.find_v6_by_addr(&addr).is_none());
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn find_v6_by_clid_iaid() {
        use crate::types::dhcp::LEASE_NA;
        let mut db = LeaseDb::new();
        let addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let clid = vec![0x00, 0x01, 0xAA, 0xBB];
        {
            let lease = db.allocate_v6(addr, LEASE_NA).unwrap();
            lease.clid = Some(clid.clone());
            lease.iaid = 42;
        }
        assert!(db.find_v6_by_clid_iaid(&clid, 42, &addr).is_some());
        assert!(db.find_v6_by_clid_iaid(&clid, 99, &addr).is_none()); // wrong iaid
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn reset_v6_used_clears_flag() {
        use crate::types::dhcp::{LEASE_NA, LEASE_USED};
        let mut db = LeaseDb::new();
        let addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        {
            let lease = db.allocate_v6(addr, LEASE_NA).unwrap();
            lease.flags |= LEASE_USED;
        }
        db.reset_v6_used();
        let lease = db.find_v6_by_addr(&addr).unwrap();
        assert_eq!(lease.flags & LEASE_USED, 0);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn allocate_v6_respects_max() {
        use crate::types::dhcp::LEASE_NA;
        let mut db = LeaseDb::new();
        db.max_leases = 1;
        let a1: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let a2: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        assert!(db.allocate_v6(a1, LEASE_NA).is_some());
        assert!(db.allocate_v6(a2, LEASE_NA).is_none());
    }
}
