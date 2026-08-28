//! `zones.d` — a watched directory of dnsmasq directive-syntax fragment
//! files, each an independently loadable "zone" of local DNS answer data.
//! No upstream counterpart (issue #177) — see
//! `docs/superpowers/specs/2026-08-27-zones-d-design.md`.

use crate::types::dns_records::{Cname, HostRecord, MxSrvRecord, Naptr, PtrRecord, TxtRecord};

/// Aggregate of local DNS answer data loaded from every currently-present
/// file across every configured `--zones-dir`. Rebuilt wholesale on any
/// change by [`rescan_zones_dirs`]; never mutated incrementally. Field
/// types match the corresponding `Daemon`/`crate::forward::LocalData`
/// fields exactly, since it's merged into `LocalData` at
/// `dnsmasq::daemon_local_data`.
#[derive(Debug, Clone, Default)]
pub struct ZonesDRecords {
    pub host_records: Vec<HostRecord>,
    pub cnames: Vec<Cname>,
    pub txt_records: Vec<TxtRecord>,
    /// `mx-host` and `srv-host` both land here, matching
    /// `Daemon.mxnames`/`LocalData.mx_records`.
    pub mx_records: Vec<MxSrvRecord>,
    pub naptr_records: Vec<Naptr>,
    pub ptr_records: Vec<PtrRecord>,
    pub address_server_list: Vec<crate::types::server::Server>,
}

impl ZonesDRecords {
    /// Merge `other`'s records into `self`, field by field.
    pub fn extend(&mut self, other: ZonesDRecords) {
        self.host_records.extend(other.host_records);
        self.cnames.extend(other.cnames);
        self.txt_records.extend(other.txt_records);
        self.mx_records.extend(other.mx_records);
        self.naptr_records.extend(other.naptr_records);
        self.ptr_records.extend(other.ptr_records);
        self.address_server_list.extend(other.address_server_list);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extend_merges_every_field() {
        let mut a = ZonesDRecords::default();
        a.host_records.push(HostRecord {
            ttl: 0,
            flags: 0,
            names: vec!["a.example".to_string()],
            addr4: Some(std::net::Ipv4Addr::new(1, 2, 3, 4)),
            addr6: None,
        });

        let mut b = ZonesDRecords::default();
        b.host_records.push(HostRecord {
            ttl: 0,
            flags: 0,
            names: vec!["b.example".to_string()],
            addr4: Some(std::net::Ipv4Addr::new(5, 6, 7, 8)),
            addr6: None,
        });

        a.extend(b);

        assert_eq!(a.host_records.len(), 2);
        assert_eq!(a.host_records[0].names[0], "a.example");
        assert_eq!(a.host_records[1].names[0], "b.example");
    }
}
