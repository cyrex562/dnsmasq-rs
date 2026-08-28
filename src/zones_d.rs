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

/// Parse one zone file into its own aggregate. Whole-file atomic: the
/// first disallowed directive or parse error aborts the file entirely
/// (matching upstream-style "one bad file must not corrupt others," but
/// unlike `option::read_dhcp_bank_file`'s per-line tolerance -- zones.d
/// deliberately does not partially apply a broken file).
pub fn parse_zone_file(path: &std::path::Path) -> Result<ZonesDRecords, crate::option::ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        crate::option::ConfigError::Io(std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))
    })?;
    let lines = crate::option::parse_config_text(&text, &path.to_string_lossy())?;

    let mut records = ZonesDRecords::default();
    for cl in &lines {
        crate::option::apply_zone_directive(&mut records, cl)?;
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_zone_file_loads_a_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("example.test.conf");
        std::fs::write(&path, "host-record=zone.test,10.0.0.5\ntxt-record=zone.test,hello\n").unwrap();

        let records = parse_zone_file(&path).unwrap();

        assert_eq!(records.host_records.len(), 1);
        assert_eq!(records.txt_records.len(), 1);
    }

    #[test]
    fn parse_zone_file_rejects_whole_file_on_disallowed_directive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.conf");
        // The host-record before the bad line must NOT survive -- a bad file
        // is dropped in full, not partially applied.
        std::fs::write(&path, "host-record=zone.test,10.0.0.5\ndhcp-range=1.2.3.4,1.2.3.10\n").unwrap();

        assert!(parse_zone_file(&path).is_err());
    }

    #[test]
    fn parse_zone_file_rejects_whole_file_on_malformed_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad2.conf");
        std::fs::write(&path, "host-record=\n").unwrap();

        assert!(parse_zone_file(&path).is_err());
    }

    #[test]
    fn parse_zone_file_errors_on_unreadable_path() {
        let result = parse_zone_file(std::path::Path::new("/nonexistent/zones-d-test-path.conf"));
        assert!(result.is_err());
    }

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
