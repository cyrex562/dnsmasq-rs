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
///
/// Dispatches by extension the same way `main.rs`'s top-level `--conf-file`
/// loader does (issue #170): `.yaml`/`.yml` goes to
/// [`crate::yaml_config::parse_yaml_config_text`] when built with
/// `yaml-config`, anything else to the legacy `key=value`
/// [`crate::option::parse_config_text`] -- both produce the identical
/// `ConfigLine` shape, so `apply_zone_directive` below never needs to know
/// which format a zone file was written in.
pub fn parse_zone_file(path: &std::path::Path) -> Result<ZonesDRecords, crate::option::ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        crate::option::ConfigError::Io(std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))
    })?;
    let path_str = path.to_string_lossy();

    #[cfg(feature = "yaml-config")]
    let lines = if crate::yaml_config::is_yaml_path(&path_str) {
        crate::yaml_config::parse_yaml_config_text(&text, &path_str)?
    } else {
        crate::option::parse_config_text(&text, &path_str)?
    };
    #[cfg(not(feature = "yaml-config"))]
    let lines = crate::option::parse_config_text(&text, &path_str)?;

    let mut records = ZonesDRecords::default();
    for cl in &lines {
        crate::option::apply_zone_directive(&mut records, cl)?;
    }
    Ok(records)
}

/// Rescan every configured `--zones-dir`, aggregate every successfully
/// parsed file, and replace `daemon.zones_d` wholesale. Called once at
/// startup (via `inotify::set_dynamic_inotify`) and once per hit on any
/// watched zones-dir (via `inotify::inotify_check`) -- issue #177.
#[cfg(feature = "inotify")]
pub fn rescan_zones_dirs(daemon: &mut crate::types::daemon::Daemon) {
    use crate::types::network::DynDirFlags;

    let mut aggregate = ZonesDRecords::default();

    for dd in daemon.dynamic_dirs.iter().filter(|dd| dd.flags.contains(DynDirFlags::ZONES)) {
        let entries = match std::fs::read_dir(&dd.dname) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("zones-dir {} is not readable: {e}", dd.dname);
                continue;
            }
        };

        let mut paths: Vec<std::path::PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| !crate::inotify::is_ignorable_filename(n))
                    .unwrap_or(false)
            })
            .collect();
        paths.sort();

        for path in paths {
            match parse_zone_file(&path) {
                Ok(records) => aggregate.extend(records),
                Err(e) => tracing::error!("zones.d: skipping {}: {e}", path.display()),
            }
        }
    }

    daemon.zones_d = aggregate;
}

#[cfg(not(feature = "inotify"))]
pub fn rescan_zones_dirs(_daemon: &mut crate::types::daemon::Daemon) {}

#[cfg(feature = "inotify")]
#[cfg(test)]
mod rescan_tests {
    use super::*;
    use crate::types::daemon::Daemon;
    use crate::types::network::{DynDir, DynDirFlags};

    fn make_zones_dyndir(dname: &str) -> DynDir {
        DynDir { files: vec![], flags: DynDirFlags::ZONES, dname: dname.to_string(), wd: -1 }
    }

    #[test]
    fn rescan_aggregates_multiple_valid_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.conf"), "host-record=a.test,10.0.0.1\n").unwrap();
        std::fs::write(dir.path().join("b.conf"), "host-record=b.test,10.0.0.2\n").unwrap();

        let mut daemon = Daemon::default();
        daemon.dynamic_dirs.push(make_zones_dyndir(dir.path().to_str().unwrap()));

        rescan_zones_dirs(&mut daemon);

        assert_eq!(daemon.zones_d.host_records.len(), 2);
    }

    #[test]
    fn rescan_skips_a_bad_file_without_blocking_others() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("good.conf"), "host-record=good.test,10.0.0.1\n").unwrap();
        std::fs::write(dir.path().join("bad.conf"), "dhcp-range=1.2.3.4,1.2.3.10\n").unwrap();

        let mut daemon = Daemon::default();
        daemon.dynamic_dirs.push(make_zones_dyndir(dir.path().to_str().unwrap()));

        rescan_zones_dirs(&mut daemon);

        assert_eq!(daemon.zones_d.host_records.len(), 1);
    }

    #[test]
    fn rescan_drops_records_for_a_deleted_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gone.conf");
        std::fs::write(&path, "host-record=gone.test,10.0.0.1\n").unwrap();

        let mut daemon = Daemon::default();
        daemon.dynamic_dirs.push(make_zones_dyndir(dir.path().to_str().unwrap()));
        rescan_zones_dirs(&mut daemon);
        assert_eq!(daemon.zones_d.host_records.len(), 1);

        std::fs::remove_file(&path).unwrap();
        rescan_zones_dirs(&mut daemon);
        assert_eq!(daemon.zones_d.host_records.len(), 0);
    }

    #[test]
    fn rescan_ignores_dotfiles_and_backup_names() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("real.conf"), "host-record=real.test,10.0.0.1\n").unwrap();
        std::fs::write(dir.path().join(".hidden.conf"), "host-record=hidden.test,10.0.0.2\n").unwrap();
        std::fs::write(dir.path().join("real.conf~"), "host-record=backup.test,10.0.0.3\n").unwrap();

        let mut daemon = Daemon::default();
        daemon.dynamic_dirs.push(make_zones_dyndir(dir.path().to_str().unwrap()));

        rescan_zones_dirs(&mut daemon);

        assert_eq!(daemon.zones_d.host_records.len(), 1);
        assert_eq!(daemon.zones_d.host_records[0].names[0], "real.test");
    }

    #[test]
    fn rescan_with_no_zones_dirs_configured_produces_empty_aggregate() {
        let mut daemon = Daemon::default();
        rescan_zones_dirs(&mut daemon);
        assert!(daemon.zones_d.host_records.is_empty());
    }

    #[test]
    fn rescan_warns_and_continues_on_missing_directory() {
        let mut daemon = Daemon::default();
        daemon.dynamic_dirs.push(make_zones_dyndir("/nonexistent-zones-d-test-dir-xyz"));
        // Must not panic.
        rescan_zones_dirs(&mut daemon);
        assert!(daemon.zones_d.host_records.is_empty());
    }
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

    #[cfg(feature = "yaml-config")]
    #[test]
    fn parse_zone_file_loads_a_valid_yaml_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("example.test.yaml");
        std::fs::write(&path, "host-record: \"yaml.test,10.0.0.9\"\ntxt-record: \"yaml.test,hello\"\n").unwrap();

        let records = parse_zone_file(&path).unwrap();

        assert_eq!(records.host_records.len(), 1);
        assert_eq!(records.txt_records.len(), 1);
    }

    #[cfg(feature = "yaml-config")]
    #[test]
    fn parse_zone_file_rejects_whole_yaml_file_on_disallowed_directive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yml");
        std::fs::write(&path, "host-record: \"yaml.test,10.0.0.9\"\ndhcp-range: \"1.2.3.4,1.2.3.10\"\n").unwrap();

        assert!(parse_zone_file(&path).is_err());
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
