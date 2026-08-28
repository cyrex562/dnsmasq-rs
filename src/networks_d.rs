//! `networks.d` — a watched directory of dnsmasq directive-syntax fragment
//! files, each an independently loadable DHCP pool ("network"). No upstream
//! counterpart (issue #182) — see
//! `docs/superpowers/specs/2026-08-28-networks-d-design.md`.
//!
//! Whole-file gated on `dhcp` (unlike `zones_d.rs`, which is ungated):
//! `NetworksDRecords`'s fields all come from `crate::types::dhcp`, itself
//! gated `#[cfg(feature = "dhcp")]` at the module level.
#![cfg(feature = "dhcp")]

use crate::types::dhcp::{DhcpConfig, DhcpContext, DhcpOpt, DhcpRelay};

/// Aggregate of DHCP pool data loaded from every currently-present file
/// across every configured `--networks-dir`. Rebuilt wholesale on any
/// change by [`networks_d_records`]; never mutated incrementally. Merged
/// into [`crate::dnsmasq::DhcpReloadConfig`] at
/// `dnsmasq::daemon_dhcp_reload_config`, not stored on `Daemon`.
#[derive(Debug, Clone, Default)]
pub struct NetworksDRecords {
    pub contexts: Vec<DhcpContext>,
    pub relay4: Vec<DhcpRelay>,
    pub configs: Vec<DhcpConfig>,
    pub dhcp_opts: Vec<DhcpOpt>,
}

impl NetworksDRecords {
    /// Merge `other`'s records into `self`, field by field.
    pub fn extend(&mut self, other: NetworksDRecords) {
        self.contexts.extend(other.contexts);
        self.relay4.extend(other.relay4);
        self.configs.extend(other.configs);
        self.dhcp_opts.extend(other.dhcp_opts);
    }
}

/// Parse one network file into its own aggregate. Whole-file atomic: the
/// first disallowed directive or parse error aborts the file entirely
/// (matching `zones_d::parse_zone_file`'s same "one bad file must not
/// corrupt others" behavior).
pub fn parse_network_file(path: &std::path::Path) -> Result<NetworksDRecords, crate::option::ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        crate::option::ConfigError::Io(std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))
    })?;
    let lines = crate::option::parse_config_text(&text, &path.to_string_lossy())?;

    let mut records = NetworksDRecords::default();
    for cl in &lines {
        crate::option::apply_network_directive(&mut records, cl)?;
    }
    Ok(records)
}

/// List every configured `--networks-dir`, parse every currently-present
/// file, and aggregate every successfully-parsed one into a fresh
/// `NetworksDRecords`. Called by `dnsmasq::daemon_dhcp_reload_config` on
/// every call -- both the startup path and every reload trigger already
/// funnel through that one function (issue #182), unlike `zones_d`'s
/// `rescan_zones_dirs`, which needed its own separate call sites.
#[cfg(feature = "inotify")]
pub fn networks_d_records(daemon: &crate::types::daemon::Daemon) -> NetworksDRecords {
    use crate::types::network::DynDirFlags;

    let mut aggregate = NetworksDRecords::default();

    for dd in daemon.dynamic_dirs.iter().filter(|dd| dd.flags.contains(DynDirFlags::NETWORKS)) {
        let entries = match std::fs::read_dir(&dd.dname) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("networks-dir {} is not readable: {e}", dd.dname);
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
            match parse_network_file(&path) {
                Ok(records) => aggregate.extend(records),
                Err(e) => tracing::error!("networks.d: skipping {}: {e}", path.display()),
            }
        }
    }

    aggregate
}

#[cfg(not(feature = "inotify"))]
pub fn networks_d_records(_daemon: &crate::types::daemon::Daemon) -> NetworksDRecords {
    NetworksDRecords::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_context(start: Ipv4Addr, end: Ipv4Addr) -> DhcpContext {
        DhcpContext {
            lease_time: 3600,
            addr_epoch: 0,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::UNSPECIFIED,
            local: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::UNSPECIFIED,
            start,
            end,
            flags: crate::types::dhcp::ContextFlags::empty(),
            netid: crate::types::dhcp::DhcpNetid { net: String::new() },
            filter: vec![],
            #[cfg(feature = "dhcp6")]
            start6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            end6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            local6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            prefix: 0,
            #[cfg(feature = "dhcp6")]
            if_index: 0,
            #[cfg(feature = "dhcp6")]
            valid: 0,
            #[cfg(feature = "dhcp6")]
            preferred: 0,
            #[cfg(feature = "dhcp6")]
            ra_time: 0,
            #[cfg(feature = "dhcp6")]
            ra_short_period_start: 0,
            #[cfg(feature = "dhcp6")]
            saved_valid: 0,
            #[cfg(feature = "dhcp6")]
            address_lost_time: 0,
        }
    }

    #[test]
    fn parse_network_file_loads_a_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lab.conf");
        std::fs::write(&path, "dhcp-range=192.168.70.10,192.168.70.100\ndhcp-option=6,192.168.70.1\n").unwrap();

        let records = parse_network_file(&path).unwrap();

        assert_eq!(records.contexts.len(), 1);
        assert_eq!(records.dhcp_opts.len(), 1);
    }

    #[test]
    fn parse_network_file_rejects_whole_file_on_disallowed_directive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.conf");
        // The dhcp-range before the bad line must NOT survive -- a bad file is
        // dropped in full, not partially applied.
        std::fs::write(&path, "dhcp-range=192.168.70.10,192.168.70.100\nhost-record=x.test,1.2.3.4\n").unwrap();

        assert!(parse_network_file(&path).is_err());
    }

    #[test]
    fn parse_network_file_rejects_whole_file_on_malformed_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad2.conf");
        std::fs::write(&path, "dhcp-range=not-an-ip,also-not-an-ip\n").unwrap();

        assert!(parse_network_file(&path).is_err());
    }

    #[test]
    fn parse_network_file_errors_on_unreadable_path() {
        let result = parse_network_file(std::path::Path::new("/nonexistent/networks-d-test-path.conf"));
        assert!(result.is_err());
    }

    #[test]
    fn extend_merges_every_field() {
        let mut a = NetworksDRecords::default();
        a.contexts.push(make_context(Ipv4Addr::new(10, 0, 0, 10), Ipv4Addr::new(10, 0, 0, 50)));

        let mut b = NetworksDRecords::default();
        b.contexts.push(make_context(Ipv4Addr::new(10, 0, 1, 10), Ipv4Addr::new(10, 0, 1, 50)));

        a.extend(b);

        assert_eq!(a.contexts.len(), 2);
        assert_eq!(a.contexts[0].start, Ipv4Addr::new(10, 0, 0, 10));
        assert_eq!(a.contexts[1].start, Ipv4Addr::new(10, 0, 1, 10));
    }
}

#[cfg(all(test, feature = "inotify"))]
mod records_tests {
    use super::*;
    use crate::types::daemon::Daemon;
    use crate::types::network::{DynDir, DynDirFlags};

    fn make_networks_dyndir(dname: &str) -> DynDir {
        DynDir { files: vec![], flags: DynDirFlags::NETWORKS, dname: dname.to_string(), wd: -1 }
    }

    #[test]
    fn records_aggregates_multiple_valid_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.conf"), "dhcp-range=192.168.80.10,192.168.80.50\n").unwrap();
        std::fs::write(dir.path().join("b.conf"), "dhcp-range=192.168.81.10,192.168.81.50\n").unwrap();

        let mut daemon = Daemon::default();
        daemon.dynamic_dirs.push(make_networks_dyndir(dir.path().to_str().unwrap()));

        let records = networks_d_records(&daemon);

        assert_eq!(records.contexts.len(), 2);
    }

    #[test]
    fn records_skips_a_bad_file_without_blocking_others() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("good.conf"), "dhcp-range=192.168.80.10,192.168.80.50\n").unwrap();
        std::fs::write(dir.path().join("bad.conf"), "host-record=x.test,1.2.3.4\n").unwrap();

        let mut daemon = Daemon::default();
        daemon.dynamic_dirs.push(make_networks_dyndir(dir.path().to_str().unwrap()));

        let records = networks_d_records(&daemon);

        assert_eq!(records.contexts.len(), 1);
    }

    #[test]
    fn records_reflect_a_deleted_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gone.conf");
        std::fs::write(&path, "dhcp-range=192.168.80.10,192.168.80.50\n").unwrap();

        let mut daemon = Daemon::default();
        daemon.dynamic_dirs.push(make_networks_dyndir(dir.path().to_str().unwrap()));
        assert_eq!(networks_d_records(&daemon).contexts.len(), 1);

        std::fs::remove_file(&path).unwrap();
        assert_eq!(networks_d_records(&daemon).contexts.len(), 0);
    }

    #[test]
    fn records_ignore_dotfiles_and_backup_names() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("real.conf"), "dhcp-range=192.168.80.10,192.168.80.50\n").unwrap();
        std::fs::write(dir.path().join(".hidden.conf"), "dhcp-range=192.168.81.10,192.168.81.50\n").unwrap();
        std::fs::write(dir.path().join("real.conf~"), "dhcp-range=192.168.82.10,192.168.82.50\n").unwrap();

        let mut daemon = Daemon::default();
        daemon.dynamic_dirs.push(make_networks_dyndir(dir.path().to_str().unwrap()));

        let records = networks_d_records(&daemon);

        assert_eq!(records.contexts.len(), 1);
        assert_eq!(records.contexts[0].start, std::net::Ipv4Addr::new(192, 168, 80, 10));
    }

    #[test]
    fn records_with_no_networks_dirs_configured_is_empty() {
        let daemon = Daemon::default();
        assert!(networks_d_records(&daemon).contexts.is_empty());
    }

    #[test]
    fn records_warns_and_continues_on_missing_directory() {
        let mut daemon = Daemon::default();
        daemon.dynamic_dirs.push(make_networks_dyndir("/nonexistent-networks-d-test-dir-xyz"));
        // Must not panic.
        assert!(networks_d_records(&daemon).contexts.is_empty());
    }
}
