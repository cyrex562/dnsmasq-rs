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
