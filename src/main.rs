

pub mod option;

pub mod network;
pub mod netlink;
pub mod arp;

pub mod cache;
pub mod dns_protocol;
pub mod dhcp_protocol;
pub mod dhcp6_protocol;
pub mod radv_protocol;
pub mod metrics;
pub mod types;

// Phase 2 — Core utilities
pub mod rfc1035;
pub mod edns0;
pub mod rrfilter;
pub mod blockdata;
pub mod domain;
pub mod domain_match;
pub mod log;
pub mod outpacket;
pub mod pattern;
pub mod poll;
pub mod util;

// Phase 10 — DNS forwarding
pub mod hash_questions;
pub mod forward;

#[cfg(feature = "dnssec")]
pub mod crypto;

#[cfg(feature = "auth")]
pub mod auth;

#[cfg(feature = "dhcp")]
pub mod dhcp_common;
#[cfg(feature = "dhcp")]
pub mod rfc2131;
#[cfg(feature = "dhcp")]
pub mod lease;

#[cfg(feature = "dhcp6")]
pub mod rfc3315;
#[cfg(feature = "dhcp6")]
pub mod radv;
#[cfg(feature = "dhcp6")]
pub mod slaac;

#[cfg(feature = "tftp")]
pub mod tftp;
#[cfg(feature = "dump")]
pub mod dump;
#[cfg(feature = "ipset")]
pub mod ipset;
#[cfg(feature = "conntrack")]
pub mod conntrack;
#[cfg(feature = "loop")]
pub mod loop_detect;

fn main() {
    // Entry point placeholder — full tokio main will be implemented in Phase 11.
}
