// Re-exports all public modules so integration tests (and downstream crates)
// can use `dnsmasq_rs::*` imports.

pub mod error;
pub mod dnsmasq;
pub mod option;
pub mod yaml_config;
pub mod web_api;

pub mod network;
pub mod netlink;
pub mod arp;
pub mod cmsg;

pub mod cache;
pub mod dns_protocol;
pub mod dhcp_protocol;
pub mod dhcp6_protocol;
pub mod radv_protocol;
pub mod metrics;
pub mod types;

pub mod byte_cursor;
pub mod rfc1035;
pub mod edns0;
pub mod rrfilter;
pub mod domain;
pub mod domain_match;
pub mod hostname;
pub mod log;
pub mod pattern;
pub mod poll;
pub mod sys;
pub mod util;

pub mod hash_questions;
pub mod forward;

#[cfg(feature = "dnssec")]
pub mod crypto;

#[cfg(feature = "auth")]
pub mod auth;

#[cfg(feature = "dhcp")]
pub mod dhcp;
#[cfg(feature = "dhcp")]
pub mod dhcp_common;
#[cfg(feature = "dhcp")]
pub mod rfc2131;
#[cfg(feature = "dhcp")]
pub mod lease;

#[cfg(feature = "dhcp6")]
pub mod dhcp6;
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

#[cfg(all(feature = "dhcp", feature = "script"))]
pub mod helper;
#[cfg(feature = "inotify")]
pub mod inotify;
#[cfg(feature = "nftset")]
pub mod nftset;
#[cfg(feature = "ubus")]
pub mod ubus;

#[cfg(feature = "dnssec")]
pub mod dnssec;
#[cfg(feature = "dbus")]
pub mod dbus;
