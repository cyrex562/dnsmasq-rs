/// Central type definitions for dnsmasq-rs.
/// Ported from `dnsmasq.h`.

pub mod addr;
pub mod cache;
pub mod constants;
pub mod daemon;
pub mod dns_records;
pub mod network;
pub mod server;

#[cfg(feature = "dhcp")]
pub mod dhcp;

pub use addr::*;
pub use cache::*;
pub use constants::*;
pub use server::*;
