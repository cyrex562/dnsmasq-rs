

pub mod dns_protocol;
pub mod dhcp_protocol;
pub mod dhcp6_protocol;
pub mod radv_protocol;
pub mod metrics;
pub mod types;

// Phase 2 — Core utilities
pub mod blockdata;
pub mod domain;
pub mod domain_match;
pub mod log;
pub mod outpacket;
pub mod pattern;
pub mod poll;
pub mod util;

fn main() {
    // Entry point placeholder — full tokio main will be implemented in Phase 11.
}
