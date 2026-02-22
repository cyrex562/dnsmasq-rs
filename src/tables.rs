//! BSD PF table manipulation.
//!
//! On non-BSD platforms the operations are no-ops that return
//! `Err(PfError::NotSupported)`.  On BSD systems a real implementation
//! would issue `ioctl(2)` calls against `/dev/pf`, but that is outside
//! scope here.

use std::net::IpAddr;
use thiserror::Error;

// ─── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PfError {
    #[error("table not found: {0}")]
    NotFound(String),
    #[error("not supported on this platform")]
    NotSupported,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// ─── PF table handle ─────────────────────────────────────────────────────────

/// An in-memory representation of a PF address table.
#[derive(Debug, Clone)]
pub struct PfTable {
    pub name:  String,
    pub addrs: Vec<IpAddr>,
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Add `addr` to the named PF table.
///
/// Always returns `Err(PfError::NotSupported)` on non-BSD platforms.
pub fn add_to_table(_table: &str, _addr: IpAddr) -> Result<(), PfError> {
    #[cfg(target_os = "openbsd")]
    {
        // Real BSD implementation would call ioctl(DIOCRADDADDRS) here.
        return Err(PfError::NotSupported);
    }
    #[allow(unreachable_code)]
    Err(PfError::NotSupported)
}

/// Delete `addr` from the named PF table.
///
/// Always returns `Err(PfError::NotSupported)` on non-BSD platforms.
pub fn del_from_table(_table: &str, _addr: IpAddr) -> Result<(), PfError> {
    #[cfg(target_os = "openbsd")]
    {
        return Err(PfError::NotSupported);
    }
    #[allow(unreachable_code)]
    Err(PfError::NotSupported)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_add_to_table() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let result = add_to_table("block", addr);
        match result {
            Ok(()) | Err(PfError::NotSupported) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_del_from_table() {
        let addr = IpAddr::V6(Ipv6Addr::new(0x20, 1, 0, 0, 0, 0, 0, 1));
        let result = del_from_table("block", addr);
        match result {
            Ok(()) | Err(PfError::NotSupported) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_pftable_struct() {
        let t = PfTable {
            name:  "test".to_string(),
            addrs: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        };
        assert_eq!(t.name, "test");
        assert_eq!(t.addrs.len(), 1);
    }
}
