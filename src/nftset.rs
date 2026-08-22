#![cfg(feature = "nftset")]

//! nftables named set integration.
//!
//! Port of `nftset.c`. Unlike `ipset.c`, upstream does not build a raw
//! netlink message here at all: it links against libnftables and hands it a
//! textual command (`"add element %s { %s }"`), letting libnftables do its
//! own netlink I/O internally (`nft_run_cmd_from_buffer()`). This module
//! mirrors that mechanism via a small hand-written FFI surface rather than
//! reimplementing nftables' wire format from scratch.

use std::net::IpAddr;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NftsetError {
    #[error("failed to create nftset context")]
    ContextInit,
    #[error("{0}")]
    CommandFailed(String),
    #[error("nftset is a Linux-only facility")]
    Unsupported,
}

/// Strip a `"4 "`/`"6 "` family prefix from `setname` — produced by the
/// `#`→space substitution `nftset=` config parsing applies to each
/// `4#table#set`/`6#table#set` token (`option.c:3268-3271`) — and filter out
/// addresses that don't match the requested family.
///
/// Mirrors `add_to_nftset()`'s family check (`nftset.c:53-62`). Returns
/// `None` when the entry is family-scoped and `flags` doesn't match the
/// address (the caller silently skips, matching upstream's `return -1` with
/// no error logged); `Some(name)` otherwise, with the prefix removed if one
/// was present.
fn strip_family_prefix(setname: &str, flags: u32) -> Option<&str> {
    use crate::types::constants::{F_IPV4, F_IPV6};

    let bytes = setname.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b' ' && (bytes[0] == b'4' || bytes[0] == b'6') {
        if bytes[0] == b'4' && flags & F_IPV4 == 0 {
            return None;
        }
        if bytes[0] == b'6' && flags & F_IPV6 == 0 {
            return None;
        }
        Some(&setname[2..])
    } else {
        Some(setname)
    }
}

/// Build the exact command text upstream sends to libnftables
/// (`nftset.c:28-29`, formatted at `nftset.c:64-79`).
fn format_cmd(remove: bool, setname: &str, addr: &str) -> String {
    if remove {
        format!("delete element {} {{ {} }}", setname, addr)
    } else {
        format!("add element {} {{ {} }}", setname, addr)
    }
}

#[cfg(target_os = "linux")]
mod ffi_impl {
    use super::{format_cmd, strip_family_prefix, NftsetError};
    use std::ffi::{CStr, CString};
    use std::net::IpAddr;
    use std::os::raw::{c_char, c_int};

    // Hand-written declarations for the slice of libnftables' public API
    // that `nftset.c` uses (`#include <nftables/libnftables.h>`, nftset.c:22).
    // Not bindgen'd: the surface is five stable functions and this crate
    // otherwise has no dependency on libnftables headers being installed —
    // only the shared library needs to be present at link time (see
    // `build.rs`).
    #[repr(C)]
    struct RawNftCtx {
        _private: [u8; 0],
    }

    const NFT_CTX_DEFAULT: u32 = 0;

    // `#[link(...)]` (rather than relying solely on build.rs's
    // `cargo:rustc-link-lib`) so the dependency travels with this code into
    // every crate that compiles it — both `lib.rs` and `main.rs` pull in
    // `nftset.rs` separately (the lib/bin module duplication noted in
    // `CLAUDE.md`), and each needs the link requirement independently.
    // build.rs still contributes the `-L` search path via
    // `cargo:rustc-link-search` for the versioned-runtime-only fallback case.
    #[link(name = "nftables", kind = "dylib")]
    extern "C" {
        fn nft_ctx_new(flags: u32) -> *mut RawNftCtx;
        fn nft_ctx_free(ctx: *mut RawNftCtx);
        fn nft_ctx_buffer_error(ctx: *mut RawNftCtx);
        fn nft_run_cmd_from_buffer(ctx: *mut RawNftCtx, buf: *const c_char) -> c_int;
        fn nft_ctx_get_error_buffer(ctx: *mut RawNftCtx) -> *const c_char;
    }

    /// Owns a libnftables context (`struct nft_ctx *`). Mirrors
    /// `nftset_init()` (`nftset.c:31-39`): one context, with its own error
    /// buffer capture enabled so failures never print straight to stderr.
    ///
    /// Upstream keeps a single `static struct nft_ctx *ctx` for the whole
    /// process lifetime, created once at startup (`dnsmasq.c:365`). This port
    /// creates and frees a context per [`super::add_to_nftset`] call instead
    /// — the same efficiency-only divergence `ipset::open_ipset_socket`
    /// already takes for the analogous per-call netlink socket; the command
    /// run and its result are identical either way. See `tasks.md`.
    pub struct NftCtx(*mut RawNftCtx);

    impl NftCtx {
        pub fn new() -> Result<Self, NftsetError> {
            let ctx = unsafe { nft_ctx_new(NFT_CTX_DEFAULT) };
            if ctx.is_null() {
                return Err(NftsetError::ContextInit);
            }
            unsafe { nft_ctx_buffer_error(ctx) };
            Ok(NftCtx(ctx))
        }
    }

    impl Drop for NftCtx {
        fn drop(&mut self) {
            unsafe { nft_ctx_free(self.0) };
        }
    }

    /// `nftset_init()` (`nftset.c:31-39`).
    pub fn nftset_init() -> Result<NftCtx, NftsetError> {
        NftCtx::new()
    }

    /// Add (or remove) an address in an nftables named set.
    ///
    /// Port of `add_to_nftset()` (`nftset.c:41-98`): formats
    /// `"add element <set> { <ip> }"` / `"delete element <set> { <ip> }"` and
    /// runs it through libnftables' own command interpreter — upstream never
    /// opens a netlink socket itself here, `nft_run_cmd_from_buffer()` does
    /// its own netlink I/O internally. On failure, the first line of
    /// libnftables' error buffer is logged and returned, mirroring
    /// `nftset.c:84-95`'s truncate-at-newline `my_syslog(LOG_ERR, ...)`.
    pub fn add_to_nftset(
        setname: &str,
        addr: IpAddr,
        flags: u32,
        remove: bool,
    ) -> Result<(), NftsetError> {
        let Some(setname) = strip_family_prefix(setname, flags) else {
            return Ok(());
        };

        let ctx = NftCtx::new()?;
        let cmd = format_cmd(remove, setname, &addr.to_string());
        let cmd_c = CString::new(cmd)
            .map_err(|_| NftsetError::CommandFailed("command contains a NUL byte".to_string()))?;

        let ret = unsafe { nft_run_cmd_from_buffer(ctx.0, cmd_c.as_ptr()) };
        if ret != 0 {
            let err = unsafe { nft_ctx_get_error_buffer(ctx.0) };
            let err_str = if err.is_null() {
                String::new()
            } else {
                unsafe { CStr::from_ptr(err) }.to_string_lossy().into_owned()
            };
            let first_line = err_str.lines().next().unwrap_or("").to_string();
            tracing::error!(set = %setname, error = %first_line, "nftset");
            return Err(NftsetError::CommandFailed(first_line));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use ffi_impl::{add_to_nftset, nftset_init, NftCtx};

/// No-op stub on non-Linux targets — nftables (and libnftables) is a Linux
/// kernel facility, same gate `ipset::add_to_ipset` uses.
#[cfg(not(target_os = "linux"))]
pub fn add_to_nftset(_setname: &str, _addr: IpAddr, _flags: u32, _remove: bool) -> Result<(), NftsetError> {
    Err(NftsetError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::constants::{F_IPV4, F_IPV6};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn strip_family_prefix_no_prefix_is_unchanged() {
        assert_eq!(strip_family_prefix("myset", 0), Some("myset"));
        assert_eq!(strip_family_prefix("myset", F_IPV4 | F_IPV6), Some("myset"));
    }

    #[test]
    fn strip_family_prefix_ipv4_matching_flag() {
        assert_eq!(strip_family_prefix("4 inet filter myset", F_IPV4), Some("inet filter myset"));
    }

    #[test]
    fn strip_family_prefix_ipv4_mismatched_flag_is_filtered() {
        assert_eq!(strip_family_prefix("4 inet filter myset", F_IPV6), None);
    }

    #[test]
    fn strip_family_prefix_ipv6_matching_flag() {
        assert_eq!(strip_family_prefix("6 inet filter myset6", F_IPV6), Some("inet filter myset6"));
    }

    #[test]
    fn strip_family_prefix_ipv6_mismatched_flag_is_filtered() {
        assert_eq!(strip_family_prefix("6 inet filter myset6", F_IPV4), None);
    }

    #[test]
    fn strip_family_prefix_short_string_is_unchanged() {
        // A single-character set name can't carry a "N " prefix; must not panic.
        assert_eq!(strip_family_prefix("4", F_IPV4), Some("4"));
        assert_eq!(strip_family_prefix("", F_IPV4), Some(""));
    }

    #[test]
    fn strip_family_prefix_non_family_digit_is_unchanged() {
        // Second byte is a space but the first isn't '4'/'6' — must not be
        // mistaken for a family prefix.
        assert_eq!(strip_family_prefix("x set", F_IPV4), Some("x set"));
    }

    #[test]
    fn format_cmd_add() {
        assert_eq!(
            format_cmd(false, "inet filter myset", "192.168.1.1"),
            "add element inet filter myset { 192.168.1.1 }"
        );
    }

    #[test]
    fn format_cmd_delete() {
        assert_eq!(
            format_cmd(true, "inet filter myset6", "fd00::1"),
            "delete element inet filter myset6 { fd00::1 }"
        );
    }

    /// Capability-dependent: creating an nftables context and running a
    /// command against a fabricated set touches the real netfilter subsystem
    /// via libnftables. The sandbox this runs in may deny it outright (no
    /// `nf_tables` kernel module, no permission) or libnftables may reject the
    /// made-up set reference — either way `add_to_nftset` must not panic; only
    /// a crash would be a bug, `Ok` and `Err` are both legitimate outcomes.
    #[test]
    #[cfg(target_os = "linux")]
    fn add_to_nftset_does_not_panic() {
        let _ = add_to_nftset(
            "inet dnsmasq_rs_test_table dnsmasq_rs_test_set",
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            F_IPV4,
            false,
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn add_to_nftset_family_mismatch_is_ok_without_touching_ffi() {
        // A `4 `-prefixed set queried with an IPv6 hit must be filtered out
        // before any FFI call is made — Ok(()), not an error.
        assert_eq!(
            add_to_nftset(
                "4 inet filter v4only",
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                F_IPV6,
                false,
            ),
            Ok(())
        );
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn add_to_nftset_is_unsupported_off_linux() {
        let err = add_to_nftset(
            "myset",
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            F_IPV4,
            false,
        )
        .unwrap_err();
        assert_eq!(err, NftsetError::Unsupported);
    }
}
