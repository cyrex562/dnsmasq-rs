//! Locates libnftables when the `nftset` feature is enabled.
//!
//! `nftset.c` links against libnftables rather than talking raw netlink
//! itself (see `src/nftset.rs`), so this feature needs the shared library at
//! link time. No headers are required — `src/nftset.rs` hand-declares the
//! small FFI surface it uses via `#[link(name = "nftables")]` — but the
//! `.so` must be *findable*, which is this script's only job.
//!
//! Most distributions ship `libnftables-dev` with an unversioned
//! `libnftables.so` symlink that the default system linker search path picks
//! up for free — nothing to do here. When only a versioned runtime library is
//! installed (no `-dev` package), this script symlinks it to an unversioned
//! name under `OUT_DIR` and adds that to the link search path. Override the
//! search directory with `NFTABLES_LIB_DIR` if it lives somewhere
//! nonstandard.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    if env::var_os("CARGO_FEATURE_NFTSET").is_none() {
        return;
    }

    // libnftables is a Linux netfilter frontend; `src/nftset.rs` only links
    // against it under `#[cfg(target_os = "linux")]`, so there is nothing to
    // find (or fail to find) when cross-compiling elsewhere.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    println!("cargo:rerun-if-env-changed=NFTABLES_LIB_DIR");

    let search_dirs: Vec<PathBuf> = if let Ok(dir) = env::var("NFTABLES_LIB_DIR") {
        vec![PathBuf::from(dir)]
    } else {
        vec![
            PathBuf::from("/usr/lib/x86_64-linux-gnu"),
            PathBuf::from("/usr/lib/aarch64-linux-gnu"),
            PathBuf::from("/usr/lib64"),
            PathBuf::from("/usr/local/lib"),
            PathBuf::from("/usr/lib"),
        ]
    };

    // Prefer a real dev symlink (`libnftables.so`) if one is installed.
    for dir in &search_dirs {
        if dir.join("libnftables.so").is_file() || is_symlink(&dir.join("libnftables.so")) {
            println!("cargo:rustc-link-search=native={}", dir.display());
            return;
        }
    }

    // Fall back to a versioned runtime-only install (no `-dev` package):
    // `-lnftables` only ever looks for `libnftables.so`, so symlink the
    // versioned file to that name under `OUT_DIR` and add it to the search
    // path.
    let versioned = search_dirs.iter().find_map(|dir| find_versioned_so(dir));
    let Some(versioned) = versioned else {
        panic!(
            "the `nftset` feature requires libnftables, but no libnftables.so, \
             libnftables.so.<N>, or NFTABLES_LIB_DIR override was found in {search_dirs:?}. \
             Install libnftables-dev (or point NFTABLES_LIB_DIR at a directory containing it)."
        );
    };

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let link_name = out_dir.join("libnftables.so");
    let _ = fs::remove_file(&link_name);
    std::os::unix::fs::symlink(&versioned, &link_name).unwrap_or_else(|e| {
        panic!("failed to symlink {versioned:?} -> {link_name:?}: {e}");
    });

    println!("cargo:rustc-link-search=native={}", out_dir.display());
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn find_versioned_so(dir: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(dir).ok()?;
    let mut best: Option<PathBuf> = None;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().starts_with("libnftables.so.") {
            best = Some(entry.path());
        }
    }
    best
}
