# networks.d Dynamic DHCP Pool Directory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let dnsmasq-rs add a new `dhcp-range` pool (plus its `dhcp-relay`/`dhcp-host`/
`dhcp-option` entries) at runtime, via a watched `--networks-dir` directory, without a process
restart — for pools reachable by the daemon's existing DHCP socket (relay-reached, or on an
already-bound/wildcard interface).

**Architecture:** A new `NetworksDRecords` aggregate (contexts/relay4/configs/dhcp_opts) is
parsed fresh from every file in every configured `--networks-dir` by a pure function,
`networks_d::networks_d_records(daemon)`. Unlike issue #177's `zones.d` (which lives on
`Daemon` and needs a dedicated merge step), this is folded directly into
`dnsmasq::daemon_dhcp_reload_config` — the one function issue #179 already made both the
startup path (`resolve_run_config`) and every reload path (`clear_cache_and_reload`) call to
build `DhcpReloadConfig`. `run_dhcp_loop`'s existing reload tick picks up the new
`contexts`/`relay4` fields the same way it already picks up `configs`/`dhcp_opts`. A live
`--networks-dir` file change reuses the existing `inotify.rs` dynamic-directory watch and,
mirroring the flag-then-react pattern already used for resolv-file/conf-file hits (not
`zones.d`'s own synchronous-rescan pattern, which doesn't fit here — see Task 6), triggers a
lightweight re-invocation of the same `daemon_dhcp_reload_config` builder.

**Tech Stack:** Rust, tokio, existing dnsmasq-rs config-parsing pipeline (`option.rs`), existing
inotify integration (`inotify.rs`).

**Spec:** `docs/superpowers/specs/2026-08-28-networks-d-design.md`

## Global Constraints

- No new RFC-format zone/network-file parser — a network file is dnsmasq-rs directive syntax.
- A network file may contain **only** `dhcp-range`, `dhcp-relay`/`dhcp-split-relay`,
  `dhcp-host`, `dhcp-option`. Any other directive is a parse error for that file.
- A file that produces even one disallowed-directive or parse error is dropped **entirely**
  from the current rescan (not partially applied). Other files in the same rescan are
  unaffected.
- **Out of scope, do not attempt:** a genuinely new local (non-relayed) subnet on an interface
  the existing DHCP socket bind can't receive from (needs a new privileged socket — still
  needs a restart), DHCPv6 pools, reachability validation at load time.
- **`src/networks_d.rs` must be gated `#![cfg(feature = "dhcp")]` for its whole body** (unlike
  `zones_d.rs`, which is ungated) — `NetworksDRecords` is built from `DhcpContext`/`DhcpRelay`/
  `DhcpConfig`/`DhcpOpt`, all of which live in `crate::types::dhcp`, itself gated
  `#[cfg(feature = "dhcp")]` at the module-declaration level (`src/types/mod.rs`). This is a
  real difference from `zones_d.rs`'s ungated pattern, not an oversight — verify with
  `cargo check --no-default-features` at every task, not just `--all-features`.
- `apply_network_directive` (in `option.rs`) must be `#[cfg(feature = "dhcp")]`-gated too — it
  calls `parse_dhcp_range`/`parse_dhcp_host`/`parse_dhcp_relay`/`parse_dhcp_option`, all four of
  which are themselves already `#[cfg(feature = "dhcp")]`-gated in `option.rs`.
- `networks_d_records`'s *real* body is additionally `#[cfg(feature = "inotify")]`-gated (needs
  `crate::inotify::is_ignorable_filename`), with a `#[cfg(not(feature = "inotify"))]` no-op twin
  — mirrors `zones_d::rescan_zones_dirs`'s existing two-variant pattern, nested one level
  deeper (inside the file-level `dhcp` gate).
- The `networks-dir=<path>` directive registration itself (in `apply_line`) is **not**
  `dhcp`-gated — it unconditionally pushes a `DynDir` the same way `zones-dir=` does. This
  matches the established convention for `dhcp-range`/`dhcp-host` etc. themselves (accepted and
  parsed unconditionally, silently inert when the `dhcp` feature is off) rather than rejecting
  the directive outright.
- Do not run `cargo fmt` (this tree is deliberately not rustfmt-formatted).
- Every new `Daemon`-reachable module must be declared in **both** `src/lib.rs` and
  `src/main.rs` (see `CLAUDE.md`'s "lib/bin duplication gotcha") or the binary silently loses
  it.
- `DhcpContext`/`DhcpRelay` derive only `Debug, Clone` — no `PartialEq`. Tests must compare
  specific fields (e.g. `.start`/`.end`, `.local_addr`/`.iface_index`), not whole-struct
  `assert_eq!`.

---

## File Structure

- **Create `src/networks_d.rs`** — `#![cfg(feature = "dhcp")]`-gated whole-file. Holds
  `NetworksDRecords` (the aggregate struct), `parse_network_file` (parses one file), and
  `networks_d_records` (lists every configured `--networks-dir`, parses every file, aggregates
  successes) — the DHCP-pool analog of `zones_d.rs`.
- **Modify `src/option.rs`** — add `pub fn apply_network_directive` (the allowlist dispatcher,
  `#[cfg(feature = "dhcp")]`-gated, placed near `apply_zone_directive`); add the
  `"networks-dir"` directive to `apply_line`.
- **Modify `src/types/network.rs`** — add `DynDirFlags::NETWORKS`.
- **Modify `src/dnsmasq.rs`** — `DhcpReloadConfig` gains `contexts`/`relay4` fields (both
  `#[cfg(feature = "dhcp")]`-gated); `daemon_dhcp_reload_config`'s `dhcp`-feature variant folds
  in `networks_d::networks_d_records(daemon)`'s output and runs the relay `iface_index` fixup;
  `first_ipv4_listen_addr`/`first_bind_interface` (already private, already in this file) are
  reused as-is, no visibility change needed.
- **Modify `src/dhcp.rs`** — `run_dhcp_loop`'s reload tick gains
  `cfg.contexts = fresh.contexts; cfg.relay4 = fresh.relay4;`.
- **Modify `src/inotify.rs`** — `InotifyHits` gains a `networks_dir: bool` field; `inotify_check`
  gains a hit-detection block (flag-only, no rescan call, unlike `zones_dir`'s); a new
  `push_fresh_dhcp_reload_config` helper (mirrors `push_fresh_forward_config`); wired into
  `watch_inotify_changes`.
- **Modify `src/lib.rs`, `src/main.rs`** — declare `pub mod networks_d;`, gated
  `#[cfg(feature = "dhcp")]`.

---

### Task 1: `NetworksDRecords` data model and module scaffolding

**Files:**
- Create: `src/networks_d.rs`
- Modify: `src/lib.rs`, `src/main.rs` (declare the module)

**Interfaces:**
- Produces: `pub struct NetworksDRecords { pub contexts: Vec<DhcpContext>, pub relay4:
  Vec<DhcpRelay>, pub configs: Vec<DhcpConfig>, pub dhcp_opts: Vec<DhcpOpt> }` with
  `#[derive(Debug, Clone, Default)]`, plus `impl NetworksDRecords { pub fn extend(&mut self,
  other: NetworksDRecords) }` extending every field pairwise. Consumed by Tasks 2-5.

- [ ] **Step 1: Write the failing test**

Create `src/networks_d.rs`:

```rust
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
```

**Note on `DhcpContext`'s `#[cfg(feature = "dhcp6")]` fields:** run `cargo test --all-features`
first; if the field list above doesn't match (this repo's `DhcpContext` may have grown/changed
fields since this plan was written), read `src/types/dhcp.rs`'s current `DhcpContext` struct
definition and adjust `make_context` to match exactly — every field must be named, since
`DhcpContext` has no `Default` impl.

Add `pub mod networks_d;` gated `#[cfg(feature = "dhcp")]` to `src/lib.rs` and `src/main.rs`,
right after the existing `pub mod zones_d;` line in each file.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --all-features extend_merges_every_field`
Expected: FAIL to compile if `make_context`'s field list doesn't match the real `DhcpContext` —
fix per the note above. Once it compiles, the test should pass immediately (nothing outside
`networks_d.rs` references it yet).

- [ ] **Step 3: Run tests to verify everything passes**

Run: `cargo test --all-features networks_d`
Expected: PASS.

Run: `cargo check --no-default-features`
Expected: clean — `--no-default-features` excludes `dhcp`, so `networks_d.rs`'s entire body
(including its test module) must not be compiled at all. Confirm by checking
`cargo test --no-default-features networks_d` reports zero tests found, not a compile error.

- [ ] **Step 4: Commit**

```bash
git add src/networks_d.rs src/lib.rs src/main.rs
git commit -m "networks.d: add NetworksDRecords data model (issue #182)"
```

---

### Task 2: `apply_network_directive` allowlist dispatcher

**Files:**
- Modify: `src/option.rs` (new function, placed directly after `apply_zone_directive`)

**Interfaces:**
- Consumes: `NetworksDRecords` (Task 1), and the existing private parsers `parse_dhcp_range`,
  `parse_dhcp_relay`, `parse_dhcp_host`, `parse_dhcp_option` (all already in `option.rs`,
  unchanged, all already `#[cfg(feature = "dhcp")]`-gated).
- Produces: `#[cfg(feature = "dhcp")] pub fn apply_network_directive(target: &mut
  crate::networks_d::NetworksDRecords, cl: &ConfigLine) -> Result<(), ConfigError>` — used by
  Task 3's `parse_network_file`.

- [ ] **Step 1: Write the failing tests**

Add to `src/option.rs`'s `#[cfg(test)] mod tests` block, near the existing
`apply_zone_directive_*` tests:

```rust
#[test]
fn apply_network_directive_dhcp_range() {
    use crate::networks_d::NetworksDRecords;
    let lines = parse_config_text("dhcp-range=192.168.50.10,192.168.50.100", "test").unwrap();
    let mut target = NetworksDRecords::default();
    apply_network_directive(&mut target, &lines[0]).unwrap();
    assert_eq!(target.contexts.len(), 1);
    assert_eq!(target.contexts[0].start, std::net::Ipv4Addr::new(192, 168, 50, 10));
    assert_eq!(target.contexts[0].end, std::net::Ipv4Addr::new(192, 168, 50, 100));
}

#[test]
fn apply_network_directive_dhcp_relay() {
    use crate::networks_d::NetworksDRecords;
    let lines = parse_config_text("dhcp-relay=192.168.50.1,192.168.60.1", "test").unwrap();
    let mut target = NetworksDRecords::default();
    apply_network_directive(&mut target, &lines[0]).unwrap();
    assert_eq!(target.relay4.len(), 1);
}

#[test]
fn apply_network_directive_dhcp_host() {
    use crate::networks_d::NetworksDRecords;
    let lines = parse_config_text("dhcp-host=aa:bb:cc:dd:ee:ff,192.168.50.20", "test").unwrap();
    let mut target = NetworksDRecords::default();
    apply_network_directive(&mut target, &lines[0]).unwrap();
    assert_eq!(target.configs.len(), 1);
}

#[test]
fn apply_network_directive_dhcp_option() {
    use crate::networks_d::NetworksDRecords;
    let lines = parse_config_text("dhcp-option=6,192.168.50.1", "test").unwrap();
    let mut target = NetworksDRecords::default();
    apply_network_directive(&mut target, &lines[0]).unwrap();
    assert_eq!(target.dhcp_opts.len(), 1);
}

#[test]
fn apply_network_directive_rejects_disallowed_directive() {
    use crate::networks_d::NetworksDRecords;
    let lines = parse_config_text("host-record=zone.test,10.0.0.5", "test").unwrap();
    let mut target = NetworksDRecords::default();
    let err = apply_network_directive(&mut target, &lines[0]).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidValue(..)));
}

#[test]
fn apply_network_directive_propagates_parse_errors() {
    use crate::networks_d::NetworksDRecords;
    let lines = parse_config_text("dhcp-range=not-an-ip,also-not-an-ip", "test").unwrap();
    let mut target = NetworksDRecords::default();
    assert!(apply_network_directive(&mut target, &lines[0]).is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --all-features apply_network_directive`
Expected: FAIL with "cannot find function `apply_network_directive`".

- [ ] **Step 3: Write the dispatcher**

Add to `src/option.rs`, directly after `apply_zone_directive`'s closing brace:

```rust
/// Apply one [`ConfigLine`] from a `--networks-dir` file, restricted to the
/// fixed allowlist of DHCP-pool directives (issue #182 — see
/// `docs/superpowers/specs/2026-08-28-networks-d-design.md`). Any other
/// directive is rejected outright — a network file must not be able to
/// reconfigure listening addresses, DNS behavior, or anything outside a
/// DHCP pool's own data.
///
/// Dispatches to the exact same per-directive parser functions `apply_line`
/// uses, writing into `target` instead of a live `Daemon`.
#[cfg(feature = "dhcp")]
pub fn apply_network_directive(
    target: &mut crate::networks_d::NetworksDRecords,
    cl: &ConfigLine,
) -> Result<(), ConfigError> {
    let key = cl.key.as_str();
    let require_value = |opt: &str| -> Result<&str, ConfigError> {
        cl.value.as_deref().ok_or_else(|| ConfigError::MissingValue(opt.to_string(), cl.file.clone(), cl.line))
    };

    match key {
        "dhcp-range" => {
            let v = require_value("dhcp-range")?;
            target.contexts.push(parse_dhcp_range(v, cl)?);
        }
        "dhcp-relay" | "dhcp-split-relay" => {
            let v = require_value(key)?;
            match parse_dhcp_relay(v, cl, key == "dhcp-split-relay")? {
                RelayEntry::V4(r) => target.relay4.push(r),
                #[cfg(feature = "dhcp6")]
                RelayEntry::V6(_) => {
                    return Err(invalid_value_for(cl, key, v, "IPv6 relays are not supported in a networks-dir file"));
                }
            }
        }
        "dhcp-host" => {
            let v = require_value("dhcp-host")?;
            target.configs.push(parse_dhcp_host(v, cl)?);
        }
        "dhcp-option" => {
            let v = require_value("dhcp-option")?;
            target.dhcp_opts.push(parse_dhcp_option(v, cl, "dhcp-option", crate::types::dhcp::DhOptFlags::empty())?);
        }
        _ => {
            return Err(invalid_value_for(
                cl,
                key,
                cl.value.as_deref().unwrap_or(""),
                "directive is not allowed in a networks-dir file",
            ));
        }
    }

    Ok(())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --all-features apply_network_directive`
Expected: PASS, all 6 tests.

Run: `cargo check --no-default-features`
Expected: clean (`apply_network_directive` is `#[cfg(feature = "dhcp")]`-gated, so it's simply
absent from that build, matching `apply_zone_directive`'s unconditional presence vs. this
function's conditional one — this asymmetry is expected, not a bug).

- [ ] **Step 5: Commit**

```bash
git add src/option.rs
git commit -m "networks.d: add apply_network_directive allowlist dispatcher (issue #182)"
```

---

### Task 3: `parse_network_file` and the `networks-dir` directive

**Files:**
- Modify: `src/networks_d.rs` (add `parse_network_file`)
- Modify: `src/option.rs` (add the `"networks-dir"` directive to `apply_line`)
- Modify: `src/types/network.rs` (add `DynDirFlags::NETWORKS`)

**Interfaces:**
- Consumes: `apply_network_directive` (Task 2), `option::parse_config_text` (existing),
  `NetworksDRecords` (Task 1).
- Produces: `fn parse_network_file(path: &std::path::Path) -> Result<NetworksDRecords,
  option::ConfigError>` in `src/networks_d.rs` — used by Task 4's `networks_d_records`.
- Produces: `daemon.dynamic_dirs` gains a `DynDir` entry with `DynDirFlags::NETWORKS` whenever
  `networks-dir=<path>` is configured.

- [ ] **Step 1: Write the failing tests**

Add to `src/networks_d.rs`'s test module:

```rust
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --all-features parse_network_file`
Expected: FAIL with "cannot find function `parse_network_file`".

- [ ] **Step 3: Write `parse_network_file`**

Add to `src/networks_d.rs`:

```rust
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
```

- [ ] **Step 4: Add `DynDirFlags::NETWORKS`**

In `src/types/network.rs`, in the `DynDirFlags` bitflags block (next to `const ZONES = 1 <<
6;`):

```rust
        /// `--networks-dir` (issue #182; no upstream `AH_*` counterpart).
        const NETWORKS = 1 << 7;
```

- [ ] **Step 5: Add the `networks-dir` directive**

In `src/option.rs`'s `apply_line`, add a new arm right after the existing `"zones-dir"` arm:

```rust
        "networks-dir" => {
            let v = require_value("networks-dir")?;
            daemon.dynamic_dirs.push(make_dynamic_dir(v, DynDirFlags::NETWORKS));
        }
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test --all-features parse_network_file`
Expected: PASS, all 4 tests.

Also add one `apply_line` test to `src/option.rs`'s test module confirming the directive
registers correctly:

```rust
#[test]
fn apply_networks_dir_registers_a_dynamic_dir() {
    let mut d = Daemon::default();
    let lines = parse_config_text("networks-dir=/etc/dnsmasq-rs/networks.d", "test").unwrap();
    apply_config(&mut d, &lines).unwrap();
    assert_eq!(d.dynamic_dirs.len(), 1);
    assert_eq!(d.dynamic_dirs[0].dname, "/etc/dnsmasq-rs/networks.d");
    assert!(d.dynamic_dirs[0].flags.contains(DynDirFlags::NETWORKS));
}
```

Run: `cargo test --all-features apply_networks_dir_registers_a_dynamic_dir` — Expected: PASS.

Then run the full suite: `cargo test --all-features` and `cargo test --no-default-features`.
Expected: PASS on both — `DynDirFlags::NETWORKS` and the `"networks-dir"` `apply_line` arm are
both ungated (matching `zones-dir`'s own unconditional acceptance), even though
`apply_network_directive`/`parse_network_file`/`networks_d.rs` are `dhcp`-gated.

- [ ] **Step 7: Commit**

```bash
git add src/networks_d.rs src/option.rs src/types/network.rs
git commit -m "networks.d: add parse_network_file and the networks-dir directive (issue #182)"
```

---

### Task 4: `networks_d_records` — directory listing and aggregation

**Files:**
- Modify: `src/networks_d.rs` (add `networks_d_records`)

**Interfaces:**
- Consumes: `parse_network_file` (Task 3), `inotify::is_ignorable_filename` (already
  `pub(crate)`, bumped in issue #177's Task 5), `daemon.dynamic_dirs: Vec<DynDir>` filtered by
  `DynDirFlags::NETWORKS`.
- Produces: `#[cfg(feature = "inotify")] pub fn networks_d_records(daemon: &Daemon) ->
  NetworksDRecords` (real implementation) and `#[cfg(not(feature = "inotify"))] pub fn
  networks_d_records(_daemon: &Daemon) -> NetworksDRecords { NetworksDRecords::default() }`
  (no-op) — used by Task 5's `daemon_dhcp_reload_config`.

- [ ] **Step 1: Write the failing tests**

Add to `src/networks_d.rs`'s test module (needs `#[cfg(feature = "inotify")]` since
`networks_d_records`'s real body only exists under that feature):

```rust
#[cfg(feature = "inotify")]
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --all-features records_`
Expected: FAIL with "cannot find function `networks_d_records`".

- [ ] **Step 3: Write `networks_d_records`**

Add to `src/networks_d.rs`:

```rust
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --all-features records_`
Expected: PASS, all 6 tests.

Then: `cargo check --no-default-features --features "dhcp dhcp6 auth tftp loop dump ipset script legacy-config"` (every default feature except `inotify`, the one combination that
actually exercises the `#[cfg(not(feature = "inotify"))]` twin while keeping `dhcp` on).
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/networks_d.rs
git commit -m "networks.d: add networks_d_records directory aggregation (issue #182)"
```

---

### Task 5: Merge into `DhcpReloadConfig` / `daemon_dhcp_reload_config`

**Files:**
- Modify: `src/dnsmasq.rs` (`DhcpReloadConfig` struct, `daemon_dhcp_reload_config`)

**Interfaces:**
- Consumes: `networks_d::networks_d_records` (Task 4), existing private
  `first_ipv4_listen_addr(&[Iname]) -> Option<Ipv4Addr>` and `first_bind_interface(&Daemon) ->
  Option<String>` (both already in `src/dnsmasq.rs`, used unchanged — no visibility bump
  needed, they're in the same file as the code that now also calls them).
- Produces: `DhcpReloadConfig.contexts: Vec<DhcpContext>` and `.relay4: Vec<DhcpRelay>` (both
  `#[cfg(feature = "dhcp")]`) — consumed by Task 6's `run_dhcp_loop` reload tick and Task 7's
  `push_fresh_dhcp_reload_config`.

- [ ] **Step 1: Write the failing test**

Add near `daemon_local_data_merges_zones_d_records` in `src/dnsmasq.rs`'s test module:

```rust
#[cfg(feature = "dhcp")]
#[test]
fn daemon_dhcp_reload_config_merges_networks_d_records() {
    use crate::types::network::{DynDir, DynDirFlags};

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("lab.conf"),
        "dhcp-range=192.168.90.10,192.168.90.50\ndhcp-relay=192.168.90.1,192.168.100.1\n",
    )
    .unwrap();

    let mut daemon = Daemon::default();
    daemon.dynamic_dirs.push(DynDir {
        files: vec![],
        flags: DynDirFlags::NETWORKS,
        dname: dir.path().to_str().unwrap().to_string(),
        #[cfg(feature = "inotify")]
        wd: -1,
    });

    let reload = daemon_dhcp_reload_config(&daemon);

    assert_eq!(reload.contexts.len(), 1);
    assert_eq!(reload.contexts[0].start, std::net::Ipv4Addr::new(192, 168, 90, 10));
    assert_eq!(reload.relay4.len(), 1);
}
```

**Note:** if the `#[cfg(feature = "inotify")]` field gate on `DynDir.wd` doesn't match this
repo's current `src/types/network.rs`, adjust to match — it's a real field-level `cfg`, not a
placeholder.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --all-features daemon_dhcp_reload_config_merges_networks_d_records`
Expected: FAIL to compile — `DhcpReloadConfig` has no `contexts`/`relay4` fields yet.

- [ ] **Step 3: Add the fields and the relay `iface_index` fixup**

In `src/dnsmasq.rs`, update `DhcpReloadConfig`:

```rust
#[derive(Debug, Clone, Default)]
pub struct DhcpReloadConfig {
    #[cfg(feature = "dhcp")]
    pub configs:   Vec<crate::types::dhcp::DhcpConfig>,
    #[cfg(feature = "dhcp")]
    pub dhcp_opts: Vec<crate::types::dhcp::DhcpOpt>,
    /// `--networks-dir`-sourced pools merged in alongside the
    /// statically-configured ones (issue #182). Pool bounds/contexts were
    /// previously startup-only (see `run_dhcp_loop`'s reload-tick comment,
    /// issue #179) -- this is what makes them live-reloadable.
    #[cfg(feature = "dhcp")]
    pub contexts: Vec<crate::types::dhcp::DhcpContext>,
    /// Same as `contexts`, for `dhcp-relay`/`dhcp-split-relay` entries.
    #[cfg(feature = "dhcp")]
    pub relay4: Vec<crate::types::dhcp::DhcpRelay>,
    pub generation: u64,
}
```

Then replace `daemon_dhcp_reload_config`'s `#[cfg(feature = "dhcp")]` body:

```rust
#[cfg(feature = "dhcp")]
pub fn daemon_dhcp_reload_config(daemon: &Daemon) -> DhcpReloadConfig {
    let mut contexts = daemon.dhcp.clone();
    let mut relay4 = daemon.relay4.clone();
    let mut configs = daemon.dhcp_conf.clone();
    let mut dhcp_opts = daemon.dhcp_opts.clone();

    let networks_d = crate::networks_d::networks_d_records(daemon);
    contexts.extend(networks_d.contexts);
    relay4.extend(networks_d.relay4);
    configs.extend(networks_d.configs);
    dhcp_opts.extend(networks_d.dhcp_opts);

    // Mirrors `daemon_dhcp_runtime`'s own relay `iface_index` fixup
    // (`dhcp.c:669-673`'s `complete_context` equivalent): without it,
    // `relay_upstream4`'s `relay.iface_index != 0` dispatch guard never
    // matches and a non-split-mode relay silently never fires. Run over the
    // *combined* list (not just `networks_d`'s contribution), for
    // correctness independent of source.
    let bind_ip = first_ipv4_listen_addr(&daemon.if_addrs).unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
    let bind_interface = first_bind_interface(daemon);
    let relay_iface_index = bind_interface
        .as_deref()
        .map_or(0, |name| crate::network::nametoindex(name) as i32);
    for relay in relay4.iter_mut() {
        if relay.split_mode == 0 {
            if let crate::types::addr::AllAddr::Addr4(local4) = relay.local_addr {
                if local4 == bind_ip {
                    relay.iface_index = relay_iface_index;
                }
            }
        }
    }

    DhcpReloadConfig {
        configs,
        dhcp_opts,
        contexts,
        relay4,
        // Overwritten by `clear_cache_and_reload`'s own read-modify-write on
        // every reload; left at 0 here so a fresh startup snapshot (this
        // function's other caller, `resolve_run_config`) matches
        // `run_dhcp_loop`'s initial `last_reload_generation` and no reload
        // is spuriously assumed to have already happened.
        generation: 0,
    }
}
```

**Do not change** the `#[cfg(not(feature = "dhcp"))]` variant — `DhcpReloadConfig::default()`
already correctly produces empty `contexts`/`relay4` (both absent as fields entirely when
`dhcp` is off, same as `configs`/`dhcp_opts` already are).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --all-features daemon_dhcp_reload_config`
Expected: PASS.

Then: `cargo test --all-features` (full suite) and `cargo test --no-default-features`.
Expected: PASS on both.

- [ ] **Step 5: Commit**

```bash
git add src/dnsmasq.rs
git commit -m "networks.d: merge into DhcpReloadConfig via daemon_dhcp_reload_config (issue #182)"
```

---

### Task 6: Wire `cfg.contexts`/`cfg.relay4` into `run_dhcp_loop`'s reload tick

**Files:**
- Modify: `src/dhcp.rs` (the reload-tick branch inside `run_dhcp_loop`, around line 1585)

**Interfaces:**
- Consumes: `DhcpReloadConfig.contexts`/`.relay4` (Task 5).
- Produces: nothing new downstream — `cfg.contexts()`/`cfg.relay4` are already read by every
  existing dispatch site (`narrow_context`, `relay_reply4`/`relay_upstream4`); from here on, a
  `networks.d`-sourced pool/relay is indistinguishable from a statically-configured one.

- [ ] **Step 1: Write the failing test**

Add near `run_dhcp_loop_picks_up_a_reloaded_static_host_mapping` in `src/dhcp.rs`'s test
module:

```rust
/// Issue #182: a `--networks-dir` pool must reach a *running* `run_dhcp_loop`'s
/// dispatch, not just the config it was constructed with.
#[tokio::test]
async fn run_dhcp_loop_picks_up_a_reloaded_dhcp_context() {
    let Some(server) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
    let Some(client) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
    let Some(receiver) = bind_udp_or_skip("127.0.0.1:0").await else { return; };

    let receiver_addr = receiver.local_addr().unwrap();
    let server = std::sync::Arc::new(server);
    // No contexts at all initially -- default_cfg()'s existing pool_start/
    // pool_end fallback only applies when cfg.contexts() is empty, so this
    // proves the *new* context is what answers, not the legacy fallback.
    let mut cfg = default_cfg();
    cfg.pool_start = std::net::Ipv4Addr::new(10, 0, 0, 100);
    cfg.pool_end = std::net::Ipv4Addr::new(10, 0, 0, 100);
    let opts = DhcpLoopOptions {
        reply_port_override: Some(receiver_addr.port()),
        ..Default::default()
    };
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let reload = std::sync::Arc::new(tokio::sync::Mutex::new(crate::dnsmasq::DhcpReloadConfig::default()));
    let loop_task = tokio::spawn(run_dhcp_loop(
        server.clone(), cfg, opts, std::sync::Arc::new(tokio::sync::Mutex::new(LeaseDb::new())),
        shutdown_rx, Box::new(NullProbe), reload.clone(),
    ));

    let new_context = crate::types::dhcp::DhcpContext {
        lease_time: 3600,
        addr_epoch: 0,
        netmask: std::net::Ipv4Addr::new(255, 255, 255, 0),
        broadcast: std::net::Ipv4Addr::UNSPECIFIED,
        local: std::net::Ipv4Addr::UNSPECIFIED,
        router: std::net::Ipv4Addr::UNSPECIFIED,
        start: std::net::Ipv4Addr::new(10, 0, 5, 50),
        end: std::net::Ipv4Addr::new(10, 0, 5, 50),
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
    };
    {
        let mut guard = reload.lock().await;
        guard.contexts = vec![new_context];
    }
    // `run_dhcp_loop` only checks for a fresh reload config once per second
    // (its periodic-tick branch) -- see that branch's doc comment.
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let mut pkt = base_packet();
    pkt.giaddr = std::net::Ipv4Addr::new(10, 0, 5, 1); // relayed from the new pool's subnet
    let wire = packet_to_wire(&pkt);
    client.send_to(&wire, server.local_addr().unwrap()).await.unwrap();

    let mut buf = [0u8; 512];
    let (len, _) = tokio::time::timeout(Duration::from_millis(250), receiver.recv_from(&mut buf))
        .await
        .expect("timed out waiting for DHCP loop reply")
        .unwrap();
    let reply = parse_dhcp_packet(&buf[..len]).expect("loop reply should parse");
    assert_eq!(get_message_type(&reply.options), Some(DhcpMsgType::Offer));
    assert_eq!(
        reply.yiaddr,
        std::net::Ipv4Addr::new(10, 0, 5, 50),
        "the live loop must offer from the reloaded context, not the legacy pool_start/pool_end fallback"
    );

    shutdown_tx.send(true).unwrap();
    loop_task.await.unwrap().unwrap();
}
```

**Note:** this test relies on `narrow_context`-style subnet matching picking the context whose
`start`/`end`/`netmask` covers the relayed `giaddr`. If the real dispatch logic in this repo
narrows differently (e.g. requires `netmask` to actually contain both `giaddr` and
`start`/`end` consistently, or requires `router` to be set), read `dispatch_dhcp_with_arrival`/
`narrow_context` in `src/dhcp.rs` first and adjust the test's `new_context`/`pkt.giaddr` so the
match is unambiguous — the point of the test is proving the *reload* reaches dispatch, not
exercising `narrow_context`'s own matching rules (already covered by other existing tests).

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --all-features run_dhcp_loop_picks_up_a_reloaded_dhcp_context`
Expected: FAIL — either a timeout waiting for a reply (no context matches, so nothing answers)
or a reply from the legacy `pool_start`/`pool_end` fallback instead of the new context.

- [ ] **Step 3: Update the reload tick**

In `src/dhcp.rs`, in `run_dhcp_loop`'s `_ = reload_ticker.tick() => { ... }` branch, right after
the existing `cfg.dhcp_opts = fresh.dhcp_opts;` line, add:

```rust
                // Issue #182: a --networks-dir pool reaches dispatch the
                // same way configs/dhcp_opts already do.
                cfg.contexts = fresh.contexts;
                cfg.relay4   = fresh.relay4;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --all-features run_dhcp_loop_picks_up_a_reloaded_dhcp_context`
Expected: PASS.

Then: `cargo test --all-features` (full suite) and `cargo test --no-default-features`.
Expected: PASS on both.

- [ ] **Step 5: Commit**

```bash
git add src/dhcp.rs
git commit -m "networks.d: wire cfg.contexts/relay4 into run_dhcp_loop reload tick (issue #182)"
```

---

### Task 7: Wire the live inotify watch (`InotifyHits` + `watch_inotify_changes`)

**Files:**
- Modify: `src/inotify.rs` (`InotifyHits`, `inotify_check`, new `push_fresh_dhcp_reload_config`,
  `watch_inotify_changes`)

**Interfaces:**
- Consumes: `dnsmasq::daemon_dhcp_reload_config` (Task 5, already `networks.d`-aware),
  `DynDirFlags::NETWORKS` (Task 3).
- Produces: `InotifyHits.networks_dir: bool` — observable in tests. Unlike `zones_dir`'s hit
  (which triggers its rescan *synchronously inside* `inotify_check`), the actual push happens
  in `watch_inotify_changes`, since it needs to lock `SharedDhcpReloadConfig`, a handle
  `inotify_check` (fully synchronous, only touches `&mut Daemon`/`&mut DnsCache`) doesn't have
  access to.

- [ ] **Step 1: Write the failing tests**

Add to `src/inotify.rs`'s `#[cfg(test)] mod tests` block, near the existing `zones_dir`-focused
tests:

```rust
fn make_networks_dyndir(dname: &str) -> DynDir {
    DynDir { files: vec![], flags: DynDirFlags::NETWORKS, dname: dname.to_string(), wd: -1 }
}

#[test]
fn inotify_check_flags_a_networks_dir_hit_without_rescanning_inline() {
    let dir = tempfile::tempdir().unwrap();
    let (mut daemon, _guard) = init_test_daemon_with_fd();
    daemon.dynamic_dirs.push(make_networks_dyndir(dir.path().to_str().unwrap()));
    let mut cache = DnsCache::new(1000);
    set_dynamic_inotify(&mut daemon, &mut cache);

    std::fs::write(dir.path().join("new.conf"), "dhcp-range=192.168.95.10,192.168.95.50\n").unwrap();

    let hits = inotify_check(&mut daemon, &mut cache);

    assert!(hits.networks_dir);
    // Unlike zones_dir, inotify_check itself does NOT touch daemon.dhcp or
    // any DHCP reload state -- there's nothing on Daemon for it to update.
}

#[test]
fn inotify_check_networks_dir_hit_does_not_set_other_hits() {
    let dir = tempfile::tempdir().unwrap();
    let (mut daemon, _guard) = init_test_daemon_with_fd();
    daemon.dynamic_dirs.push(make_networks_dyndir(dir.path().to_str().unwrap()));
    let mut cache = DnsCache::new(1000);
    set_dynamic_inotify(&mut daemon, &mut cache);

    std::fs::write(dir.path().join("new.conf"), "dhcp-range=192.168.95.10,192.168.95.50\n").unwrap();

    let hits = inotify_check(&mut daemon, &mut cache);

    assert!(hits.networks_dir);
    assert!(!hits.resolv);
    assert!(!hits.conf_file);
    assert!(!hits.zones_dir);
}

#[cfg(feature = "dhcp")]
#[tokio::test]
async fn push_fresh_dhcp_reload_config_includes_networks_d_contexts() {
    use crate::types::network::{DynDir, DynDirFlags};

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("lab.conf"), "dhcp-range=192.168.96.10,192.168.96.50\n").unwrap();

    let daemon_handle = crate::dnsmasq::init_daemon();
    daemon_handle.write().await.dynamic_dirs.push(DynDir {
        files: vec![],
        flags: DynDirFlags::NETWORKS,
        dname: dir.path().to_str().unwrap().to_string(),
        wd: -1,
    });
    let dhcp_reload: crate::dnsmasq::SharedDhcpReloadConfig =
        std::sync::Arc::new(tokio::sync::Mutex::new(crate::dnsmasq::DhcpReloadConfig::default()));

    push_fresh_dhcp_reload_config(&daemon_handle, &dhcp_reload).await;

    let cfg = dhcp_reload.lock().await;
    assert_eq!(cfg.contexts.len(), 1);
    assert_eq!(cfg.contexts[0].start, std::net::Ipv4Addr::new(192, 168, 96, 10));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --all-features networks_dir`
Expected: FAIL — `hits.networks_dir` doesn't exist yet, `push_fresh_dhcp_reload_config` doesn't
exist yet.

- [ ] **Step 3: Add `InotifyHits::networks_dir`**

In `src/inotify.rs`, update the `InotifyHits` struct:

```rust
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct InotifyHits {
    pub resolv: bool,
    pub conf_file: bool,
    pub zones_dir: bool,
    /// A watched `--networks-dir` changed (issue #182; no upstream
    /// counterpart). Unlike `zones_dir`, the rescan does *not* happen
    /// inline here -- it needs `SharedDhcpReloadConfig`, which
    /// `inotify_check` (fully synchronous) has no access to. The caller
    /// (`watch_inotify_changes`) reacts to this flag instead.
    pub networks_dir: bool,
}
```

- [ ] **Step 4: Detect the hit in `inotify_check`**

In `src/inotify.rs`, inside `inotify_check`'s per-event loop, directly after the existing
`hits.zones_dir = true;` block's closing brace (still inside the same `while offset <
data.len()` iteration), add:

```rust
            if daemon
                .dynamic_dirs
                .iter()
                .any(|dd| dd.wd == wd && dd.flags.contains(DynDirFlags::NETWORKS))
            {
                hits.networks_dir = true;
            }
```

**Do not** add a `networks_d`-rescan call inside `inotify_check` (unlike the existing `if
hits.zones_dir { crate::zones_d::rescan_zones_dirs(daemon); }` block right before `inotify_check`'s
final `hits` return) — leave that block untouched, and do not add a `networks_dir` equivalent
next to it. The push happens in `watch_inotify_changes` (Step 6).

- [ ] **Step 5: Add `push_fresh_dhcp_reload_config`**

In `src/inotify.rs`, add this function directly after the existing
`push_fresh_forward_config`:

```rust
/// Push a fresh [`crate::dnsmasq::DhcpReloadConfig`] into the live DHCP
/// loop without going through `clear_cache_and_reload` — the `dhcp_reload`
/// analog of `push_fresh_forward_config`, used for a `--networks-dir`
/// change (issue #182). `daemon_dhcp_reload_config` (the same builder both
/// the startup path and every full reload already use) is already
/// `networks.d`-aware, so this needs no separate rescan step.
async fn push_fresh_dhcp_reload_config(
    daemon_handle: &crate::dnsmasq::DaemonHandle,
    dhcp_reload: &crate::dnsmasq::SharedDhcpReloadConfig,
) {
    let d = daemon_handle.read().await;
    let fresh = crate::dnsmasq::daemon_dhcp_reload_config(&d);
    drop(d);
    *dhcp_reload.lock().await = fresh;
}
```

**Note:** `daemon_dhcp_reload_config` only exists under `#[cfg(feature = "dhcp")]` (with a
`#[cfg(not(feature = "dhcp"))]` twin returning `DhcpReloadConfig::default()`) — both variants
have the identical signature `fn(&Daemon) -> DhcpReloadConfig`, so
`push_fresh_dhcp_reload_config` itself does not need its own `dhcp`-feature split; it compiles
and calls whichever variant is active.

- [ ] **Step 6: Wire it into `watch_inotify_changes`**

In `src/inotify.rs`, in `watch_inotify_changes`'s loop body, right after the existing
`if hits.zones_dir { push_fresh_forward_config(&daemon_handle, &fwd_config).await; }` block,
add:

```rust
        if hits.networks_dir {
            push_fresh_dhcp_reload_config(&daemon_handle, &dhcp_reload).await;
        }
```

(`dhcp_reload: crate::dnsmasq::SharedDhcpReloadConfig` is already a parameter of
`watch_inotify_changes`, threaded through since issue #179 — no new plumbing needed between
`dnsmasq.rs` and `inotify.rs`.)

- [ ] **Step 7: Run tests to verify they pass**

Run: `cargo test --all-features` (full suite — this task touches shared code paths).
Expected: PASS, including every pre-existing `zones_dir`/resolv/conf-file inotify test
unchanged.

Then: `cargo check --no-default-features`.
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add src/inotify.rs
git commit -m "networks.d: wire networks-dir into inotify watch (issue #182)"
```

---

### Task 8: Documentation, module map, and full verification

**Files:**
- Modify: `CLAUDE.md` (module map table)
- Modify: `tasks.md` (dated entry)

**Interfaces:** None — this task only documents and verifies what Tasks 1-7 built.

- [ ] **Step 1: Update `CLAUDE.md`'s module map**

In `CLAUDE.md`'s module map table, add a new row right after the `src/zones_d.rs` row:

```markdown
| `src/networks_d.rs` | `--networks-dir` dynamic DHCP pool directory: watched via `src/inotify.rs`, merged into `dnsmasq::DhcpReloadConfig` at `daemon_dhcp_reload_config` (issue #182) — no upstream counterpart |
```

- [ ] **Step 2: Add a `tasks.md` entry**

Find the most recent dated entry in `tasks.md` and add, directly after it:

```markdown
  **Issue #182 (2026-08-28):** Implemented, following the architectural design at
  `docs/superpowers/specs/2026-08-28-networks-d-design.md`. `--networks-dir=<path>` watches a
  directory of dnsmasq directive-syntax fragment files, restricted to `dhcp-range`,
  `dhcp-relay`/`dhcp-split-relay`, `dhcp-host`, `dhcp-option`. Unlike issue #177's `zones.d`
  (which lives on `Daemon` and needed a dedicated merge step plus a separate startup-ordering
  fix), `networks.d`'s rescan is folded directly into `dnsmasq::daemon_dhcp_reload_config` --
  the single function issue #179 already made both the startup path and every reload trigger
  call -- so there was no equivalent startup-ordering bug to find or fix here.

  Corrected the original issue's own framing during brainstorming: the "new pool needs a new
  socket" obstacle only applies to a genuinely new *local* subnet when `--interface=`
  restricted the DHCP socket bind away from it. A relay-reached pool, or a directly-attached
  pool on an already-bound (including the common wildcard-bind) interface, needs no new socket
  at all -- `daemon_dhcp_runtime` already binds a single `0.0.0.0:67` socket by default. Relay
  support was explicitly requested; a live-added non-split-mode relay gets the same
  `iface_index` fixup `daemon_dhcp_runtime` already applies at startup, now re-run over the
  combined static+`networks.d` relay list on every `daemon_dhcp_reload_config` call.

  `src/networks_d.rs` is gated `#![cfg(feature = "dhcp")]` for its whole body (unlike
  `zones_d.rs`, which is ungated) -- `NetworksDRecords`'s fields all come from
  `crate::types::dhcp`, itself gated on that feature.
```

- [ ] **Step 3: Run the full verification suite**

```bash
cargo test --all-features 2>&1 | tail -30
cargo check --no-default-features 2>&1 | tail -10
cargo clippy --all-features --all-targets 2>&1 | grep -c '^warning'
```

Expected: `cargo test --all-features` shows 0 failures, with the total test count higher than
before this plan started by roughly the number of new tests across Tasks 1-7 (1 + 6 + 4 + 6 + 1
+ 1 + 3 = 22, plus whichever `apply_line`/registration tests were added). `cargo check
--no-default-features` shows 0 errors. The clippy warning count should match the pre-existing
baseline (check `tasks.md`'s most recent clippy-count mention) — no new warnings introduced.

- [ ] **Step 4: Live smoke test**

```bash
mkdir -p /tmp/networks-d-smoke/networks.d
cat > /tmp/networks-d-smoke/networks.d/lab.conf <<'EOF'
dhcp-range=192.168.99.50,192.168.99.50,12h
EOF
cat > /tmp/networks-d-smoke/dnsmasq.conf <<'EOF'
no-daemon
port=0
networks-dir=/tmp/networks-d-smoke/networks.d
EOF
cargo build --all-features
(sudo ./target/debug/dnsmasq-rs --conf-file=/tmp/networks-d-smoke/dnsmasq.conf > /tmp/networks-d-smoke/log.txt 2>&1 &)
sleep 1
cat /tmp/networks-d-smoke/log.txt
# DHCP needs a raw/broadcast-capable socket on port 67, which needs root in
# this environment -- if sudo isn't available non-interactively, this step
# can't complete end-to-end; the automated tests in Task 6/7 already cover
# the live-reload mechanism itself directly over ephemeral test-bound
# sockets (the same workaround used for every DHCP live-reload issue this
# session, e.g. issues #179/#180), so treat that as sufficient verification
# if root access isn't available, and say so explicitly rather than
# skipping verification silently.
echo 'dhcp-range=192.168.100.50,192.168.100.50,12h' >> /tmp/networks-d-smoke/networks.d/lab2.conf
sleep 2
grep -i "networks" /tmp/networks-d-smoke/log.txt
pkill -f "dnsmasq-rs --conf-file=/tmp/networks-d-smoke" 2>/dev/null
rm -rf /tmp/networks-d-smoke
```

If root/sudo is unavailable non-interactively (as in prior sessions this repo has worked in),
this step cannot bind the real DHCP socket. In that case, rely on Task 6's
`run_dhcp_loop_picks_up_a_reloaded_dhcp_context` integration test (which exercises the exact
same live-reload mechanism directly over an ephemeral test-bound UDP socket, no root needed) as
the acceptance-bar proof instead, and state clearly in the closing report that the real-binary
smoke test wasn't run and why — do not claim it passed if it wasn't actually executed.

- [ ] **Step 5: Commit the docs**

```bash
git add CLAUDE.md tasks.md
git commit -m "networks.d: update CLAUDE.md module map and tasks.md (issue #182)"
```

At this point the feature is complete and every commit is in place. Follow up with
`superpowers:finishing-a-development-branch` to decide how to integrate this work — do not push
as part of this plan; that decision belongs to whoever executes it.

---

## Self-Review

**Spec coverage:**
- Directive & config surface (`networks-dir=<path>`) — Task 3. ✓
- Allowed directives (all 4) — Task 2. ✓
- Data model (`NetworksDRecords`) — Task 1. ✓
- Loading model (list, parse-in-isolation, whole-file-atomic, aggregate) — Tasks 3-4. ✓
- Relay `iface_index` fixup — Task 5. ✓
- Merge point (`DhcpReloadConfig`/`daemon_dhcp_reload_config`, `run_dhcp_loop` reload tick) —
  Tasks 5-6. ✓
- Watch integration (flag-then-react, not `zones_dir`'s synchronous-rescan pattern) — Task 7. ✓
- Error handling (bad file dropped, others unaffected; missing dir logged-and-continue) — Task
  4. ✓
- Alternatives considered — no task needed (design record only, not implementation).
- Testing strategy (unit on dispatcher, unit on aggregation, unit on merge, unit on fixup,
  integration via real inotify + real `run_dhcp_loop`) — Tasks 2, 4, 5, 6, 7. ✓

**Placeholder scan:** No TBD/TODO markers. The two intentionally-flagged uncertainties (Task
1's `DhcpContext` field list, Task 6's `narrow_context` matching behavior, Task 4's `DynDir.wd`
cfg-gating) are each called out explicitly with a concrete instruction for what to check and
adjust, not left as unresolved gaps — verifying exact current struct shapes against a
fast-moving codebase at execution time is cheaper and more reliable than freezing a snapshot
that might already be stale.

**Type consistency:** `NetworksDRecords` field names (`contexts`, `relay4`, `configs`,
`dhcp_opts`) are identical across Tasks 1, 2, 4, 5. `apply_network_directive`'s signature
(`target: &mut NetworksDRecords, cl: &ConfigLine`) matches its Task 3 caller exactly.
`networks_d_records(daemon: &Daemon) -> NetworksDRecords` matches its Task 5 call site exactly.
`push_fresh_dhcp_reload_config(daemon_handle: &DaemonHandle, dhcp_reload:
&SharedDhcpReloadConfig)` matches its Task 7 call site exactly.
