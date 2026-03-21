# agents.md — dnsmasq-rs Agent Instructions

## Project Context

This is a Rust port of dnsmasq (C DNS forwarder + DHCP server). See `CLAUDE.md` for full architecture, module map, and conventions.

## Agent Roles

### Porting Agent

**Goal:** Port remaining C functions to idiomatic Rust.

**Process:**
1. Read the C source file in `original_dnsmasq_src/dnsmasq-master/src/`
2. Read the corresponding Rust file in `src/`
3. Identify functions present in C but missing or stubbed in Rust
4. Implement missing functions using Rust idioms (see conventions below)
5. Add unit tests for each new function
6. Verify `cargo test` passes

**Priority order** (by impact and % remaining):
1. `option.rs` ← `option.c` (6322 LOC, ~17% done) — config parser
2. `dnsmasq.rs` ← `dnsmasq.c` (2478 LOC, ~15% done) — main daemon
3. `rfc2131.rs` ← `rfc2131.c` (3265 LOC, ~51% done) — DHCP
4. `rfc3315.rs` ← `rfc3315.c` (2348 LOC, ~29% done) — DHCPv6
5. `radv.rs` ← `radv.c` (1039 LOC, ~26% done) — router ads
6. `lease.rs` ← `lease.c` (1346 LOC, ~23% done) — lease mgmt
7. `helper.rs` ← `helper.c` (948 LOC, ~23% done) — DHCP helper
8. `tftp.rs` ← `tftp.c` (1040 LOC, ~22% done) — TFTP server
9. `dbus.rs` ← `dbus.c` (1106 LOC, ~9% done) — D-Bus
10. `dnssec.rs` ← `dnssec.c` (2410 LOC, ~41% done) — DNSSEC

### Testing Agent

**Goal:** Increase test coverage across all modules.

**Process:**
1. Read the Rust source file
2. Identify public functions without test coverage
3. Write unit tests that exercise:
   - Happy path
   - Edge cases (empty input, boundary values, overflow)
   - Error paths (invalid input, missing data)
4. For protocol code, add roundtrip tests (encode → decode → compare)
5. For parsers, add proptest property-based tests
6. Run `cargo test` to verify

**Test patterns:**
- Unit tests: `#[cfg(test)] mod tests { use super::*; ... }`
- Integration tests: `tests/` directory, import via `dnsmasq_rs::*`
- Property tests: `proptest! { ... }` macro with `proptest::prelude::*`
- Feature-gated tests: `#[cfg(all(test, feature = "dhcp"))]`

### Review Agent

**Goal:** Review ported code for correctness, safety, and Rust idioms.

**Process:**
1. Compare Rust implementation against C source function-by-function
2. Check for:
   - Off-by-one errors in buffer/packet parsing
   - Missing bounds checks (C relies on caller discipline)
   - Integer overflow (C uses implicit wrapping)
   - Correct feature gating
   - Proper error propagation (no silent failures)
   - Memory safety (no `unsafe` unless absolutely necessary)
3. Verify tests cover the reviewed code
4. Flag any deviations from C behavior that may be intentional vs bugs

## Conventions for All Agents

### Porting Rules

- C `union` → Rust `enum`
- C null pointer → `Option<T>`
- C `goto` → early return, `loop`/`break`, or helper functions
- C global state → access via `DaemonHandle` (never raw `Daemon`)
- C `#ifdef HAVE_X` → `#[cfg(feature = "x")]`
- C `malloc`/`free` → Rust ownership, `Vec`, `Box`
- C raw sockets → `socket2`, `nix`, or `tokio` abstractions
- C `syslog` → `tracing::info!`, `tracing::warn!`, `tracing::error!`
- C string manipulation → `&str`, `String`, standard library methods

### Error Handling

- Return `Result<T, DnsmasqError>` from public functions
- Use `?` operator for propagation
- Module-local error types implement `From<LocalError> for DnsmasqError`
- Never panic in library code — reserve `unwrap()`/`expect()` for truly impossible cases

### Naming

- Module files: C `dhcp-common.c` → Rust `dhcp_common.rs`
- Functions: C `cache_find_non_terminal()` → Rust `cache_find_non_terminal()`
- Types: C `struct crec` → Rust `CacheRecord`
- Constants: C `F_IPV4` → Rust `F_IPV4` (keep same names for traceability)

### Testing Requirements

Every new function should have at least:
- 1 happy-path test
- 1 edge-case test (empty/zero/boundary)
- 1 error-path test (if function returns Result)

For packet parsing functions, add proptest roundtrip tests.

### Build Verification

After any change, verify:
```bash
cargo build --all-features
cargo test
cargo check --no-default-features
```

## Reference Files

- `original_dnsmasq_src/dnsmasq-master/src/` — C source (read-only)
- `old/` — Prior Rust attempt (read-only reference, may contain useful patterns)
- `tasks.md` — Detailed 12-phase porting plan
- `.github/copilot-instructions.md` — Architecture guide
- `CLAUDE.md` — Project overview and module status
