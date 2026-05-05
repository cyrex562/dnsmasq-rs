# CLAUDE.md

## Overview

`dnsmasq-rs` is an in-progress Rust port of the upstream `dnsmasq` binary. The target is behavioral parity for the supported feature set, with safe Rust internals and strong regression coverage.

This repository already contains broad module coverage and substantial tests, but it should not yet be described as feature-complete or upstream-equivalent.

Primary references:

- Upstream C source: `original_dnsmasq_src/dnsmasq-master/src/`
- Earlier Rust attempt: `old/`
- Current execution tracker: `tasks.md`

The upstream tree and `old/` tree are reference-only.

## What Matters Most

Current top priorities:

1. Complete `src/option.rs` enough to support realistic config parity fixtures.
2. Close the behavioral gap in `src/dnsmasq.rs` and `src/main.rs` for startup, reload, and runtime control flow.
3. Separate or harden permission-sensitive runtime tests so restricted environments do not produce misleading failures.
4. Build functional parity tests that compare `dnsmasq-rs` against the original dnsmasq binary under identical fixtures.

Module presence is not the same as parity. Passing unit tests are not the same as executable equivalence.

## Build And Test Reality

Useful commands:

```bash
cargo test -- --list
cargo test
cargo test --test dns_roundtrip
cargo test proptest
cargo build
cargo build --no-default-features
cargo check
```

Current state observed in this environment:

- `cargo test -- --list` reports about `1306` unit and integration tests plus the existing property-based suites.
- Full `cargo test` is not clean in this sandbox.
  Observed result: `1287` passed, `19` failed.
  Failure class: permission-sensitive socket or interface tests in `network`, `forward`, and `dhcp_common`.
- `cargo check --all-features` was not confirmed in this session because dependency unpacking hit a read-only cargo registry path in the sandbox.

Interpretation:

- Core logic coverage is already substantial.
- Runtime and environment-sensitive behavior still needs work.
- The repository does not yet have the upstream parity harness required to prove binary-equivalent behavior.

## Architecture Notes

Central state:

- `DaemonHandle = Arc<RwLock<Daemon>>` in `src/types/daemon.rs`

Important modules:

- `src/option.rs`
  Config parsing and application. This is one of the main parity blockers because many directives are still partial or stubbed.

- `src/dnsmasq.rs` and `src/main.rs`
  Startup, daemon control flow, signal handling, and reload path. Present, but simplified relative to upstream.

- `src/rfc1035.rs`, `src/cache.rs`, `src/forward.rs`
  Core DNS packet, cache, and forwarding logic. Broadly implemented with strong internal coverage, but still need parity validation.

- `src/rfc2131.rs`, `src/dhcp.rs`, `src/rfc3315.rs`, `src/dhcp6.rs`, `src/radv.rs`
  DHCPv4, DHCPv6, and RA behavior. Useful internal coverage exists, but config-driven and executable-level parity is still incomplete.

- `src/network.rs`, `src/dhcp_common.rs`
  Runtime socket and interface behavior. Important because current failures cluster here in restricted environments.

## Porting Rules

- Preserve observable upstream behavior first.
- Prefer safe Rust types and ownership-based design, but do not invent new semantics accidentally.
- Map C unions, pointers, and flags into reviewable Rust forms without losing wire-format or decision logic.
- Treat placeholder acceptance of config directives as a bug, not a convenience.
- Keep unsupported behavior explicit in docs and TODOs.

## Testing Strategy

This project needs three layers of confidence.

### 1. Unit Tests

Use for deterministic logic:

- parsers
- state transitions
- cache operations
- packet construction
- config application

### 2. Property-Based Tests

Use for:

- parser panic-freedom
- protocol roundtrips
- invariant preservation
- replacement and expiry behavior in stateful structures

### 3. Functional Parity Tests

This layer is still missing and must be built.

Required shape:

- launch upstream dnsmasq and `dnsmasq-rs` with the same fixture inputs
- use isolated temp directories and test-specific ports
- drive both binaries with the same DNS and DHCP requests
- compare normalized behavior, not brittle log formatting

Required parity areas:

- DNS forwarding and reply semantics
- cache behavior and expiry
- config acceptance and rejection
- DHCPv4 exchanges
- DHCPv6 and RA behavior for supported scenarios
- local data, filtering, and rebind protections
- SIGHUP reload and related runtime state changes

## Guidance For Contributors

When implementing new work:

- Start from upstream behavior, not from line-count completion goals.
- Add tests in the same change.
- Add a regression test for every bug found.
- Keep capability-dependent tests distinct from pure logic tests.
- Update `tasks.md` when a blocker is resolved or re-scoped.

When reviewing:

- Check for semantic drift against upstream.
- Check that docs do not overclaim completion.
- Check that externally visible behavior is either tested or still tracked as incomplete.

## Files To Treat As Read-Only References

- `original_dnsmasq_src/`
- `old/`

Do not edit those trees as part of the Rust implementation.
