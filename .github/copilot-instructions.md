# dnsmasq-rs Copilot Instructions

## Project Overview

This is an in-progress port of [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html) (a C DNS forwarder + DHCP server, ~47k lines across 42 files) to idiomatic, async-safe Rust. The original C source lives in `original_dnsmasq_src/dnsmasq-master/src/` for reference. Skeleton/partial files from a prior attempt live in `old/` — evaluate each one before reusing.

## Build & Test Commands

```bash
# Build with default features
cargo build

# Build with all features
cargo build --all-features

# Build with no default features
cargo build --no-default-features

# Run all tests
cargo test

# Run a single test by name (substring match)
cargo test <test_name>

# Run a specific integration test file
cargo test --test cache_integration
cargo test --test dns_roundtrip
cargo test --test config_integration

# Run proptest-based tests
cargo test proptest

# Feature-gated check
cargo check --all-features
cargo check --no-default-features
```

Logging is controlled via `RUST_LOG` (e.g. `RUST_LOG=debug cargo run`).

## Architecture

### Central State: `Daemon`

`src/types/daemon.rs` holds the `Daemon` struct — a direct port of C's global `struct daemon` from `dnsmasq.h`. It is the single source of truth for all runtime configuration and state. It is always accessed through a `DaemonHandle`:

```rust
pub type DaemonHandle = Arc<RwLock<Daemon>>;
```

All async tasks receive a clone of `DaemonHandle`. Never store a raw `Daemon` — always go through the handle.

### Module Layout

| Path | Purpose |
|---|---|
| `src/types/` | All major structs/enums ported from `dnsmasq.h` (daemon, addr, cache, dhcp, server, network, dns_records, constants) |
| `src/dns_protocol/` | DNS wire-format constants (opcodes, rcodes, RR types, flag bitmasks) |
| `src/dhcp_protocol/`, `src/dhcp6_protocol/`, `src/radv_protocol/` | Protocol constants for DHCP, DHCPv6, RA |
| `src/rfc1035.rs` | DNS packet parser/encoder — port of `rfc1035.c` |
| `src/cache.rs` | Bounded LRU DNS cache keyed by `(name, type-flags)` |
| `src/option.rs` | Config-file parser — port of `option.c` |
| `src/dnsmasq.rs` | Daemon init, privilege drop, daemonization, main loop |
| `src/forward.rs` | DNS query forwarding |
| `src/metrics/` | Metric index enum — port of `metrics.h` |
| `src/error.rs` | Central `DnsmasqError` (uses `thiserror`) |

### Feature Flags

All optional subsystems are gated behind Cargo features that mirror dnsmasq's compile-time `HAVE_*` defines. Default features: `dhcp dhcp6 dnssec auth tftp loop inotify dump bpf`. Feature-gated code uses `#[cfg(feature = "...")]` on both `mod` declarations in `lib.rs`/`main.rs` and inside modules.

| Cargo feature | Enables |
|---|---|
| `dhcp` | `dhcp`, `dhcp_common`, `rfc2131`, `lease`, `helper` |
| `dhcp6` | `dhcp6`, `rfc3315`, `radv`, `slaac` (implies `dhcp`) |
| `dnssec` | `crypto`, `dnssec` |
| `dbus` | `dbus` (pulls in `zbus`) |
| `bpf`, `conntrack`, `ipset`, `nftset`, `ubus`, `inotify`, `dump`, `tftp`, `auth`, `loop` | respective modules |

## Key Conventions

### Types: Rust idioms over C idioms

- C `union all_addr` → Rust `enum AllAddr`
- C null pointers → `Option<T>`
- C `struct crec` (cache record) → `CacheRecord` in `src/cache.rs`
- C raw sockets → `socket2` / `nix` / `tokio` abstractions

### Error Handling

All errors propagate as `DnsmasqError` (defined in `src/error.rs`). Module-local errors (e.g. `DnsError` in `rfc1035`, `ConfigError` in `option`) implement `From<_>` into `DnsmasqError`.

### Testing

- Unit tests live in `#[cfg(test)]` blocks inside each module.
- Integration tests live in `tests/` and import via `dnsmasq_rs::*`.
- Property-based tests use `proptest` (see `tests/proptest_*.rs` and `tests/proptest_cache.proptest-regressions` for regression corpus).

### Constants (F_* flags)

DNS record type and flag bits (e.g. `F_IPV4`, `F_NEG`, `F_DNSSEC`) are defined as `const u32` in `src/types/constants.rs`. Use `cache::type_flags(flags)` to extract only the type bits when constructing a `CacheKey`.

### Async

The tokio runtime is started in `main.rs`. All long-running tasks are spawned with `tokio::spawn`. Signal handling (SIGTERM, SIGHUP) uses `tokio::signal::unix`. **Daemonization must happen before the tokio runtime starts** (fork is not tokio-safe).
