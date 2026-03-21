# CLAUDE.md — dnsmasq-rs

## Project Overview

Rust port of [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html), a DNS forwarder and DHCP server. The original C source (~47k lines, 42 files) lives in `original_dnsmasq_src/dnsmasq-master/src/` for reference. Prior skeleton/partial files live in `old/` — evaluate before reusing.

## Build & Test

```bash
cargo build                          # default features
cargo build --all-features           # all features
cargo build --no-default-features    # minimal build
cargo test                           # all tests (760+ unit + integration)
cargo test <name>                    # run specific test by substring
cargo test --test dns_roundtrip      # specific integration test
cargo test proptest                  # property-based tests only
cargo check --all-features           # feature-gate validation
RUST_LOG=debug cargo run             # run with debug logging
```

**Known test issue:** `network::tests::make_sock_ipv6_creates_socket` fails in environments without IPv6 support — this is an environment limitation, not a code bug.

## Architecture

### Central State

`DaemonHandle = Arc<RwLock<Daemon>>` in `src/types/daemon.rs`. All async tasks receive a clone. Never store a raw `Daemon`.

### Module Map

| Module | C Source | LOC (Rust) | LOC (C) | Status |
|--------|----------|------------|---------|--------|
| `rfc1035.rs` | rfc1035.c | 2200 | 2400 | Complete |
| `cache.rs` | cache.c | 2298 | 2500 | Complete |
| `forward.rs` | forward.c | 2283 | 3319 | Mostly complete |
| `rfc2131.rs` | rfc2131.c | 1668 | 3265 | Partial (~51%) |
| `network.rs` | network.c | 1487 | 1812 | Mostly complete |
| `dhcp_common.rs` | dhcp-common.c | 1449 | 1081 | Complete |
| `netlink.rs` | netlink.c | 1144 | 414 | Complete (expanded) |
| `option.rs` | option.c | 1097 | 6322 | Partial (~17%) |
| `dnssec.rs` | dnssec.c | 997 | 2410 | Partial (~41%) |
| `domain_match.rs` | domain-match.c | 913 | 778 | Complete |
| `util.rs` | util.c | 781 | 1006 | Mostly complete |
| `rfc3315.rs` | rfc3315.c | 673 | 2348 | Partial (~29%) |
| `auth.rs` | auth.c | 654 | 915 | Partial (~71%) |
| `dump.rs` | dump.c | 513 | 303 | Complete (expanded) |
| `arp.rs` | arp.c | 498 | 240 | Complete (expanded) |
| `edns0.rs` | edns0.c | 482 | 574 | Mostly complete |
| `log.rs` | log.c | 416 | 494 | Mostly complete |
| `dnsmasq.rs` | dnsmasq.c | 363 | 2478 | Partial (~15%) |
| `outpacket.rs` | outpacket.c | 361 | 118 | Complete |
| `dhcp.rs` | dhcp.c | 336 | 1124 | Partial (~30%) |
| `crypto.rs` | crypto.c | 316 | 504 | Partial (~63%) |
| `lease.rs` | lease.c | 313 | 1346 | Partial (~23%) |
| `dhcp6.rs` | dhcp6.c | 294 | 881 | Partial (~33%) |
| `rrfilter.rs` | rrfilter.c | 287 | 413 | Mostly complete |
| `pattern.rs` | pattern.c | 283 | 386 | Mostly complete |
| `radv.rs` | radv.c | 271 | 1039 | Partial (~26%) |
| `poll.rs` | poll.c | 259 | 118 | Complete (expanded) |
| `tftp.rs` | tftp.c | 232 | 1040 | Partial (~22%) |
| `helper.rs` | helper.c | 220 | 948 | Partial (~23%) |
| `loop_detect.rs` | loop.c | 212 | 113 | Complete |
| `ipset.rs` | ipset.c | 209 | 216 | Mostly complete |
| `conntrack.rs` | conntrack.c | 199 | 85 | Complete (expanded) |
| `domain.rs` | domain.c | 184 | 301 | Partial (~61%) |
| `blockdata.rs` | blockdata.c | 149 | 241 | Complete |
| `slaac.rs` | slaac.c | 151 | 213 | Mostly complete |
| `ubus.rs` | ubus.c | 142 | 391 | Partial (~36%) |
| `inotify.rs` | inotify.c | 142 | 372 | Partial (~38%) |
| `nftset.rs` | nftset.c | 140 | 100 | Complete |
| `bpf.rs` | bpf.c | 135 | 440 | Partial (~31%) |
| `dbus.rs` | dbus.c | 101 | 1106 | Partial (~9%) |
| `tables.rs` | tables.c | 95 | 144 | Mostly complete |
| `metrics/` | metrics.c/h | 128 | 128 | Complete |

### Porting Priority (files needing most work)

1. **option.rs** — Config parser is only ~17% ported (1097 vs 6322 LOC). Critical for full functionality.
2. **dnsmasq.rs** — Main daemon logic only ~15% ported (363 vs 2478 LOC). Event loop is skeletal.
3. **rfc2131.rs** — DHCP server ~51% ported. Missing many option handlers.
4. **rfc3315.rs** — DHCPv6 ~29% ported.
5. **radv.rs** — Router advertisements ~26% ported.
6. **lease.rs** — Lease management ~23% ported.
7. **helper.rs** — DHCP script helper ~23% ported.
8. **tftp.rs** — TFTP server ~22% ported.
9. **dbus.rs** — D-Bus integration ~9% ported.
10. **dnssec.rs** — DNSSEC validation ~41% ported.

### Type System

| Path | Purpose |
|------|---------|
| `src/types/daemon.rs` | Central `Daemon` struct (port of C global state) |
| `src/types/addr.rs` | `AllAddr`, `MySockAddr` etc. |
| `src/types/constants.rs` | F_* flags, option bits |
| `src/types/cache.rs` | Cache record types |
| `src/types/dns_records.rs` | MX, SRV, TXT, CNAME record types |
| `src/types/server.rs` | Upstream server config |
| `src/types/network.rs` | Network interface types |
| `src/types/dhcp.rs` | DHCP types (feature `dhcp`) |

### Protocol Constants

| Path | Source Header |
|------|--------------|
| `src/dns_protocol/mod.rs` | dns-protocol.h |
| `src/dhcp_protocol/mod.rs` | dhcp-protocol.h |
| `src/dhcp6_protocol/mod.rs` | dhcp6-protocol.h |
| `src/radv_protocol/mod.rs` | radv-protocol.h |

### Feature Flags

Default: `dhcp dhcp6 dnssec auth tftp loop inotify dump bpf`
Optional: `conntrack dbus ubus ipset nftset`

Feature-gated code uses `#[cfg(feature = "...")]` on mod declarations and implementations.

## Conventions

- **Types:** C unions → Rust enums, null pointers → `Option<T>`, raw sockets → `socket2`/`nix`/`tokio`
- **Errors:** Central `DnsmasqError` (thiserror). Module-local errors implement `From` into `DnsmasqError`.
- **Testing:** Unit tests in `#[cfg(test)]` blocks. Integration tests in `tests/`. Property tests via `proptest`.
- **Constants:** F_* flags are `const u32` in `types/constants.rs`. Use `cache::type_flags()` for type bits.
- **Async:** tokio runtime started in `main.rs`. Signal handling via `tokio::signal::unix`. Daemonization must precede tokio start (fork safety).
- **Naming:** Rust snake_case. Module names match C file names with `-` → `_` (e.g., `dhcp-common.c` → `dhcp_common.rs`).

## Test Coverage Summary

| Module | Tests | Notes |
|--------|-------|-------|
| cache.rs | 71 | Excellent — LRU, TTL, eviction, flags |
| forward.rs | 54 | Good — forwarding, retry, TCP fallback |
| dhcp_common.rs | 53 | Good — DHCP utilities |
| rfc2131.rs | 48 | Good — DHCP protocol |
| rfc1035.rs | 47 | Good — DNS parser/encoder |
| network.rs | 41 | Good (1 env-dependent failure) |
| option.rs | 32 | Moderate — config parsing |
| dnssec.rs | 29 | Good — validation logic |
| domain_match.rs | 26 | Good |
| util.rs | 24 | Good |
| rfc3315.rs | 24 | Good — DHCPv6 |
| crypto.rs | 19 | Good — RSA, ECDSA, Ed25519 parsing + verification |
| domain.rs | 18 | Good — range checks, synthesis |
| lease.rs | 14 | Good — CRUD, serialization, error paths |
| pattern.rs | 14 | Good |
| netlink.rs | 14 | Good |
| arp.rs | 14 | Good |
| edns0.rs | 13 | Good |
| blockdata.rs | 11 | Good — alloc, stats, IO |
| Integration tests | 6 files | proptest, roundtrip, cache, config |

## Files Not to Modify

- `original_dnsmasq_src/` — Reference C source (read-only)
- `old/` — Prior attempt skeletons (read-only reference)

## Key Dependencies

- **Runtime:** tokio (full)
- **CLI:** clap (derive)
- **Errors:** thiserror
- **Logging:** tracing, tracing-subscriber
- **Network:** nix 0.29, socket2, if-addrs, libc, caps
- **Crypto:** ring, rsa 0.9, sha2, p256, p384, ed25519-dalek
- **Collections:** bytes, lru 0.12
- **Testing:** proptest, tempfile
- **Optional:** zbus (D-Bus, feature `dbus`)
