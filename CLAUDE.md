# CLAUDE.md — dnsmasq-rs

## Project Overview

Rust port of [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html), a DNS forwarder and DHCP server. The original C source (~47k lines, 42 files) lives in `original_dnsmasq_src/dnsmasq-master/src/` for reference. Prior skeleton/partial files live in `old/` — evaluate before reusing.

## Build & Test

```bash
cargo build                          # default features
cargo build --all-features           # all features
cargo build --no-default-features    # minimal build
cargo test                           # all tests (1165+ unit + integration)
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
| `rfc2131.rs` | rfc2131.c | 2019 | 3265 | Partial (~62%) |
| `network.rs` | network.c | 1487 | 1812 | Mostly complete |
| `dhcp_common.rs` | dhcp-common.c | 1449 | 1081 | Complete |
| `netlink.rs` | netlink.c | 1144 | 414 | Complete (expanded) |
| `lease.rs` | lease.c | 1238 | 1346 | Mostly complete |
| `option.rs` | option.c | 1433 | 6322 | Partial (~23%) |
| `dnssec.rs` | dnssec.c | 1352 | 2410 | Partial (~56%) |
| `domain_match.rs` | domain-match.c | 913 | 778 | Complete |
| `dnsmasq.rs` | dnsmasq.c | 863 | 2478 | Partial (~35%) |
| `util.rs` | util.c | 781 | 1006 | Mostly complete |
| `rfc3315.rs` | rfc3315.c | 1195 | 2348 | Partial (~51%) |
| `auth.rs` | auth.c | 862 | 915 | Mostly complete |
| `tftp.rs` | tftp.c | 1017 | 1040 | Mostly complete |
| `radv.rs` | radv.c | 786 | 1039 | Mostly complete |
| `dump.rs` | dump.c | 513 | 303 | Complete (expanded) |
| `helper.rs` | helper.c | 803 | 948 | Mostly complete |
| `arp.rs` | arp.c | 498 | 240 | Complete (expanded) |
| `edns0.rs` | edns0.c | 664 | 574 | Complete (expanded) |
| `log.rs` | log.c | 416 | 494 | Mostly complete |
| `outpacket.rs` | outpacket.c | 361 | 118 | Complete |
| `dhcp.rs` | dhcp.c | 744 | 1124 | Partial (~66%) |
| `crypto.rs` | crypto.c | 625 | 504 | Complete (expanded) |
| `dhcp6.rs` | dhcp6.c | 530 | 881 | Partial (~60%) |
| `rrfilter.rs` | rrfilter.c | 287 | 413 | Mostly complete |
| `pattern.rs` | pattern.c | 283 | 386 | Mostly complete |
| `poll.rs` | poll.c | 259 | 118 | Complete (expanded) |
| `loop_detect.rs` | loop.c | 212 | 113 | Complete |
| `ipset.rs` | ipset.c | 209 | 216 | Mostly complete |
| `conntrack.rs` | conntrack.c | 199 | 85 | Complete (expanded) |
| `domain.rs` | domain.c | 614 | 301 | Complete (expanded) |
| `blockdata.rs` | blockdata.c | 149 | 241 | Complete |
| `slaac.rs` | slaac.c | 365 | 213 | Complete (expanded) |
| `ubus.rs` | ubus.c | 142 | 391 | Partial (~36%) |
| `inotify.rs` | inotify.c | 142 | 372 | Partial (~38%) |
| `nftset.rs` | nftset.c | 140 | 100 | Complete |
| `bpf.rs` | bpf.c | 135 | 440 | Partial (~31%) |
| `dbus.rs` | dbus.c | 101 | 1106 | Partial (~9%) |
| `tables.rs` | tables.c | 95 | 144 | Mostly complete |
| `metrics/` | metrics.c/h | 128 | 128 | Complete |

### Porting Priority (files needing most work)

1. **option.rs** — Config parser ~23% ported (1433 vs 6322 LOC). Critical for full functionality.
2. **dnsmasq.rs** — Main daemon logic ~35% ported (863 vs 2478 LOC). Event system and resolv monitor added.
3. **rfc2131.rs** — DHCP server ~62% ported. Missing some option handlers.
4. **rfc3315.rs** — DHCPv6 ~51% ported.
5. **dnssec.rs** — DNSSEC validation ~56% ported.
6. **dhcp.rs** — DHCP listener ~66% ported.
7. **dhcp6.rs** — DHCPv6 listener ~60% ported.
8. **dbus.rs** — D-Bus integration ~9% ported.
9. **bpf.rs** — BPF support ~31% ported.
10. **ubus.rs** — uBus integration ~36% ported.

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
| lease.rs | 60 | Excellent — allocate, expire, hwaddr, hostname, file I/O |
| forward.rs | 54 | Good — forwarding, retry, TCP fallback |
| dhcp_common.rs | 53 | Good — DHCP utilities |
| rfc2131.rs | 48 | Good — DHCP protocol |
| rfc1035.rs | 47 | Good — DNS parser/encoder |
| network.rs | 41 | Good (1 env-dependent failure) |
| tftp.rs | 36 | Good — packet ops, transfer state, sanitization, options |
| option.rs | 32 | Moderate — config parsing |
| dnssec.rs | 29 | Good — validation logic |
| domain_match.rs | 26 | Good |
| util.rs | 24 | Good |
| rfc3315.rs | 42 | Good — DHCPv6, IA helpers, lifetime calc, status codes |
| helper.rs | 24 | Good — script exec, format, queue, roundtrip |
| dnsmasq.rs | 22 | Good — event system, resolv monitor, ICMP pinger |
| domain.rs | 21 | Good — range checks, synthesis, IPv6 helpers |
| radv.rs | 20 | Good — RA scheduling, priority, interval calc |
| crypto.rs | 20 | Good — RSA, ECDSA, Ed25519 parsing + verification |
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
