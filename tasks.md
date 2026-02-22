# dnsmasq-rs: Rust Porting Tasks

## Overview

Port [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html) from C to idiomatic, safe, async-ready Rust.

- **Source:** `original_dnsmasq_src/dnsmasq-master/src/` (42 C files, ~47k lines)
- **Existing stubs:** `old/` (~100 Rust files, partial/skeleton quality — evaluate each module)
- **Style:** Idiomatic Rust, `async`/`await` via **tokio**, safe abstractions over raw sockets
- **Features:** All optional features gated behind **Cargo features** mirroring dnsmasq's compile-time options
- **Testing:** Unit tests (`#[test]`) + property-based tests (**proptest**) per module

---

## Cargo Features (mirrors dnsmasq compile-time options)

| Cargo Feature | dnsmasq equivalent |
|---|---|
| `dnssec` | `HAVE_DNSSEC` |
| `dhcp` | `HAVE_DHCP` |
| `dhcp6` | `HAVE_DHCP6` |
| `tftp` | `HAVE_TFTP` |
| `dbus` | `HAVE_DBUS` |
| `ubus` | `HAVE_UBUS` |
| `ipset` | `HAVE_IPSET` |
| `nftset` | `HAVE_NFTSET` |
| `conntrack` | `HAVE_CONNTRACK` |
| `auth` | `HAVE_AUTH` |
| `loop` | `HAVE_LOOP` |
| `inotify` | `HAVE_INOTIFY` |
| `dump` | `HAVE_DUMP` |
| `bpf` | `HAVE_BPF` |

---

## Phased Execution Plan

### Phase 1 — Project Scaffold & Central Types

**Goal:** Establish a compilable skeleton with all types, feature flags, and the Cargo workspace.

---

#### Task 1.1 — `Cargo.toml`: Add dependencies and feature flags

- Add `tokio` (full features), `proptest`, `thiserror`, `tracing`, `tracing-subscriber`
- Add optional deps: `dbus` crate (feature `dbus`), `zbus` or `dbus` for D-Bus
- Declare all Cargo features listed above
- Gate optional deps under their respective features
- **old/ status:** `Cargo.toml` needs updating (current deps: only `libc`, `pnet`)
- **Tests:** Verify `cargo check --all-features` passes; verify `cargo check --no-default-features` passes

---

#### Task 1.2 — `src/types/` module: Port `dnsmasq.h` (1971 lines)

The central header defines all major structs, enums, and constants used everywhere.

**Subtasks:**
- 1.2.1 Port all `#define` constants → Rust `const` / `enum` in `src/types/constants.rs`
- 1.2.2 Port `struct daemon` (the global state bag) → `src/types/daemon.rs` as an `Arc<Mutex<Daemon>>` or tokio `RwLock`
- 1.2.3 Port address types: `union all_addr`, `struct my_addr6`, `struct mysockaddr` → `src/types/addr.rs` using Rust enums
- 1.2.4 Port cache record types: `struct crec`, `struct bigname` → `src/types/cache.rs`
- 1.2.5 Port server/resolver types: `struct server`, `struct resolvc`, `struct frec` → `src/types/server.rs`
- 1.2.6 Port DHCP types: `struct dhcp_lease`, `struct dhcp_opt`, `struct dhcp_netid`, etc. → `src/types/dhcp.rs` (gated `#[cfg(feature = "dhcp")]`)
- 1.2.7 Port DNS record types: `struct crec`, `struct mx_srv_record`, `struct txt_record`, `struct naptr`, etc. → `src/types/dns_records.rs`
- 1.2.8 Port interface/network types: `struct irec`, `struct iname`, `struct listener` → `src/types/network.rs`
- 1.2.9 Port remaining types: `struct auth_zone`, `struct ds_config`, `struct ra_interface`, etc.
- 1.2.10 Re-export all types from `src/types/mod.rs`
- **old/ status:** `old/` has many individual struct files (daemon.rs, crec.rs, frec.rs, all_addr.rs, etc.) — good reference but need full replacement with idiomatic Rust (enums instead of unions, `Option<>` instead of null pointers, etc.)
- **Tests:** Smoke-compile all type definitions; test `Default` and `Clone` derives

---

#### Task 1.3 — Protocol constant modules (headers → Rust)

Port the protocol header files to standalone modules:

- 1.3.1 `dns-protocol.h` (194 lines) → `src/dns_protocol/mod.rs`
  - DNS opcode/rcode enums, record type constants, flag bitmasks
  - **old/:** `old/dns_protocol.rs` is a good start
- 1.3.2 `dhcp-protocol.h` (110 lines) → `src/dhcp_protocol/mod.rs` (feature `dhcp`)
  - DHCP option numbers, message types, BOOTP constants
  - **old/:** `old/dhcp_protocol.rs` — partial
- 1.3.3 `dhcp6-protocol.h` (77 lines) → `src/dhcp6_protocol/mod.rs` (feature `dhcp6`)
  - DHCPv6 option/message type constants
  - **old/:** `old/dhcp6_protocol.rs` — partial
- 1.3.4 `radv-protocol.h` (55 lines) → `src/radv_protocol/mod.rs` (feature `dhcp6`)
  - Router Advertisement ICMPv6 constants
  - **old/:** `old/radv_protocol.rs` — partial
- 1.3.5 `ip6addr.h` (33 lines) → `src/types/ip6addr.rs`
  - `union in6_addr` helpers → wrapper around `std::net::Ipv6Addr`
  - **old/:** `old/ip6addr.rs` — trivial, port directly
- 1.3.6 `metrics.h` (54 lines) → `src/metrics/mod.rs`
  - Metric index enum → `src/metrics/mod.rs`
  - **old/:** `old/metrics.rs` — partial
- **Tests:** All constants match original values; enums are exhaustive

---

### Phase 2 — Core Utilities

---

#### Task 2.1 — `src/util.rs`: Port `util.c` (1006 lines)

General utility functions used across all modules.

**Subtasks:**
- 2.1.1 Safe string helpers: `safe_strncpy`, `hostname_isequal` → Rust `str` / `String` equivalents
- 2.1.2 `rand_init()`, `rand16()` → use `rand` crate
- 2.1.3 Address utilities: `is_same_net`, `is_same_net6`, `addr_diff`, `addr_diff6`
- 2.1.4 `prettyprint_time`, `prettyprint_addr` → `Display` impls on address/time wrappers
- 2.1.5 `retry_send` → async `tokio::io` retry helper
- 2.1.6 `eat_whitespace`, `split_chr`, `split` → string parsing helpers
- 2.1.7 `whine_malloc`, `safe_malloc` → replace with standard `Vec`/`Box` (panics or `Result`)
- **old/:** `old/util.rs` (303 lines) — decent skeleton; needs async adaptation
- **Tests:**
  - Unit: test each string helper, address comparison function
  - Proptest: hostname parsing roundtrip; address arithmetic properties

---

#### Task 2.2 — `src/log.rs`: Port `log.c` (494 lines)

Logging subsystem.

**Subtasks:**
- 2.2.1 Replace `syslog`/`vsyslog` with `tracing` crate macros
- 2.2.2 `my_syslog` → `tracing::info!` / `warn!` / `error!` wrapper
- 2.2.3 Log file support → `tracing_subscriber` with file appender
- 2.2.4 Async-safe log flushing
- **old/:** `old/log.rs` (154 lines) — partial; needs replacing with `tracing`
- **Tests:** Unit: verify log levels route correctly; test log drain under concurrent writes

---

#### Task 2.3 — `src/blockdata.rs`: Port `blockdata.c` (241 lines)

Pooled block allocator for DNS RR data.

**Subtasks:**
- 2.3.1 Replace the C slab allocator with a `Vec<Box<[u8]>>` pool or `slab` crate
- 2.3.2 `blockdata_alloc`, `blockdata_free` → Rust-safe API returning `BlockRef`
- 2.3.3 `blockdata_expand`, `blockdata_write`, `blockdata_retrieve`
- **old/:** `old/blockdata.rs` (212 lines) — skeleton with `unimplemented!()`
- **Tests:**
  - Unit: alloc/free roundtrip, expand boundary
  - Proptest: arbitrary sequences of alloc/free don't corrupt pool

---

#### Task 2.4 — `src/poll.rs`: Port `poll.c` (118 lines)

Fd-based poll abstraction.

**Subtasks:**
- 2.4.1 Replace with `tokio::select!` / `tokio::io::Interest` abstractions
- 2.4.2 `poll_reset`, `poll_listen`, `poll_check` → async-aware wrappers
- **old/:** `old/poll.rs` — skeleton
- **Tests:** Unit: register/deregister fds; verify readiness detection

---

#### Task 2.5 — `src/outpacket.rs`: Port `outpacket.c` (118 lines)

Dynamic outgoing packet buffer.

**Subtasks:**
- 2.5.1 `expand_buf` → `bytes::BytesMut` or `Vec<u8>` with capacity management
- 2.5.2 `new_outpacket`, `free_outpacket` lifecycle → RAII struct
- **old/:** `old/outpacket.rs` — skeleton
- **Tests:** Unit: write/read roundtrip; capacity growth

---

### Phase 3 — DNS Core

---

#### Task 3.1 — `src/rfc1035.rs`: Port `rfc1035.c` (2400 lines)

DNS packet parsing and construction.

**Subtasks:**
- 3.1.1 DNS header parsing → `DnsHeader` struct with bitfield methods
- 3.1.2 Name compression/decompression: `extract_name`, `compress_name`
- 3.1.3 Question/answer/authority/additional section parsing
- 3.1.4 RR-type specific parsing: A, AAAA, CNAME, MX, SRV, TXT, PTR, SOA, NS, etc.
- 3.1.5 Packet builder: `setup_reply`, `add_resource_record`
- 3.1.6 `resize_packet` → safe `bytes::BytesMut` operation
- 3.1.7 TCP DNS framing (2-byte length prefix)
- **old/:** `old/rfc1035.rs` (230 lines) — very partial
- **Tests:**
  - Unit: parse known-good wire-format packets (A, AAAA, CNAME, MX, PTR, SOA)
  - Unit: encode/decode roundtrip for each RR type
  - Proptest: random valid names survive compress/decompress roundtrip; truncated input does not panic

---

#### Task 3.2 — `src/cache.rs`: Port `cache.c` (2500 lines)

DNS cache implementation.

**Subtasks:**
- 3.2.1 Cache data structure: replace the C linked-list hash table with `HashMap` + LRU eviction (`lru` crate or manual)
- 3.2.2 `cache_init`, `cache_reload` → async-safe initialization
- 3.2.3 `cache_insert`, `cache_find_by_name`, `cache_find_by_addr`
- 3.2.4 Negative caching (NXDOMAIN, NODATA)
- 3.2.5 TTL tracking and expiry (`tokio::time::Instant`)
- 3.2.6 CNAME chain resolution
- 3.2.7 DNSSEC validation records in cache (feature `dnssec`)
- 3.2.8 `dump_cache` → `Display` impl or tracing event
- **old/:** `old/cache.rs` (168 lines) — data structures only, no logic
- **Tests:**
  - Unit: insert/lookup, TTL expiry, CNAME chains, negative cache
  - Proptest: concurrent insert/lookup doesn't corrupt state; LRU eviction is correct

---

#### Task 3.3 — `src/forward.rs`: Port `forward.c` (3319 lines)

DNS query forwarding engine.

**Subtasks:**
- 3.3.1 `get_new_frec` — pending query tracking with tokio tasks
- 3.3.2 `lookup_frec` — query deduplication
- 3.3.3 UDP forward path: `forward_query` → async UDP send on tokio UdpSocket
- 3.3.4 TCP forward path: `tcp_request` → async TCP with `tokio::net::TcpStream`
- 3.3.5 Reply handling: `reply_query` — match replies to pending queries
- 3.3.6 Retry/fallback: upstream server rotation, SERVFAIL handling
- 3.3.7 EDNS0 probe and subnet option handling
- 3.3.8 DNSSEC forwarding (feature `dnssec`)
- 3.3.9 `check_for_bogus_wildcard`, `check_for_ignored_address`
- **old/:** `old/forward.rs` — skeleton with `unimplemented!()`
- **Tests:**
  - Unit: frec allocation/lookup/free lifecycle
  - Unit: reply matching (correct/incorrect transaction ID)
  - Proptest: server rotation with arbitrary failure patterns

---

#### Task 3.4 — `src/edns0.rs`: Port `edns0.c` (574 lines)

EDNS0 option processing.

**Subtasks:**
- 3.4.1 `add_pseudoheader` — append/update OPT record
- 3.4.2 `find_pseudoheader` — locate OPT RR in packet
- 3.4.3 `check_source_subnet` — client subnet option (ECS, RFC 7871)
- 3.4.4 `add_source_addr` — ECS option insertion
- **old/:** `old/edns0.rs` (221 lines) — decent skeleton
- **Tests:**
  - Unit: OPT record round-trip; ECS option parsing
  - Proptest: arbitrary packet input doesn't panic in find_pseudoheader

---

#### Task 3.5 — `src/rrfilter.rs`: Port `rrfilter.c` (413 lines)

Filter/strip DNS resource records.

**Subtasks:**
- 3.5.1 `rrfilter` — strip unwanted RR types from answer
- 3.5.2 `expand_workspace` — safe buffer management
- **old/:** `old/rrfilter.rs` (236 lines) — reasonable start
- **Tests:**
  - Unit: known packet before/after filter
  - Proptest: filter is idempotent; filtered packet is valid DNS

---

#### Task 3.6 — `src/loop_detect.rs`: Port `loop.c` (113 lines) (feature `loop`)

DNS loop detection.

**Subtasks:**
- 3.6.1 `detect_loop` — send probe queries to detect routing loops
- 3.6.2 `loop_send_probes`, `loop_check` — periodic probe management with `tokio::time`
- **old/:** `old/loop_impl.rs` (196 lines) — partial
- **Tests:** Unit: probe sent/received logic; loop detected → correct state change

---

#### Task 3.7 — `src/domain.rs` + `src/domain_match.rs`: Port `domain.c` (301 lines) + `domain-match.c` (778 lines)

Domain name handling and matching.

**Subtasks:**
- 3.7.1 `domain.c`: `is_name_synthesized`, `add_update_server`, `next_server` → domain utility fns
- 3.7.2 `domain-match.c`: `domain_in_list` — match domain against config list
- 3.7.3 `largest_domain`, `min_ttl_for_cache` — helper fns
- 3.7.4 `server_for_query` — select upstream server for a query name
- **old/:** `old/domain.rs`, `old/domain_match.rs` (155 lines) — partial
- **Tests:**
  - Unit: exact/wildcard/subdomain matching
  - Proptest: arbitrary domain names classified correctly

---

#### Task 3.8 — `src/hash_questions.rs`: Port implied query hashing

(Extracted from `forward.c`/`dnsmasq.h`)

- 3.8.1 `hash_questions` — hash DNS question section for deduplication
- **old/:** `old/hash_questions.rs` (153 lines) — partial
- **Tests:** Unit: same question → same hash; different question → different hash (collision test)

---

### Phase 4 — DNSSEC (feature `dnssec`)

---

#### Task 4.1 — `src/crypto.rs`: Port `crypto.c` (504 lines)

Low-level crypto for DNSSEC.

**Subtasks:**
- 4.1.1 Replace OpenSSL/nettle C calls with `ring` or `rustls-native-certs` + `p256`/`ed25519` crates
- 4.1.2 RSA signature verification → `rsa` crate
- 4.1.3 ECDSA (P-256, P-384) → `p256`/`p384` crates
- 4.1.4 Ed25519 → `ed25519-dalek` crate
- 4.1.5 `dnsmasq_random_seed` → `rand::thread_rng()`
- **old/:** `old/crypto.rs` — skeleton
- **Tests:**
  - Unit: verify known-good DNSSEC signatures
  - Unit: reject tampered signatures

---

#### Task 4.2 — `src/dnssec.rs`: Port `dnssec.c` (2410 lines)

DNSSEC validation logic.

**Subtasks:**
- 4.2.1 `dnssec_validate_reply` — validate RRSIGs in a DNS reply
- 4.2.2 NSEC/NSEC3 negative proof validation
- 4.2.3 DS/DNSKEY chain of trust verification
- 4.2.4 `check_dnssec_valid` — classify replies as secure/insecure/bogus
- 4.2.5 Trust anchor management (`trust-anchors.conf` parsing)
- **old/:** `old/dnssec.rs` — skeleton
- **Tests:**
  - Unit: validate replies from known-signed zones (use `dig` captures)
  - Unit: bogus RRSIG rejected; NSEC proof tested
  - Proptest: fuzzed NSEC3 proofs don't panic

---

### Phase 5 — DHCP (feature `dhcp`)

---

#### Task 5.1 — `src/dhcp_common.rs`: Port `dhcp-common.c` (1081 lines)

Shared DHCPv4/v6 utilities.

**Subtasks:**
- 5.1.1 `get_client_mac`, `match_netid`
- 5.1.2 DHCP option string parsing helpers
- 5.1.3 `log_packet` — structured log of DHCP packets
- 5.1.4 Vendor class / client identifier handling
- **old/:** `old/dhcp_common.rs` — partial
- **Tests:** Unit: netid matching; option string parsing

---

#### Task 5.2 — `src/dhcp.rs`: Port `dhcp.c` (1124 lines)

DHCPv4 request dispatch.

**Subtasks:**
- 5.2.1 Async receive loop on `tokio::net::UdpSocket`
- 5.2.2 `dhcp_packet` — demux incoming DHCP packets
- 5.2.3 `send_packet` → async UDP send
- 5.2.4 Relay agent detection and forwarding
- **old/:** `old/dhcp.rs` — partial
- **Tests:** Unit: packet demux by message type; relay detection

---

#### Task 5.3 — `src/rfc2131.rs`: Port `rfc2131.c` (3265 lines)

DHCPv4 protocol state machine.

**Subtasks:**
- 5.3.1 `dhcp_reply` — full DISCOVER/OFFER/REQUEST/ACK/NAK state machine
- 5.3.2 Option construction: `option_put`, `option_put_string`, `option_find`
- 5.3.3 Address allocation: match host reservations, find free address in range
- 5.3.4 `do_options` — build complete DHCP reply options
- 5.3.5 PXE boot support
- **old/:** `old/rfc2131.rs` (236 lines) — skeleton
- **Tests:**
  - Unit: DISCOVER → OFFER roundtrip with known options
  - Unit: host reservation honoured; pool exhaustion returns NAK
  - Proptest: arbitrary option sequences parse without panic

---

#### Task 5.4 — `src/lease.rs`: Port `lease.c` (1346 lines)

DHCP lease database.

**Subtasks:**
- 5.4.1 Replace file-backed lease storage with async `tokio::fs` writes
- 5.4.2 `lease_init`, `lease_update_file` — async lease file I/O
- 5.4.3 `lease_find_by_addr`, `lease_find_by_client`
- 5.4.4 `lease_prune` — expire old leases with `tokio::time`
- 5.4.5 `lease_set_*` — update lease fields
- **old/:** `old/lease.rs` — partial
- **Tests:**
  - Unit: add/renew/expire lease lifecycle
  - Unit: lease file write/reload roundtrip

---

#### Task 5.5 — `src/helper.rs`: Port `helper.c` (948 lines)

Helper process (privilege separation for lease scripts).

**Subtasks:**
- 5.5.1 `fork()` → `tokio::process::Command` for lease-change script execution
- 5.5.2 Unix socket IPC between main process and helper
- 5.5.3 `queue_script` / `run_scripts_child` → async task queue
- **old/:** `old/helper.rs` (174 lines) — partial
- **Tests:** Unit: message serialization/deserialization; script invocation mock

---

### Phase 6 — DHCPv6, SLAAC, Router Advertisement (feature `dhcp6`)

---

#### Task 6.1 — `src/dhcp6.rs`: Port `dhcp6.c` (881 lines)

DHCPv6 server/relay dispatch.

**Subtasks:**
- 6.1.1 Async ICMPv6/UDP receive on `tokio` socket
- 6.1.2 `dhcp6_packet` — demux by message type
- 6.1.3 Relay agent support
- **old/:** `old/dhcp6.rs` — partial

---

#### Task 6.2 — `src/rfc3315.rs`: Port `rfc3315.c` (2348 lines)

DHCPv6 protocol state machine.

**Subtasks:**
- 6.2.1 Solicit/Advertise/Request/Reply/Renew/Rebind/Release/Decline
- 6.2.2 IA_NA, IA_TA, IA_PD option handling
- 6.2.3 `do_options6` — build DHCPv6 reply options
- 6.2.4 Prefix delegation
- **old/:** `old/rfc3315.rs` (240 lines) — skeleton
- **Tests:**
  - Unit: Solicit → Advertise → Request → Reply roundtrip
  - Unit: prefix delegation option handling

---

#### Task 6.3 — `src/radv.rs`: Port `radv.c` (1039 lines)

IPv6 Router Advertisement daemon.

**Subtasks:**
- 6.3.1 Send RAs via raw `tokio` socket or `socket2`
- 6.3.2 `send_ra`, `send_ra_alias` — periodic RA scheduling with `tokio::time`
- 6.3.3 Router Solicitation handling
- 6.3.4 RA option construction: prefix, MTU, RDNSS, DNSSL
- **old/:** `old/radv.rs` (158 lines) — partial

---

#### Task 6.4 — `src/slaac.rs`: Port `slaac.c` (213 lines)

SLAAC address tracking.

**Subtasks:**
- 6.4.1 `slaac_add_addrs` — synthesize SLAAC addresses for DHCP clients
- 6.4.2 Integration with lease database
- **old/:** `old/slaac.rs` (182 lines) — partial

---

### Phase 7 — Network & System Interface

---

#### Task 7.1 — `src/network.rs`: Port `network.c` (1812 lines)

Network interface management.

**Subtasks:**
- 7.1.1 `create_bound_listener` — `tokio::net::UdpSocket` bind per interface
- 7.1.2 `enumerate_interfaces` — use `if-addrs` crate
- 7.1.3 `join_multicast` → `socket2::Socket` multicast join
- 7.1.4 `create_tcp_listener` → `tokio::net::TcpListener`
- 7.1.5 Interface change detection → trigger `netlink` events
- 7.1.6 `iface_check` — match interfaces against config allow/deny lists
- **old/:** `old/network.rs` (197 lines) — partial

---

#### Task 7.2 — `src/netlink.rs`: Port `netlink.c` (414 lines) (Linux)

Linux netlink for interface/route change notifications.

**Subtasks:**
- 7.2.1 Open `NETLINK_ROUTE` socket → `tokio` async reader
- 7.2.2 `netlink_multicast_enabled` — subscribe to `RTMGRP_*` groups
- 7.2.3 Parse `RTM_NEWADDR`/`RTM_DELADDR`/`RTM_NEWROUTE` messages
- 7.2.4 Notify main loop of interface changes
- **old/:** `old/netlink.rs` (163 lines) — skeleton
- **Tests:** Unit: parse known netlink messages

---

#### Task 7.3 — `src/bpf.rs`: Port `bpf.c` (440 lines) (feature `bpf`)

BPF/packet filter for DHCP.

**Subtasks:**
- 7.3.1 `init_bpf` — attach BPF filter to raw socket
- 7.3.2 Build BPF programs with `bpf-sys` or `libbpf-rs` or raw `libc`
- 7.3.3 BPF filter for DHCP relay agent packets
- **old/:** `old/bpf.rs` (175 lines) — skeleton

---

#### Task 7.4 — `src/arp.rs`: Port `arp.c` (240 lines)

ARP table cache.

**Subtasks:**
- 7.4.1 `find_mac` — look up MAC address from ARP cache via netlink
- 7.4.2 `arp_inject` — inject ARP entry via socket
- 7.4.3 `update_arp_cache` — refresh ARP table
- **old/:** `old/arp.rs` (219 lines) — partial

---

#### Task 7.5 — `src/conntrack.rs`: Port `conntrack.c` (85 lines) (feature `conntrack`)

Linux conntrack integration.

**Subtasks:**
- 7.5.1 `set_mark` — set conntrack mark on forwarded packets
- **old/:** `old/conntrack.rs` — skeleton
- **Tests:** Unit: conntrack message construction

---

### Phase 8 — Configuration & Startup

---

#### Task 8.1 — `src/option.rs`: Port `option.c` (6322 lines)

Command-line and config-file option parsing — the largest file.

**Subtasks:**
- 8.1.1 Replace `getopt_long` with `clap` crate
- 8.1.2 Config file parser: line-by-line tokenizer → `Daemon` fields
- 8.1.3 All option handlers (one per `--option`) — map each to `Daemon` field setter
- 8.1.4 `read_opts` — dispatch between CLI args and config file directives
- 8.1.5 Address/subnet/range parsing helpers
- 8.1.6 DHCP option spec parsing (type codes, data formats)
- 8.1.7 Error reporting with line numbers
- **old/:** `old/option.rs` — partial
- **Tests:**
  - Unit: parse known-good config lines; verify each option
  - Unit: malformed config returns descriptive error
  - Proptest: fuzzed config input doesn't panic

---

#### Task 8.2 — `src/pattern.rs`: Port `pattern.c` (386 lines)

Wildcard/glob pattern matching for domain names.

**Subtasks:**
- 8.2.1 `wildcard_match` — `*` and `?` wildcard support
- **old/:** `old/pattern.rs` — partial
- **Tests:**
  - Unit: comprehensive match/no-match table
  - Proptest: matching is reflexive; non-matching patterns don't falsely match

---

#### Task 8.3 — `src/inotify.rs`: Port `inotify.c` (372 lines) (feature `inotify`)

`inotify` based config-file reload.

**Subtasks:**
- 8.3.1 Use `inotify` crate or `tokio` file watcher
- 8.3.2 Watch `/etc/resolv.conf` and config directories for changes
- 8.3.3 Trigger re-read on `IN_CLOSE_WRITE`/`IN_MOVED_TO`
- **old/:** `old/inotify.rs` — partial

---

### Phase 9 — Authoritative DNS (feature `auth`)

---

#### Task 9.1 — `src/auth.rs`: Port `auth.c` (915 lines)

Authoritative DNS server mode.

**Subtasks:**
- 9.1.1 `auth_request` — serve SOA/NS/A/AAAA/PTR from local zone data
- 9.1.2 Zone transfer (AXFR) handling
- 9.1.3 `answer_auth` — build authoritative replies
- 9.1.4 `in_zone` — check if name falls within a served zone
- **old/:** `old/auth.rs` (169 lines) — partial
- **Tests:**
  - Unit: SOA/NS/A queries answered from zone data
  - Unit: AXFR zone transfer content

---

### Phase 10 — Optional Integrations

---

#### Task 10.1 — `src/dbus.rs`: Port `dbus.c` (1106 lines) (feature `dbus`)

D-Bus interface for runtime control.

**Subtasks:**
- 10.1.1 Use `zbus` crate (async, idiomatic)
- 10.1.2 Implement `uk.org.thekelleys.dnsmasq` interface
- 10.1.3 Methods: `GetVersion`, `ClearCache`, `SetServers`, `SetDomainServers`
- 10.1.4 Signals: `DhcpLeaseAdded`, `DhcpLeaseDeleted`, `DhcpLeaseUpdated`
- **old/:** `old/dbus.rs` (228 lines) — partial with `libc`-style bindings; replace with `zbus`

---

#### Task 10.2 — `src/ubus.rs`: Port `ubus.c` (391 lines) (feature `ubus`)

ubus (OpenWrt) interface.

**Subtasks:**
- 10.2.1 Use `ubus` FFI or reimplement protocol over Unix socket
- 10.2.2 Register dnsmasq object and methods
- **old/:** `old/ubus.rs` (220 lines) — partial

---

#### Task 10.3 — `src/ipset.rs`: Port `ipset.c` (216 lines) (feature `ipset`)

Linux ipset integration.

**Subtasks:**
- 10.3.1 Netlink-based ipset protocol → add resolved addresses to ipsets
- **old/:** `old/ipset.rs` — skeleton

---

#### Task 10.4 — `src/nftset.rs`: Port `nftset.c` (100 lines) (feature `nftset`)

nftables named set integration.

**Subtasks:**
- 10.4.1 `nftset_init`, `add_to_nftset` — use `nftnl` crate or netlink directly
- **old/:** `old/nftset.rs` — skeleton

---

#### Task 10.5 — `src/tables.rs`: Port `tables.c` (144 lines) (BSD PF)

BSD PF table manipulation.

**Subtasks:**
- 10.5.1 `add_to_table`, `del_from_table` — `/dev/pf` ioctl calls
- **old/:** `old/tables.rs` (152 lines) — partial

---

#### Task 10.6 — `src/tftp.rs`: Port `tftp.c` (1040 lines) (feature `tftp`)

TFTP server.

**Subtasks:**
- 10.6.1 Async TFTP session state machine via `tokio::net::UdpSocket`
- 10.6.2 `handle_tftp` — RRQ/WRQ/DATA/ACK/ERROR
- 10.6.3 File serving with `tokio::fs::File`
- 10.6.4 Block size negotiation (OACK)
- **old/:** `old/tftp.rs` (160 lines) — skeleton

---

#### Task 10.7 — `src/dump.rs`: Port `dump.c` (303 lines) (feature `dump`)

Packet capture dump to pcap format.

**Subtasks:**
- 10.7.1 Write pcap file header and packet records
- 10.7.2 `dump_packet` → async `tokio::fs::File` write
- **old/:** `old/dump.rs` (167 lines) — partial

---

#### Task 10.8 — `src/metrics.rs`: Port `metrics.c` (74 lines)

Runtime counters/statistics.

**Subtasks:**
- 10.8.1 Replace global C array with `std::sync::atomic::AtomicU64` array or `prometheus` crate
- **old/:** `old/metrics.rs` — partial

---

### Phase 11 — Main Entry Point

---

#### Task 11.1 — `src/main.rs` + `src/dnsmasq.rs`: Port `dnsmasq.c` (2478 lines)

Daemon initialization, signal handling, and main event loop.

**Subtasks:**
- 11.1.1 `#[tokio::main]` entry point
- 11.1.2 Signal handling: `tokio::signal::unix::signal` for SIGHUP/SIGTERM/SIGALRM/SIGUSR1/SIGUSR2
- 11.1.3 Daemon mode: `nix::unistd::daemon` or manual `fork()`/`setsid()`
- 11.1.4 Main select/poll loop → `tokio::select!` over all active sockets
- 11.1.5 PID file management
- 11.1.6 Capability dropping (`caps` crate or `nix::sys::prctl`)
- 11.1.7 `cache_reload` on SIGHUP; `dump_cache` on SIGUSR1
- **old/:** `old/dnsmasq.rs`, `old/main.rs` — partial; need async rewrite

---

### Phase 12 — Integration & Cross-Cutting Concerns

---

#### Task 12.1 — Error handling strategy

- 12.1.1 Define `DnsmasqError` enum using `thiserror`
- 12.1.2 Audit all `unimplemented!()` / `todo!()` / `unwrap()` / `expect()` calls
- 12.1.3 Replace with `?`-propagated `Result<_, DnsmasqError>` throughout

---

#### Task 12.2 — Global state (`Daemon`) threading model

- 12.2.1 Wrap `Daemon` in `Arc<RwLock<Daemon>>` (tokio)
- 12.2.2 Audit all cross-task accesses; minimize lock scope
- 12.2.3 Replace C global `daemon` pointer with passed `Arc` references

---

#### Task 12.3 — Integration testing

- 12.3.1 Spin up dnsmasq-rs in test harness; send real DNS queries via `trust-dns-client` or raw UDP
- 12.3.2 Verify A/AAAA/PTR/CNAME/MX resolution
- 12.3.3 DHCP integration test: DISCOVER/OFFER/REQUEST/ACK via raw socket
- 12.3.4 Config file reload (SIGHUP) integration test
- 12.3.5 Fuzz test DNS packet parser with `cargo-fuzz` / AFL

---

#### Task 12.4 — CI / build

- 12.4.1 `cargo clippy --all-features -- -D warnings` in CI
- 12.4.2 `cargo test --all-features`
- 12.4.3 `cargo test --no-default-features`
- 12.4.4 Feature matrix test (all feature combinations)
- 12.4.5 `cargo audit` for dependency vulnerabilities

---

## File-by-File Reference

| C Source File | Lines | Rust Target Module | old/ Coverage | Phase |
|---|---|---|---|---|
| `dnsmasq.h` | 1971 | `src/types/` (multiple) | Good stubs | 1 |
| `config.h` | 488 | `Cargo.toml` features | Partial | 1 |
| `dns-protocol.h` | 194 | `src/dns_protocol/` | Partial | 1 |
| `dhcp-protocol.h` | 110 | `src/dhcp_protocol/` | Partial | 1 |
| `dhcp6-protocol.h` | 77 | `src/dhcp6_protocol/` | Partial | 1 |
| `radv-protocol.h` | 55 | `src/radv_protocol/` | Partial | 1 |
| `ip6addr.h` | 33 | `src/types/ip6addr.rs` | Partial | 1 |
| `metrics.h` | 54 | `src/metrics/` | Partial | 1 |
| `util.c` | 1006 | `src/util.rs` | 303 lines | 2 |
| `log.c` | 494 | `src/log.rs` | 154 lines | 2 |
| `blockdata.c` | 241 | `src/blockdata.rs` | 212 lines | 2 |
| `poll.c` | 118 | `src/poll.rs` | skeleton | 2 |
| `outpacket.c` | 118 | `src/outpacket.rs` | skeleton | 2 |
| `rfc1035.c` | 2400 | `src/rfc1035.rs` | 230 lines | 3 |
| `cache.c` | 2500 | `src/cache.rs` | 168 lines | 3 |
| `forward.c` | 3319 | `src/forward.rs` | skeleton | 3 |
| `edns0.c` | 574 | `src/edns0.rs` | 221 lines | 3 |
| `rrfilter.c` | 413 | `src/rrfilter.rs` | 236 lines | 3 |
| `loop.c` | 113 | `src/loop_detect.rs` | 196 lines | 3 |
| `domain.c` | 301 | `src/domain.rs` | partial | 3 |
| `domain-match.c` | 778 | `src/domain_match.rs` | 155 lines | 3 |
| `crypto.c` | 504 | `src/crypto.rs` | skeleton | 4 |
| `dnssec.c` | 2410 | `src/dnssec.rs` | skeleton | 4 |
| `dhcp-common.c` | 1081 | `src/dhcp_common.rs` | partial | 5 |
| `dhcp.c` | 1124 | `src/dhcp.rs` | partial | 5 |
| `rfc2131.c` | 3265 | `src/rfc2131.rs` | 236 lines | 5 |
| `lease.c` | 1346 | `src/lease.rs` | partial | 5 |
| `helper.c` | 948 | `src/helper.rs` | 174 lines | 5 |
| `dhcp6.c` | 881 | `src/dhcp6.rs` | partial | 6 |
| `rfc3315.c` | 2348 | `src/rfc3315.rs` | 240 lines | 6 |
| `radv.c` | 1039 | `src/radv.rs` | 158 lines | 6 |
| `slaac.c` | 213 | `src/slaac.rs` | 182 lines | 6 |
| `network.c` | 1812 | `src/network.rs` | 197 lines | 7 |
| `netlink.c` | 414 | `src/netlink.rs` | 163 lines | 7 |
| `bpf.c` | 440 | `src/bpf.rs` | 175 lines | 7 |
| `arp.c` | 240 | `src/arp.rs` | 219 lines | 7 |
| `conntrack.c` | 85 | `src/conntrack.rs` | skeleton | 7 |
| `option.c` | 6322 | `src/option.rs` | partial | 8 |
| `pattern.c` | 386 | `src/pattern.rs` | partial | 8 |
| `inotify.c` | 372 | `src/inotify.rs` | partial | 8 |
| `auth.c` | 915 | `src/auth.rs` | 169 lines | 9 |
| `dbus.c` | 1106 | `src/dbus.rs` | 228 lines | 10 |
| `ubus.c` | 391 | `src/ubus.rs` | 220 lines | 10 |
| `ipset.c` | 216 | `src/ipset.rs` | skeleton | 10 |
| `nftset.c` | 100 | `src/nftset.rs` | skeleton | 10 |
| `tables.c` | 144 | `src/tables.rs` | 152 lines | 10 |
| `tftp.c` | 1040 | `src/tftp.rs` | 160 lines | 10 |
| `dump.c` | 303 | `src/dump.rs` | 167 lines | 10 |
| `metrics.c` | 74 | `src/metrics.rs` | partial | 10 |
| `dnsmasq.c` | 2478 | `src/main.rs` + `src/dnsmasq.rs` | partial | 11 |

---

## Key Crate Dependencies

| Purpose | Crate |
|---|---|
| Async runtime | `tokio` (full) |
| CLI parsing | `clap` |
| Error types | `thiserror` |
| Logging/tracing | `tracing`, `tracing-subscriber` |
| Property testing | `proptest` |
| Crypto (DNSSEC) | `ring`, `rsa`, `p256`, `ed25519-dalek` |
| D-Bus | `zbus` (feature `dbus`) |
| Random | `rand` |
| Byte buffers | `bytes` |
| LRU cache | `lru` |
| System/network | `nix`, `socket2`, `if-addrs` |
| Capabilities | `caps` |

---

## Testing Strategy

Each module must have:

1. **Unit tests** (`#[cfg(test)]` inside each file):
   - Happy path: correct output for known inputs
   - Error path: malformed input returns `Err`, not panic
   - Edge cases: empty input, max-length values, boundary conditions

2. **Property-based tests** (`proptest!` macros):
   - Encode/decode roundtrips (DNS packets, DHCP options, config lines)
   - Idempotence: applying an operation twice equals applying it once
   - Invariants: cache size never exceeds limit; lease IDs are unique

3. **Integration tests** (`tests/` directory):
   - Full DNS query resolution end-to-end
   - DHCP lease cycle end-to-end
   - Config reload (SIGHUP) correctness

4. **Fuzz targets** (`fuzz/` directory, `cargo-fuzz`):
   - `fuzz_dns_packet_parser`
   - `fuzz_dhcp_option_parser`
   - `fuzz_config_file_parser`
