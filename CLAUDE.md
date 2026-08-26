# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`dnsmasq-rs` is an in-progress Rust port of the upstream `dnsmasq` binary. The target is behavioral parity for the supported feature set, with safe Rust internals and strong regression coverage.

The repository has broad module coverage and substantial tests, but it is not yet feature-complete or upstream-equivalent. Module presence is not parity. Passing unit tests are not executable equivalence.

Primary references:

- Upstream C source: `original_dnsmasq_src/dnsmasq-master/src/` — read-only reference
- Earlier Rust attempt: `old/` — read-only reference
- Execution tracker: `tasks.md`
- Sibling agent guidance: `agents.md` (roles/process), `.github/copilot-instructions.md`

Note that `tasks.md` and `agents.md` describe some blockers that have since been resolved (see "Build and test reality"). Verify a claimed blocker before treating it as current.

## Build and test reality

```bash
cargo build                       # default features
cargo check --all-features        # clean
cargo check --no-default-features # BROKEN — see below
cargo test                        # full suite, ~3019 tests, currently clean
cargo test -- --list              # enumerate tests
cargo test <substring>            # single test by name
cargo test --test dns_roundtrip   # one integration target
cargo test proptest               # property suites
RUST_LOG=debug cargo run          # logging via tracing EnvFilter
```

Verified state in this environment:

- Full `cargo test` passes: 1500 (lib) + 1472 (bin) unit tests + 5/5/6 integration + 31 proptests, **0 failures**. Earlier docs claiming ~1306 tests with 19 permission-related failures are stale.
- `cargo check --all-features` compiles clean (warnings only).
- `cargo check --no-default-features` **fails to compile** with 3 errors in `src/option.rs`: `parse_dhcp_alternate_port` not in scope, and `dhcp_server_port` / `dhcp_client_port` missing from `Daemon`. These are `dhcp`-gated items referenced from ungated code. Fixing this gate leakage is real outstanding work — do not treat the command as merely unsupported.

Before claiming a build or test state, run the command and read the output. The prior version of this file over-reported failures and under-reported progress in both directions.

## Parity harness

The container-backed parity harness exists at `parity/` (earlier docs said it was missing).

```bash
./parity/run-major.sh                                    # build, start both, probe, diff
FIXTURE=basic UPSTREAM_PORT=2053 CANDIDATE_PORT=3053 ./parity/run-major.sh
KEEP_CONTAINERS=1 ./parity/run-major.sh                  # leave containers up for inspection
cargo run --bin parity_probe -- --queries <file> --upstream <addr> --candidate <addr>
```

How it works: `compose.major.yaml` builds an upstream `dnsmasq` image from the vendored C tree and a `dnsmasq-rs` image from this repo, mounts the same fixture read-only into both, and binds them to isolated loopback ports. `src/bin/parity_probe.rs` (host-side, no Python or extra container) sends identical queries to both, normalizes each reply into a `NormalizedPacket` (rcode, TC bit, sorted answer/authority/additional RRs) and fails on any difference.

Scope today is DNS only, fixture `parity/fixtures/dns/basic/`. DHCP, DHCPv6, RA, and interface-sensitive behavior are out of scope for this harness version and would need `NET_ADMIN`/`NET_RAW`. The current codebase is not expected to pass every future parity suite.

## Architecture

### Central state

`Daemon` (`src/types/daemon.rs`, ~450 lines) is a direct port of C's global `struct daemon` from `dnsmasq.h` — the single source of truth for runtime configuration and state. It is always shared as:

```rust
pub type DaemonHandle = Arc<RwLock<Daemon>>;   // defined in src/dnsmasq.rs:18
```

`DaemonHandle` lives in `src/dnsmasq.rs`, not in `src/types/daemon.rs` — other docs in this repo get this wrong. Async tasks take a clone of the handle; never store a bare `Daemon`.

### Config pipeline

This is the parity-critical path and spans several files:

```
CliArgs (clap, src/option.rs)  ─┐
                                ├─> Vec<ConfigLine>  ─> resolve_config ─> ResolvedConfig
conf-file text ─> parse_config_text ─┘                      │                    │
                  (recursive conf-file, depth 10)           │              .into_daemon()
                                                            │                    ▼
                                          apply_line per directive        init_daemon_with
                                          then normalize_config                 ▼
                                                                            DaemonHandle
```

- `ConfigLine` is the single raw directive form. CLI flags are converted to `ConfigLine`s by `config_lines_from_cli` and appended **after** file-derived lines, so CLI overrides win by application order.
- `normalize_config` holds post-processing that upstream does implicitly: DNSSEC fast-retry defaults, local-TTL fill-in for host records and CNAMEs, MX/auth defaults, `local-service` handling, and auth validation. Put new cross-directive defaulting here, in a named helper — not in the tail of `apply_config`.
- `src/option.rs` is ~6600 lines and the largest parity surface. A directive is not done until it parses valid forms, rejects invalid forms clearly, mutates `Daemon` correctly, affects runtime behavior, and has directive-level plus fixture-level tests. Never accept a directive as a silent no-op; if a no-op is deliberate, document it and track it in `tasks.md`.

#### Config file formats

`--conf-file=<path>` dispatches on extension in `main.rs`'s `load_top_level_conf_file`: `.yaml`/`.yml` goes to `yaml_config::parse_yaml_config_text` (feature `yaml-config`), anything else to `option::parse_config_text` (feature `legacy-config`, default-on). Both produce the exact same `Vec<ConfigLine>` shape, so `resolve_config`/`apply_line`/`normalize_config` never know which format the directives came from — `yaml_config.rs` is purely an alternate *source* of `ConfigLine`s, not a second config-application pipeline. The YAML schema is flat and mirrors existing directive names 1:1 (`port: 5353`, `server: ["8.8.8.8", "1.1.1.1"]` for a repeatable directive, `no-resolv: true` for a bare flag) rather than a nested/sectioned structure, specifically so it needs no separate mapping layer.

`--convert-config <input> <output>` (feature `yaml-config`, also needs `legacy-config` to read the input) parses a legacy file and re-serializes its `ConfigLine`s as YAML, then exits without starting the daemon — see `main.rs`'s `convert_legacy_config_to_yaml`.

Note `legacy-config` only gates the *runtime entry point* (`main.rs`'s dispatch and `yaml_config.rs`'s cross-format `conf-file:` include fallback) — `option::parse_config_text` itself stays unconditionally compiled, since gating it would require touching every one of its hundreds of existing direct unit-test call sites in `option.rs` for a build combination (`legacy-config` off) that isn't part of default features.

### Runtime flow

`main.rs` reads the config, resolves it once, calls `dnsmasq::init_daemon_with`, installs SIGTERM/SIGHUP handlers, and enters `dnsmasq::run_main_loop`. `run_main_loop` snapshots port/upstreams/DHCP runtime from the handle, binds the DNS UDP socket, and spawns `forward::run_forward_loop` (plus `dhcp::run_dhcp_loop` under the `dhcp` feature).

This path is deliberately simpler than upstream `dnsmasq.c`. SIGHUP reload in `main.rs` is still a logging stub; `dnsmasq::on_sighup` / `clear_cache_and_reload` are the real hooks to grow. Startup, reload, and listener lifecycle parity is open work.

Daemonization (`dnsmasq::daemonize`) must happen **before** the tokio runtime starts — `fork` is not tokio-safe.

### The lib/bin duplication gotcha

`src/main.rs` re-declares the entire module tree with `pub mod ...` instead of importing the `dnsmasq_rs` library crate. Consequences you will hit:

- Every module is compiled twice and its unit tests run twice (hence 1500 lib + 1472 bin test counts).
- The two module lists have already drifted: `pub mod dhcp6;` is in `lib.rs` but missing from `main.rs`.
- Adding a module means editing **both** `src/lib.rs` and `src/main.rs`, with matching `#[cfg(feature = ...)]` gates, or the binary silently loses it.

Integration tests in `tests/` import through the library (`dnsmasq_rs::*`), so they only see `lib.rs`'s view.

### Module map

| Path | Purpose |
|---|---|
| `src/types/` | Structs/enums ported from `dnsmasq.h` (daemon, addr, cache, dhcp, server, network, dns_records, constants) |
| `src/dns_protocol/`, `src/dhcp_protocol/`, `src/dhcp6_protocol/`, `src/radv_protocol/` | Wire-format constants (opcodes, rcodes, RR types, flag bitmasks) |
| `src/rfc1035.rs` | DNS packet parser/encoder — port of `rfc1035.c` |
| `src/cache.rs` | Bounded LRU DNS cache keyed by `(name, type-flags)` |
| `src/forward.rs` | DNS query forwarding engine |
| `src/option.rs` | Config parsing and application — port of `option.c` |
| `src/yaml_config.rs` | YAML `conf-file` support (`yaml-config` feature) — parses into the same `ConfigLine`s `option.rs`'s text parser produces; no upstream counterpart |
| `src/dnsmasq.rs`, `src/main.rs` | Daemon init, privilege drop, daemonization, signals, main loop |
| `src/rfc2131.rs`, `src/dhcp.rs`, `src/lease.rs`, `src/helper.rs` | DHCPv4 |
| `src/rfc3315.rs`, `src/dhcp6.rs`, `src/radv.rs`, `src/slaac.rs` | DHCPv6 and RA |
| `src/network.rs`, `src/netlink.rs`, `src/dhcp_common.rs`, `src/arp.rs` | Runtime socket and interface behavior |
| `src/dnssec.rs`, `src/crypto.rs` | DNSSEC validation |
| `src/error.rs` | Central `DnsmasqError` (`thiserror`) |
| `src/bin/parity_probe.rs` | Host-side parity comparison tool |

### Feature flags

Cargo features mirror upstream's compile-time `HAVE_*` defines. Defaults: `dhcp dhcp6 dnssec auth tftp loop inotify dump`. `dhcp6` implies `dhcp`. Non-default: `conntrack`, `dbus` (pulls `zbus`), `ubus`, `ipset`, `nftset`. There is no `bpf` feature — `src/bpf.rs` was speculative classic-BPF filter code with no upstream counterpart and no caller; it was removed (see `tasks.md` P5). Upstream `bpf.c` is BSD/Solaris-only routing-socket code with no Linux relevance; its Linux analog is `netlink.rs`.

`legacy-config` (default-on) and `yaml-config` (default-off, pulls `serde`/`serde_norway`) are dnsmasq-rs-specific, with no upstream `HAVE_*` counterpart — see "Config file formats" below.

Gates apply both to `pub mod` declarations (in *both* `lib.rs` and `main.rs`) and inside modules. Gate leakage is a live bug class — see the `--no-default-features` failure above.

### Conventions

- C `union all_addr` → Rust `enum AllAddr`; C null pointer → `Option<T>`; C globals → explicit shared state that invents no new semantics; C `#ifdef HAVE_X` → `#[cfg(feature = "x")]`; C allocation patterns → ownership-based types.
- `F_*` flag bits (`F_IPV4`, `F_NEG`, `F_DNSSEC`, ...) are `const u32` in `src/types/constants.rs`. Use `cache::type_flags(flags)` to extract only the type bits when building a `CacheKey`.
- Module-local errors (`DnsError` in `rfc1035`, `ConfigError` in `option`) implement `From<_>` into `DnsmasqError`.
- Prefer safe Rust; keep `unsafe` tightly scoped to platform boundaries. Keep naming traceable to upstream where that aids review.

## Porting rules

- Preserve observable upstream behavior first. Read the upstream C for the target behavior before writing Rust.
- Do not drop upstream behavior because the Rust shape is cleaner. Preserve flag semantics and wire format exactly unless the deviation is documented.
- Map C unions, pointers, and flags into reviewable Rust forms without losing wire-format or decision logic.
- Keep unsupported behavior explicit in docs and TODOs, and tracked in `tasks.md`.
- Do not edit `original_dnsmasq_src/` or `old/`.

## Testing strategy

1. **Unit tests** — `#[cfg(test)]` blocks in each module, for parsers, state transitions, cache ops, packet construction, config application.
2. **Property tests** — `tests/proptest_*.rs` with `proptest`, for parser panic-freedom, protocol roundtrips, and invariants. `tests/proptest_cache.proptest-regressions` is a committed regression corpus; keep new shrunk cases in it.
3. **Functional parity** — `parity/` fixtures compared against the real upstream binary. Extend by adding a fixture directory under `parity/fixtures/dns/` and running with `FIXTURE=<name>`.

Every behavior slice should land with happy-path, boundary, malformed-input, and error-path coverage in the same change, plus a regression test for every bug found.

Keep capability-dependent tests (sockets, interface enumeration, bind-to-device) separated, gated, or expectation-aware, so restricted environments do not produce misleading failures — and do not read a restricted-environment failure as evidence the implementation is wrong.

## Current priorities

1. Finish `src/option.rs` for the directives needed to boot realistic parity fixtures.
2. Fix `--no-default-features` gate leakage in `src/option.rs`.
3. Close the startup/reload/runtime gap in `src/dnsmasq.rs` and `src/main.rs` — especially real SIGHUP reload behavior.
4. Expand `parity/` beyond the single DNS fixture: cache, reload, forwarding, then a capability-enabled DHCP lane.
5. Resolve the `lib.rs` / `main.rs` module duplication rather than maintaining two trees.
