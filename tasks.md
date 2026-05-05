# dnsmasq-rs TODO

## Current State

This repository is an in-progress Rust port of the upstream `dnsmasq` binary. The codebase already has broad module coverage and a large amount of unit and property-based testing, but it is not yet at executable parity with upstream.

What is true right now:

- Core protocol and data-path modules exist for DNS, cache, forwarding, DHCPv4, DHCPv6, TFTP, DNSSEC, and related helpers.
- `cargo test -- --list` reports about `1306` unit and integration tests plus the existing property-based test suites.
- Property tests already exist for DNS packet parsing, cache invariants, and DHCP packet/state helpers.
- There is no upstream-vs-Rust black-box parity harness yet.
- `src/main.rs` and `src/dnsmasq.rs` still run a simplified daemon path compared with the original binary.
- `src/option.rs` still contains many stubbed directives and placeholder behavior, which blocks realistic config parity.
- Full `cargo test` in this environment does not pass cleanly: `1287` tests passed and `19` failed due to socket or capability restrictions in network-heavy tests.
- `cargo check --all-features` was not confirmed in this session because dependency unpacking hit a read-only cargo registry path in the sandbox.

Reference material:

- Upstream C source: `original_dnsmasq_src/dnsmasq-master/src/`
- Earlier Rust attempt: `old/`

Both are reference-only. Do not treat either tree as code to edit in place.

## P0 Parity Blockers

- [ ] Finish `src/option.rs` for the directives needed to boot realistic parity fixtures.
  Source of truth: upstream `option.c`, current TODO markers in `src/option.rs`.
  Required tests: directive-level unit tests, malformed-input tests, config fixture integration tests.
  Done when: supported directives are parsed and applied with the same observable behavior as upstream for the parity fixture set.

- [ ] Unify CLI parsing and config-file parsing behind one normalization pipeline.
  Source of truth: current `src/main.rs`, `src/option.rs`, upstream option semantics.
  Required tests: CLI-to-config-line tests, resolved-config normalization tests, startup tests using CLI overrides plus config files.
  Done when: CLI flags are translated into the same raw directive form as config files, normalization is explicit, and startup consumes a resolved config instead of mutating a default daemon ad hoc.
  Next concrete tasks:
  1. Introduce a raw-input to resolved-config split: keep `ConfigLine` as raw input and add an explicit `ResolvedConfig`.
  2. Move normalization/post-processing out of implicit `apply_config` tail logic into named helpers.
  3. Convert supported `clap` CLI flags into `ConfigLine` entries with source metadata.
  4. Make `src/main.rs` build one merged directive list from config file plus CLI overrides and resolve it once.
  5. Add regression tests for ordering, override behavior, and post-processing rules such as DNSSEC fast-retry defaults.

- [ ] Close the gap between the current simplified daemon flow and upstream startup/reload behavior.
  Source of truth: upstream `dnsmasq.c`, current `src/main.rs`, `src/dnsmasq.rs`.
  Required tests: startup tests, SIGHUP reload tests, cache flush/reload tests, listener lifecycle tests.
  Done when: startup, shutdown, and reload paths match upstream behavior for supported features.

- [ ] Define and build an upstream binary parity harness.
  Source of truth: this document's functional criteria, upstream `dnsmasq` behavior.
  Required tests: fixture-driven black-box comparisons between upstream dnsmasq and `dnsmasq-rs`.
  Done when: the harness can run both binaries against the same fixtures and report normalized behavioral diffs.

- [ ] Treat behavioral mismatches against upstream as first-class bugs.
  Source of truth: parity harness output, packet captures, fixture expectations.
  Required tests: regression tests for each fixed mismatch.
  Done when: each known mismatch has either a fix with regression coverage or an explicit documented unsupported-feature note.

## P1 Runtime And Integration Gaps

- [ ] Split pure logic tests from capability-dependent socket tests.
  Source of truth: current failing tests in `network.rs`, `forward.rs`, and `dhcp_common.rs`.
  Required tests: deterministic unit coverage for pure logic, gated or capability-aware integration coverage for privileged paths.
  Done when: restricted environments do not fail due to avoidable permission assumptions, while real socket behavior is still exercised where supported.

- [ ] Harden listener and socket creation paths to match upstream error handling.
  Source of truth: upstream `network.c`, `forward.c`, `dhcp-common.c`.
  Required tests: bind failure tests, address family tests, listener reuse tests, mark/bindtodevice behavior tests where supported.
  Done when: runtime setup failures degrade or report errors in a controlled and upstream-compatible way.

- [ ] Replace remaining daemon reload stubs with real behavior.
  Source of truth: upstream reload flow, current `clear_cache_and_reload`, `main.rs` SIGHUP handling.
  Required tests: repeated SIGHUP, cache invalidation, hosts/resolv reload, no-op reload stability.
  Done when: reload mutates runtime state intentionally and repeatably instead of only toggling placeholder flags.

- [ ] Audit runtime paths that currently exist only as simplified helpers.
  Source of truth: comments marked `stub`, `TODO`, `unimplemented`, and parity mismatches.
  Required tests: focused regression tests per audited path.
  Done when: remaining simplifications are either implemented or explicitly tracked as unsupported.

## P2 Config Parser Completion

- [ ] Port the DHCP-related directives still stubbed in `src/option.rs`.
  Examples: `dhcp-range`, `dhcp-host`, `dhcp-option`, `dhcp-boot`, tag and class matching directives.
  Required tests: per-directive parsing tests, apply-to-daemon tests, DHCP fixture tests.
  Done when: parity fixtures can express real DHCP server setups through config files.

- [ ] Port local DNS data directives still stubbed in `src/option.rs`.
  Examples: MX, SRV, TXT, PTR, host-record, CNAME, NAPTR, DS, bogus address, doctoring, auth-zone related directives.
  Required tests: parse/apply tests plus black-box answer tests through the executable harness.
  Done when: config-defined local DNS data produces upstream-compatible answers.

- [ ] Complete remaining network and policy directives needed for production-like configs.
  Examples: rebind controls, ipset/nftset hooks, filter variants, port-limit, no-hosts6, logging-related directives.
  Required tests: parser tests and feature-gated integration tests.
  Done when: supported config files do not silently ignore implemented features.

- [ ] Remove silent placeholder acceptance of directives.
  Source of truth: current TODO branches in `apply_line`.
  Required tests: unsupported directives must fail clearly unless intentionally no-op and documented.
  Done when: the parser never gives a false impression that a feature works when it does not.

## P3 Feature-Specific Completion

- [ ] Finish behavior-critical gaps in DNS forwarding and cache interaction.
  Focus: upstream retry behavior, server rotation, reply matching, cache insertion edge cases, AD bit and EDNS0 semantics.
  Required tests: unit tests, property tests where appropriate, parity harness DNS scenarios.
  Done when: forwarding behavior matches upstream for the supported DNS suite.

- [ ] Finish DHCPv4 behavior beyond packet helpers.
  Focus: lease policy, config-driven behavior, relay interactions, option handling, script interactions where supported.
  Required tests: state-machine tests, fixture-based DHCP exchanges, regression coverage for pool and tag logic.
  Done when: DHCPv4 parity scenarios pass against upstream.

- [ ] Finish DHCPv6 and RA behavior beyond current helpers.
  Focus: IA handling, relay behavior, status codes, RA timing and option emission.
  Required tests: unit coverage plus parity fixture exchanges.
  Done when: supported DHCPv6 and RA scenarios are behaviorally aligned with upstream.

- [ ] Reassess DNSSEC claims against actual implementation status.
  Source of truth: `src/dnssec.rs`, `src/crypto.rs`, existing TODO notes, parity outcomes.
  Required tests: validation-path tests, malformed input tests, upstream comparison for supported DNSSEC scenarios.
  Done when: docs and behavior agree on what DNSSEC support is real versus partial.

- [ ] Treat DBus, UBus, BPF, ipset, nftset, and similar integrations as feature-gated completion tracks.
  Required tests: feature-gated compile checks, targeted integration tests, parity scenarios only when implementation is real.
  Done when: each optional feature is either implemented with tests or explicitly marked incomplete.

## P4 Test Harness And Tooling

- [ ] Build reusable parity fixtures.
  Include: config files, hosts files, resolv files, zone-like local data, deterministic query sets, DHCP packet traces.
  Done when: the same fixture directory can drive both upstream dnsmasq and `dnsmasq-rs`.

- [ ] Build a test runner that launches both binaries in isolation.
  Requirements: temp directories, isolated ports, deterministic inputs, normalized output capture, cleanup on failure.
  Done when: one command can execute a parity suite and emit actionable diffs.

- [ ] Normalize comparison outputs to behavior, not brittle incidental details.
  Compare: DNS replies, DHCP replies, cache/reload effects, exit status, accepted or rejected configs, stable log signals where useful.
  Do not overcompare: nondeterministic timestamps, unstable ordering, environment-specific formatting.
  Done when: failures point to real semantic differences.

- [ ] Expand property-based coverage where it protects porting work best.
  Priority areas: config parsing invariants, DNS name and RR roundtrips, DHCP option handling, cache and lease state invariants.
  Done when: new parser and protocol work ships with panic-freedom and roundtrip properties where appropriate.

- [ ] Add regression fixtures for every upstream mismatch found.
  Done when: parity bugs stay fixed after refactors.

## P5 Cleanup And Documentation

- [ ] Keep `CLAUDE.md` and `agents.md` aligned with actual repo status.
  Done when: they reflect current test reality, parity expectations, and porting priorities without optimistic completion claims.

- [ ] Reduce warning noise that hides real regressions.
  Source of truth: current `cargo test` and `cargo check` warning output.
  Done when: dead imports, unreachable matches, and placeholder leftovers are trimmed enough that new warnings are meaningful.

- [ ] Document unsupported behavior explicitly rather than implying parity.
  Done when: users and contributors can tell which features are complete, partial, or intentionally deferred.

- [ ] Keep the top-level TODO current.
  Rule: when a task is completed, replace it with the next concrete blocker instead of letting this file become historical.

## Functional Test Criteria

The project is done when `dnsmasq-rs` behaves the same as the original dnsmasq binary for the supported feature set under identical fixtures.

Required parity suites:

- DNS forwarding
  Cover A, AAAA, CNAME, MX, SRV, TXT, PTR, SOA, NXDOMAIN, NODATA, truncation, EDNS0 handling, reply matching, and retry behavior.

- Cache behavior
  Cover positive caching, negative caching, TTL clamping, expiry, and reload-triggered cache flush behavior.

- Config behavior
  Cover config acceptance and rejection, plus the runtime effects of supported directives.

- DHCPv4
  Cover DISCOVER, OFFER, REQUEST, ACK, NAK, and supported relay scenarios.

- DHCPv6 and RA
  Cover SOLICIT, ADVERTISE, REQUEST, REPLY, supported IA flows, and RA emission behavior for supported configs.

- Local data and filtering
  Cover `/etc/hosts`-style records, local zones, rebind and bogus/private protections, RR filtering, and locally configured records.

- Signals and reload
  Cover SIGHUP reload, reread of dynamic inputs, and cache or runtime state changes expected after reload.

Rules for the parity harness:

- Run upstream dnsmasq and `dnsmasq-rs` side by side with the same fixture inputs.
- Use isolated temp directories and dynamically assigned ports.
- Capture wire responses and normalize them before comparison.
- Compare behavior, not unstable formatting.
- Exclude unsupported features from required suites until they are explicitly implemented and tracked here.

## Working Rules

- Port from upstream behavior first, then make the Rust code cleaner without changing semantics.
- Never silently accept a config directive that is not really implemented.
- Prefer safe Rust abstractions, but not at the cost of changing observable dnsmasq behavior by accident.
- Every bug found during parity work must gain a regression test.
