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

- [x] Wire local-data answering into the live query path.
  `run_forward_loop` now calls `rfc1035::answer_request` (via `try_local_answer`) before
  `forward_query`, matching the order `udp_request()` uses in upstream `forward.c`, and
  `run_main_loop` snapshots the `Daemon` local-data lists into `ForwardConfig::local`
  (`dnsmasq::daemon_local_data`) plus the answer cache size (`dnsmasq::daemon_cache_size`).
  A purely local config with zero upstreams now answers instead of timing out.
  Covered by `tests/local_answer_integration.rs` and `tests/parity_dns_basic_local.rs`.

  Explicitly **not** covered by that wiring — upstream behavior still missing:

  - EDNS0 pseudo-header round-tripping. Upstream `udp_request()` calls
    `add_edns0_config()` before `answer_request()` and re-attaches an OPT RR (plus any
    EDE option) with `add_pseudoheader()` afterwards. The Rust `answer_request` drops the
    query's additional section entirely, so a locally-answered EDNS query comes back
    without an OPT RR and never carries an EDE code.
  - `stale`/`filtered` answer signalling. Upstream threads `int *stale, int *filtered`
    out of `answer_request()` to pick `METRIC_DNS_STALE_ANSWERED` and set
    `EDE_STALE`/`EDE_FILTERED`. The Rust signature has no equivalent, so
    `Metric::DnsStaleAnswered` is never incremented from this path.
  - Response truncation. Upstream sets TC and empties the answer sections when a reply
    exceeds the client's advertised UDP size; the Rust path always writes the full reply.
  - MX/SRV additional-section glue. Upstream appends cached A/AAAA records for MX and SRV
    targets (`rec->offset` loop at the end of `answer_request()`); the Rust port emits an
    empty additional section. Harmless for `parity/fixtures/dns/basic` because no target
    there resolves, but wrong once a fixture configures one.
  - `qtype == T_CNAME` chain termination. Upstream stops after the first CNAME when the
    query type is CNAME; the Rust port follows the whole chain, so a multi-hop alias
    answers with every CNAME in the chain instead of one.
  - `no-cache`/`do-bit`/`CD` handling, and the auth (`--auth-zone`) and conntrack
    allowlist branches of `udp_request()`, which have no Rust call site at all.
  - TCP DNS service. Only the UDP listener consults local data; there is no TCP listener.
  - Answer-cache population. `run_forward_loop` builds a `DnsCache` and passes it to
    `answer_request`, but nothing ever inserts forwarded upstream replies into it —
    `ForwardEngine::process_reply` has no cache write. The cache therefore only ever
    serves what `answer_request` itself stores, so the cache-hit branches of
    `answer_request` (cached CNAME, cached NXDOMAIN, MX/SRV glue) are unreachable in the
    live path. Upstream caches every forwarded reply in `cache_insert()`.
  - `cache-size=0`. Upstream treats `0` as "caching disabled"; `DnsCache` has no disabled
    mode, so `run_forward_loop` clamps the size to 1 entry (`cache_size.max(1)`) instead
    of bypassing the cache.
  - Reload staleness. `run_main_loop` snapshots the local data once at startup and moves
    the clone into the forward task, so the query loop keeps answering from the
    startup-time config forever. Upstream re-reads `daemon->` config data on every query,
    so a SIGHUP reload takes effect immediately. Whoever implements real SIGHUP reload
    (`dnsmasq::on_sighup` / `clear_cache_and_reload`) must also republish the snapshot —
    a shared `ArcSwap`/`watch` channel rather than a moved clone.

- [x] Wire daemonization, pid-file writing and privilege dropping into `src/main.rs`.
  `main` is no longer `#[tokio::main]`: it runs the upstream startup sequence
  (`dnsmasq.c:499-820`) synchronously and only then builds the tokio runtime, because
  `fork()` is unsound once the reactor and its worker threads exist. The order is
  upstream's — resolve `user=`/`group=` → bind listeners → `chdir("/")` → double-fork +
  `setsid` → write the pid file → stdio to `/dev/null` → drop privileges → main loop.

  Listeners are now bound by `dnsmasq::bind_listeners` *before* the fork and the drop
  (upstream does the same at `dnsmasq.c:325-409`), so port 53 is claimed while the
  process is still root and a bind failure is still reportable on the invoking terminal.
  `run_main_loop_with` adopts those sockets; `run_main_loop` still binds its own, which
  is what the in-process tests use.

  Also landed: `setgroups(0, ...)` supplementary-group clearing, `PR_SET_KEEPCAPS` +
  `capset` capability retention across the `setuid` (with `CAP_SETUID` dropped
  afterwards), `unlink` + `O_EXCL` symlink-race protection and `fchown` on the pid file,
  an `err_pipe` equivalent (`dnsmasq::StartupPipe`) so the invoking shell blocks until
  startup finishes and sees fatal startup errors, and `username`/`runfile` defaulting to
  `CHUSER` ("nobody") and `RUNFILE` (`/var/run/dnsmasq.pid`) as upstream's `read_opts`
  does (option.c:5976-5977). Those two are seeded *before* the config lines are applied,
  not filled in afterwards, so `user=`/`pid-file=` with an empty value clears them the
  way `opt_string_alloc` (option.c:677-691) does. Covered by
  `tests/daemon_startup_integration.rs` plus unit tests in `src/dnsmasq.rs`.

  `log::log_start` is now called from `main.rs` too, before the `/dev/null` redirect, and
  installs the `tracing` sink — so `log-facility=<file>` receives the daemon's ordinary
  output and a backgrounded or `-k` daemon is not silent. `StartupPipe::fail` reports
  through that sink as well, which is what upstream's `fatal_event` → `die` → syslog path
  gives the `-k` case, where there is neither a pipe nor a usable stderr.

  Two flag-semantics fixes came with it: `--no-daemon`/`-d` now sets `OPT_DEBUG`
  (`option.c:428`), not `OPT_NO_FORK`, so it suppresses the pid file, the stdio redirect
  and the privilege drop as well as the fork; `-k`/`--keep-in-foreground` was added for
  `OPT_NO_FORK` (`option.c:456`) and was previously missing entirely.

  Explicitly **not** covered — upstream behavior still missing:

  - `need_cap_net_admin`/`need_cap_net_raw` are approximated: a DHCP context implies
    `NET_ADMIN` and (unless `--no-ping`) `NET_RAW`, ignoring the `force_broadcast` list
    (`dnsmasq.c:332`), and the DHCPv6/RA, ipset, nftset, DBus and UBus contributors have
    no Rust equivalent yet. `CAP_NET_BIND_SERVICE` is never requested, because nothing
    binds after the drop — once `bind-dynamic`/DAD deferred binds exist it must be.
  - `server=<addr>@<interface>` is not parsed at all, so `Server::interface` is always
    empty and the `NET_RAW`-for-`SO_BINDTODEVICE` rule (`dnsmasq.c:537-540`) is only
    reachable from unit tests.
  - No `capget` pre-flight. Upstream checks the permitted set up front and dies with
    "process is missing required capability NET_ADMIN" (`dnsmasq.c:576-583`); here a
    capability that is not permitted surfaces later as a `capset` failure during the drop.
    Both are fatal, but the Rust diagnostic is worse.
  - No syslog *socket*. `src/log.rs` ports `log_start`/`log_reopen`/`my_syslog` and is now
    wired into startup, but with no `log-facility` the fallback is stderr, not
    `/dev/log` — so a backgrounded daemon with no `log-facility` still logs nowhere,
    where upstream would reach syslog. Consequently `log-facility=<facility-name>`
    (`daemon`, `local0`, …) and `log-facility=-` are treated as file paths rather than as
    facility selectors, and `log_fac`/`log-async` queueing are parsed but inert.
    `log_start` also does not `fchown` the log file to the run user (log.c), so a
    root-created log file stays root-owned after the drop.
  - `my_syslog` output now passes through the `tracing` `EnvFilter`, so `RUST_LOG` can
    suppress records upstream would always write. Upstream filters only on `MS_DEBUG`.
  - Solaris `priv_set`/`setppriv` (`dnsmasq.c:775-795`) is deliberately out of scope; the
    capability path is Linux-only and other platforms just `setgroups`/`setgid`/`setuid`.
  - No helper process is forked before the privilege drop, so `dhcp-script`/`dhcp-luascript`
    (`create_helper`, `dnsmasq.c:740`) still cannot run as a separate uid.
  - The pid file is never removed on shutdown, and `PR_SET_DUMPABLE` (debug mode,
    `dnsmasq.c:823`) is not set.
  - Acceptance evidence caveat: `user_and_group_change_the_running_ids_and_clear_supplementary_groups`
    is root-gated and skips on an unprivileged runner, so the `setuid`/`setgid`/`setgroups`
    and pid-file-`fchown` assertions only actually execute under root. Likewise the
    parity lane needs Docker; `parity_compose_keeps_the_candidate_in_the_foreground`
    guards the `-k` flag the candidate container depends on without needing it.
  - `StartupPipe::ready()` fires once the runtime is built, not once the forwarding task
    is actually serving, so a failure inside `run_main_loop` still escapes the invoking
    process's notice.

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
