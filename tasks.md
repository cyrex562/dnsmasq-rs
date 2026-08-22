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

- [x] `src/conntrack.rs` issues an nfnetlink `IPCTNL_MSG_CT_GET` query (was
  building an unsent `IPCTNL_MSG_CT_NEW` set-message with no caller — the
  semantic opposite of upstream `get_incoming_mark()`, `conntrack.c:27-73`).
  `get_incoming_mark()` opens a `NETLINK_NETFILTER` socket, sends the query,
  and parses `CTA_MARK` out of the response, mirroring `callback()`
  (`conntrack.c:75-83`); it is `None`-returning and panic-free when
  unprivileged or when no entry matches. Wired into the UDP client forward
  path: `ForwardEngine::forward_query` now threads the arrival destination
  address into `FrecSrc::dest`, and `send_upstream` calls
  `conntrack_mark_for`/`apply_conntrack_mark` (gated on `--conntrack` /
  `OPT_CONNTRACK`) to copy the mark onto the outbound socket via the existing
  `set_outgoing_mark`, mirroring `set_outgoing_mark()` + the `OPT_CONNTRACK`
  check at `forward.c:531-535`.

  Still not ported (left for a future conntrack/ubus pass):

  - The TCP path (`tcp_request()`/`tcp_talk()`, `forward.c:2384-2395`,
    `forward.c:2079-2082`) — there is no Rust TCP DNS listener yet (see the
    "TCP DNS service" gap above), so `istcp = 1` queries are unreachable.
  - The DNSSEC-retry mark copy (`forward.c:1072-1074`) — the DNSSEC
    sub-query retry path in `forward_query`'s C equivalent has no Rust
    counterpart yet.
  - The `HAVE_UBUS`-gated connmark-allowlist branch at the main UDP fan-out
    reply path (`forward.c:1429-1447`, i.e. `accept_reply`'s per-target
    delivery loop in `run_forward_loop`) is now wired up: `rfc1035::
    report_addresses` (a pure port of `rfc1035.c:1148-1218`, returning
    `Vec<ReportedAddress>` rather than reaching into ubus itself — mirrors
    how `extract_addresses` reports `ipset_hits` for the caller to act on)
    is called per `ReplyTarget` behind `ForwardConfig::cmark_alst_en`
    (`OPT_CMARK_ALST_EN`), gated on `feature = "conntrack"` +
    `feature = "ubus"`, using `conntrack::get_incoming_mark` for the
    per-client mark exactly as `forward.c:1439-1444` does. Each reported
    name/target pair is broadcast via the new `ubus::
    ubus_event_bcast_connmark_allowlist_resolved`, which sends this crate's
    existing simplified project-defined wire encoding (see `ubus.rs`'s module
    doc — not OpenWrt's real binary ubus protocol) to a `UnixStream` at the
    well-known `/var/run/ubus.sock` path, best-effort (silently dropped if
    nothing is listening).

    Still not ported: the other three `report_addresses` call sites
    (`forward.c:604-613` synchronous local-answer reply, `1902-1997` and
    `2546-2555`, both inside DNSSEC-validation-retry/failure paths) — none
    of those reply paths have a Rust counterpart yet to hang the call off of.
    The TCP reply path has no `report_addresses` call either, for the same
    reason noted above (no Rust TCP DNS listener yet).

- [x] `is_query_allowed_for_mark()` / `answer_disallowed()` (`forward.c:1523-1567`)
  — the query-*admission* half of `--connmark-allowlist-enable`, distinct from
  `report_addresses`'s reply-*reporting* role above. Ported as
  `rfc1035::is_query_allowed_for_mark` (pure port of the mark/mask/pattern
  loop, ungated like `report_addresses` so it is unit-testable without the
  `conntrack` feature) plus `forward::mark_admits_query` (the
  `have_mark && (mark & allowlist_mask)` admission guard from
  `forward.c:1905-1907`, also kept feature-independent for the same testing
  reason). Wired into `run_forward_loop_on`'s UDP client-query branch ahead of
  both `answer_locally` and `forward_query` — matching upstream, where the
  admission check gates the entire `answer_request`/forward decision, not
  just the forwarding half. A disallowed query gets `make_refused_answer`'s
  REFUSED reply (the same reply upstream's `answer_disallowed()` builds via
  `setup_reply(header, 0, EDE_BLOCKED)`, minus the `EDE_BLOCKED` extended
  error — this crate's wire encoder has no EDE option support at all yet, a
  pre-existing gap noted on `make_refused_answer` itself) and, behind
  `feature = "conntrack"` + `feature = "ubus"`, a
  `ubus::ubus_event_bcast_connmark_allowlist_refused` broadcast mirroring
  `answer_disallowed()`'s `ubus_event_bcast_connmark_allowlist_refused` call.
  The mark lookup itself (`crate::conntrack::get_incoming_mark`) is gated on
  `feature = "conntrack"` same as everywhere else it's called.

  Still not ported: the TCP call site (`forward.c:2542-2563`) — no Rust TCP
  DNS listener yet, same gap as above — and the DNSSEC sub-query retry site,
  which inherits its parent query's admission decision in C rather than
  re-checking, and has no Rust DNSSEC-retry path to hang that inheritance off
  of yet.
  - Reload staleness (partially fixed). SIGHUP reload (`dnsmasq::on_sighup` /
    `clear_cache_and_reload`) now flushes and rebuilds the *live* `DnsCache` — it is a
    `cache::SharedDnsCache` threaded into `run_forward_loop_on` rather than a task-local
    value, so cache effects are immediate. What is still stale: `run_main_loop_with`
    snapshots `ForwardConfig` (upstream server list, host-records, CNAMEs, TXT/MX/PTR/
    NAPTR records) once at startup and moves the clone into the forward task, so a
    config change — including the `daemon.servers` update `clear_cache_and_reload` now
    makes from `--resolv-file` — only reaches the query loop on the next process start,
    not the next query. Closing this needs the same treatment the cache got: a shared
    `ArcSwap`/`watch` channel for `ForwardConfig` rather than a moved clone.

- [x] Wire the DNS answer cache into the live forward path.
  `run_forward_loop_on` now calls `forward::cache_upstream_reply` → `cache::cache_reply` →
  `rfc1035::extract_addresses` for every accepted, non-truncated upstream reply, mirroring
  the unconditional `extract_addresses()` call `process_reply()` makes at `forward.c:824`.
  A repeated query is answered from the cache and never reaches an upstream server.
  Covered by `tests/forward_cache_integration.rs` (22 tests driving the real loop against a
  scripted fake upstream, counting the datagrams that actually reach it) and the round-trip
  hit/miss tests in `tests/cache_integration.rs`.

  What that wiring **does** now reach, and where the enforcement lives:

  - `dnsmasq::daemon_forward_config` is the single `Daemon` → `ForwardConfig` conversion.
    `cache-size`, `min-cache-ttl`, `max-cache-ttl`, `max-ttl`, `neg-ttl`, `no-negcache`,
    `stop-dns-rebind` (`OPT_NO_REBIND`), `rebind-localhost-ok` (`OPT_LOCAL_REBIND`) and
    `rebind-domain-ok` (`no_rebind`) are all copied there and all observably affect run-time
    behavior.
  - `rebind-localhost-ok` reaches the rebind test as `ExtractConfig::local_rebind_ok` and is
    passed to `private_net` / `private_net6` as `!local_rebind_ok`, which is C's
    `private_net(addr.addr4, !option_bool(OPT_LOCAL_REBIND))` (`rfc1035.c:997,1001`). It
    narrows the check to exempt `127.0.0.0/8` and `::1`; RFC1918, ULA and link-local space
    stay blocked.
  - `min-cache-ttl` / `max-cache-ttl` are enforced in `DnsCache::really_insert`, and
    `extract_addresses` now inserts through `really_insert` rather than `insert`. Building
    the cache with `with_ttl_limits` alone would *look* wired without being wired — the
    live insert path has to reach the clamping function. Same for zero-TTL rejection and
    static-record conflict detection, which also live in `really_insert`.
  - `max-ttl` is applied earlier, in `extract_addresses` itself (`rfc1035.c:752,834`), which
    is a different clamp from `max-cache-ttl` (`cache.c:680-683`). Both now apply.
  - `cache-size=0` means "caching disabled": `DnsCache::new(0)` keeps no storage and
    `really_insert` reports `CachingDisabled`. It does **not** short-circuit the reply
    path — `extract_addresses` still runs, so `stop-dns-rebind` keeps working with a zero
    cache size, matching C, where a zero `cachesize` only leaves `really_insert()` with no
    free `crec`.
  - Cached records are served with their remaining lifetime (`DnsCache::crec_ttl`, a port
    of `rfc1035.c:1570`), not the TTL they were stored with. This applies to the cached
    A/AAAA, cached-CNAME and cached-PTR branches of `answer_request`; the cached-CNAME
    branch previously replayed `local-ttl` (0 by default), which is a static-record default
    unrelated to an upstream answer.
  - Upstream replies are now validated before they can affect anything, since a cached
    reply is a persistent one. `ForwardEngine::accept_reply` requires the QR bit, a known
    transaction ID, a question hash matching the outstanding query (what C gets from
    `lookup_frec()`'s name/class/type match at `forward.c:1173`) and a source address equal
    to the server the query went to (`forward.c:1201-1209`). Transaction IDs are drawn from
    `rand::random` rather than a counter, mirroring `get_id()` (`forward.c:3302`). A failed
    check drops the datagram and leaves the pending entry in place so the genuine answer can
    still arrive.
  - Inserts are **staged and committed as a unit**, the way C builds `new_chain` and commits
    it in `cache_end_insert()` (`rfc1035.c:1121-1128`). `extract_addresses` collects records
    into a local list and `commit_staged` writes them only when the walk finishes cleanly, so
    a reply that bails out with `RebindBlocked` or `BadPacket` leaves nothing behind — not
    even the records processed before the offending one. The same gate drops replies with
    `CD` set (the client is validating for itself).
  - Every accepted reply gets `RA` set before anything else looks at it
    (`forward::set_recursion_available`, C's `header->hb4 |= HB4_RA` at `forward.c:776`),
    which is both what the client sees and why the `RA` half of `commit_staged`'s gate
    (`rfc1035.c:1124-1127`) is always true on the live path. An answer from a non-recursive
    nameserver — what an authoritative server named by `server=/domain/addr` returns — is
    therefore cached like any other, as it is in C. The check is kept in `commit_staged` for
    fidelity to `rfc1035.c`, but it is not what governs caching here.
  - A cached CNAME does **not** answer a query by itself. Upstream sets `ans` for a CNAME only
    when the record is `F_CONFIG` or `qtype == T_CNAME` (`rfc1035.c:1704-1705`); otherwise the
    chain has to bottom out in something that answers, or `if (!ans) return 0`
    (`rfc1035.c:2295`) forwards the query. Serving a dead-ended chain locally would return a
    CNAME-only NOERROR — a resolution failure — for as long as a CNAME outlives its target,
    which is the everyday CDN TTL pattern.
  - NODATA negative entries are reachable. C stores them with the queried type bit plus
    `F_NEG` and finds them again because `cache_find_by_name()` matches bitwise; the Rust
    cache is keyed on the exact type bits, so `DnsCache::lookup_forward` probes the positive
    key and then the `| F_NEG` key, counting one hit or miss for the pair. The A/AAAA cache
    branches of `answer_request` use it. Without this the NODATA half of negative caching is
    written to a key nothing reads.
  - `--cache-rr` is now wired end to end (`daemon.rrlist_cache` → `ForwardConfig::cache_rr` →
    `ExtractConfig::cache_rr`, `dnsmasq.rs`/`forward.rs`). It was previously parsed by
    `option.rs` into `Daemon` and never read again — a silent no-op. `extract_addresses`
    ports C's `insert` gate (`rfc1035.c:788-804`): only `T_A`/`T_AAAA`, `T_SRV`, `T_PTR`, and
    any type on `cache_rr` (or a `T_ANY` wildcard entry on `cache_rr`) are cached; every other
    RR type — previously caught by an unconditional `_ => F_RR` fallthrough — is not, and
    neither is a `T_CNAME` query's own answer ("do not cache data from CNAME queries",
    `rfc1035.c:804`). The `insert` gate also covers NODATA negative caching (a NODATA answer
    to an uncacheable type is not cached either), but not NXDOMAIN, which C always allows to
    cache regardless of qtype (`rfc1035.c:1074-1076`). Rollback-on-`BadPacket` was already
    correct (staged inserts, see above); this closes the other half of Issue #13.
  - A locally generated answer — which is now every cache hit — carries the EDNS0 OPT
    pseudo-header back when the client sent one. C strips the additional section while
    building the answer and re-adds OPT in `receive_query()` (`forward.c:1969`); the re-added
    record advertises `daemon->edns_pktsz` (`edns-packet-max`, threaded through
    `LocalData::edns_pktsz`), drops the client's options and carries only the DO bit
    (`edns0.c:204-210`).

  Explicitly **not** covered — upstream behavior still missing on this path:

  - DNSSEC. `ForwardConfig::extract_config` always sets `secure: false`, so no cached record
    is ever marked `F_DNSSECOK` and `cache_secure` / `bogusanswer` have no live equivalent.
    `process_reply` therefore never turns a bogus answer into SERVFAIL and never *sets* the
    `AD` bit; the `--dnssec`-gated halves it does run are the DO-bit reset and the DNSSEC RR
    strip. See the reply-path entry below.
  - `--dhcp-ttl` / `use_dhcp_ttl`. `crec_ttl` returns the stored TTL for any `F_IMMORTAL`
    record; C additionally applies a lease-length ceiling to `F_DHCP` entries
    (`rfc1035.c:1577-1585`).
  - `--max-ttl` as a *serve-time* ceiling. C applies it again in `crec_ttl()`
    (`rfc1035.c:1597`); the Rust port only applies it at insert time.
  - Zero-TTL answers. `really_insert` drops them; C caches them with `ttd == now` so they
    can be served once before going stale.
  - Cache lookups for record types `answer_request` does not consult. Only A, AAAA, CNAME,
    NXDOMAIN and PTR are read back out of the cache, so an upstream MX/TXT/SRV answer is
    cached as `F_RR` but re-forwarded on every query. The NODATA negative entry for such a
    query is likewise stored under `F_RR | F_NEG` and never probed — `lookup_forward` closes
    this only for the A and AAAA types that `answer_request` actually reads.
  - EDNS0 on a *locally generated* answer beyond re-attaching the OPT record: no client
    option (client-subnet, cookies) is parsed or echoed, and the advertised payload size is
    not used to size or truncate a locally generated answer. The relayed-reply path is
    covered separately, below.
  - `forward::tcp_fallback` / `tcp_query` still have no non-test caller, deliberately. They
    escalate a truncated UDP reply to TCP, which upstream does *not* do on the client's
    behalf — C relays the truncated reply and the client retries. They are also wired to
    resend the reply packet rather than the original query, so activating them as they stand
    would send a QR=1 packet upstream. The real gap is the missing TCP listener, above.

- [x] Wire `process_reply` into the live reply path (rebind, bogus-wildcard, rrfilter, EDNS0).
  `forward::process_reply` was an unreached copy of a *subset* of C's `process_reply()`; it
  never mutated the packet it was handed, so even the rebind branch it implemented could not
  have taken effect. It is now the real thing, called once per accepted upstream answer from
  `run_forward_loop_on`, in C's order (`forward.c:696-889`): restore the client's CD bit →
  EDNS0 fix-up → clear `AD` / set `RA` → opcode and rcode gates → truncation gate →
  `--bogus-nxdomain` → `extract_addresses` (caching + rebind) → `--filter-rr` → DNSSEC RR
  strip → EDE option.

  Load-bearing details:

  - The per-query context C threads into `process_reply()` (`FREC_HAS_PHEADER`,
    `FREC_DO_QUESTION`, `FREC_AD_QUESTION`, `FREC_CHECKING_DISABLED`) is decided when the
    *client* asks, not when the answer arrives, so `ReplyAction::Deliver` now carries the
    completed `Frec`'s flags out of `accept_reply` — the record is freed there.
    `ReplyContext::from_flags` unpacks them.
  - `--ignore-address` is checked in `accept_reply`, not `process_reply`, because C checks it
    in `reply_query()` *before* the REFUSED/SERVFAIL failover (`forward.c:1228-1230`) and
    returns without freeing the frec: the reply is dropped but the query stays in flight, so
    an honest answer from another server can still be accepted.
  - `rrfilter.rs` is now a faithful port of the four-pass algorithm, not a byte-splice.
    Eliding records from the middle of a message invalidates every compression pointer past
    the first removal; upstream rewrites the survivors and abandons the whole operation if
    one points *into* an elided record (`rrfilter.c:23-155`). The previous implementation did
    neither, which was harmless while nothing called it and a corruption bug the moment
    something did.
  - `strip_dnssec_if_not_requested` no longer removes DNSKEY (C's `RRFILTER_DNSSEC` lists
    only RRSIG/NSEC/NSEC3) and keeps an answer-section record that is exactly what was asked
    for, so a query *for* RRSIG still gets one.
  - `check_for_bogus_wildcard` now matches AAAA as well as A — `--bogus-nxdomain` takes an
    IPv6 prefix (`option.c` case `'B'`) and `check_bad_address()` checks both — and takes the
    negative entry's TTL from the offending answer rather than `local-ttl`, which is what C
    does and why (`rfc1035.c:1406`: "there is no SOA record to get the ttl from").
  - That negative entry goes in through `DnsCache::really_insert`, not `insert`. C reaches it
    via `cache_insert()` (`cache.c:661-687`), which applies `--max-cache-ttl` /
    `--min-cache-ttl` clamping and then `really_insert()`'s zero-TTL rejection; inserting
    directly would have made both directives silent no-ops for every `--bogus-nxdomain` hit,
    and the entry is live — `answer_locally` serves it.
  - It is keyed on the owner name of the *matching* answer record, not the question name.
    C's `check_bad_address()` re-extracts `name` from every answer as it walks
    (`rfc1035.c:1332`), so the buffer the caller passed holds the offending record's owner
    when it returns 1 — behind a CNAME that is the chain target.
  - The DNSSEC halves are gated on `--dnssec` (`OPT_DNSSEC_VALID`) exactly as C gates them.
    Without it, C neither resets the DO bit nor strips DNSSEC RRs, so neither do we.
  - `rrfilter()` bails out untouched unless the packet has exactly one question
    (`rrfilter.c:173-175`); `filter_with` now matches (`hdr.qdcount != 1` short-circuits before
    any elision decision), rather than generalizing to arbitrary question counts.
  - `filter_rr_types` (the EDNS0-mode entry point, used to strip a self-added OPT record) now
    only considers the additional section, matching `i < ancount+nscount || type != T_OPT`
    (`rrfilter.c:200-205`); it previously matched by TYPE alone across all three sections, which
    only differs from upstream if an adversarial/malformed upstream reply places a type-41 RR
    in the answer or authority section.
  - `tests/proptest_rrfilter.rs` covers the "filtering never corrupts a surviving compression
    pointer" property across all three entry points. Note for future property tests on this
    module: `DnsPacket::parse(..).is_ok()` alone is too weak an oracle — `parse_rr` swallows a
    bad in-RDATA pointer and falls back to the raw (still-corrupt) bytes instead of erroring, so
    a mis-rescaled pointer can still "parse". The property has to decode the surviving pointer
    and check it resolves to the right name, not just that parsing succeeds.

  Left as a **literal**, not behavioral, parity gap:

  - Upstream's `to_wire()`/`from_wire()` (`rrfilter.c:356-412`) convert between presentation and
    wire name forms and are used for DNSSEC canonicalization (`dnssec.c`) and for
    `daemon->workspacename` handling (`rfc1035.c:578,952`). `rrfilter.rs` has no equivalent
    function — `dnssec.rs` has its own independent `name_to_wire` that covers the DNSSEC
    canonicalization use, so there is no live behavioral gap from `rrfilter()`'s side, but
    nothing in `rfc1035.rs` covers the `workspacename` use, and no upstream-hosted
    `to_wire`/`from_wire` pair exists in this crate.

  Explicitly **not** covered on this path:

  - `do_doctor` (`--alias` address rewriting) is implemented in `rfc1035.rs` and still has no
    caller. C runs it between the NXDOMAIN→NODATA conversion and the bogus-wildcard check
    (`forward.c:806-807`).
  - The NXDOMAIN→NODATA conversion for a locally-known name (`forward.c:795-804`). Needs
    `check_for_local_domain` plus a `lookup_domain(F_CONFIG)` equivalent.
  - `is_sign`. C leaves the pseudoheader and the `AD` bit alone when the reply carries a
    TSIG/SIG(0) record; there is no TSIG support here, so the check is unconditional.
  - `--add-subnet` reply verification (`check_source()`, `forward.c:727-731`) is now wired:
    `edns0::check_source` (a faithful two-mode port, replacing the old ad hoc
    `verify_ecs_reply`) is called from `forward::process_reply`, gated on the new
    `ForwardConfig::client_subnet`/`add_subnet4`/`add_subnet6` (threaded from `Daemon` in
    `dnsmasq::daemon_forward_config`), against `ReplyContext::query_source` (the primary
    client's address, C's `frec->frec_src.source`). `process_reply` now returns `bool`
    (`false` = discard outright) and the reply loop in `run_forward_loop` skips delivery
    when it does. `edns0::calc_subnet_opt` (port of `edns0.c:350-407`, including the
    `add_subnet4`/`add_subnet6` constant-address override and its cacheability rule) backs
    both `check_source` and the query-construction side. Still not wired: the *outgoing*
    side. `edns0::add_edns0_config`/`add_client_subnet`/`add_mac`/`add_dns_client`/
    `add_umbrella_opt`/`edns0_needs_mac` are ported (pure functions, fully unit-tested
    against upstream's field-by-field wire format and cacheability rules) but nothing calls
    them yet — there is no call site in the forward path that builds an outgoing query's
    EDNS0 options at all (`--add-subnet`, `--add-mac`, `--mac-base64`/`--mac-hex`,
    `--add-cpe-id`, `--umbrella` all remain no-ops on the request side), so `FREC_NO_CACHE`
    is still never set. `Daemon::umbrella_org`/`umbrella_asset`/`umbrella_device` now exist
    and are populated by the `umbrella` directive's `orgid:`/`assetid:`/`deviceid:`
    sub-options (Issue #56/T3-daemon-struct; see the "Issue #18 / Issue #56" entry
    elsewhere in this file) — `add_umbrella_opt` still takes them as plain parameters
    rather than reading `Daemon` directly, so a real caller only needs to thread
    `daemon.umbrella_org`/`umbrella_asset`/`umbrella_device` through once the
    outgoing-query path exists.
  - ipset kernel population is now wired end to end: `rfc1035::extract_addresses` matches the
    query name against `ExtractConfig::ipsets` (a local `domain_find_sets`, duplicating
    `forward::domain_find_sets`/`IpSet` — nothing constructs an `IpSet` from parsed config,
    so unifying the two types is still follow-up work) and reports every matched A/AAAA address
    via `ExtractOutcome::ipset_hits`; `forward::cache_upstream_reply` now calls
    `ipset::add_to_ipset` for each hit (feature = `ipset`, Linux only), which sends the
    `IPSET_CMD_ADD` built by the existing `ipset::build_ipset_msg`, mirroring
    `add_to_ipset()`/`new_add_to_ipset()` (`ipset.c:104-141,177-193`) fire-and-forget (no ACK is
    awaited, matching upstream). Off Linux or without the `ipset` feature, the match is still
    logged via `tracing::debug!` so it stays observable. `ipset::ipset_init()` now ports the
    new-kernel half of `ipset_init()` (`ipset.c:86-100`): it opens and binds one persistent
    `NETLINK_NETFILTER` socket, called from `dnsmasq::init_daemon_with` when `daemon.ipsets` is
    non-empty (mirroring `dnsmasq.c:352-358`), and every `add_to_ipset` call reuses that socket
    when present, falling back to a per-call socket otherwise (e.g. `ipset_init` was never
    called, or failed). Unlike upstream's `die()` on socket failure, `ipset_init` returns `Err`
    for the caller to log; this port doesn't kill the whole daemon over an ipset socket failure,
    and every call site still degrades to the working per-call fallback. Not ported: the
    pre-2.6.32 `SOL_IP`/`getsockopt` fallback (`old_kernel` in `ipset.c` — this crate tracks no
    `kernel_version` to gate it on). `ipset::parse_ipset_list` (parses `/proc/net/ip_set`) has no
    upstream counterpart and no caller anywhere in the crate — it's invented, documented as such
    in its doc comment, and kept only as a potential building block for a future startup sanity
    check that has not been implemented.

  - **nftset now uses upstream's real mechanism (libnftables FFI), not raw netlink.** The
    previous `nftset.rs` built a raw `NEWSETELEM` nfnetlink message with attribute numbers that
    were, by its own comment, "simplified" and did not correspond to real `NFTA_*` constants, and
    never sent it anywhere — a different mechanism from upstream, which never opens a netlink
    socket itself (`nftset.c`, `#include <nftables/libnftables.h>`). `nftset.rs` is now a thin
    hand-written FFI binding to the five libnftables entry points `nftset.c` actually calls
    (`nft_ctx_new`, `nft_ctx_free`, `nft_ctx_buffer_error`, `nft_run_cmd_from_buffer`,
    `nft_ctx_get_error_buffer`) — declared directly rather than via `bindgen`, since the surface is
    small and stable, so no header dependency is added, only a link-time one. `build.rs` (new)
    links `libnftables` when the `nftset` feature is enabled and the target is Linux; it falls back
    to symlinking a versioned runtime-only install (no `-dev` package, just `libnftables.so.*`)
    into `OUT_DIR` when no unversioned `libnftables.so` is found, since a bare `-lnftables` only
    ever looks for the unversioned name. `add_to_nftset(setname, addr, flags, remove)` formats the
    exact `"add element <set> { <ip> }"` / `"delete element <set> { <ip> }"` text upstream sends
    (`nftset.c:28-29,64-79`), strips a `"4 "`/`"6 "` family prefix and filters by `F_IPV4`/`F_IPV6`
    before running anything (`nftset.c:53-62`), and on a non-zero return, logs and returns the
    first line of libnftables' own error buffer (`nftset.c:82-95`) instead of dropping it. `nftset=`
    config parsing is wired in (`option::parse_nftset`, sharing `option::parse_ipset`'s syntax and
    `struct ipsets` storage, differing only in the `#`→space substitution `option.c:3268-3271`
    applies per set-name token) into a new `Daemon::nftsets`, threaded through
    `ExtractConfig::nftsets`/`ForwardConfig::nftsets` in lockstep with the existing `ipsets` fields;
    `rfc1035::extract_addresses` reports matches via `ExtractOutcome::nftset_hits`, and
    `forward::cache_upstream_reply` calls `nftset::add_to_nftset` for each hit (feature = `nftset`,
    Linux only), mirroring the `ipset_hits`/`add_to_ipset` dispatch added for ipset.

    Divergences kept, documented as efficiency-only (observable behavior is unaffected): upstream
    keeps one `static struct nft_ctx *ctx` for the process lifetime, created once by
    `nftset_init()` at startup (`dnsmasq.c:365`) and reused by every `add_to_nftset()` call; this
    port creates and frees a context per call instead (the same shape `ipset::open_ipset_socket`
    already uses for its per-call netlink socket instead of a persistent one) — so there is no
    `nftset_init()` call from `dnsmasq.rs` at startup, and no `need_cap_net_admin` signal
    (`dnsmasq.c:362-368`) is set for it. Not ported at all: `libnftables`'s own JSON/native output
    modes and anything beyond the five functions `nftset.c` calls — this binding is intentionally
    narrow to that surface, not a general libnftables wrapper.
  - `find_soa` (`rfc1035.rs`, port of `rfc1035.c:519-650`) does not apply DNSSEC TTL capping
    from a per-answer signature-validity array (`daemon->rr_status[i + ancount]`,
    `rfc1035.c:609-618`) — that array does not exist anywhere in the DNSSEC path yet
    (`grep rr_status` finds nothing outside upstream C), so capping it here in isolation would
    be unverifiable. It does now: verify the SOA's owner name is a byte suffix of the queried
    name before using it (`rfc1035.c:554-556`), and cache the SOA RR itself as `F_RR|F_KEYTAG`
    (`rfc1035.c:620`).
  - `log_txt` (`rfc1035.rs`, port of `rfc1035.c:653-682`) truncates each TXT string at its first
    non-printable byte and logs via `tracing::debug!` per string, called from
    `extract_addresses`'s TXT branch. `answer_request`'s local-config TXT branch (`rfc1035.c`'s
    second `log_txt` call site, serving from cache/local data) still does not call `log_txt`, so
    TXT answers built from `--txt-record` are not logged the way a forwarded TXT reply is — this
    is unrelated to `log_query` below, which now exists and is wired into the same branch.
  - **`log_query` (Issue #23 / T3-cache) — implemented in `cache.rs`, wired into every query
    processed by the client-facing forward loop plus a representative subset of local-answer
    call sites, not exhaustive.** `crate::cache::log_query` is a faithful, unit-tested port of
    `cache.c:2311-2500` (all `OPT_LOG`/`OPT_LOG_ONLY_FAILED`/`OPT_AUTH_LOG` gates, the full
    `source`/`name`/`verb`/`dest`/`extra` flag matrix including `F_IPSET`, `F_KEYTAG`,
    `F_RCODE`+EDE, `F_REVERSE`, the `OPT_EXTRALOG` two-branch format) — see
    `cache::tests::log_query_*`. It is a pure function returning `Option<String>`
    (`LogQueryOptions` gates it, no hidden global state) rather than calling `my_syslog`
    directly, so callers own emission; `rfc1035::answer_request` wires it into: the config/cached
    CNAME chain, cached NXDOMAIN, local TXT/MX/SRV/NAPTR records, the arbitrary cached-RR branch
    (`--dns-rr`, `t.class` passed as the type argument matching `rfc1035.c:1783`'s `t->class`),
    host_records and cached A/AAAA (positive and negative), PTR from host_records/cache,
    `--domain-needed`'s local NXDOMAIN/NOERR decision, and the new CHAOS NOTIMP fallback.
    `forward.rs` (the dominant real-world path — a fresh, uncached query that gets forwarded)
    now logs the three points `forward.c`'s `udp_request()`/`process_reply()` do: every incoming
    client query (`F_QUERY[|F_CONFIG]`, `run_forward_loop_on`'s query-receipt branch, mirroring
    `forward.c:1826-1834`), every query actually sent upstream (`F_SERVER`,
    `ForwardEngine::send_upstream`, only once the send succeeds, mirroring `forward.c:541-557`),
    and a non-NOERROR/NXDOMAIN or truncated upstream reply (`F_UPSTREAM[|F_RCODE]`,
    `process_reply`, mirroring `forward.c:781-792`). `forward::log_query_mysockaddr` — previously
    dead code with only its own unit tests as callers — now has a real caller via
    `forwarded_query_log_line`, which reuses it for the family-flag/port-as-rrtype computation
    before handing the result to `crate::cache::log_query`. **Still not wired**: a cache *hit*
    inside the forward loop (`answer_locally`'s success path currently reaches `answer_request`,
    which does log — but a hit served by `forward.rs`'s own `cache_upstream_reply`/extract path
    on a *subsequent* identical forwarded query does not re-log per-record); `dnssec.rs`/`auth.rs`
    validation-result logging (`F_SECSTAT`/`F_DNSSEC`); ipset/nftset match logging (`F_IPSET`,
    logic ported and tested but no live call site); the freeform `ptr_records` branch (no clean
    address to attach); ANY of the auth-server (`auth.rs`) answer paths; DNSSEC retry logging
    (`F_DNSSEC`, `forward.c:560-561`, since DNSSEC retry queries are not implemented). `log_query`'s
    `id`/`source_addr` parameters (the `OPT_EXTRALOG` `<id> <addr>/<port>` prefix) are always
    passed `0`/`None` from every call site — there is no per-transaction display-id counter
    threaded through yet, so extralog output is well-formed but the id is always `0`.
  - **`record_source` (Issue #23 / T3-cache) — implemented.** `crate::cache::record_source`
    ports `cache.c:2190-2215`: a `uid -> file path` registry populated by `load_hosts_file`
    (every hosts-format file this port loads, `/etc/hosts` included, goes through it with its
    own path, so a flat map is equivalent to C's `SRC_CONFIG`/`SRC_HOSTS`/`addn_hosts`-list
    lookup) and consulted by `record_source`, falling back to `"<unknown>"` for an unregistered
    `uid` exactly as C does. `rfc1035::answer_request`'s five cached-lookup `log_query` call
    sites (cached CNAME, cached NXDOMAIN, PTR-from-cache positive match, and A/AAAA-from-cache
    positive match) now thread the record's `uid` through `cached_answer_source_arg` instead of
    always passing `None`, matching C's `record_source(crecp->uid)` at `rfc1035.c:1690,1710,1898,
    2077` call-for-call — including which branches get it (positive answers) and which don't
    (negative/NXDOMAIN branches at `rfc1035.c:1889,2063` pass `NULL` in C too). Previously an
    `/etc/hosts`- or `--addn-hosts`-sourced answer logged via `--log-queries` had an empty source
    field instead of naming the file; see `cache::tests::record_source_*` and
    `rfc1035::tests::cached_answer_source_arg_*` / `answer_request_a_record_from_hosts_file_*`.
  - **Transactional insert (Issue #23 / T3-cache) — implemented.** `DnsCache::start_insert` /
    `stage_insert` / `end_insert` (`cache.rs`) port `cache_start_insert`/`cache_insert`/
    `cache_end_insert` (`cache.c:646-905`): a sticky `insert_error` flag makes every `stage_insert`
    after the first failure a no-op, and `end_insert` discards the *whole* batch when any record
    in it failed, instead of the previous behaviour where `rfc1035::commit_staged` committed each
    staged record independently via `really_insert` in a loop (so a CNAME ahead of a rejected
    terminal record stayed live, pointing at nothing). `commit_staged` now uses the transactional
    API. `really_insert` still exists as a single-record transaction (used by the one remaining
    direct caller, the SOA negative-cache insert in `answer_request`'s domain-needed path, and by
    ~15 existing unit tests) and is unaffected by any concurrently-open `stage_insert` batch.
  - **`is_outdated_cname_pointer` (Issue #23 / T3-cache) — implemented, exercises a code path no
    current caller reaches.** `DnsCache::is_outdated_cname_pointer` ports `cache.c:449-462` and is
    applied inside `end_insert`. Every CNAME this crate constructs sets `CnameAddr::is_name_ptr =
    true` (the target is always resolved by a fresh name lookup, never a cached raw pointer into
    another `crec` slot), so the stale-pointer bug class C guards against cannot occur through any
    real call site today — the `is_name_ptr == false` branch (checked against `uid`/target
    liveness) is implemented and unit-tested (`pointer_cname_with_stale_uid_is_dropped`,
    `pointer_cname_with_missing_target_is_dropped`) but currently dead code, kept for parity if
    that representation is ever added.
  - **`cache_make_stat` / built-in `.bind` stat TXT records (Issue #23 / T3-cache) — partially
    implemented.** `crate::cache::cache_make_stat` ports `cache.c:1906-1996` for
    `cachesize.bind`/`insertions.bind`/`evictions.bind`/`misses.bind`/`hits.bind` (dynamic TXT
    content from the live `METRIC_DNS_CACHE_INSERTED`/`METRIC_DNS_CACHE_LIVE_FREED`/
    `METRIC_DNS_QUERIES_FORWARDED`/`METRIC_DNS_LOCAL_ANSWERED` counters, matching upstream's own
    somewhat confusing naming — `misses.bind`/`hits.bind` are forwarded-vs-locally-answered query
    counts, not literal cache hit/miss counts, upstream included). `dnsmasq::daemon_local_data`
    registers these five as CHAOS-class synthetic TXT records unless `--no-ident` is set
    (`option.c:6097-6113`), and `answer_request`'s TXT branch (now reachable for CHAOS queries —
    see below) renders them dynamically with `ttl=0`, matching `rfc1035.c:1736-1743`. **Not
    ported**: `version.bind`/`authors.bind`/`copyright.bind` (static text, unrelated to caching —
    no `TXT_STAT_*` involved, just plain `add_txt` calls) and `TXT_STAT_AUTH`/`TXT_STAT_SERVERS`
    (need an auth-query counter and per-upstream-server query/failure counters this crate does not
    track anywhere yet).
  - **CHAOS-class query handling fixed as a side effect of the above.** `answer_request` used to
    special-case `qclass == 3` before any local-answer attempt and always return NOTIMP for
    `*.bind`/`*.server`-suffixed names, which meant a configured CHAOS TXT record (or the new
    built-in stat records) could never actually answer a CHAOS query — dead code from the moment
    any CHAOS TXT record existed. It now matches upstream's real structure (`rfc1035.c`: local-data
    branches run for both IN and CHAOS, gated per-section by `qclass == C_IN` only where C gates
    them; the CHAOS NOTIMP fallback runs last, only `if !ans`). One upstream quirk is preserved
    deliberately, not fixed: the NOTIMP fallback calls `hostname_issubdomain("bind", name)` with
    the arguments in the opposite order from every other call site in C, so it only matches the
    literal names `"bind"`/`"server"`, never an actual `*.bind` subdomain query — see the comment
    at the call site in `answer_request` for the full trace. Also fixed in passing: the TXT
    answer's wire-format `class` field was hardcoded to `1` (IN) even when serving a CHAOS-class
    record, which would have produced a malformed CHAOS reply the first time this path became
    reachable.
  - `check_for_local_domain` now checks `daemon->int_names` (`--interface-name`) for a
    domain-suffix match, matching upstream — but only for the domain-needed NOERR/NXDOMAIN
    decision. Actually *answering* an A/AAAA/PTR query for an interface-name domain with the
    interface's runtime address (upstream's other `int_names` consumers) is not implemented
    anywhere in this crate; `daemon.int_names` is parsed and now read once, but never turned
    into a real answer.
  - The reply is not sized against each client's advertised `udp_pkt_size`, so C's
    per-`frec_src` truncation fallback (`forward.c:1463-1475`) has no equivalent — this port
    also never rewrites the payload size on the *outgoing* query, so it forwards whatever the
    client advertised.
  - `--rebind-domain-ok` only accepts a plain domain. C strips a leading `/` and splits the
    rest on `/` (`option.c` case `LOPT_NO_REBIND`), so `rebind-domain-ok=/lan/` is stored here
    as one literal domain named `/lan/` and matches nothing. `parse_rebind_domains` splits on
    `,` instead. Fixing it is an `option.rs` change, tracked here so the misparse is not
    mistaken for a reply-path bug.

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
  - `src/log.rs` now has a real syslog client (Issue #51 / T3-log): a non-blocking
    `AF_UNIX SOCK_DGRAM` connection to `/dev/log` (falling back to `SOCK_STREAM` on
    `EPROTOTYPE`), a `max_logs`-bounded queue with the `EAGAIN`/`EPIPE`/`ECONNREFUSED`/
    `ENOTCONN`/`EDESTADDRREQ`/`ECONNRESET`/`ENOBUFS` recovery state machine from
    `log_write()` (log.c:164-284), and the exponential nanosleep-backoff retry from
    `my_syslog()` (log.c:406-442). With no `--log-facility`, output now reaches the real
    syslog socket by default (previously it reached nowhere but stderr/tracing).
    `--log-facility=<name>` (`daemon`, `local0`, …) is looked up against a facility table
    and sets `daemon.log_fac`; `--log-facility=<path-or-->` still sets `daemon.log_file`
    (`option.c:2279-2298`). A permanently unreachable/closed socket falls back to a
    blocking `openlog()`/`syslog()` call, matching `my_syslog`'s `log_fd == -1` branch —
    the one place either implementation deliberately blocks.
    `set_log_writer`/`check_log_writer` are wired to `forward.rs`'s existing 1-second
    ticker rather than to `POLLOUT` fd-readiness (no generic poll-registration exists to
    hook into); since every write is already non-blocking this costs at most one tick of
    latency, never correctness. Still not ported: `fchown`-ing a log file to the run user,
    `log-facility=-` duplicating `STDERR_FILENO` instead of being treated as a filename
    named `-`, and the Android/Solaris branches (`__android_log_vprint`, the
    `HAVE_SOLARIS_NETWORK` no-socket path) — all deliberately out of scope for a
    Linux-only port.
  - `my_syslog` output now passes through the `tracing` `EnvFilter`, so `RUST_LOG` can
    suppress records upstream would always write. Upstream filters only on `MS_DEBUG`.
    This is additive, not a replacement: the real `/dev/log` delivery above happens
    regardless of what `tracing`/`RUST_LOG` does with the same message.
  - Solaris `priv_set`/`setppriv` (`dnsmasq.c:775-795`) is deliberately out of scope; the
    capability path is Linux-only and other platforms just `setgroups`/`setgid`/`setuid`.
  - `helper::create_helper` (a real port of `create_helper`, helper.c:79-691: forks a
    child, drops that child's privileges to `script-user`/`script-group` via
    `setgroups`/`setgid`/`setuid` *before* it reads anything off the pipe, then loops
    exec'ing `dhcp-script` per event) exists and is unit-tested, but startup
    (`dnsmasq.rs`/`main.rs`) does not call it yet — so today's real privilege-drop path
    still does not fork a separate-uid helper the way `dnsmasq.c:744` does ahead of its own
    `drop_root()`. See the dedicated `helper.rs` entry below for the current state and
    remaining gaps in that module itself.
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

- [x] `helper.rs`: fork a privilege-dropped script helper, replacing the two invented,
  mutually-inconsistent wire formats that used to live there (a newline-delimited text
  format and an ad hoc binary `queue_script` layout, neither resembling `struct
  script_data`) with `ScriptData` — one explicit, versioned binary encoding (a fixed
  104-byte header + a `clid ++ NUL-terminated hostname ++ extradata` blob, mirroring
  `queue_script`'s own packing order at helper.c:829-844). `create_helper` forks a child
  that ignores SIGTERM/SIGALRM/SIGINT, drops to `script-user`/`script-group` via
  `setgroups(&[])`/`setgid`/`setuid` *before* it reads anything off the pipe (helper.c:100-127),
  then loops reading `ScriptData` events and running `dhcp-script` for each — inheriting the
  already-dropped privileges rather than execing with the daemon's own, closing the
  regression the issue flagged. The old in-process, non-forked `run_script()` is gone.
  Root-gated test `create_helper_drops_privileges_in_child` asserts the forked child's
  reported uid/gid actually differ from root; `parent_is_not_blocked_by_a_hanging_script`
  and `parent_survives_helper_child_crashing` assert the caller only ever does a pipe
  `write()` and is never blocked on or brought down by the script it queued. The child
  also closes every fd it inherited from the main process (sockets, log files, ...)
  before touching the pipe or exec'ing anything — `close_inherited_fds`, a port of
  `close_fds()` (util.c:789) called at helper.c:134 — so a compromised script can't reach
  those fds even though it inherits the process's open-fd table across `fork()`;
  `create_helper_child_does_not_leak_unrelated_fds_to_script` asserts this end-to-end and
  `close_inherited_fds_closes_unrelated_descriptors` covers the helper in isolation.
  `DNSMASQ_LOG_DHCP` (helper.c:667, `option_bool(OPT_LOG_OPTS)`) is threaded through as a
  `log_dhcp: bool` parameter on `create_helper`/`run_helper_loop`/`run_script_child` and
  set last in the lease-action env block, matching upstream's ordering.

  Explicitly **not** covered — upstream behavior still missing:

  - `run_dhcp_loop` (dhcp.rs) does call `LeaseDb::run_lease_scripts` every dispatch, and it
    does build a real `ScriptData::for_lease` and run it via `helper::run_script_child` — a
    real, synchronous, in-process execution (Issue #31 / T3-lease). `dhcp-script`/
    `dhcp-scriptuser` are not a no-op.
    Still missing: nothing calls `create_helper`/`HelperHandle::send`. `dnsmasq.rs`/
    `main.rs` startup does not fork the persistent privilege-dropped helper process ahead of
    the main privilege drop (`dnsmasq.c:744`), so every script still runs in the
    (already-privilege-dropped) main process rather than the dedicated child — no privilege
    boundary is crossed incorrectly, but a slow/hanging script blocks the DHCP dispatch loop
    the way upstream's async pipe-fed helper is specifically designed to avoid. `lease.rs`'s
    `rerun_scripts` (lease.rs:480) only flips the per-lease flags `run_lease_scripts` acts on
    (by design — SIGHUP-triggered "re-announce everything" support); it never calls a script
    itself. Same "runs inline, not via the persistent helper" gap applies to any future
    ARP/TFTP call sites.
  - Lua scripting (`grab_extradata_lua`, `daemon->luascript`, helper.c:136-175,319-498) is
    deliberately out of scope, per the issue.
  - The DHCPv6-specific env vars/argv (`DNSMASQ_IAID`, `DNSMASQ_SERVER_DUID`, the
    per-vendorclass `DNSMASQ_VENDOR_CLASS_ID`/`DNSMASQ_VENDOR_CLASSn` loop, and the DUID
    string used as argv[2] instead of the MAC for `is6` lease events) are not built — the
    IPv4 lease path (`ACTION_ADD`/`ACTION_OLD`/`ACTION_DEL`) has full argv/env fidelity;
    the `is6` case falls back to formatting `addr6`/an empty MAC field rather than the DUID.
  - No `event_fd`/`err_fd` channel back to a main process (helper.c's `send_event` for
    `EVENT_SCRIPT_LOG`/`EVENT_EXITED`/`EVENT_KILLED`/`EVENT_USER_ERR`/`EVENT_DIE`): script
    stdout/stderr and nonzero exit/signal status are logged locally via `tracing` instead of
    forwarded to the (not-yet-existing) caller, and a failed privilege drop just exits the
    helper rather than killing the main daemon the way `EVENT_DIE` does.
  - `helper_write`'s non-blocking, buffered, partial-write-tolerant queue
    (helper.c:927-946) is not reproduced; `HelperHandle::send` does a blocking
    `write_all`. Fine for the event sizes here (well under `PIPE_BUF`), but a future
    integration into `run_main_loop`'s poll loop should restore the non-blocking queue
    before large `extradata` blobs become possible.

- [x] Apply `--interface` / `--except-interface` / `--listen-address` to the DNS listeners.
  `run_main_loop` used to bind a single `0.0.0.0:{port}` socket and never read
  `daemon.if_names`, `if_except` or `if_addrs`, so a config that named one LAN interface
  listened on every interface — and `network::create_listeners`, `create_bound_listeners`,
  `iface_allowed_v4`/`_v6` and `iface_check` had no non-test callers at all.

  `dnsmasq::bind_dns_listeners` now mirrors the dispatch in `dnsmasq.c:378-409`:

  - `--bind-interfaces` and `--bind-dynamic` are rejected together (`dnsmasq.c:378-379`).
  - `network::enumerate_allowed_interfaces` walks `getifaddrs(3)` and offers every address
    to `iface_allowed_v4`/`_v6`, which apply the `--interface`/`--except-interface`/
    `--listen-address` filter and record the `INAME_USED` equivalent. It also ports
    `network.c:500-519`: when `--interface` is given at all, loopback interfaces are added
    to the allowed set, so a restricted box can still resolve names for itself. That rule
    keys off `if_names` alone — a bare `--listen-address` does *not* pull loopback in.
  - Bound mode (`--bind-interfaces`/`--bind-dynamic`) binds one socket per allowed address
    via `create_bound_listeners`, plus one per `--listen-address` that no interface carries
    (`network.c:1219-1233`). Under plain `--bind-interfaces` an unmatched `--interface` is
    fatal with "unknown interface %s" (`dnsmasq.c:396-398`); `--bind-dynamic` tolerates it.
  - Default mode binds the two wildcard sockets via `create_wildcard_listeners`.
  - **Every mode hands the query loop a `network::ArrivalFilter`**, because binding an
    address is not by itself access control: a query addressed to an internal interface can
    still arrive via an external one. `run_forward_loop_on` reads each datagram with
    `recvmsg` + `IP_PKTINFO`/`IPV6_PKTINFO` (`network::recv_with_dest`) and re-applies
    `iface_check`, with the `loopback_exception` and `label_exception` fallbacks, exactly as
    `udp_request()` does at `forward.c:1771-1780`. Which listeners consult it is upstream's
    `check_dst = !option_bool(OPT_NOWILD) || family == AF_INET6` (`forward.c:1612`), carried
    per socket as `BoundDnsSocket::check_dst` / `DnsListener::check_dst`:
      - default (wildcard) mode — both families checked;
      - `--bind-dynamic` (`OPT_CLEVERBIND`, *not* `OPT_NOWILD`) — both families checked.
        This is the whole point of the option: `network.c:1240-1250` says so in as many
        words ("The fix is to use `--bind-dynamic`, which actually checks the arrival
        interface too");
      - `--bind-interfaces` (`OPT_NOWILD`) — IPv6 checked, IPv4 not. IPv4 is the only case
        where upstream gives the check up, and `warn_bound_listeners` exists precisely to
        shout about it.

    `make_sock`'s `nowild` argument is therefore the *global* `OPT_NOWILD`, matching
    `network.c:962`, and not "is this socket address-bound": `--bind-dynamic`'s per-address
    sockets still request `IP_PKTINFO`, which is what makes their arrival check possible.
    Without all of this, `--listen-address` could not work in the default mode, and
    `--bind-dynamic` would be indistinguishable from `--bind-interfaces`.
  - A `bind()` failure is never silently swallowed. `network.c:900-905` exempts
    `EPROTONOSUPPORT`/`EAFNOSUPPORT`/`EINVAL` for the `socket()` call only; everything after
    it reaches `goto err` and `die()`. `make_sock` tags the socket-creation error so
    `create_listeners_checked` can apply the exemption where upstream does and nowhere else
    — an errno-only test would swallow, for instance, the `EINVAL` from binding a link-local
    address with no scope id.

  `iface_check` itself was previously name-only; it now implements the full
  `network.c:112-181` algorithm including address matching and the `match_addr` rule that
  lets an explicit `--listen-address` outrank `--except-interface`. `loopback_exception`
  was a one-line `addr.is_loopback()` and is now the real check (arrival interface is
  loopback *and* the destination is an address we serve).

  The forward loop takes N sockets instead of one (`poll_recv_ready` across all of them,
  rotating to avoid starvation) and each in-flight query records which listener it arrived
  on so the reply leaves by the same socket. `run_main_loop_with` no longer has its own
  `0.0.0.0:{port}` fallback bind: when it is handed no listeners it calls `bind_listeners`,
  so there is one code path deciding what the daemon listens on.

  Explicitly **not** covered — upstream behavior still missing:

  - **TCP listeners are not created.** `ListenerKinds::UDP_ONLY` is passed everywhere,
    because there is no TCP DNS serving loop; binding a listening TCP socket that nothing
    `accept()`s would open a port that silently swallows connections. Upstream binds the
    UDP/TCP pair. Whoever adds TCP DNS service must flip this and add a TCP accept loop.
    TFTP listeners (`OPT_TFTP` → `iface->tftp_ok`) are likewise not created; `tftp_ok` is
    computed by `iface_allowed_*` and then discarded.
  - **Replies are sent with `send_to`, not `send_from`.** Upstream answers a wildcard-socket
    query from the datagram's recorded destination address via `IP_PKTINFO` on the way out
    (`forward.c` `send_from`); here the kernel picks the source by route lookup, which can
    differ on a multi-homed host. `forward::send_from` exists and is tested but has no
    caller.
  - **`--bind-dynamic` does not actually re-bind.** Its arrival check is wired up (see
    above), but the dynamic half is not: there is no netlink listener re-running
    `create_bound_listeners` when an interface appears, and no
    `RTM_NEWADDR`/`RTM_DELADDR` handling. `is_dad_listeners`/DAD-tentative deferral
    (`network.c:1300`) is absent too, so an IPv6 address still in DAD is bound or skipped
    by whatever `getifaddrs` reports rather than retried.
  - **IPv6 link-local addresses are never enumerated, so no link-local listener is bound.**
    `enumerate_interfaces()` goes through `if_addrs::get_if_addrs()`, which drops
    `fe80::/10` addresses; upstream's `iface_enumerate` reports them and
    `create_bound_listeners` binds one per interface. `IfaceRecord::listen_addr` already
    carries the interface index into `sin6_scope_id` for link-local addresses as
    `iface_allowed_v6` does (`network.c:617-620`) — without it Linux rejects the bind with
    `EINVAL` — so only the enumeration source has to change. Pinned by
    `enumeration_omits_ipv6_link_local_addresses` in
    `tests/listener_binding_integration.rs`, which fails once enumeration reports them.
  - **The interface set is never garbage-collected.** `clean_interfaces` has no caller;
    `ArrivalFilter::refresh` re-enumerates on a failed check (matching upstream's
    `enumerate_interfaces(0)` retry) but nothing releases listeners for addresses that went
    away (`release_listener`).
  - **`--local-service` (net) is not enforced.** `--local-service=host` works, because
    `option.rs` lowers it to a NULL-named `--interface` plus `OPT_NOWILD` as upstream does,
    and that path now reaches real listeners. Plain `--local-service` needs the
    `daemon->interface_addrs` subnet-membership check on the *source* address
    (`network.c:272`, `forward.c:1672`), which is not implemented — the option is parsed
    and normalised but has no runtime effect.
  - **`--auth-server` interfaces are ignored.** `iface_check`'s `auth` output parameter
    (`network.c:153-179`) is not ported, so `iface->dns_auth` is always false and
    `--auth-zone` interface names do not affect which queries are served.
  - **Interface labels/aliases (`eth0:0`) are not enumerated.** `if-addrs` reports no label,
    so `iface_allowed_v4` is always called with `label: None` and `is_label` is always
    false. `label_exception` is wired into the arrival check but can only match on index +
    address, never on a genuine alias name. `warn_wild_labels`/`warn_int_names`/
    `warn_bound_listeners` (the "LOUD WARNING" for globally-routable `--bind-interfaces`
    addresses, `network.c:1240-1275`) have no Rust equivalent.
  - **DHCP socket binding is unchanged.** `bind_dhcp_socket_to_device` still picks the
    first non-wildcard `--interface` name itself rather than going through the enumerated
    set; `whichdevice`/`bind_dhcp_devices` (`dnsmasq.c:400-405`) are not ported.
  - Capability-dependent assertions in `tests/listener_binding_integration.rs` skip rather
    than fail when the sandbox has no spare loopback aliasing or refuses the bind, so a
    restricted environment reports a pass it did not actually verify.

- [x] `src/netlink.rs`: fix the EPERM-only multicast-bind fallback and give `netlink_open` a
  runtime caller (issue #38).

  `netlink_open` used to retry the no-multicast bind on *any* first-bind failure
  (`EADDRINUSE`, `EINVAL`, `EACCES`, ...), silently masking errors upstream treats as fatal.
  `netlink.c:76-81` only retries when `errno == EPERM`; anything else is a hard failure. Fixed
  by capturing the first bind's `io::Error` and gating the fallback on a new pure
  `should_retry_without_multicast` (`err.raw_os_error() == Some(libc::EPERM)`), covered by
  `retries_without_multicast_only_on_eperm` / `does_not_retry_on_other_bind_errors`.

  `netlink_open`/`iface_enumerate`/`netlink_multicast` previously had zero production callers
  — `network::enumerate_interfaces()` uses the `if-addrs` crate and never touches this module.
  `dnsmasq::spawn_netlink_watch_task` (Linux-only; a no-op stub elsewhere) now opens a netlink
  socket at `run_main_loop_with` startup and drives `netlink::watch_address_changes` — an
  `AsyncFd`-based readiness loop around `netlink_multicast`/`nl_async` — as a background task,
  aborted alongside the forward/DHCP tasks on shutdown. On `STATE_NEWADDR` it re-runs
  `network::enumerate_interfaces()` and logs the refreshed count, mirroring upstream's
  `nl_async()` → `queue_event(EVENT_NEWADDR)` reaction (`netlink.c:406-411`). A netlink-open
  failure (no `CAP_NET_ADMIN`, non-Linux) is logged and treated as "no live notifications"
  rather than aborting startup, same as `slaac::Icmp6Socket::create`.
  `netlink_multicast_drains_and_detects_newaddr` proves the drain/dispatch wiring against a
  real socket (an `AF_UNIX` socketpair standing in for the netlink fd, since `netlink_multicast`
  only ever calls `recv()`).

  Explicitly **not** covered — the re-enumeration is observational only:
  - It does not feed the refreshed interface list into the live `network::ArrivalFilter` or
    rebuild bound listeners. That's the pre-existing `--bind-dynamic` re-bind gap noted above
    ("there is no netlink listener re-running `create_bound_listeners` when an interface
    appears") — this change opens the socket and detects the event, but does not yet close
    that gap.
  - `STATE_NEWROUTE`'s upstream purpose (re-send a queued DNS packet once a dial-on-demand
    route appears, `netlink.c:391-395`) has no consumer here; the watch task only logs it.
  - `iface_enumerate`/`parse_newneigh_record`/`parse_newlink_record` (ARP/DUID-MAC lookup via
    netlink) still have no caller; `arp.rs`/DHCPv6 DUID generation don't use them.

- [x] Randomise the outbound source port and unify the two pending-query implementations.
  `run_forward_loop_on` used to bind one `0.0.0.0:0` socket at startup and send every
  upstream query from it, so the whole daemon had a single, stable source port for its
  lifetime. A random transaction ID alone is 16 bits; C makes an attacker guess the port
  too by giving each in-flight query its own socket — `forward_query()` calls
  `allocate_rfd(&forward->rfds, srv)` for every send (`forward.c:528`) and `random_sock()`
  `bind()`s a fresh port whenever a slot in `daemon->randomsocks[]` is free
  (`forward.c:2782`).

  `RandFdPool` is now live and follows `allocate_rfd()`'s order: reuse one of *this*
  transaction's sockets only once it is at `randport_limit`, otherwise take a free pool slot
  and bind a new port, otherwise share a live socket for the same server, otherwise open a
  temporary socket outside the pool (C's `refcount == 0xffff` record). `free_rfds()` closes
  a socket as soon as its last query finishes. The pool is sized as `dnsmasq.c:427` sizes it
  (`ftabsize / 2`) and the reply arm of the loop polls the live set rather than one fixed
  socket, rotating the scan so a flooded port cannot starve the others.

  The rival pending-query types are gone: `PendingQuery`/`ForwardTable` (single client, no
  admission control) and the `reply_query` wrapper built on them were deleted, and
  `ForwardEngine` now drives the faithful `Frec`/`FrecSrc`/`FrecTable` port. That brings two
  behaviours the live path never had:

  - **Per-server-group admission control.** `forward_query` calls `get_new_frec(now, srv,
    force = false)`, so once `--dns-forward-max` queries are in flight to one group the next
    is answered REFUSED (`forward.c:369` → `setup_reply()` with no flags). `rfc1035::
    setup_reply` had NOERROR in that final `else`; it now sets REFUSED as
    `domain-match.c:430` does. `--dns-forward-max`/`--port-limit` reach the engine through
    `ForwardConfig::ftabsize`/`randport_limit`, and `Daemon::randport_limit` now defaults to
    1 (`option.c:5986`) instead of 0.
  - **Duplicate-client folding.** A second client asking the identical question within the
    frec's lifetime is appended as another `FrecSrc` instead of opening a second upstream
    transaction, and the single answer is fanned out to every waiting client under its own
    transaction ID (`forward.c:221-323`, `forward.c:1435-1440`). The `FrecSrc` budget is the
    same global `ftabsize` C uses, and exhausting it returns REFUSED. Queries less than two
    seconds old are not re-forwarded, matching `forward.c:315-318`.

    Folding is bounded by the query's EDNS0/DNSSEC context, not just its question.
    `fwd_flags_from_query` ports C's `fwd_flags` derivation (`forward.c:1867-1898`) —
    `FREC_HAS_PHEADER` from an OPT record found by `find_pseudoheader` (a port of
    `edns0.c:19`), `FREC_DO_QUESTION`/`FREC_AD_QUESTION` from the DO bit and header AD
    (RFC 6840 5.7), `FREC_CHECKING_DISABLED` from header CD — the result is stored on the
    `Frec` (`forward.c:373`), and `lookup_frec_by_question` requires *equality* on C's mask
    (`forward.c:3226`) before it will merge. Without that, a plain query folded onto a DO=1
    one would come back carrying an OPT record and RRSIGs it never asked for (RFC 6891
    §6.1.1 forbids the former), and the reverse would hand a validating stub an answer it
    cannot validate.

  The reply path checks *which socket* a datagram arrived on before anything acts on it —
  C's "Check that this arrived on the file descriptor we expected", which walks
  `forward->rfds` and returns if none matches (`forward.c:1178-1199`). `RandFdPool::sockets`
  yields each live socket with its slot index, the loop carries that index into
  `accept_reply`, and `validate_reply` requires it to be in the query's own `rfds`. This is
  what makes the per-query source port worth anything: without it an attacker need only land
  a forgery on *any* port the resolver currently holds open, not the one specific port
  belonging to the query being poisoned. (C's fallback to a server's bound `sfd` has no
  counterpart here because this port has no such sockets — every send goes through the pool.)

  SERVFAIL/REFUSED failover is also wired into the live loop for the first time
  (`forward.c:1242-1250`): `accept_reply` re-sends to the next untried server, on a new
  source port, instead of relaying the failure. `sent_at` is deliberately not refreshed on a
  retry, because C only ever sets `forward->time` in `get_new_frec()`.

  A REFUSED generated here re-attaches the client's pseudo-header when the query carried
  one, as C's `reply:` path does via `add_pseudoheader()` (`forward.c:595-601`), advertising
  our own payload size rather than echoing the client's. A query whose question cannot be
  read gets that REFUSED too, rather than being dropped: C sets `flags = 0` and jumps to the
  same `reply:` label (`forward.c:337-343`). The one case where C still says nothing is when
  `make_local_answer()`'s `skip_questions()` cannot walk the question section
  (`domain-match.c:429-430`); `make_refused_answer` returns `None` in exactly that case
  (`DnsPacket::parse` fails) and the loop sends nothing.

  `RandFdPool::sized_for` applies both halves of C's sizing rule — `numrrand = ftabsize/2`,
  capped at `sysconf(_SC_OPEN_MAX)/3` (`dnsmasq.c:426-429`). Without the cap a large
  `--dns-forward-max` would size the pool past the process fd limit and every `bind()` past
  it would fail, turning `allocate()` into `None` and refusing the client for no visible
  reason. Unlike C the result is floored at one slot, since a zero-slot pool would put every
  query on the shared path.

  `FrecTable::lookup_frec` takes `Option<u16>` for the transaction ID, where `None` is C's
  `id == -1` (`forward.c:3227`). The sentinel is deliberately outside the 16-bit ID space:
  C's argument is an `int` and the only wire-derived value passed to it is
  `ntohs(header->id)` (`forward.c:1173`), so no packet can reach it. Spelling it `0xFFFF`
  instead would let a forged reply carrying that one ID match whichever query was in flight,
  and would also misroute the genuine answer to any query `get_id()` happened to issue with
  that ID.

  Covered by `tests/forward_source_port_dedup.rs` (distinct source ports for concurrent
  queries, a forged reply delivered to another in-flight query's socket being ignored while
  the identical datagram on the right socket is accepted, REFUSED past `--dns-forward-max`,
  two clients folded onto one upstream query, two clients *not* folded across an EDNS
  boundary, an EDNS-shaped REFUSED) and unit coverage of the pool, the flag derivation and
  its malformed-input behaviour, the duplicate lookup, the `FrecSrc` budget and the failover
  path. Each integration test was checked red against a deliberately broken implementation.

  Explicitly **not** covered — upstream behavior still missing:

  - **The port range is ignored.** C honours `--query-port`/`--min-port`/`--max-port` in
    `local_bind()` and refuses to open more sockets than the range has ports
    (`forward.c:2856-2864`, `dnsmasq.c:269`); `RandFdPool` always binds `0.0.0.0:0` and lets
    the kernel choose. A configured port range therefore has no effect on outbound queries.
  - **Source address and interface are ignored.** `random_sock()` binds
    `srv->source_addr`/`srv->interface` and sets `IPV6_V6ONLY`; the pool binds the IPv4
    wildcard, so `server=<addr>@<source>` and IPv6 upstreams cannot be reached through it.
  - **`serv->sfd` (a server's pre-allocated fixed socket) has no equivalent**, so a server
    configured with an explicit local port still gets a random one.
  - **No DNS-0x20 encoding.** C scrambles query-name case and records a per-`FrecSrc`
    bitmap so each duplicate client gets its own case pattern back (`forward.c:250-300`,
    `flip_queryname`). `FrecSrc::encode_bitmap` exists but is always zero, so the fold-out
    replays the same name to every client. This is the third leg of C's anti-spoofing, next
    to the random ID and the random port.
  - **`forwardall` / `--all-servers` and strict-order retry are not ported.** One query goes
    to one server; `Frec::forwardall` is never set, and `next_server` round-robins rather
    than following `filter_servers`/`master->last_server`.
  - **A client retransmission is re-sent to the same server**, where C sets `forwardall` and
    fans it to every server in the group (`forward.c:474-478`).
  - **No `udp_pkt_size` per client.** C sends a truncated answer to any `frec_src` whose
    advertised EDNS payload is smaller than the reply (`forward.c:1455-1470`); every folded
    client here gets the full packet.
  - **With no upstream servers configured a query is dropped, not REFUSED.** C reaches
    `setup_reply()` with no flags and answers REFUSED for "nowhere to forward to"; the loop
    stays silent, which `tests/local_answer_integration.rs` currently pins.
  - **Only part of C's `!gotname` test is implemented.** `extract_request`
    (`rfc1035.c`) also rejects `qdcount != 1` and a query carrying a non-zero
    `ancount`/`nscount`, and C answers REFUSED for both. `hash_questions` accepts them, so
    such a query is forwarded here instead. The forwarded/dropped split above only follows C
    for an unreadable question name.
  - **A non-`QUERY` opcode is forwarded, where C answers NOTIMP.** C takes the
    `OPCODE(header) != QUERY` branch to `reply:` with `flags = F_RCODE`
    (`forward.c:329-333`), which `setup_reply()` renders as NOTIMP. `rfc1035::setup_reply`
    already has that arm; the forward loop screens only on the QR bit, so nothing reaches
    it.
  - **`fast_retry` (`--fast-dns-retry`) is not ported.** C's `frec->forward_delay` and
    `frec->forward_timestamp` (`forward.c:626-660`) have no counterpart on `Frec`, so a slow
    server is never re-probed before the query times out.
  - **No EDE option on a locally generated REFUSED.** C attaches `EDNS0_OPTION_EDE` with a
    reason code whenever it has one (`forward.c:597-599`); this path has none of C's `ede`
    plumbing, so the OPT record it re-attaches is always empty.
  - **`FREC_NO_CACHE` is never set**, because `add_edns0_config` (`--add-subnet`,
    `--add-mac`, `--add-cpe-id`) has no call site on the outgoing-query path — `edns0::
    add_edns0_config` itself is now ported (see the `edns0.c` entry above), but no
    client-specific EDNS option is ever actually added to a forwarded query, so no query is
    contingent on one (`forward.c:1934-1939`). If those directives land, the flag has to be
    set with them or such queries become eligible for
    duplicate folding, which C forbids.
  - **`Frec::flags` carries only the four `fwd_flags` bits.** `FREC_NOREBIND`,
    `FREC_GONE_TO_TCP`, `FREC_ANSWER` and the DNSSEC sub-query flags are defined but never
    assigned, since the paths that set them (rebind policy on the live reply path, TCP
    escalation, DNSSEC validation) are themselves not ported.

- [ ] Split pure logic tests from capability-dependent socket tests.
  Source of truth: current failing tests in `network.rs`, `forward.rs`, and `dhcp_common.rs`.
  Required tests: deterministic unit coverage for pure logic, gated or capability-aware integration coverage for privileged paths.
  Done when: restricted environments do not fail due to avoidable permission assumptions, while real socket behavior is still exercised where supported.

- [ ] Harden listener and socket creation paths to match upstream error handling.
  Source of truth: upstream `network.c`, `forward.c`, `dhcp-common.c`.
  Required tests: bind failure tests, address family tests, listener reuse tests, mark/bindtodevice behavior tests where supported.
  Done when: runtime setup failures degrade or report errors in a controlled and upstream-compatible way.

- [x] Replace remaining daemon reload stubs with real behavior.
  Source of truth: upstream reload flow (`dnsmasq.c` `async_event()` EVENT_RELOAD,
  `clear_cache_and_reload()`, `network.c` `reload_servers()`), current `clear_cache_and_reload`,
  `main.rs` SIGHUP handling.
  `main.rs`'s SIGHUP handler now calls `dnsmasq::on_sighup`, which calls the real
  `clear_cache_and_reload`. The forward loop's `DnsCache` is now a
  `cache::SharedDnsCache` (`Arc<tokio::sync::Mutex<DnsCache>>`) built once by
  `dnsmasq::build_shared_cache` and threaded through `run_main_loop_with` /
  `run_forward_loop_on`, rather than a task-local value — reload flushes the exact
  cache the running loop reads from, using the already-tested `cache::reload_hosts`
  to flush and rebuild `F_HOSTS` entries from `/etc/hosts` (unless `--no-hosts`) and
  each `--addn-hosts` file. `--resolv-file` entries are re-read and merged into
  `daemon.servers` as `SERV_FROM_RESOLV`-flagged entries, replacing only the
  previously-resolv-derived ones so explicit `--server=` entries survive.
  Covered by `dnsmasq::tests::clear_cache_and_reload_*` / `on_sighup_*` (cache flush,
  hosts reload, resolv reload, repeated-SIGHUP idempotency, explicit-server survival)
  and `tests/forward_cache_integration.rs::sighup_reload_flushes_the_live_forward_cache`
  (drives the real `run_forward_loop_on` loop and confirms a cached answer is evicted).

  Deliberate simplifications, still open:
  - Upstream only discards non-`F_DHCP` cache entries on reload
    (`cache_unhash_dhcp`-adjacent logic in `cache_reload()`); this port's cache never
    receives `F_DHCP` records yet, so a full flush is currently equivalent but must be
    revisited once DHCP leases feed the cache.
  - Upstream gates the resolv-file re-read on `OPT_NO_POLL` (`dnsmasq.c:1553`) for the
    *SIGHUP* path specifically — `if (daemon->resolv_files && option_bool(OPT_NO_POLL))
    reload_servers(...)` — because when polling/inotify is active, the ordinary
    inotify-triggered reload (see below) is expected to already keep `daemon->servers`
    current, so SIGHUP doesn't force a redundant read on top of it. This port's SIGHUP
    path (`clear_cache_and_reload`) always re-reads resolv-files regardless of
    `--no-poll` — a real, if harmless (re-reading is idempotent), divergence from
    upstream's gating, not a match as an earlier version of this note claimed. The
    inotify-triggered reload (see below) does honor `--no-poll`, matching
    `dnsmasq.c:1236`.
  - `clear_cache_and_reload` (`src/dnsmasq.rs`) now calls `inotify::set_dynamic_inotify`
    (gated `#[cfg(feature = "inotify")]`) right after `cache::reload_hosts` flushes the
    cache, so `--hostsdir` entries are rescanned and repopulated on every SIGHUP —
    mirroring `cache_reload()`'s own `set_dynamic_inotify(AH_HOSTS, ...)` call
    (`cache.c:1709`). Before this fix, a `--hostsdir`-loaded record was silently and
    permanently dropped by the first SIGHUP after it loaded, since nothing re-triggered
    the initial-scan step that originally populated it. Covered by
    `dnsmasq::tests::clear_cache_and_reload_rescans_hostsdir_entries`. Only `AH_HOSTS`
    directories are rescanned this way; `dhcp-hostsdir`/`dhcp-optsdir` are not, matching
    `set_dynamic_inotify`'s existing scope limits below.
  - `--servers-file` re-read (`read_servers_file()`) and DHCP reload
    (`reread_dhcp`/`dhcp_read_ethers`/`lease_update_from_configs`/`rerun_scripts`) are not
    implemented — SIGHUP is DNS-only for now.
  - See "Reload staleness" below: `daemon.servers` is updated correctly, but the
    already-running forward task's `ForwardConfig` (upstream list, host-records, CNAMEs)
    is still a one-time snapshot, so a resolv-file-driven server-list change only takes
    effect on the next process start, not the next query.

- [x] `inotify.c` — real watch establishment, initial scan, and event dispatch (Issue #50).
  Previously only the byte-parsing helpers (`parse_inotify_event`/`to_watch_event`) existed
  with zero non-test callers; no watches were ever established and `--no-poll` was parsed
  but read nowhere. Now implemented in `src/inotify.rs`:
  - `inotify_dnsmasq_init` (called once from `dnsmasq::init_daemon_with`): opens the
    inotify fd, follows symlinks (bounded `MAXSYMLINKS`-style loop via
    `resolve_symlink_chain`) for each `--resolv-file`, and watches its containing
    directory (`IN_CLOSE_WRITE | IN_MOVED_TO`).
  - `set_dynamic_inotify` (called once from `dnsmasq::run_main_loop_with`, after the cache
    exists): watches each `daemon.dynamic_dirs` entry
    (`IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE`), then — watch-then-scan, matching upstream's
    race avoidance — for `AH_HOSTS` (`--hostsdir`) entries only, loads any pre-existing
    files into the cache via `cache::load_hosts_file`.
  - `inotify_check` + `watch_inotify_changes` (an `AsyncFd` readiness loop spawned by
    `dnsmasq::spawn_inotify_watch_task`, mirroring the existing netlink-watch task
    pattern): drains events, flags a resolv-file hit for the caller, and for `AH_HOSTS`
    hits flushes the previous load via `DnsCache::remove_by_uid` and reloads unless the
    event was a deletion.
  - `--no-poll` (`OPT_NO_POLL`) now has a real effect: `should_force_resolv_reload` gates
    the inotify-triggered resolv reload exactly as `dnsmasq.c:1236` does
    (`daemon->port != 0 && !option_bool(OPT_NO_POLL)`).
  - Covered by `inotify::tests::*` (30 tests): symlink resolution (relative, cycle-bounded,
    missing-path), watch establishment (including missing-directory error path), initial
    scan (existing files loaded, dotfiles/emacs-backups/lock-files ignored), the event
    cascade (new/modified/deleted file in a watched `--hostsdir`, ignored dotfile events,
    resolv-file hit detection, `--no-poll` gating), and an `FdGuard` unit test — all against a
    real kernel inotify fd and real temp-directory filesystem changes, not a mock. Tests that
    open a real inotify fd close it via an `FdGuard` (`src/inotify.rs` test module) rather
    than leaking it for the rest of the test binary's process lifetime: an earlier version of
    this change leaked one real fd per fd-opening test, which raced with unrelated tests
    elsewhere that inspect `/proc/self/fd` (e.g.
    `ipset::tests::add_to_ipset_reuses_persistent_socket_after_init`) and made them flaky
    under `cargo test --all-features`.

  Deliberate simplifications, still open:
  - `dhcp-hostsdir`/`dhcp-optsdir` (`AH_DHCP_HST`/`AH_DHCP_OPT`) directories are watched
    (so `inotify_check` recognizes their `wd` rather than erroring) but not scanned or
    read back on change: this port has no `option_read_dynfile` /
    `dhcp_update_configs`/`lease_update_from_configs`/`lease_update_file`/`lease_update_dns`
    equivalent yet — only whole-config `reread_dhcp` (SIGHUP) exists. Building the
    per-file DHCP dynfile reader is a separate, larger chunk of work than this issue's
    scope (Issue #50 / T3-inotify targeted `inotify.c` itself, not `option.c`'s
    `option_read_dynfile`).
  - No mtime-based polling fallback exists for builds without the `inotify` feature
    (`--no-default-features`); upstream's non-`HAVE_INOTIFY` build polls resolv-file
    mtime once per second instead. The dead-code `dnsmasq::ResolvMonitor`/`poll_resolv`
    (still uncalled) would be the natural basis for that fallback if it's ever needed.

- [x] Wire `LeaseDb` into DHCPv4 dispatch and reach Release/Decline/Inform.
  `LeaseDb` (`src/lease.rs`) had zero callers outside its own tests; `dispatch_dhcp_with_meta`
  (`src/dhcp.rs`) dropped RELEASE/DECLINE and never called the already-implemented
  `rfc2131::handle_release/handle_decline/handle_inform`. Now: a REQUEST that is ACK'd
  creates/renews a lease (`record_lease`, mirroring `lease_set_*` at `rfc2131.c:1683-1730`),
  RELEASE frees the matching lease (`LeaseDb::remove_by_addr`, ported from `lease_prune`'s
  by-address case), DECLINE removes the declined lease so it is not re-offered, and INFORM is
  answered by `handle_inform` without allocating an address. `daemon.lease_file` now defaults
  to `/var/lib/misc/dnsmasq.leases` when DHCP(v6) is configured and no `--dhcp-leasefile` was
  given (`option::apply_dhcp_leasefile_default`, mirroring `dnsmasq.c:151-156`); it is threaded
  through `DhcpServerConfig::lease_file` into `run_dhcp_loop`, which loads the file at spawn
  and rewrites it whenever a dispatch marks `LeaseDb::file_dirty`. OFFER and the ACK answering
  a REQUEST now carry `OPTION_LEASE_TIME` (51), matching `rfc2131.c:1384,1744`; the ACK
  answering an INFORM deliberately does not (`rfc2131.c:1797-1810` only includes it there if
  the client asked for it via the parameter request list). REQUEST also NAKs when the
  requested address is a `dhcp-host` static reservation belonging to a *different* client
  (`config_find_by_address(...) != config`, `rfc2131.c:1529-1530`), compared by pointer
  identity into `cfg.configs`.
  INFORM also never gets T1/T2 (options 58/59): `do_options()` only emits them when its
  `lease_time` isn't `u32::MAX`, so `decorate_reply` passes `u32::MAX` there for INFORM while
  still using the real `ctx.lease_time` for the (INFORM-excluded) option-51 value — mirroring
  `rfc2131.c:1817` calling `do_options(..., 0xffffffff, ...)` for DHCPINFORM.
  Covered by `dhcp::tests::{request_ack_creates_persisted_lease, release_frees_lease,
  release_for_out_of_pool_ciaddr_leaves_lease_store_untouched, decline_removes_lease,
  inform_returns_ack_without_allocating_address,
  request_for_address_reserved_to_another_client_is_nak_d,
  request_for_own_reserved_address_is_acked, offer_and_ack_carry_lease_time_option,
  inform_ack_does_not_carry_lease_time_option, inform_ack_does_not_carry_t1_t2_options,
  run_dhcp_loop_persists_lease_to_configured_file}`, `rfc2131::tests::handle_request_nak_when_reserved_for_other`,
  `lease::tests::remove_by_addr_*`, and `option::tests::{dhcp_range_without_explicit_leasefile_defaults_lease_file,
  explicit_dhcp_leasefile_is_not_overridden_by_default, no_dhcp_range_leaves_lease_file_unset}`.

  Deliberate simplifications, still open:
  - **No re-offer avoidance / DECLINE backoff.** Upstream bumps `context->addr_epoch` on a
    DECLINE against a dynamic address, or sets `CONFIG_DECLINED` with a timed backoff when the
    address is a `dhcp-host` static reservation (`rfc2131.c:1237-1269`). Neither `DhcpContext`
    nor `DhcpConfig` carries mutable state across dispatch calls in this port, so a declined
    address is only removed from `LeaseDb` — nothing currently stops it being immediately
    re-offered to the same client on the next DISCOVER.
  - **`handle_discover` never reuses an existing lease.** `dispatch_dhcp_with_meta` still calls
    `handle_discover(..., None, ...)` unconditionally; upstream looks up `lease_find_by_client_id`
    first so a returning client is re-offered its own address. `handle_discover`'s
    `existing_lease` parameter (and its own unit test) already supports this — it is just not
    wired to `LeaseDb` from dispatch.
  - **Lease time value is not full `calc_time` fidelity.** OPTION_LEASE_TIME and the recorded
    expiry both use `ctx.lease_time` (the same value `do_options` already used for T1/T2), not
    `calc_time()`'s client-requested-lease-time negotiation, decline-time floor, or
    `min_leasetime` clamp (`rfc2131.c` `calc_time()`).
  - **RELEASE/DECLINE do not re-validate the server-id.** Upstream's `DHCPRELEASE`/`DHCPDECLINE`
    cases call `narrow_context`/check the server-id option before acting; `handle_release`/
    `handle_decline` only check the address against the pool bounds.

- [x] Atomic lease-file persistence and dhcp-script hooks (lease.c:278-1308).
  `LeaseDb::write_to_file` (`src/lease.rs`) was a bare `std::fs::write` — a crash or
  write failure mid-call could truncate/corrupt the lease file, unlike upstream's
  fsync'd rewrite. It now writes to a `.{name}.tmp` sibling in the same directory,
  `File::sync_all()`s it, then `std::fs::rename`s it over the target — the rename is
  atomic on the same filesystem, so readers only ever see the old complete file or the
  new one, never a partial write. This is a stronger crash-safety guarantee than
  upstream's `lease_update_file` (which truncates a long-lived fd in place and fsyncs),
  while preserving the same observable property upstream cares about (durable writes
  survive, failed writes don't corrupt the file).

  `LeaseDb::run_lease_scripts(command)` is the `do_script_run()`-equivalent that was
  entirely missing: `helper::run_script`/`build_env`/`queue_script` existed and were
  tested but had zero callers outside their own tests, and `daemon.lease_change_command`
  (set by `dhcp-script=`) was read nowhere. `run_lease_scripts` now fires `add`/`old`/`del`
  events for `LEASE_NEW`/`LEASE_CHANGED` leases and for leases queued on a new
  `LeaseDb::old_leases` list (populated by `prune`/`remove_by_addr`, mirroring lease.c's
  `old_leases` list), including the "announce the lost hostname before the new one"
  ordering at lease.c:1274-1283. It is wired into `run_dhcp_loop` (`src/dhcp.rs`) right
  after the lease-file write, gated on the new `DhcpServerConfig::lease_change_command`
  (threaded from `daemon.lease_change_command` in `daemon_dhcp_runtime`,
  `src/dnsmasq.rs`). Also fixed while touching this code: `run_dhcp_loop` was clearing
  `LeaseDb::file_dirty` unconditionally, even when `write_to_file` returned `Err` — a
  failed write was silently treated as done and never retried; it now only clears the
  flag on `Ok`.

  Deliberate simplification: upstream's `do_script_run` fires one event per call and
  relies on the main loop invoking it repeatedly (its return value signals "more work
  pending"), because upstream's main loop is itself a single-threaded poll loop where a
  long-running script would stall everything else. `run_lease_scripts` drains all
  pending events in one call instead, since the caller here is one `run_dhcp_loop`
  iteration rather than a busy-poll main loop; the fire order and env vars per event are
  otherwise unchanged. Like upstream, a script that fails to spawn does not get retried
  — the pending flags/queue entry are cleared regardless of `run_script`'s result.

  Follow-up fix: `run_lease_scripts` originally took `command: &str` and was only called
  from `run_dhcp_loop` inside `if let Some(command) = cfg.lease_change_command...` — so
  with no `dhcp-script=` configured (the default), `remove_by_addr` kept pushing onto
  `old_leases` on every RELEASE/DECLINE but nothing ever drained it, leaking one
  `DhcpLease` per release for the life of the process. Upstream avoids this because
  `do_script_run()` is called unconditionally from the main loop regardless of
  `HAVE_SCRIPT`/script configuration — draining the queue and clearing per-lease flags
  isn't gated on a script existing, only the `queue_script()` spawn is. Fixed by changing
  the signature to `run_lease_scripts(command: Option<&str>)` and calling it
  unconditionally from `run_dhcp_loop`; `run_script` is only invoked when `command` is
  `Some`, but the drain/clear always happens. Covered by
  `lease::tests::{run_lease_scripts_drains_old_leases_without_command_configured,
  run_lease_scripts_clears_lease_flags_without_command_configured}`.

  Also added: `write_to_file` now `fsync`s the containing directory (Unix only) after
  the `rename`, so the rename entry itself is durable across a crash/power loss —
  previously only the temp file's contents were fsync'd, which protects against a torn
  file but not against ext4/xfs losing the rename itself on power loss.

  Still open: `helper::run_script` calls `Command::status()`, a blocking wait, from
  inside `run_dhcp_loop`'s async select arm. A slow/hung dhcp-script now stalls that
  loop's DHCP dispatch for its duration (this was pre-existing in `helper.rs` but had no
  caller until this change gave it one). Moving the call behind `spawn_blocking` (or
  otherwise off the async task) is unaddressed.

  Still not ported: `lease_ping_reply`, `lease_update_slaac`, `lease_find_interfaces`,
  `lease_make_duid` (lease.c:497-556) have no Rust equivalents — these are
  SLAAC/RA-adjacent (periodic ping-before-assign for SLAAC addresses, interface
  enumeration for the DHCPv6 DUID, DUID generation) and out of scope for this pass;
  `slaac.rs`/`radv.rs` may cover overlapping ground under different names but that
  hasn't been checked. `rerun_scripts()` (which marks every lease `LEASE_CHANGED` so a
  reload re-fires all hooks) still has no caller outside its own unit tests — wiring it
  into the SIGHUP/reload path is tracked separately above ("DHCP reload
  (`reread_dhcp`/.../`rerun_scripts`) are not implemented — SIGHUP is DNS-only for
  now").
  Covered by `lease::tests::{write_to_file_uses_tmp_file_and_rename,
  write_to_file_failed_write_leaves_original_untouched, run_lease_scripts_fires_add_for_new_lease,
  run_lease_scripts_fires_old_for_changed_lease, run_lease_scripts_fires_del_for_removed_lease,
  run_lease_scripts_announces_lost_hostname_before_del, run_lease_scripts_clears_new_and_changed_flags,
  run_lease_scripts_drains_old_leases_queue}`.

  Fixed in review: `helper::run_script` only set env vars
  (`DNSMASQ_ACTION`/`DNSMASQ_IP`/`DNSMASQ_MAC`/`DNSMASQ_SUPPLIED_HOSTNAME`) and passed
  zero positional args, so `$1`-`$4` were empty for any invoked script. Upstream's
  `execl(daemon->lease_change_command, basename, action_str, mac_or_duid, ip, hostname,
  NULL)` (helper.c:681-684) is the documented calling convention (dnsmasq.8:1826-1841:
  "The arguments to the process are 'add', 'old' or 'del', the MAC address ..., the IP
  address, and the hostname") that real dhcp-script hooks, including dnsmasq's own
  contrib scripts, rely on. `run_script` now does `cmd.arg(action).arg(mac).arg(ip)` and
  conditionally `.arg(hostname)` only when `Some` — matching upstream's behavior of
  omitting the hostname arg entirely (not passing an empty string) when
  `execl`'s vararg list ends early. Covered by
  `helper::tests::{run_script_passes_positional_args, run_script_omits_hostname_arg_when_none}`.

- [x] Port the ICMP conflict probe, `--read-ethers`, and real per-interface
  context selection (dhcp.c: `do_icmp_ping`/`address_allocate`/
  `dhcp_read_ethers`/`guess_range_netmask`/`complete_context`).

  **ICMP conflict probe.** `IcmpPinger::ping` (`src/dnsmasq.rs`) was a stub
  that always returned `false` and was never called by anything. It now
  opens a real `SOCK_RAW`/`IPPROTO_ICMP` socket, sends an echo request built
  by the (previously dead) `icmp_checksum` via the new
  `dhcp::build_icmp_echo_request`, and blocks up to its configured timeout
  for a matching reply parsed by `dhcp::parse_icmp_echo_reply` — matching
  `icmp_ping()`/`delay_dhcp()` (dnsmasq.c:2339-2469). If the raw socket can't
  be opened (no `CAP_NET_RAW`) it falls back to "no reply", the same
  fallback `icmp_ping()` itself takes on `make_icmp_sock()` failure.
  `dhcp::address_allocate` (dhcp.c:825-922) is the actual free-address
  scanner: seeded from `sdbm_hash(hwaddr)` (or `LeaseDb::find_max_addr` under
  `--dhcp-sequential-ip`/`OPT_CONSEC_ADDR`), it walks a context's range
  skipping router/leased/statically-reserved/non-`is_allocatable_addr`
  addresses and confirms freedom via the new `dhcp::PingCache` (a port of
  `do_icmp_ping`'s cache/load-limiter, dhcp.c:769-823). It replaces
  `pick_offer_addr`'s old "always return `pool_start`" fallback in
  `rfc2131::handle_discover` — `dispatch_dhcp_with_meta` now runs the real
  scan (when no static reservation already decided the offer) and passes
  the result in as `handle_discover`'s new `scanned_addr` parameter, so
  `handle_discover` itself no longer knows how a free address is found.
  `sdbm_hash`/`hash_to_addr`/`is_allocatable_addr` (previously dead, only
  reachable from their own unit tests) are real callers now. `AddressProbe`
  is the seam: `IcmpPinger` implements it in production, and tests use fake
  probes instead of real sockets, so conflict detection is deterministically
  testable in a CAP_NET_RAW-less sandbox.
  Covered by `dhcp::tests::{address_allocate_*, ping_cache_*,
  build_icmp_echo_request_checksums_to_zero, parse_icmp_echo_reply_*,
  dispatch_discover_skips_address_that_answers_icmp_ping}` and
  `dnsmasq::tests::icmp_pinger_*` (capability-gated: the raw-socket-required
  assertions skip themselves when the sandbox turns out to have
  `CAP_NET_RAW`, per the existing "gate capability-dependent tests" rule
  rather than hard-coding an unprivileged result).

  **`--read-ethers`.** `dhcp::dhcp_read_ethers` reads `/etc/ethers`
  (`dhcp::ETHERS_FILE`), purges any `CONFIG_FROM_ETHERS` entries from a
  previous run, and merges each `<hwaddr> <ip-or-hostname>` line into
  `dhcp_conf` — matching or creating entries the same way
  `dhcp_read_ethers()` does (dhcp.c:924-1083): reuse a `dhcp-host` entry
  matched by address/hostname, or one whose sole hwaddr already equals this
  line's, else create a fresh `CONFIG_FROM_ETHERS` entry. Wired into
  `dnsmasq::init_daemon_with`, gated on `OPT_ETHERS`, so it now runs at
  startup instead of being a stored-but-unread flag. Parsing
  (`parse_ethers_text`) and merging (`apply_ethers_records`) are split out
  as pure, file-free functions for unit testing.
  Covered by `dhcp::tests::{parse_ethers_text_*, apply_ethers_records_*,
  dhcp_read_ethers_*}`.

  **Per-interface context selection.** `context_for_reply` was a flat "first
  pool-range match, or else the first context regardless of subnet"
  heuristic; it now delegates to `narrow_context` (already ported and
  tested, but previously uncalled) for the pool-match →
  static-same-subnet → any-same-subnet fallback chain `narrow_context()`
  actually implements (dhcp.c:717-752). Separately, `link_contexts_for_interface`
  ports `guess_range_netmask`/the local-subnet half of `complete_context`
  (dhcp.c:568-660): given an arriving interface's local/netmask/broadcast,
  it fills in netmask for ranges missing `CONTEXT_NETMASK`, computes
  router/local/broadcast for every context on that subnet, and returns which
  contexts are valid for a host on that interface.

  `link_contexts_for_interface` now has a real runtime caller:
  `bind_listeners` enables `IP_PKTINFO` on the DHCP socket
  (`network::set_ipv4pktinfo`), `run_dhcp_loop` reads it back per datagram
  via `recv_dhcp_datagram` → `network::recv_with_dest`/`parse_pktinfo`
  (already used by the DNS wildcard-listener path in `forward.rs`), resolves
  the `if_index` to an `ArrivalInterface` via `dhcp::arrival_interface`
  (`network::enumerate_interfaces`), and dispatches through the new
  `dispatch_dhcp_with_arrival` instead of `dispatch_dhcp_with_meta` directly.
  `dispatch_dhcp_with_arrival` links/completes `cfg.contexts` for that
  interface and, when at least one context links, restricts *both*
  `context_for_reply`/`narrow_context` and `address_allocate`'s pool scan to
  just that linked subset for the rest of the packet's dispatch — so a
  DISCOVER arriving on an interface with its own `dhcp-range` can no longer
  be offered an address from an unrelated interface's range. When nothing
  links (unknown interface, or a relayed request from a subnet with no local
  `dhcp-range`), it falls back to the full context list, same as before.
  `dispatch_dhcp_with_meta`'s own signature and every existing call site
  (tests included) are unchanged — `dispatch_dhcp_with_arrival` is a thin
  wrapper that narrows `cfg.contexts` before delegating.
  Covered by `dhcp::tests::{link_contexts_for_interface_*, arrival_interface_*,
  dispatch_with_arrival_*, run_dhcp_loop_restricts_offer_to_arriving_interfaces_subnet}`
  — the last one exercises the real socket/`IP_PKTINFO`/`recvmsg` path
  end-to-end, not just `dispatch_dhcp_with_arrival` called directly with a
  hand-built `ArrivalInterface`.

  Deliberate simplifications, still open:
  - **Only meaningful with one bound DHCP address per box.** `bind_listeners`
    still binds the DHCP socket to a single specific address
    (`daemon_dhcp_runtime`'s `bind_ip`, the first configured listen address),
    not a wildcard `INADDR_ANY` socket serving several interfaces at once —
    that's the `make_fd`/multi-interface bind gap described elsewhere in this
    file. `IP_PKTINFO` still reports a real, correct arrival interface index
    for every datagram on a single-address-bound socket (the kernel doesn't
    care how the socket was bound), so the wiring above is real production
    code, not test-only — but until the daemon can bind more than one
    interface for DHCP, every packet it receives arrives on the same
    interface, so `link_contexts_for_interface` only ever narrows to
    whichever `dhcp-range`s share that one interface's subnet. True
    multi-interface selection needs the wildcard-bind work landed first.
  - **`complete_context`'s `shared_networks`/`dhcp-relay` linking is not
    ported** — only the local-subnet half. Shared-network address pools and
    `relay->iface_index` assignment (already handled separately by
    `daemon_dhcp_runtime`'s single-bound-interface relay wiring) are out of
    scope for `link_contexts_for_interface`.
  - **`address_allocate`'s `addr_epoch` perturbation is not ported.** Upstream
    nudges a context's `addr_epoch` when a candidate is rejected
    (dhcp.c:900-921) so a future scan for the same hwaddr starts somewhere
    else; every scan here always starts from the same hash-seeded address.
  - **No requested-IP ping check in DISCOVER.** Upstream also pings a
    client's *requested* address (option 50) directly, before falling back
    to a full `address_allocate` scan (rfc2131.c:1340-1341); this port only
    scans, so a client that asks for a specific free address by number
    doesn't get it preferentially.
  - **`make_fd`/`dhcp_init` socket options are still unported**: no
    `IP_MTU_DISCOVER`/`IP_PMTUDISC_DONT`, `IP_TOS`, `IP_PKTINFO`,
    `SO_REUSEPORT`/`SO_REUSEADDR` gating, or PXE-port (4011) bind. DHCP
    socket setup in `bind_listeners` is still a plain bind + `set_nonblocking`
    + optional `SO_BINDTODEVICE`. `Daemon::enable_pxe` now exists and is set
    by `pxe-prompt`/`pxe-service` (Issue #56/T3-daemon-struct), but
    `daemon->pxefd` and the PXE-port bind/response path it would gate still
    don't exist in this port at all.
  - **`host_from_dns` is not ported** — DHCP lease hostname resolution has
    no fallback to a reverse `F_HOSTS` cache lookup.
  - **No SIGHUP re-run of `--read-ethers`.** Upstream re-reads
    `/etc/ethers` on reload; this port only reads it once at
    `init_daemon_with` time, consistent with the rest of the SIGHUP-reload
    gap already tracked above ("Replace remaining daemon reload stubs").

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
  Examples: rebind controls, ipset/nftset hooks, filter variants, port-limit, logging-related directives.
  Required tests: parser tests and feature-gated integration tests.
  Done when: supported config files do not silently ignore implemented features.

- [ ] Remove silent placeholder acceptance of directives.
  Source of truth: current TODO branches in `apply_line`.
  Required tests: unsupported directives must fail clearly unless intentionally no-op and documented.
  Done when: the parser never gives a false impression that a feature works when it does not.

- [x] Issue #18 / Issue #56 (T3-daemon-struct) remaining DHCP/PXE directives:
  recognized and accepted by `apply_line` (`src/option.rs`), and now update
  real `Daemon` state (previously parsed-and-discarded) — but most still lack
  a DHCP/PXE runtime consumer:
  - `dhcp-broadcast`, `dhcp-generate-names`, `dhcp-ignore-names`,
    `bootp-dynamic` (option.c:4660-4700, shared `dhcp_netid_list` case;
    `dhcp-ignore` itself shares the parsing helper but is `ARG_REQUIRED`,
    unlike these four's `ARG_DUP`) now populate `Daemon::force_broadcast`/
    `dhcp_gen_names`/`dhcp_ignore_names`/`dhcp_ignore` respectively (new
    `DhcpNetidList` type, `types/dhcp.rs`), each entry a literal tag list
    (leading `tag:`/`net:` stripped via `is_tag_prefix`, `set:` is *not*
    special in this shared case). `dhcp_ignore` is now wired into the DHCP
    runtime: `dhcp::dispatch_dhcp_with_meta` checks a client's derived tags
    against `DhcpServerConfig::dhcp_ignore` (non-wildcard `match_netid`
    semantics, mirroring `dhcp.rs::context_filter_matches`) independently of
    any `DhcpConfig` match, matching `rfc2131.c:614,851`. This fixed a
    same-name-different-model bug: `dhcp-ignore` used to be routed through
    `parse_dhcp_config_matchers`/`daemon.dhcp_conf` with `CONFIG_DISABLE` —
    the same per-host matcher machinery `dhcp-host=...,ignore` uses — instead
    of upstream's separate global tag-list mechanism; a `dhcp-ignore=<mac>`
    line, for instance, now creates a literal tag named `<mac>` rather than a
    MAC-address selector. `force_broadcast`/`dhcp_gen_names`/
    `dhcp_ignore_names` are still parse-and-store only: no `dhcp.rs`/
    `rfc2131.rs` consumer reads them yet.
  - `dhcp-proxy` (option.c:4703-4714) now sets `Daemon::dhcp_override` and
    collects `Daemon::override_relays` (`Vec<Ipv4Addr>`). Neither is consumed
    yet — the relay-trust/server-id-override logic at `rfc2131.c:858-870` has
    no Rust equivalent.
  - `dhcp-pxe-vendor` (option.c:4716-4727) now populates
    `Daemon::dhcp_pxe_vendors` (new `DhcpPxeVendor` type). Not consumed: PXE
    client-vendor matching against it doesn't exist (no PXE runtime at all —
    see below).
  - `pxe-prompt` (option.c:4422-4457) now pushes a real `dhcp_opt` entry
    (option 10, `DHOPT_VENDOR|DHOPT_VENDOR_PXE`) onto `Daemon::dhcp_opts` and
    sets `Daemon::enable_pxe`. `pxe-service` (option.c:4461-4539) now
    populates `Daemon::pxe_services` (new `PxeService` type), including the
    CSA-name table, the numeric-vs-basename boot-type branch (with
    `Daemon::pxe_boottype_next` mirroring upstream's function-local
    `static int boottype` counter, seeded at 32768), and the
    address-vs-hostname `server`/`sname` branch. Neither is consumed: no PXE
    menu support (responding on the PXE port, building the boot-menu wire
    format) exists anywhere in this port.
  - `conf-script` (option.c:2068): value still discarded, and deliberately
    never executed. Upstream runs the referenced file as a program and reads
    config directives back from its stdout (`one_file(file,
    LOPT_CONF_SCRIPT)`). Executing an arbitrary external program from config
    parsing is a capability this port intentionally does not implement.
  - `umbrella` (option.c:2808-2850): the `deviceid:`/`orgid:`/`assetid:`
    sub-options (there is no `userid:` sub-option upstream) now populate
    `Daemon::umbrella_device`/`umbrella_org`/`umbrella_asset`, and `deviceid:`
    sets `OPT_UMBRELLA_DEVID`. `edns0::add_umbrella_opt`/`add_edns0_config`
    are ported and can now be fed real `Daemon` state, but nothing calls
    `add_edns0_config` from the forward path yet — see the `edns0.c` entry
    above.
  - `doing_ra`/`doing_dhcp6` (`dnsmasq.h:1238`) are not directly config-set —
    upstream derives them at startup (`dnsmasq.c:288-296`) from whether any
    `dhcp6` context is configured, `option_bool(OPT_RA)` (the `enable-ra`
    directive), and each context's `CONTEXT_DHCP`/`CONTEXT_RA` flags. Both
    fields now exist on `Daemon` (`dhcp6`-gated) and are populated in
    `dnsmasq::init_daemon_with`, mirroring the upstream gating exactly
    (the whole block is skipped when `daemon.dhcp6` is empty, so `OPT_RA`
    alone never sets `doing_ra` without at least one `dhcp6` context). No
    consumer reads them yet — the RA/DHCPv6 socket bring-up and poll-loop
    dispatch that upstream gates on these flags
    (`dnsmasq.c:337,413,1010,1146,1149,1316,1319`; `network.c:1787-1806`;
    `radv.c:93,114`) has no Rust equivalent, consistent with the broader
    startup/runtime gap tracked under CLAUDE.md priority #3.
  Required tests: `src/option.rs` directive-level tests for every directive
  above (`apply_dhcp_broadcast_*`, `apply_dhcp_proxy_*`,
  `apply_dhcp_pxe_vendor`, `apply_pxe_prompt_*`, `apply_pxe_service_*`,
  `apply_umbrella_*`), plus `dhcp.rs`'s `discover_matching_global_dhcp_ignore_tag_produces_no_reply`/
  `discover_not_matching_global_dhcp_ignore_tag_still_offers`/
  `discover_empty_dhcp_ignore_entry_does_not_match_anyone` for the one
  directive with a real runtime consumer.
  Done when: `force_broadcast`/`dhcp_gen_names`/`dhcp_ignore_names`/
  `override_relays`/`dhcp_pxe_vendors`/`pxe_services`/`enable_pxe` gain
  DHCP/PXE runtime consumers (tracked here until then), and `umbrella`'s
  fields get threaded into a real outgoing-EDNS0 call site.

- [ ] Issue #30 remainder — `rfc2131.c` PXE proxyDHCP path (BOOTP,
  LEASEQUERY, and `apply_delay`'s ACK gating are now done; see
  `dispatch_bootp`/`dispatch_leasequery`/`handle_leasequery` in `src/dhcp.rs`
  and `src/rfc2131.rs`, and `dhcp-rapid-commit` support in the `Discover` arm
  of `dispatch_dhcp_with_meta`):
  - `pxe_uefi_workaround()` / `pxe_opts()` (rfc2131.c:2392-2556) are not
    ported, and this gap is **not** limited to the proxyDHCP branch. Upstream
    calls them from two places: (1) the proxyDHCP reply branch
    (rfc2131.c:955-1050, gated on `CONTEXT_PROXY` + DISCOVER/REQUEST), and
    (2) unconditionally from the shared `do_options()` (rfc2131.c:2934-2941,
    `if (context && pxe_arch != -1)`) — i.e. for *any* ordinary OFFER/ACK
    reply to a client that sent a PXE arch option (option 93), not just proxy
    replies. This port's `do_options` (`src/rfc2131.rs`) only calls
    `pxe_misc` — it never calls `pxe_uefi_workaround`/`pxe_opts` — so the core
    DISCOVER/REQUEST reply path already in scope for this port is missing the
    PXE menu, not just the unimplemented proxy branch. Both call sites are
    blocked on the `pxe-service`/`pxe-prompt` no-ops above: there is no
    `PxeService` type or `daemon.pxe_services` to build the PXE menu
    (PXE_MENU / PXE_SERVERS / PXE_MENU_PROMPT / PXE_DISCOVERY_CONTROL) from,
    and no `CONTEXT_PROXY` handling anywhere in `dispatch_dhcp_with_meta` for
    call site (1). Port 4011 redirection (rfc2131.c:994-998) is unported for
    the same reason. `apply_delay`'s PXE-proxy call site (rfc2131.c:1046) has
    nothing to call it from yet.
  - Upstream's `known`/`known-othernet` netid tagging (rfc2131.c:544-560,
    based on whether `find_config` matches with vs. without the arriving
    `context`) is not derived for any message type, BOOTP included — this
    port's `derived_tags`/`dispatch_bootp` never add those tags. Pre-existing
    gap, not new to BOOTP.
  - BOOTP's proxy-context exclusion (`context->flags & CONTEXT_PROXY`,
    rfc2131.c:571-572) is not checked in `dispatch_bootp` for the same
    "no `CONTEXT_PROXY` concept in dispatch" reason as above.
  - `do_options`'s unconditional `mess->siaddr = context->local` default
    (rfc2131.c:2667-2668, before any `dhcp-boot` match) is not ported for
    *any* message type — `decorate_reply`/`handle_bootp` only ever set
    `siaddr` from a `dhcp-boot` match or the handler's own `server_id`, never
    from a context's `local` address. Pre-existing gap, not new to BOOTP.
  Required tests: `pxe_uefi_workaround`/proxyDHCP need a PXE menu data model
  before they're testable; `known`/`known-othernet` tagging and the
  `siaddr` default need `dhcp.rs`/`rfc2131.rs` consumer tests once ported.
  Done when: each gap above is closed or the PXE menu/`CONTEXT_PROXY`
  infrastructure it depends on exists and is tracked separately.

- [x] `connmark-allowlist` / `connmark-allowlist-enable` (option.c:3283-3330,
  `OPT_CMARK_ALST_EN`): parsing is gated on the `conntrack` feature (mirroring
  upstream's `#ifndef HAVE_CONNTRACK` hard error — the directive is rejected
  with `InvalidValue` when the feature is off, not silently accepted), and
  `daemon.allowlist_mask`/`daemon.allowlists` are populated correctly when it
  is on. Both the admission side (`forward::mark_admits_query` /
  `rfc1035::is_query_allowed_for_mark`, gating the UDP client-query branch of
  `run_forward_loop_on` ahead of local-data lookup and forwarding) and the
  reply-reporting side (`rfc1035::report_addresses`, called from the upstream
  fan-out loop) now consume these fields — see the `is_query_allowed_for_mark`
  and `report_addresses` entries above for the call-site detail.
  Still not covered: the TCP call sites (`forward.c:2542-2563`, `2743`) — no
  Rust TCP DNS listener yet — and the DNSSEC sub-query retry call sites
  (`1822`/`1906`-adjacent retry path, `rfc1035.c:1153-1212`'s other callers),
  which have no Rust DNSSEC-retry path to hang off of yet.

- [ ] `dhcp-vendorclass` (`src/option.rs::parse_dhcp_vendor`) only supports the 2-field
  `tag,vendor-class` form. Upstream's shared `'U'`/`'j'`/circuit/remote/subscriber case
  (option.c:4564-4634) also accepts a `tag,enterprise:N,vendor-class` 3-field form unique to
  `-U`, which scopes the match to an RFC 3925 enterprise number, and auto-hex-decodes the
  class string when it looks like a colon-separated hex blob (matching `dhcp-mac`-style
  input) for all directives in that shared case except `-U`/`-j`. Neither is implemented here.
  Required tests: parser tests for the 3-field enterprise form and the hex-decode path.
  Done when: `dhcp-vendorclass=set:tag,enterprise:N,data` parses and `DhcpVendorRule` carries
  the enterprise number through to DHCP packet matching.

- [ ] Issue #19 `tag-if`/`dhcp-match`/`dhcp-name-match`: parsed into
  `Daemon::tag_if`/`dhcp_match`/`dhcp_name_match` and wired into
  `dhcp.rs::derived_tags` (dhcp-match/dhcp-name-match) and
  `dhcp.rs::decorate_reply`'s `option_filter` call (`tag-if`, via
  `dhcp_common::run_tag_if`), so a client matched by `dhcp-match` and
  conditionally re-tagged by `tag-if` gets the tag-conditional
  `dhcp-option`/`dhcp-boot`. Known narrowings, left deliberate for this pass:
  - `run_tag_if` is applied exactly once, inside `option_filter` at reply-option
    time. Upstream calls it at ~12 points through `rfc2131.c` (context
    selection, `dhcp-host`/`dhcp-ignore` selection, range selection, lease
    creation, boot-file selection) so tag-if-derived tags there feed those
    decisions too. Here, `dispatch_dhcp_with_meta`'s `find_config`/context/
    ignore checks all run against the raw `derived_tags()` output (vendor/
    user-class/mac/relay-id/dhcp-match/dhcp-name-match tags) *before*
    `tag-if` expansion — a `tag-if` rule cannot itself gate config/context
    selection or `dhcp-ignore`, only which already-tagged options are sent.
  - `dhcp-match`'s RFC3925 vendor-identifying-class special case
    (`vi-encap:`/`DHOPT_RFC3925`, rfc2131.c:437-462, matching option
    124/125 sub-TLVs by IANA enterprise number) is not implemented;
    `derived_tags` only matches a `dhcp-match` rule against a single raw
    option code via `match_bytes`.
  - `option6:` inside `dhcp-match` (and `dhcp-option` generally) is rejected
    by the parser, so `Daemon::dhcp_match6` exists for structural parity but
    is never populated; DHCPv6 client classification via `dhcp-match` is
    unsupported.
  Required tests: once addressed, add a test where a `tag-if` condition
  itself depends on a tag-if-derived tag feeding context/config selection
  (not just option filtering), an RFC3925 vendor-class match test, and a
  `dhcp-match=option6:...` parser test.
  Done when: `run_tag_if` participates in the same decision points as
  upstream, or the narrowing above is still accurate and current.

- [ ] Issue #20 `rev-server`/`synth-domain`/`shared-network`/`bridge-interface`:
  all four now parse, populate `Daemon` state, and affect runtime behavior
  (`src/option.rs`, `src/types/daemon.rs`, `src/domain.rs`). `rev-server`
  reuses the existing `Server`/`daemon.servers` machinery (`SERV_LITERAL_ADDRESS`
  when no upstream is given); `synth-domain` populates `Daemon::synth_domains`
  and is wired into `rfc1035.rs::answer_request` for both forward (A/AAAA)
  and reverse (PTR) synthesis. `forward.rs::ForwardEngine::candidate_servers`
  now does domain-suffix-scoped upstream selection (longest match wins,
  falling back to domain-less "general" resolvers), so `rev-server` and the
  pre-existing `server=/domain/ip` both actually restrict which upstream a
  query can use — this was previously entirely unwired (`daemon_forward_config`
  discarded `Server.domain` outright). Known narrowings, left deliberate:
  - `synth-domain`'s `local` shorthand (upstream: `local=/xxx.in-addr.arpa/`
    + `local=/<domain>/` generated automatically) is a `--domain`-only
    feature upstream (`option.c`'s `option != 's'` check) and is correctly
    *not* implemented for `synth-domain` — only `rev-server` and the bare
    `--domain` directive have a "no address" shorthand. `--domain`'s own
    subnet form is now parsed (Issue #56/T3-daemon-struct: `option::parse_domain`
    populates `Daemon::cond_domain`, including the CIDR form, the
    `<start>[,<end>]` range form, and the `option=='s'`-only
    subnet-from-interface fallback and `domain=#` → `OPT_RESOLV_DOMAIN`
    special case), but the CIDR form's trailing `local` keyword is
    accepted only syntactically — upstream's automatic PTR-zone/NS-record
    synthesis (`domain_rev4`/`domain_rev6` + `add_update_server`) that
    `local` triggers is **not implemented**, and nothing yet consults
    `cond_domain` for domain-suffix selection or forward/reverse synthesis
    the way `synth_domains` is consulted (see the `auth.c`/
    `check_for_local_domain` entries elsewhere in this file).
  - `synth-domain`'s subnet-from-interface form (`synth-domain=<domain>,<iface>`)
    is **not implemented** — upstream restricts that fallback to `option=='s'`
    (bare `--domain`) too, so a non-address, non-CIDR second field is
    rejected as invalid for `synth-domain`, matching upstream exactly.
    `CondDomain.interface` and the newer `CondDomain.al: Vec<Addrlist>` field
    (Issue #25) exist for structural parity, and `match_domain`/`match_domain6`
    (`src/domain.rs`) now correctly implement the `c->interface`/`al` branch
    and the `prefixlen`-dependent branching from `domain.c:220-227,259-266`,
    but nothing populates `interface`/`al` yet: `network.c:459-475`'s
    "refresh `cond->al` from live interface addresses on (re-)enumeration"
    step is unported (`src/network.rs`), so a future `--domain`/`synth-domain`
    subnet-from-interface implementation has a home in both the parser and
    the matcher, but is not observable end-to-end until that population step
    lands — `Daemon::cond_domain` is now populated for the address-range and
    CIDR forms, but a `domain=<name>,<iface>` line only sets
    `CondDomain.interface`, whose `al` list stays permanently empty.
  - `bridge-interface` and `shared-network` populate `Daemon::bridges` /
    `Daemon::shared_networks`, but nothing in `src/dhcp.rs`/`src/rfc2131.rs`
    consults either yet — upstream uses `bridges` to remap an arriving
    DHCP request's interface to the bridge's primary interface for context
    matching, and `shared_networks` to treat two interfaces/subnets as one
    broadcast domain. That DHCP-side consumption is unimplemented; both
    directives are parse-and-store only until DHCP context matching grows
    an interface-remap/shared-domain step.
  - `forward.rs`'s new domain-scoped selection is longest-suffix-match only
    (no `SERV_FOR_NODOTS` wildcard-for-bare-names support, since nothing
    currently produces such an entry — `server=//ip` isn't implemented
    either). Retries reuse the same candidate set as the initial send
    (recomputed from `Frec.stash`), so a query only ever retries within the
    domain it was scoped to.
  Required tests: `src/option.rs`'s `apply_domain_range_form_populates_cond_domain`/
  `apply_domain_cidr_form_populates_range`/`apply_domain_subnet_from_interface`/
  `apply_domain_ipv6_range_form` etc. cover the new parsing. Still needed: a
  `synth-domain=...,<iface>` acceptance test, a `cond_domain` consumer test
  once one exists, and a DHCP-request test where `bridge-interface`/
  `shared-network` change context selection.
  Done when: `cond_domain` is wired into domain-suffix selection / forward
  and reverse synthesis the same way `synth_domains` now is, the CIDR form's
  `local` keyword actually generates PTR-zone/NS records, and DHCP context
  matching consumes `bridges`/`shared_networks`.

- [ ] Issue #21 remaining `dhcp-relay` gaps. `dhcp-relay`/`dhcp-split-relay`
  parsing (`src/option.rs::parse_dhcp_relay`) and `relay_upstream4`/
  `relay_reply4` (`src/rfc2131.rs`, ports of `rfc2131.c:3058-3262`) are
  implemented and wired into `run_dhcp_loop` (`src/dhcp.rs`), including real
  (non-stubbed) split-mode uplink and broadcast-address resolution via
  `network::enumerate_interfaces()`. Left unsupported:
  - Multi-interface awareness: upstream re-binds each relay's `iface_index`
    per received packet to whichever interface actually owns `relay.local`
    (`dhcp.c:669-673`), so one daemon can relay across several interfaces at
    once. This runtime resolves `DhcpLoopOptions.relay_iface_addr/_index/_name`
    once at startup from the single DHCP bind interface
    (`dnsmasq.rs::daemon_dhcp_runtime`), so only relays matching that one
    interface ever fire; a relay entry bound to a second interface is silently
    never selected.
  - DHCPv6 relay forwarding: `dhcp-relay` with IPv6 addresses parses and
    populates `Daemon.relay6` (gated `dhcp6`), but there is no
    `relay_upstream6`/`relay_reply6` — DHCPv6 relay entries are stored and
    never consumed. `rfc3315.c`'s relay path is a separate, larger port.
  - Split-mode RFC 5010 flags suboption: `relay_upstream4`'s `unicast`
    parameter is always `false` from `run_dhcp_loop` (`src/dhcp.rs`), so the
    injected agent-information flags byte (`rfc2131.c:3168`) is always `0x00`
    even for a request that actually arrived unicast. Upstream derives this
    per-packet from `IP_PKTINFO`/socket ancillary data; this runtime has no
    such plumbing yet.
  - Lease-remembered agent-id echo: option 82 is echoed back only when the
    *current* request carries it (`rfc2131.c:189-205`); upstream also re-sends
    a *previously seen* agent-id from `lease->agent_id` when the client asks
    for option 82 via the parameter-request list but didn't include one this
    time (`rfc2131.c:1230-1231`, plus `lease_set_agent_id` at `:1721-1729`).
    `DhcpLease` has no `agent_id` field and nothing stores one.
  Required tests: a multi-socket/multi-interface `run_dhcp_loop` test once
  the interface-rebinding gap is closed; `relay_upstream6`/`relay_reply6`
  parity tests once DHCPv6 relay forwarding is ported; a lease-persisted
  agent-id echo test once `DhcpLease.agent_id` exists.
  Done when: relay entries bound to interfaces other than the primary DHCP
  bind interface fire correctly, DHCPv6 relay entries actually forward
  traffic, and a lease's remembered agent-id is echoed on request.

- [ ] Issue #26 `domain-match.c`: `is_local_answer`/`make_local_answer` now
  have real callers. `ServerArray::lookup` + `domain_match::is_local_answer`
  + `domain_match::make_local_answer` are wired into
  `rfc1035.rs::answer_request` as its final local-data fallback (mirroring
  where `forward.c` calls them: only once nothing earlier already answered
  the query), fed by a `ServerArray` built once at config-reload time
  (`dnsmasq.rs::daemon_local_data`) over every `SERV_LITERAL_ADDRESS` server
  entry — `--address=/domain/ip`, `--server=/domain/` and `--local=/domain/`
  with no address, and `rev-server` with the server part omitted all share
  this path. `option.rs::parse_server_or_address` also had a real bug fixed
  here: the empty-address form (`server=`/`local=`/`address=` with no IP)
  previously hit an early `return Ok(())` and created no `Server` entry at
  all, silently doing nothing — `local=/domain/` was a complete no-op before
  this change. Left unsupported:
  - `/#/` as a domain segment (wildcard "any domain", man page: `address=/#/1.2.3.4`)
    is not special-cased by `parse_server_or_address` — it is parsed as the
    literal domain string `"#"`, not the empty (catch-all) domain, so
    `--address=/#/1.2.3.4` currently answers only queries for the name `#`.
  - `#` as the address segment (man page: `address=/example.com/#`, meaning
    "syntactic sugar for both `0.0.0.0` and `::`") is not special-cased
    either — `parse_server_or_address` tries to parse it as an IP and
    rejects it with `InvalidValue`. `SERV_ALL_ZEROS` itself is fully
    implemented and tested (`domain_match::make_local_answer` answers both
    A and AAAA with the zero address) — only the `#` config-syntax shorthand
    for it is missing.
  - Answer-size truncation (TC bit + emptied answer section when the reply
    would not fit) is implemented only for this literal-address path, not
    generally: every other locally-answered query type in `answer_request`
    (TXT, host records, PTR, MX, SRV, NAPTR, cache hits) still builds an
    unbounded answer section with no size check, unlike upstream's
    `make_local_answer()`, which upstream uses for the whole reply, not just
    address literals.
  - No `log_query`-equivalent call accompanies these answers (see the
    existing `log_txt` gap above, `tasks.md:410-412`) — this crate has no
    general `log_query` facility yet.
  Required tests: a `/#/`-wildcard-domain test and a `#`-null-address test
  once those config-syntax gaps are closed; a general (non-address) local
  answer truncation test once that is implemented.
  Done when: `/#/` and address-position `#` parse per the man page, and
  every locally-answered query type respects a reply size budget, not just
  address literals.

## P3 Feature-Specific Completion

- [x] Wire `loop.c` (forwarding-loop detection) into a live caller (Issue #44 / T3-loop).
  Source of truth: `loop.c:22-111`, `src/loop_detect.rs`.
  `loop_make_probe`/`loop_send_probes`/`detect_loop` now match upstream wire
  format exactly (`LOOP_TEST_DOMAIN="test"`, `LOOP_TEST_TYPE=T_TXT`, uid as an
  8-hex-digit label) instead of the previous ad hoc 16-byte-token/".invalid"
  scheme. `Server::uid` (already present, `loop`-gated) is now actually
  assigned a random value in `option::new_server`, mirroring
  `add_update_server()`'s `serv->uid = rand32()` (`domain-match.c:759`) — every
  prior build left every server's uid at `0`, so probes could never be told
  apart.
  Real callers: `dnsmasq::run_main_loop_with` sends one round of probes at
  startup when `--dns-loop-detect` is set and `port != 0`, mirroring
  `check_servers(0)` being called once after the pre-fork parent releases
  (`dnsmasq.c:1082-1083`). `forward::run_forward_loop_on` calls `detect_loop`
  on every incoming client query before dispatch (mirrors `forward.c:1862`)
  and drops a matching probe outright; `ForwardEngine::forward_query` filters
  `SERV_LOOP`-flagged servers out of candidate selection, mirroring
  `ServerArray::build`'s existing (already-live) `SERV_LOOP` skip in
  `domain_match.rs`.
  Known gap, deliberately left open: upstream also re-sends probes whenever
  `check_servers(0)` runs again — on SIGHUP reload after a resolv-file
  re-read, and after `servers-file` re-read. `dnsmasq::clear_cache_and_reload`
  (the SIGHUP hook) has no channel into the already-spawned forward task's
  live `ForwardEngine::loop_servers`, so a SIGHUP-triggered `server=` change
  does not get a fresh probe round; a server flagged `SERV_LOOP` before
  reload also stays flagged after. This is the same "`ForwardConfig` is a
  startup snapshot, not reactively updated on reload" gap every other
  reload-sensitive `ForwardConfig` field already has (see the P0 startup/reload
  blocker above) — fixing it for loop detection specifically, ahead of that
  general reload-plumbing work, would just be a special case that immediately
  rots once the general fix lands.
  Required tests: `src/loop_detect.rs` unit tests (wire format, eligibility
  filtering, uid matching, a real-socket loopback `send_probes` test);
  `option.rs` tests for `new_server` uid randomness and `--dns-loop-detect`
  reaching `ForwardConfig`.
  Done when: the SIGHUP/reload gap above is closed as part of the general
  `ForwardConfig` live-reload work.

- [x] Give `dbus.c` a real bus connection and full method dispatch (Issue #46 / T3-dbus).
  Source of truth: `dbus.c` (1106 lines), `src/dbus.rs`.
  Previously a 101-line "stub" with 4 fake method names and zero `zbus` usage
  despite the dependency being declared. Now a real `zbus`-backed system-bus
  service: `dbus::connect()` mirrors `dbus_init()` (`dbus.c:950-985`) —
  connects to the system bus, requests the configured well-known name, serves
  the dnsmasq interface at `/uk/org/thekelleys/dnsmasq`, and emits the
  startup `Up` signal. `dbus::run_dbus_task()` retries on a fixed backoff
  while the bus is unreachable, an async-native stand-in for upstream's
  poll-based `set_dbus_listeners()`/`check_dbus_listeners()` (zbus services
  watches/dispatch on its own internal executor, so there's nothing to poll
  once connected) — a deliberate architecture deviation, not a behavior
  change to the interface itself. `dnsmasq::run_main_loop_with` spawns this
  task whenever `--enable-dbus` (`OPT_DBUS`) is set; `option.rs`'s
  `enable-dbus` now also captures the optional bus-name argument into
  `daemon.dbus_name` (previously parsed with `set_option` only, silently
  discarding any name argument), defaulting to `DNSMASQ_SERVICE`
  (`uk.org.thekelleys.dnsmasq`) exactly like `option.c:2263-2268`.
  All 15 upstream methods are implemented, not stubbed: `GetVersion`,
  `SetServers`/`SetServersEx`/`SetDomainServers` (real `mark_servers`/
  `add_update_server`/`cleanup_servers` mutation of `daemon.servers`, reusing
  the same domain-fanout shape as `parse_server_or_address` for the `server=`
  directive), `SetFilterWin2KOption`/`SetLocaliseQueriesOption`/
  `SetBogusPrivOption` (real `OPT_*` bit toggles), `SetFilterA`/`SetFilterAAAA`
  (real `rrlist_filter` entries), `GetMetrics`/`GetServerMetrics`/
  `ClearMetrics` (real `metrics.rs` counters and per-server stats, matching
  issue #103's `clear_metrics`), `ClearCache` (calls the real
  `clear_cache_and_reload`), `GetLoopServers` (`loop` feature only, matching
  `HAVE_LOOP`), and `AddDhcpLease`/`DeleteDhcpLease` (`dhcp` feature only,
  matching `HAVE_DHCP`). `DhcpLeaseAdded`/`DhcpLeaseDeleted` signals are
  emitted on successful add/delete through these two methods
  (`dbus::emit_lease_signal`, mirroring `emit_dbus_signal`, `dbus.c:1052-1103`).
  Deliberate, documented gaps (all in `src/dbus.rs`):
  - `AddDhcpLease`/`DeleteDhcpLease` operate on a lease store owned by the
    D-Bus task (`DbusContext::leases`, seeded empty and persisted to
    `--dhcp-leasefile` if configured), **not** the `LeaseDb` the live
    `dhcp::run_dhcp_loop` task owns internally — that loop has no shared
    handle or event channel today (it takes a `LeaseDb` by value and keeps
    it private). So a D-Bus-added lease won't be seen by a concurrently
    running DHCP server in this build, and normal DHCP-protocol-driven lease
    changes (a real client's DISCOVER/REQUEST) do not emit D-Bus signals —
    only the D-Bus-triggered path does. Upstream avoids this because
    `dbus_add_lease`/`dbus_del_lease` and the DHCP state machine both mutate
    the single global `daemon->leases`, and `emit_dbus_signal` is called
    generically from `lease.c:1258,1295` on every insert/prune regardless of
    who triggered it. Closing this gap needs either a shared
    `Arc<Mutex<LeaseDb>>` or an event channel out of `run_dhcp_loop`, which is
    DHCP-loop-shaped work, not D-Bus-shaped — tracked here rather than
    attempted as a side effect of this issue.
  - `AddDhcpLease`/`DeleteDhcpLease` support IPv4 leases only; an IPv6 address
    returns an explicit `InvalidArgs` error rather than silently no-oping
    (upstream's `HAVE_DHCP6` half needs `lease6_find_by_addr`/`lease6_allocate`
    against the same not-yet-shared lease store).
  - `SetServers`/`SetServersEx`/`SetDomainServers` only accept literal IP
    addresses, not hostnames — upstream's `parse_server`/`parse_server_next`
    resolve hostnames to possibly multiple addresses via `getaddrinfo`; this
    port's address parsing (shared with `parse_server_or_address` in
    `option.rs`) doesn't do DNS resolution at all.
  - Mutating `daemon.servers`/`daemon.rrlist_filter` via these methods changes
    the canonical `Daemon` state but does not hot-reload the already-spawned
    forward loop's `ForwardConfig` snapshot — the exact same
    "`ForwardConfig` is a startup snapshot, not reactively updated" gap
    called out above for `loop.c`'s SIGHUP case, not something specific to
    D-Bus.
  - `SetServers`'s `av` argument encodes an IPv4 address as a plain `uint32`;
    upstream stores it via `ntohl()` into a field that's itself supposed to
    already be network-order, which reads as an upstream quirk rather than a
    documented contract. This port takes the unambiguous, conventional
    reading (`Ipv4Addr::from(u32)`, i.e. the wire integer *is* the address in
    network byte order) rather than replicating that byte-order ambiguity.
  - `GetServerMetrics`'s reply is naturally `Vec<HashMap<String, String>>`
    (`"aa{ss}"`, one dict per server) since that's what `dbus_get_server_metrics`
    actually builds; upstream's own introspection XML declares the return
    type as the (narrower, and arguably wrong) `"a{ss}"`. This port matches
    the real per-server-dict *behavior*, not the introspection XML text.
  - A custom `--enable-dbus=<name>` renames the *interface* upstream (the
    introspection XML is templated with `daemon->dbus_name` for both the bus
    name and the interface name); this port only renames the well-known bus
    name via `.name(dbus_name)` — the D-Bus interface name served at
    `/uk/org/thekelleys/dnsmasq` stays the fixed `DNSMASQ_DBUS_INTERFACE`
    constant, since `zbus`'s `#[interface(name = ...)]` needs a literal.
  Required tests: `src/dbus.rs` unit tests for every pure method body
  (server-list mutation incl. mark/reuse/cleanup semantics, option/filter
  toggles, metrics serialization, lease add/delete incl. validation errors);
  a `#[tokio::test]` live-bus smoke test gated to skip (not fail) when no
  D-Bus daemon is reachable, matching the sandboxed-environment gating
  pattern already used for socket/interface tests elsewhere; `option.rs`
  tests for `enable-dbus`'s default and custom bus-name argument.
  Done when: the lease-store-sharing gap above is closed as part of general
  DHCP-loop live-state-sharing work (tracked separately, not yet a task here).

- [x] Protocol header completeness: DNS RR types and IPv6 address predicates (Issue #53 / T3-protocol-consts).
  Source of truth: `dns-protocol.h:44-79`, `dhcp6-protocol.h:71-77`, `ip6addr.h:24-32`.
  Implemented, tested:
  - `RrType::from_u16` now round-trips all 27 declared variants — added 17 missing match arms
    (MD, MF, MB, MG, MR, MINFO, RP, AFSDB, RT, SIG, PX, NXT, KX, DNAME, TKEY, TSIG, MAILB).
    New unit test `rrtype_from_u16_legacy_types` verifies full coverage. Call sites
    (`rfc1035.rs` lines 201, 244, 548; `auth.rs` line 387) benefit immediately without
    signature changes.
  - Added `is_ula_zero_v6(addr)` and `is_link_local_zero_v6(addr)` to `src/network.rs`,
    checking for exactly `fd00::` and `fe80::` respectively (used by upstream `radv.c:479-501`
    and `rfc3315.c:1342-1365` to elide RA/DHCPv6 options). Unit tests verify exact-match
    semantics and reject non-zero suffixes and out-of-range addresses.
  - DHCP6 status codes were already ported (research finding #2 is stale): constants exist as
    `STATUS_SUCCESS`, `STATUS_UNSPEC_FAIL`, etc. in `src/rfc3315.rs:648-658` and as the
    `Dhcp6Status` enum in `src/dhcp6_protocol/mod.rs:88-97` under different naming convention.
    No new implementation needed — the checklist item is resolved as-is under the existing
    constants/enum, with the caveat that no reply logic ever emits failure statuses (a
    separate `rfc3315.c` behavior gap, not a header-completeness one).
  Still open (tracked, not silently dropped):
  - The new `is_ula_zero_v6` and `is_link_local_zero_v6` predicates have no production callers
    yet — `radv.rs` and `rfc3315.rs` lack the surrounding decision logic from upstream
    (RA prefix-lifetime elision, DHCPv6 address-substitution). Adding the predicate satisfies
    "macro has a Rust equivalent" but not "affects runtime behavior"; wiring these into live
    reply paths is follow-up work outside this issue's scope.
  Required tests: `cargo test` passes cleanly (2132 lib tests + 2132 bin tests, all passing).
  Done when: all requirements met above — all match arms added, new predicates tested, no
  behavioral impact from these additions (intentional, as they lack callers in this build).

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

- [ ] Wire `radv::calc_interval` / `radv::calc_lifetime` (radv.rs) into real RA scheduling and packet
  construction, matching upstream call sites `calc_interval(find_iface_param(iface_name))` /
  `calc_lifetime(find_iface_param(iface_name))` at radv.c:281, 293, 422, 981. Both functions now
  reproduce upstream clamp semantics exactly (Issue #16) but have no production callers — `new_timeout`
  and RA packet building still use ad hoc interval/lifetime values instead of these helpers.
  Required tests: call-site tests proving RA scheduling and the router-lifetime wire field reflect
  per-interface `ra-param` config (interval, lifetime, including the lifetime=0 "no default route" case).
  Done when: RA interval/lifetime are actually derived from `RaInterfaceParam` at every upstream call site.

- [ ] Reassess DNSSEC claims against actual implementation status.
  Source of truth: `src/dnssec.rs`, `src/crypto.rs`, existing TODO notes, parity outcomes.
  Required tests: validation-path tests, malformed input tests, upstream comparison for supported DNSSEC scenarios.
  Done when: docs and behavior agree on what DNSSEC support is real versus partial.
  Update (Issue #10 / T1-1): `validate_rrset` now calls `crypto::verify_sig` and
  returns `Bogus` on any failed/forged/wrong-key signature instead of an
  unconditional `Secure`. Supported algorithms: 5 (RSA/SHA1), 8 (RSA/SHA256),
  10 (RSA/SHA512), 13 (ECDSA P-256), 14 (ECDSA P-384), 15 (Ed25519) — matching
  `crypto::DnssecAlgorithm`. Algorithm 7 (RSASHA1-NSEC3-SHA1) and 16 (Ed448)
  are explicitly unsupported and skipped (RRSIG tried, then falls through to
  the next signature/`Bogus`), same as any other unknown algorithm ID.
  Still open: `validate_rrset` has no live caller anywhere in `src/` — wiring
  it into the actual resolution/reply path is separate, untouched work.
  Update (Issue #11 / T1-2): fixed a real correctness bug — algorithm 5
  (RSA/SHA1) was being verified with `RsaVerifyingKey<Sha256>`, so every
  algorithm-5 signature failed closed (never a forgery risk, but every
  legitimately-signed algorithm-5 RRset was rejected as `Bogus`).
  `verify_sig` now splits the RSA match arm so algorithm 5 hashes with
  SHA-1 (`sha1` crate, matching upstream `crypto.c:192-200`) while
  algorithm 8 keeps SHA-256; both share the same RFC 3110 key wire format
  and `RsaSha256` storage variant. Also fixed an internal inconsistency:
  `algo_digest_name(16)` (Ed448) previously returned `Some("null_hash")`
  while `parse_dnskey`/`verify_sig` both reject it — it now returns `None`
  so `algo_supported(16)` agrees with the actual rejection path. GOST
  (algorithm 12, upstream `crypto.c:279-317`, gated `MIN_VERSION(3,6)`) and
  Ed448 (algorithm 16, `crypto.c:320-362`) remain unimplemented — both are
  explicitly rejected (`DnssecAlgorithm::try_from` fails closed for 12;
  `parse_dnskey`/`verify_sig` fail closed for 16), not silently ignored.
  Update (Issue #40 / T3-dnssec-depth): the trust-chain orchestration layer
  on top of the T1-1 crypto/parsing primitives is now real, in `src/dnssec.rs`.
  Source of truth: `dnssec.c:68-2331`.
  Implemented, tested:
  - `ValidateStatus`/`StatCode`: unified `Secure|Insecure|Bogus|NeedKey|NeedDs|Abandoned`
    result carrying a `DNSSEC_FAIL_*` bitmask, replacing the never-populated `ValidationResult`.
  - `DnssecCache`: an in-memory DS/DNSKEY trust store (positive entries, `NegInsecure`
    "proved no DS at a real zone cut", `NegNotZoneCut` "proved no DS but not a
    delegation point either" — the same three outcomes as upstream's `crec`
    `F_NEG`/`F_DNSSECOK` combinations). **This is a stand-in for live `cache.rs`
    wiring, not a port of `struct crec` itself** — see "Still open" below.
  - `zone_status` (dnssec.c:1881-1956): walks a name toward a cached/configured
    trust anchor, then back down, exactly as upstream.
  - `dnssec_validate_by_ds` (dnssec.c:716-972): validates a DNSKEY RRset's
    self-signature against a cached DS, then caches every protocol-3 DNSKEY in
    the now-validated RRset — matching upstream's cache-insert loop
    (dnssec.c:895-925) exactly, which does not re-check the zone-key flag at
    that point (that flag only gates which key is *tried* against the DS, not
    which keys get cached once the RRset as a whole validates). An earlier
    version of this port over-restricted the cache-insert to zone-key-flagged
    DNSKEYs only; fixed, with a regression test
    (`dnssec_validate_by_ds_caches_non_zone_key_dnskeys_too`).
  - `dnssec_validate_ds` (dnssec.c:990-1179): validates/accepts a DS-query
    answer via `dnssec_validate_reply`, caches positive DS or a negative
    zone-cut/non-zone-cut proof. Not ported: the RFC-1918/`--bogus-priv` and
    domain-specific-server insecure-DS fallback carve-outs (dnssec.c:1026-1047)
    and the CNAME-proves-DS-absence `prim_ok` path — both need config/cache
    surfaces (`option_bool(OPT_BOGUSPRIV)`, `lookup_domain`) not wired here.
  - `ds_matches_dnskey` extended from SHA-256-only to also support digest
    types 1 (SHA-1) and 4 (SHA-384), matching `crypto::ds_digest_name`.
  - NSEC/NSEC3 negative proofs (dnssec.c:1247-1871): `prove_non_existence_nsec`,
    `check_nsec3_coverage`, `prove_non_existence_nsec3` (closest-encloser walk,
    opt-out, wildcard-non-existence check, `LIMIT_NSEC3_ITERS` bound —
    `DEFAULT_NSEC3_ITERS_LIMIT = 150` matching `config.h`), and the
    `prove_non_existence` NSEC-vs-NSEC3 dispatcher.
  - `dnssec_validate_reply` (dnssec.c:1974-2331): the top-level orchestrator —
    CNAME-chain following, per-RRset dedup, `zone_status` + multi-key
    `validate_rrset` per RRset, missing-answer NSEC/NSEC3 proof with the
    NEED_DS/NEED_KEY-vs-BOGUS fallback upstream uses when the proof itself
    fails but the zone's signedness is still unknown. Also fixes the gap the
    issue's audit flagged in the existing `explore_rrset`: RRSIGs covering one
    RRset must share a single signer name — enforced here as part of the
    per-RRset validation loop (a mismatch is `Bogus`), rather than by changing
    `explore_rrset`'s own signature and risking existing callers/tests.
    The CNAME-chain chase (a simplified single-target-by-name walk, not
    upstream's index-bounded multi-target array — see "Still open" below) is
    guarded by a `visited` set: a repeated name breaks the loop instead of
    spinning forever on an attacker-supplied CNAME cycle
    (`a -> b -> a`), falling through to the ordinary missing-answer
    non-existence-proof path so a cyclic/unresolvable chain reports
    `NeedDs`/`NeedKey`/`Bogus`, never `Secure`. Regression test:
    `dnssec_validate_reply_cname_cycle_terminates`.
  - `setup_timestamp`/`timestamp_clock_now_sane` (dnssec.c:68-141): the pure
    decision logic (mtime vs now) is ported; the actual file stat/create/touch
    IO is deliberately left to the caller (see "Still open").
  Required tests: end-to-end signed-zone validation from a trust anchor
  (`dnssec_validate_reply_secure_a_record`), corrupted-signature and
  missing-DS Bogus/NeedDs paths, NSEC and NSEC3 negative-answer proofs
  (direct-hit and closest-encloser), zone-cut vs non-zone-cut negative DS
  caching, SERVFAIL handling. All in `src/dnssec.rs`'s `#[cfg(test)]` module.
  Still open (tracked, not silently dropped):
  - **No live caller anywhere in `src/`.** Exactly as before this issue,
    `grep -rn "dnssec::" src/forward.rs` finds nothing. `DnssecCache` is a
    self-contained trust store, not the real `cache.rs` — wiring
    `dnssec_validate_by_ds`/`dnssec_validate_ds`/`dnssec_validate_reply` into
    `forward.rs`'s dead `FREC_DNSKEY_QUERY`/`FREC_DS_QUERY`/`blocking_query`/
    `dependent` scaffolding (forward.rs:246-249, 337-387), issuing real
    sub-queries on `NeedKey`/`NeedDs`, and setting `secure`/`F_DNSSECOK` from
    a real result instead of the hardcoded `secure: false`
    (`ForwardConfig::extract_config`) is separate, still-untouched work.
  - DNAME-synthesizes-CNAME pre-qualification (dnssec.c:2063-2149) is not
    ported; a DNAME reply without a literal matching CNAME RRset falls
    through to the ordinary CNAME-chase/non-existence-proof path instead of
    being pre-accepted.
  - The CNAME-target-discovery step is a single-target-by-name chase (follow
    `qname`'s CNAME chain one hop at a time, cycle-guarded by a `visited`
    set) rather than upstream's index-bounded multi-target array
    (dnssec.c:2038-2060, 2298-2325), which records *every* CNAME found in the
    answer section and proves non-existence for each one still unresolved
    after the RRset-validation loop. For a normal linear chain (A -> B -> C,
    no branching) the two are equivalent — both end up proving non-existence
    for the final unresolved name. They diverge for an answer with multiple,
    independent unresolved CNAME targets (not just one chain): upstream
    would check non-existence for each; this port only follows the one chain
    rooted at `qname`. Not exploitable into a false `Secure` (a real branch
    left unchecked would still need its own valid answer/proof to matter),
    but it is a real behavioral simplification worth closing if the
    multi-target case turns out to matter in practice.
  - The wildcard-replay re-check (dnssec.c:2271-2273: after a wildcard-expanded
    RRset validates, re-run `prove_non_existence` to rule out a replayed
    wildcard answer overlaying a genuine record) is not implemented —
    `RrsetValidation::Secure` doesn't currently carry the `wild_offset`
    upstream's `validate_rrset` returns, so `dnssec_validate_reply` has
    nothing to trigger the recheck with. This is defense-in-depth on top of
    the core validate/prove-negative state machine, not required for a
    signed zone to validate or a broken chain to come back `Bogus`.
  - `setup_timestamp`'s actual `stat`/`open`/`utimes` calls on
    `daemon.timestamp_file`, and the `back_to_the_future` flag it should set
    on `Daemon`, aren't wired into `dnsmasq.rs`'s init path — there's no
    `--dnssec-timestamp` config directive yet either (check before assuming
    one exists). The pure mtime-vs-now decision (`setup_timestamp`,
    `timestamp_clock_now_sane`) is ready for that wiring.
  - `dnssec_validate_by_ds`/`dnssec_validate_ds`/`dnssec_validate_reply` take
    already-parsed `&[DnsRr]` slices (matching this file's existing
    `explore_rrset`/`validate_rrset` convention), not a raw `dns_header*`
    packet buffer like upstream — `get_rdata`'s byte-at-a-time canonicalization
    iterator is likewise not ported 1:1; `canonicalize_rdata` (already in this
    file before this issue) is the parsed-`DnsRr` equivalent used instead.

- [ ] `src/dump.rs`: `--dump-file`/`--dump-mask` now have a real, live-wired writer
  instead of an in-memory `Vec` with no callers (Issue #43 / T3-dump).
  Source of truth: `dump.c:46-303`.
  Implemented, tested:
  - `DumpHandle::init` (`dump.c:46-92`): opens a real file — creates a new one and
    writes the 24-byte global header; reopens a FIFO for append and writes the
    header (no read-back, matching the wireshark-over-a-pipe case); reopens an
    existing regular file for append, validates the existing header's magic
    number, and scans forward through existing records (seeking by each
    `incl_len`) to recover `packet_count` so numbering continues on restart.
  - `DumpHandle::dump_packet_udp`/`dump_packet_icmp` (`dump.c:94-129`): named
    hooks gated on `mask & dump_mask`, reusing the already-correct
    `frame_udp_ipv4`/`frame_udp_ipv6`/`frame_icmp_ipv4`/`frame_icmpv6` framing.
  - `DumpFallback::Local` implements the `fd >= 0` half of upstream's
    `getsockname()` fallback (`dump.c:109-118`) — Rust callers already hold the
    socket's local address (`UdpSocket::local_addr()`), so no syscall is needed.
  - Wired into `run_main_loop_with` (`src/dnsmasq.rs`): `DumpHandle::init` is
    called once at startup when `dump_file` is configured, mirroring upstream's
    single `dump_init()` call from `main()` (`dnsmasq.c:450`); failure is fatal
    (`RunResult::IoError`), matching upstream's `die()`.
  - Wired into `run_forward_loop_on` (`src/forward.rs`): `DUMP_QUERY` on every
    client query received, `DUMP_REPLY` on every reply sent to a client —
    local answers, REFUSED answers (both the connmark-allowlist and
    forward-table-full paths), and forwarded upstream replies. Covers this
    issue's acceptance criteria (`--dump-file` produces a pcap with query and
    reply traffic); end-to-end tested in
    `dnsmasq::tests::run_main_loop_writes_query_and_reply_to_the_dump_file`.
  Still open (tracked, not silently dropped):
  - `DumpFallback`'s `fd < 0` case (a bare port number, no address at all —
    used by upstream callers with no socket handle, e.g. TFTP) is not
    implemented; only the `getsockname()`-equivalent `Local` fallback exists.
  - `DUMP_UP_QUERY`/`DUMP_UP_REPLY` (queries sent to / replies received from
    upstream servers, as distinct from the client-facing `DUMP_QUERY`/
    `DUMP_REPLY` this issue wires up) are not called anywhere.
  - `DUMP_SEC_QUERY`/`DUMP_SEC_REPLY`/`DUMP_BOGUS`/`DUMP_SEC_BOGUS` (DNSSEC
    dump points) and `DUMP_DHCP`/`DUMP_DHCPV6`/`DUMP_RA`/`DUMP_TFTP` (the
    `dhcp.rs`/`rfc2131.rs`/`dhcp6.rs`/`rfc3315.rs`/`radv.rs`/`tftp.rs` call
    sites) are unwired — none of those modules call into `dump.rs` at all.
  - ICMP dumping (`dump_packet_icmp`, used by upstream's DHCP/ARP conflict
    detection) has a working, tested `DumpHandle::dump_packet_icmp`, but no
    live caller yet — the `icmp`-adjacent code in `src/arp.rs`/`src/dhcp.rs`
    doesn't call it.

- [ ] `src/auth.rs`: `answer_auth` now answers from real `Daemon`/`DnsCache` state instead of
  the synthetic `AuthZoneConfig`/`LocalRecords` structs (Issue #41 / T3-auth).
  Source of truth: `auth.c:21-916`.
  Implemented, tested:
  - Signature changed to `answer_auth(query, config: &mut AuthConfig, cache: &mut DnsCache,
    peer_addr, local_query, now)`. `AuthConfig<'a>` borrows straight out of `Daemon`
    (`auth_zones`, `mxnames` (`&mut`, for SRV rotation), `naptr`, `rr`, `txt`, `int_names`,
    `cnames`, `auth_peers`, SOA/`auth_ttl`/`authserver`/`hostmaster` fields), matching the
    existing `rfc1035::LocalConfig` convention rather than taking the whole `Daemon`.
    `AuthZoneConfig`/`LocalRecords` are gone.
  - `in_zone` now returns `Option<Option<usize>>` (member? → cut point), restoring the `cut`
    output C's version has (`auth.c:72-96`) and dropped in the previous port.
  - `find_subnet`/`find_exclude`/`filter_zone` (already correctly ported, auth.rs pre-#41) are
    now actually called from `answer_auth`'s zone-selection, PTR, A/AAAA, and AXFR-dump paths —
    previously dead code with no caller.
  - OPCODE != QUERY → NOTIMP, `qclass != IN` → REFUSED (`auth.c:130-153`), both previously
    entirely absent.
  - PTR reverse lookups walk `int_names` address lists and `DnsCache::lookup_all_by_addr`
    (real DHCP/hosts-sourced records, identified by `F_DHCP`/`F_HOSTS`), with the
    `OPT_DHCP_FQDN` bare-name/FQDN split and zone-suffix reattachment (`auth.c:173-274`).
  - CNAME-chain and wildcard-CNAME (`*.zone`) resolution with a `cname_restart`-equivalent
    loop, appending the zone domain to a bare target (`auth.c:527-586`).
  - SRV and NAPTR are served (`daemon.mxnames` where `is_srv`, `daemon.naptr`); the first
    matching SRV record is rotated to the end of `mxnames` on each query, matching upstream's
    round-robin side effect (`auth.c:312-345`).
  - AXFR is authorized against `--auth-peer` (`daemon.auth_peers`, port ignored like upstream)
    or `--auth-sec-servers` (`daemon.secondary_forward_servers`); an unauthorized request
    returns `None` (dropped, no wire reply) instead of always succeeding.
  - Coarse (all-or-nothing) UDP truncation: the built reply's wire size is checked against
    `PACKETSZ`/`edns_pktsz` and `HB3_TC` set with counts zeroed on overflow, matching
    `auth.c:874-881`'s effect if not its incremental per-RR mechanism.
  - `Addrlist`-derived reverse-zone apex name (`X.X.X.in-addr.arpa` / `...ip6.arpa`) for the
    auth section's SOA/NS owner when a PTR/SOA/NS-on-`.arpa` query resolved via a zone subnet
    match, matching the `authname` computation at `auth.c:596-631`.
  Still open (tracked, not silently dropped):
  - **No live caller.** `grep -rn "auth::answer_auth" src/forward.rs src/dnsmasq.rs` finds
    nothing; nothing in the runtime query path routes a query into this function yet. Wiring
    it into `run_forward_loop_on`/`answer_locally` needs its own design pass — naively calling
    it for every query whenever any `--auth-zone` is configured would incorrectly REFUSE
    ordinary out-of-zone queries on interfaces that should still recurse/forward, because
    per-interface `dns_auth` gating (`--auth-server`, already tracked as missing in the
    `src/network.rs` entry above) isn't ported. A safe integration has to pre-filter on
    `in_zone`/`find_subnet` before dispatching to `answer_auth`, or port `dns_auth` first.
  - `is_name_synthetic`/`is_rev_synth` (`--synth-domain` forward/reverse synthesis fallback,
    `auth.c:260,420`) are not called. `daemon.synth_domains` exists and is consulted elsewhere
    (`rfc1035::check_for_local_domain`). `daemon.cond_domain` (the plain `--domain` subnet
    form) is now populated by `option::parse_domain` (Issue #56/T3-daemon-struct), but still
    has no consumer anywhere in this port — see the `--domain`/`synth-domain` entry
    elsewhere in this file and the existing note on `Daemon::cond_domain` in
    `src/types/daemon.rs`.
  - Multi-message TCP AXFR framing is not implemented; truncation only sets `HB3_TC` on a
    single UDP-sized reply, matching the *signal* upstream's `add_resource_record` truncation
    gives but not the TCP-retry zone-transfer path itself.
  - The AXFR dump and forward-answer paths always write full (non-cut) owner names on the
    wire; upstream's `cut`-truncate-then-restore dance around `add_resource_record` is a
    wire-compression optimization with no effect on the decoded name, and this port (like the
    rest of `src/rfc1035.rs`) writes uncompressed names throughout, so it's intentionally not
    replicated.
  Required tests: `src/auth.rs`'s `#[cfg(test)]` module — OPCODE/QCLASS gating, zone-subnet
  filtering actually applied to A/AAAA and PTR, a PTR answer sourced from a real `DnsCache`
  DHCP-style record with FQDN stripped, CNAME-chain and wildcard-CNAME resolution, SRV
  serving + rotation, NAPTR serving, AXFR authorized/refused via peer list and via
  `--auth-sec-servers`, NXDOMAIN/NODATA/SOA-at-apex, out-of-zone REFUSED.

- [x] `dhcp6::dispatch_dhcp6` real allocation/DUID/context pipeline, wired into the main loop
  (Issue #34 / T3-dhcp6).
  Source of truth: `dhcp6.c:35-689` (`dhcp6_init`, `complete_context6`, `address6_allocate`,
  `make_duid`/`make_duid1`, `dhcp_construct_contexts`/`construct_worker`).
  Implemented, tested, real (no longer stubs):
  - `make_duid`/`build_duid_en`/`build_duid_llt`/`build_duid_ll`: builds and persists a real
    on-wire DUID into `daemon.duid` — DUID-EN from `--dhcp-duid=` (`daemon.duid_config`, renamed
    from the old dual-purpose `daemon.duid` field so config input and constructed output don't
    collide), else DUID-LLT/DUID-LL from a caller-supplied MAC (`DuidMacSource`).
  - `complete_context6`: plain (non-shared-network) branch of the real algorithm — prefix/net
    matching, `CONTEXT_CONSTRUCTED`-vs-fixed lifetime handling, chain ordering by preferred time.
  - `address6_allocate`: the actual hash-seeded collision/DECLINE-retry scan (dhcp6.c:536-565),
    replacing the old single-candidate `hash_to_addr6` call with no retry.
  - `dhcp_construct_contexts`: the non-template branch of `construct_worker` — fills
    `if_index`/`local6` on plain contexts from live interface prefixes.
  - `dhcp6_init`: binds `[::]:547` via the existing `network::make_sock` (already sets
    `IPV6_V6ONLY`/`IPV6_RECVPKTINFO`/`SO_REUSEADDR`).
  - `dispatch_dhcp6`: takes real `duid`/`contexts`/`in_use` state and returns a genuine
    IA_NA/IAADDR-bearing Advertise/Reply (or a Status-Code NoAddrsAvail IA_NA when allocation
    fails), instead of the old canned empty-options stub. On a successful allocation, it now
    delegates reply construction to `rfc3315::handle_solicit`/`handle_request6` — the exact pair
    the issue named as taking `server_duid`/an address as opaque, generator-less parameters —
    feeding them the real DUID (`make_duid`) and the real `address6_allocate` result instead of
    leaving them unreachable dead code (confirmed by grep: previously `rfc3315::` had zero callers
    anywhere outside its own doc comments and unit tests). `parse_dhcp6_packet`/`write_dhcp6_packet`
    handle the conversion between this module's flat-bytes `Dhcp6Packet`/`Dhcp6Reply` and
    `rfc3315::Dhcp6Packet`'s structured `Vec<Dhcp6Option>` (`flatten_dhcp6_options`); the two
    representations are still not fully unified into one type (still a follow-up item), but the
    success path is no longer a second, parallel, unwired implementation of the same logic — it's
    a bytes-level adapter in front of the real handler. The no-address branch (Status Code
    NoAddrsAvail) is still built locally in `dhcp6.rs`, since `handle_solicit`/`handle_request6`
    always assume success (they take `Ipv6Addr`, not `Option<Ipv6Addr>`).
    Covered by `dhcp6::tests::dispatch_dhcp6_solicit_success_delegates_to_rfc3315_handle_solicit`
    (asserts the top-level Status-Code option only `rfc3315::handle_solicit`'s construction adds —
    proof the reply came from that function, not `dhcp6.rs`'s old parallel encoder).
  - `src/main.rs` was missing `pub mod dhcp6;` entirely (present in `lib.rs` only, so the release
    binary never even compiled this file) — added, matching `rfc3315`/`radv`/`slaac`.
  - **Production wiring (this pass):** `dhcp6::run_dhcp6_loop` is a real receive/dispatch loop —
    parses each datagram, calls `dispatch_dhcp6`, commits an allocated address into a `LeaseDb`
    only for Request/Renew/Rebind (never for Solicit/Advertise), and replies to the client.
    `dnsmasq::daemon_dhcp6_runtime_with`/`daemon_dhcp6_runtime` generate/persist the DUID via
    `make_duid` (skipped if `daemon.duid` is already set) and build the "current" context chain
    via `dhcp_construct_contexts` + `complete_context6` fed by
    `network::enumerate_live_addrs6()`/`network::first_dhcp6_mac_source()` (the latter reads
    `/sys/class/net/*/{type,address}` on Linux; `None` elsewhere). `bind_listeners` claims
    `[::]:547` pre-fork (mirroring the existing IPv4 DHCP socket's privileged-bind timing) when
    `daemon.dhcp6` is non-empty, and `run_main_loop_with` spawns `run_dhcp6_loop` under
    `#[cfg(feature = "dhcp6")]`, adopting that pre-bound socket or binding it itself for the
    in-process/test path — the same pre-fork-bind-or-adopt pattern the IPv4 DHCP loop already
    uses. Covered end-to-end by
    `dnsmasq::tests::run_main_loop_with_dhcp6_context_binds_port_547_and_persists_duid` (a real
    `Daemon` with a `dhcp6` context makes the running main loop actually claim port 547 and
    persist a DUID) and `dhcp6::tests::run_dhcp6_loop_*` (Solicit → Advertise with an allocated
    address over a real socket pair; a Request commits the lease so a second client requesting
    the same single-address pool is refused; the loop stops on the shutdown signal).
  - `network::join_dhcp6_multicast`/`join_dhcp6_multicast_all_interfaces` (port of the DHCPv6
    portion of `join_multicast()`, network.c:1306-1360): a wildcard `[::]:547` bind does **not**
    by itself receive multicast SOLICITs — IPv6 requires explicit `IPV6_JOIN_GROUP` membership per
    interface even for a wildcard bind, and the kernel silently drops unjoined multicast, so a real
    (non-relay, non-unicast-only) client could never have reached this server without it. Joins
    `ALL_DHCP_RELAY_AGENTS_AND_SERVERS` (ff02::1:2) and `ALL_DHCP_SERVERS` (ff05::1:3) on every
    live, non-loopback interface index from `enumerate_live_addrs6()`, deduplicated by index.
    Called from `run_main_loop_with` right after the DHCPv6 socket is adopted/bound. Unlike
    upstream, this doesn't track `iface->dhcp6_ok`/`relay6`-only join separately — it joins
    unconditionally whenever `daemon.dhcp6` is non-empty (i.e. whenever the DHCPv6 loop is
    started at all) — and a per-interface join failure is logged and skipped rather than
    `die()`-ing the whole daemon (a sandboxed environment without `CAP_NET_ADMIN`, or an interface
    that can't do multicast, must not prevent the rest of the daemon from starting). Upstream also
    joins `ALL_ROUTERS` on the ICMPv6 socket for RA; this crate's RA support does not call the new
    join helper. Covered by `network::tests::join_dhcp6_multicast_on_loopback_succeeds` (a real
    `IPV6_JOIN_GROUP` setsockopt against the loopback interface).
  Still open / explicitly unsupported:
  - `complete_context6` classifies a live address as ULA (`classify_addr6` /
    `Addr6Class::Ula`, matching upstream's `IN6_IS_ADDR_ULA(local)` at dhcp6.c:370) but does not
    record it anywhere a DNS-server-option fallback could read: upstream's `iface_param.ula_addr`
    (and `.ll_addr`/`.fallback`) exist specifically so `dhcp6_reply()` can offer a sensible
    default `--dhcp-option=6,<addr>` when none is configured. This crate's `dispatch_dhcp6` does
    not build a DNS-server option at all yet (DHCPv6 `--dhcp-option` support doesn't exist), so
    plumbing the ULA/link-local/fallback addresses through today would have no consumer; the
    classification is real but currently a dead end pending that larger feature.
  - The "current" context chain is built **once at startup**, not re-derived per packet against
    the packet's actual arrival interface the way upstream's `dhcp6_packet()` does (dhcp6.c:250).
    A context only ever offers addresses if some live interface matched it at startup; an
    interface that appears later (hotplug) won't be picked up without a restart. Re-running
    `daemon_dhcp6_runtime` on a netlink address-change event is a follow-up.
  - `run_dhcp6_loop` keeps its `LeaseDb` in-memory only — it does not load or write a shared
    `--dhcp-leasefile`. Doing that safely needs one writer for the file the IPv4 loop already
    owns (both loops independently loading/writing the same file would race), not two independent
    in-memory copies of it.
  - `complete_context6`'s shared-network branch and DHCPv6-relay `iface_index`/duplicate-warning
    bookkeeping (dhcp6.c:421-460) are not ported.
  - `dhcp_construct_contexts`'s template branch (`--dhcp-range=...,constructor:IFACE,...`) is
    still unreachable: no `template_interface` field on `DhcpContext` and no `constructor:` config
    parsing exist (same gap the log_context/log_relay entry above already flagged). Fast-RA
    kickoff and GC aging of constructed contexts are not ported either.
  - `address6_allocate` is single-pass only — upstream's two-pass `plain_range` fallback (try
    netid-matching contexts first, then any context) and `--consec-addresses` seeding mode are not
    ported.
  - `get_client_mac` (dhcp6.c:308-350, ICMPv6 neighbor-solicitation MAC resolution for
    `--dhcp-host` MAC matching over DHCPv6) is not ported. Not currently a silent dispatch gap:
    neither `address6_allocate`/`address6_valid` nor `config_find_by_address6` take a MAC
    parameter today, so no dispatch-path code assumes MAC-based host matching over DHCPv6 exists.
  - `config_find_by_address6` still only matches exact `/128` addresses, not prefix/wildcard
    address-list entries.
  - `network::enumerate_live_addrs6()` reports every address as non-deprecated with maximal
    preferred/valid lifetimes: `if-addrs` doesn't surface the kernel's actual lifetimes or the
    `IFACE_DEPRECATED` flag the way `getifaddrs`'s `ifa_flags` does. Only affects lease lifetimes
    offered from a `CONTEXT_CONSTRUCTED` context (`complete_context6` only reads those fields for
    that case).

- [x] `rfc3315.c`/`dhcp6::dispatch_dhcp6` per-message-type DHCPv6 state machine
  (Issue #35 / T3-rfc3315).
  Source of truth: `rfc3315.c:71-1301` (`dhcp6_reply()` and its per-`msg_type` case bodies),
  `:1719-1732` (`check_address`), `:1823-1868` (`calculate_times`).
  Previously `dhcp6::dispatch_dhcp6` folded Solicit/Request/Renew/Rebind/Confirm into one match
  arm that always called a fresh `address6_allocate` and delegated success replies to
  `rfc3315::handle_solicit`/`handle_request6`, which themselves hardcoded IA_NA lifetimes to
  3600/7200/1800/2880 regardless of context config; Release/Decline were a no-op empty Reply that
  never touched `lease_db`. Each message type is now its own function in `dhcp6.rs`
  (`dispatch_solicit`/`dispatch_request`/`dispatch_renew_rebind`/`dispatch_confirm`/
  `dispatch_release_or_decline`/`dispatch_inforeq`), and `dispatch_dhcp6` takes `lease_db: &mut
  LeaseDb` / `configs: &[DhcpConfig]` / `authoritative: bool` / `now_secs: u64` directly instead of
  an opaque `in_use` closure, since differentiating REQUEST's three failure statuses needs to know
  *who* holds a conflicting lease, not just whether one exists (`check_address`, ported from
  rfc3315.c:1719-1732).
  - **Lifetimes**: `rfc3315::build_ia_na`/`handle_solicit`/`handle_request6` now take a
    `lease_time: u32` argument and call `calculate_times()` instead of returning fixed constants
    (covered by `rfc3315::tests::handle_solicit_lifetimes_come_from_lease_time_argument`); however
    `dhcp6.rs`'s handlers no longer call into these — see below.
  - **Solicit**: `select_address_for_ia` tries, in order, the client's requested address (if
    `address6_valid`+`address6_available`+`check_address` all pass), an existing lease already
    bound to this client/IAID, then a fresh `address6_allocate` — a 3-tier subset of upstream's
    4-tier search (the omitted tier, preferring a statically-`--dhcp-host`-configured address ahead
    of a dynamic one via `config_valid()`, needs the fuller static-host-address port below).
    Rapid-commit (`OPTION6_RAPID_COMMIT`) is honored: reply type becomes `Reply` and the allocation
    is persisted immediately via `persist_lease` (`LeaseDb::bind_v6`); a plain Solicit
    (`Advertise`) computes lifetimes but persists nothing, matching upstream's `address6_allocate`
    being a pure candidate search. `OPTION6_PREFERENCE` (255 if `authoritative`, else 0) is added on
    success, matching `--dhcp-authoritative`.
  - **Request**: three-way status differentiation — `NoAddrsAvail` ("address unavailable") for a
    static-only range the client isn't configured for, `UnspecFail` ("address in use") when
    `check_address` finds the address leased to a different client/IAID, `NotOnLink` when the
    address matches no context at all — replacing the single `NoAddrsAvail`-only failure mode.
    Success always persists (`persist_lease`). An IA with no IAADDR sub-option redirects into the
    same `select_address_for_ia` Solicit-style search, forced to `Reply` and always persisting
    (rfc3315.c:833-839's `goto request_no_address`); a *missing* IA_NA option entirely (distinct
    from an empty one) instead falls through with no IA_NA in the reply and a top-level
    `NoAddrsAvail`, mirroring upstream's per-IA loop simply never running.
  - **Renew/Rebind**: split into their own function, no longer folded into the same allocate-fresh
    path as Solicit/Request. Looks up the existing lease by `(clid, iaid, addr)`; if found and the
    address is still `address6_valid`/`address6_available`, extends it (`persist_lease` recomputes
    lifetimes from the owning context's `lease_time` and re-binds); if the address is no longer
    valid for any context, deprecates it (preferred=valid=0) without touching the lease
    (rfc3315.c:1026-1030). If no lease is found: Renew always reports per-IA `NoBinding` with *no*
    top-level error status; Rebind additionally creates a lease when `authoritative` is set and the
    address is still plausible for some context, else reports per-IA `NoBinding` *and* a top-level
    `NoAddrsAvail` — the exact upstream asymmetry (rfc3315.c:925-1059).
  - **Confirm**: rewritten to never allocate — only checks `address6_valid` for the client's
    address and returns `NotOnLink`/`Success` accordingly. Returns `None` (no reply at all, not an
    empty one) when the packet carries no address to confirm, per RFC 3315 §18.2.2
    (rfc3315.c:1097-1098) — previously this case fell into the shared allocate-and-reply arm and
    always returned `Some`.
  - **Release/Decline**: now actually mutate `lease_db` — `LeaseDb::remove_v6_by_clid_iaid_addr`
    (new) prunes the matching lease so a subsequent Solicit/Request can reallocate the address;
    previously these were a no-op empty Reply that left `in_use` reporting the address taken
    forever. Echoes per-IA `NoBinding` when no matching lease exists but *always* returns top-level
    `Success` regardless (rfc3315.c:1139-1284) — release/decline of an unknown binding is not an
    error at the top level.
  - **Information-Request**: now rejects (drops, returns `None`) a request that carries an
    `OPTION6_IA_NA`/`OPTION6_IA_TA`, per RFC 3315 §15.12 / rfc3315.c:1110-1112 — previously any
    InfoReq got an empty-options Reply regardless of whether it illegally carried an IA.
  - **`LeaseDb`** (`lease.rs`) gained `bind_v6` (allocate-or-renew a lease bound to a specific
    `clid`/`iaid`, fixing a real bug: the old pattern of `allocate_v6()` then separately mutating
    `lease.clid`/`.iaid` on the returned reference inserted under an all-zero placeholder key and
    never re-keyed the map entry, so a second such call before the first lease's `clid` was set
    collided on the same key and silently evicted it — regression-tested by
    `bind_v6_does_not_clobber_other_clients`), `find_v6_by_client_iaid` (recall a client's address
    across a fresh Solicit without it echoing the address back, upstream's
    `lease6_find_by_client()`), and `remove_v6_by_clid_iaid_addr` (the `lease6_find()` +
    `lease_prune()` pairing Release/Decline need). `run_dhcp6_loop`'s post-dispatch lease-commit
    block is gone entirely — persistence now happens inside `dispatch_dhcp6`'s handlers themselves
    (via `persist_lease`), matching upstream where `update_leases()` is called from inside the
    per-message-type branches of `dhcp6_reply()`, not as a separate step after it returns.
  - `rfc3315::handle_solicit`/`handle_request6` are no longer called from `dhcp6.rs` (previously
    the sole non-test callers): their `Ipv6Addr`-only, always-success shape can't represent
    Request's three-way failure status or Confirm/Release/Decline's no-allocation paths, so
    `dhcp6.rs` now builds IA_NA/Status-Code options directly via small local helpers
    (`iaaddr_suboption`/`status_option`/`build_ia_na_option`) reusing only
    `rfc3315::calculate_times`/`build_status_code`/`STATUS_*`. They remain public API in
    `rfc3315.rs` with their own tests but are effectively wire-format-helper-library functions now,
    not the production reply path — the crate's two DHCPv6 packet representations
    (`rfc3315::Dhcp6Packet` vs. `dhcp6::Dhcp6Packet`) are further apart than before this change,
    not closer; unifying them is still open work.
  Not ported (scope explicitly excluded from this pass):
  - **IA_PD (prefix delegation)**: no `OPTION6_IAPREFIX` handling anywhere — this module and
    `rfc3315.rs` only ever build/read `OPTION6_IA_NA`/`IAADDR`. A distinct, large feature axis from
    IA_NA (separate context type, separate lease type, separate config directives) tracked here as
    still entirely missing.
  - **`add_options()`** (rfc3315.c:1301-1534): non-IA option delivery (DNS servers, domain search,
    SNTP, the ULA/link-local auto-prefix logic at :1342/:1360-1365) is not implemented. A valid
    Information-Request or a Solicit/Request/Renew/Rebind success reply carries no such options
    today — `--dhcp-option` for DHCPv6 doesn't exist as a config surface yet.
  - **`config_valid`/`config_implies`** (rfc3315.c:1765-1822, wildcard/prefix static-address
    matching against `--dhcp-host ... ,[addr6]`) are not ported; `config_find_by_address6` (an
    existing, narrower exact-`/128`-match helper) stands in for "is this address statically
    reserved" in `addr_in_use`/Request's `config_ok` check, but Solicit never *prefers* a static
    address the way upstream's `config_valid()` tier does, and DECLINE's static-host
    `ADDRLIST_DECLINED`/`DECLINE_BACKOFF` blacklist (rfc3315.c:1227-1235) has no equivalent.
  - **`mark_context_used`/`mark_config_used`/`CONTEXT_CONF_USED`/`CONTEXT_USED`** bookkeeping
    (rfc3315.c:1701-1716, "one address per prefix per IAID" / "configured address used at most once
    per prefix") is not ported — a consequence of not walking multiple IAs/addresses per packet
    (below).
  - **Multiple IAs / multiple addresses per IA**: this module reads only the first `OPTION6_IA_NA`
    option and, within it, only the first `OPTION6_IAADDR` sub-option — a packet with two IA_NAs,
    or one IA_NA requesting two addresses, only has its first entry processed. Upstream's
    `check_ia`/`opt6_find(..., OPTION6_IAADDR, ...)` loops walk all of them independently.
  - **DECLINE's `addr_epoch` bump** (rfc3315.c:1236-1239, nudging future hash-based allocation away
    from a declined dynamic address for *this* client) is not ported; Decline here behaves
    identically to Release (prune the matching lease) rather than the epoch-bump/static-blacklist
    split upstream does.
  - **`relay_upstream6`/`relay_reply6`** (rfc3315.c:2145-2327, forwarding a decapsulated
    RELAY-FORW to an upstream DHCPv6 relay/server and re-encapsulating the reply) — unrelated to
    this pass's per-message-type scope; still just wire encode/decode in `rfc3315.rs`
    (`parse_relay_msg`/`build_relay_reply`), same gap already flagged above.
  Covered by `dhcp6::tests::dispatch_dhcp6_*` (one or more tests per message type: Solicit
  rapid-commit persistence, Request's three failure statuses plus the empty-IA redirect, Renew
  extending an existing lease's lifetimes from context config, Rebind's authoritative-vs-not no-
  lease behavior, Confirm's no-reply-on-empty-packet and valid/invalid-address cases,
  Release/Decline actually freeing a lease vs. echoing NoBinding) and `lease::tests::bind_v6_*` /
  `find_v6_by_client_iaid_*` / `remove_v6_by_clid_iaid_addr_*`.

- [ ] Treat DBus, UBus, BPF, ipset, nftset, and similar integrations as feature-gated completion tracks.
  Required tests: feature-gated compile checks, targeted integration tests, parity scenarios only when implementation is real.
  Done when: each optional feature is either implemented with tests or explicitly marked incomplete.

- [x] `dhcp_common::log_context` / `log_relay` — startup diagnostics for dhcp-range/dhcp-relay (Issue #29 / T3-dhcp-common).
  Source of truth: `dhcp-common.c:951-1081` (`log_context`, `log_relay`), called from `dnsmasq.c:996-1008`.
  `log_context` now returns the same set of messages upstream's up-to-three `my_syslog()` calls
  produce per context: the range/static/proxy/RA-stateless line (skipped for `CONTEXT_OLD`,
  gated by `CONTEXT_DHCP || family==v4`), the DHCPv6-only "DHCPv4-derived IPv6 names" line
  (`CONTEXT_RA_NAME`), and the DHCPv6-only "router advertisement" line (`CONTEXT_RA` or
  `opt_ra && CONTEXT_DHCP`). Lease-time and "prefix deprecated" text are mutually exclusive, as
  upstream's shared buffer makes them; STATIC/PROXY branches print the end address, not start,
  and PROXY omits lease time, matching the `%.0s`-suppressed upstream format strings exactly.
  `log_relay` includes the local (`relay->local`) address, distinguishes `split_mode`, and only
  applies the broadcast/split-mode branch selection when an interface is bound (upstream's
  no-interface case is always the plain "from X to Y" form). Both are wired into
  `dnsmasq::init_daemon_with`, iterating `daemon.dhcp`/`relay4` and (`dhcp6` feature)
  `daemon.dhcp6`/`relay6`, mirroring `dnsmasq.c:996-1008`.
  Covered by `dhcp_common::tests::log_context_*` / `log_relay_*` (range/static/proxy/RA-stateless
  for both families, mutual-exclusion of lease-time vs. deprecated, RA-name/RA lines, relay
  broadcast/split-mode/no-interface/non-default-port cases) and
  `dnsmasq::tests::init_daemon_with_logs_dhcp_context_and_relay` (end-to-end: a `Daemon` with a
  configured `dhcp-range`-equivalent context and relay actually emits the expected `tracing`
  output at startup).
  Explicitly still unsupported: `CONTEXT_CONSTRUCTED`/`CONTEXT_TEMPLATE` prefix annotations
  (upstream's "constructed for X" / "template for X" suffix, which requires resolving
  `if_index` to an interface name via `indextoname()`). `DhcpContext` has no `template_interface`
  field and no ifindex→name lookup is wired up; contexts with these flags set log the same text
  as an equivalent plain range/static/proxy context, without the suffix. `dhcp_construct_contexts`
  (which is what actually sets `CONTEXT_CONSTRUCTED`/`CONTEXT_TEMPLATE` at runtime, called from
  `dhcp6.c:771/807/852`) is not ported either, so this gap is currently unreachable in practice.

- [x] `slaac::slaac_add_addrs` / `periodic_slaac` / `slaac_ping_reply` — real lease-derived SLAAC
  address tracking and ICMPv6 DAD probing (Issue #37 / T3-slaac).
  Source of truth: `slaac.c` (all three functions, gated `HAVE_DHCP6`).
  Implemented, tested, real (no longer stubs):
  - `slaac_add_addrs` (slaac.c:25-116): a real port operating on `&mut DhcpLease` +
    `&[DhcpContext]`, mutating `lease.slaac_address` in place — diffs the derived address set
    against the existing list (reuse-and-reset on `force`, drop stale entries, `ra_start_unsolicited`
    callback for genuinely new ones), replacing the old disconnected `synthesize_slaac_addrs`
    (which only returned a `Vec<Ipv6Addr>` with no lease/state tie-in and had zero callers).
    `derive_slaac_host_id` replicates all three upstream hwaddr branches (6-byte Ethernet MAC via
    EUI-64 synthesis, raw 8-byte `ARPHRD_EUI64` hardware address, FireWire EUI-64 carried in the
    client-id) with the single post-branch `^= 0x02` U/L-bit flip upstream applies uniformly.
  - `periodic_slaac` (slaac.c:119-190): real exponential-backoff/jitter DAD probe scheduling
    operating on `SlaacAddress` entries directly (not the old disconnected `SlaacProbeState`,
    which had zero callers and wasn't attached to `DhcpLease` at all) — matches the
    `EHOSTUNREACH`-at-backoff-12 give-up case, the `next_event` earliest-pending-probe
    computation, and the "nothing configured" (`!CONTEXT_RA_NAME`) early return exactly.
  - `slaac_ping_reply` (slaac.c:191-213): matches inbound ICMPv6 echo replies by `ping_id` and
    sender address, confirms (`backoff = 0`), and logs `SLAAC-CONFIRM`.
  - A real (`CAP_NET_RAW`-gated) `Icmp6Socket` (raw ICMPv6, `socket2` + `tokio::io::unix::AsyncFd`)
    for send/receive; `Icmp6Socket::create()` returns `Err` rather than failing DHCPv6 startup
    when the process lacks the capability — "DAD probing works where permissions allow", not
    "is mandatory". Ping-packet wire format (`build_ping_packet`/`parse_ping_packet`) matches
    `struct ping_packet` (type/code/checksum/identifier/sequence, checksum left zero for the
    kernel to fill in on a raw ICMPv6 socket).
  - **Production wiring — DHCPv4 loop (`dhcp.rs::run_dhcp_loop`), the real, live call site:**
    `LeaseDb` gained `refresh_slaac`/`tick_slaac`/`confirm_slaac_ping` (the lease-set-wide
    equivalents of `slaac_add_addrs`/`periodic_slaac`/`slaac_ping_reply`, setting `dns_dirty` —
    this port's existing stand-in for upstream's `lease_update_dns`). Getting a real DHCPv4 lease
    to actually satisfy `slaac_add_addrs`'s guards (slaac.c:31-35) took two separate fixes, not
    one:
    - `LeaseDb::set_hwaddr` never set `LEASE_HAVE_HWADDR` (lease.c:946 sets it unconditionally in
      `lease_set_hwaddr`); fixed, and `set_hwaddr` now takes upstream's `force` parameter and
      returns upstream's `change` value (true on `force` or a client-id change — a hwaddr-only
      change does *not* set it, matching lease.c:944-993 exactly, including the "a packet with no
      client-id must not clear an existing one" guard at lease.c:963).
    - `lease.last_interface` was **never set anywhere in production** — `LeaseDb::set_interface`
      existed but had zero non-test callers, so `slaac_add_addrs`'s `lease->last_interface == 0`
      guard (slaac.c:33) always failed for every lease `record_lease` ever committed, independent
      of the hwaddr/hostname fix above. Fixed by threading `if_index` through `ArrivalInterface`
      (from the `IP_PKTINFO` arrival metadata `run_dhcp_loop` already resolves) and calling
      `LeaseDb::set_interface` from `dispatch_dhcp_with_arrival` after a REQUEST is ACK'd — the
      Rust equivalent of upstream's `lease_set_interface()` call from `rfc2131.c:1717`
      (lease.c:1148-1159).
    `run_dhcp_loop` calls `refresh_slaac` after every dispatched packet (using the DHCPv6
    "current" RA-name context chain, threaded in via `DhcpLoopOptions::slaac_contexts` from
    `run_main_loop_with` — cloned from the already-resolved `Dhcp6DaemonRuntime.contexts` before
    it's moved into `run_dhcp6_loop`) and runs a 1s DAD probe tick plus an `Icmp6Socket::recv`
    receive arm via a `SlaacDad` state machine (`tokio::select!` branches can't be individually
    `#[cfg(...)]`-gated the way `match` arms can, so the dhcp6-on/off and
    capability-present/absent split lives inside that type instead of around the branch), both
    no-ops when the raw socket couldn't be opened or no RA-name context was configured.
    **This — not `dhcp6::run_dhcp6_loop` — is the loop that makes SLAAC tracking real**: DHCPv6
    stateful (`bind_v6`) leases are unconditionally `LEASE_NA`-flagged, so they can never pass
    `slaac_add_addrs`'s own `LEASE_TA|LEASE_NA` exclusion guard (slaac.c:32) — `run_dhcp6_loop`'s
    `refresh_slaac`/`tick_slaac`/`confirm_slaac_ping` calls are upstream-faithful (upstream's
    single shared lease list relies on that same guard to skip its own DHCPv6 leases) but
    structurally inert against its own `LeaseDb` today, and are left in place rather than removed.
    DHCPv4-committed leases are never `LEASE_NA`/`LEASE_TA`-flagged, so `run_dhcp_loop`'s `LeaseDb`
    is where real tracking and probing happens.
  - `is_slaac_for` (the Rust-only "does this address match this prefix+MAC" helper flagged by the
    original issue as having no 1:1 C counterpart and no caller) has been removed: no in-scope
    production caller exists for it (the natural one — answering AAAA queries for DHCP lease
    hostnames — doesn't exist anywhere in this port yet, IPv4 or IPv6, and building it is well
    outside this issue), and the two internal tests that used it as an assertion helper now assert
    directly against `slaac_address(...)` instead.
  Covered by `slaac::tests::*` (33 tests: all three hwaddr-derivation branches, force-reset,
  stale-entry removal, RA-trigger-only-on-new-address, "nothing configured", due/not-due/confirmed/
  give-up/reschedule probe states, ping-reply match/mismatch/malformed/already-confirmed, and a
  capability-gated `Icmp6Socket::create` test that accepts either outcome), plus
  `lease::tests::{set_hwaddr_sets_lease_have_hwaddr_flag, set_hwaddr_returns_*,
  set_hwaddr_missing_clid_does_not_clear_existing_one, refresh_slaac_*,
  tick_slaac_sends_due_probe_and_confirm_ping_clears_it}`, plus new `dhcp::tests::{
  dispatch_with_arrival_sets_last_interface_on_committed_lease,
  dispatch_with_arrival_leaves_last_interface_unset_without_arrival,
  dispatch_then_refresh_slaac_populates_address_for_real_v4_lease}` — the last one is the
  regression test for the actual production gap: it drives a REQUEST through
  `dispatch_dhcp_with_arrival` exactly as `run_dhcp_loop` does, then calls `refresh_slaac`, and
  asserts the resulting (real, non-`LEASE_NA`/`TA`-flagged) lease has a populated
  `slaac_address` — this failed before the `last_interface` fix and passes after it.
  Explicitly still unsupported / open:
  - `LeaseDb::set_hwaddr`'s `force` parameter is always passed `false` from the one production
    caller (`dhcp.rs`'s DHCPv4 commit path) — upstream's `rfc2131.c:679` passes `true` for the
    init-reboot-without-prior-record case and a context-dependent flag at `rfc2131.c:1683`; this
    port's DHCPv4 state machine doesn't yet track that distinction. Conservative (never forces a
    probe reset it shouldn't), not incorrect, but not full parity either.
  - The RA-trigger callback passed to `refresh_slaac` at both loops' call sites is a documented
    no-op: production RA scheduling itself has no main-loop caller yet either (see the
    `radv::calc_interval`/`calc_lifetime` entry above), so there is no live `RaSchedule` to invoke
    `start_unsolicited` on. Once that lands, the callback should call it for the matching context.
  - The ICMPv6 receive path passes an empty `interface` string to `confirm_slaac_ping` (no
    `IPV6_RECVPKTINFO`/cmsg support on the raw socket yet), so `SLAAC-CONFIRM` log lines never
    show a real interface name. Matching/confirm/dns_dirty behavior itself is unaffected.
  - The DHCPv6 "current" RA-name context chain is resolved once at startup (`daemon_dhcp6_runtime`)
    and handed to the DHCPv4 loop as a snapshot; it does not follow a config reload/SIGHUP or live
    interface changes without a restart. Same pre-existing scope simplification as
    `run_dhcp6_loop`'s own context chain (see its doc comment).
  - The two independent in-memory `LeaseDb` instances (DHCPv4 loop vs. DHCPv6 loop) remain
    unmerged — a pre-existing, separately-tracked P1 gap. It no longer blocks SLAAC specifically
    (SLAAC's real target, DHCPv4-committed leases, now gets tracked/probed from the loop that
    actually owns them), but still means e.g. a DHCPv6-stateful lease and its dual-stack sibling's
    DHCPv4 lease aren't visible to each other's loop.

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

- [x] Removed three orphaned modules with zero call sites (issue #54): `blockdata.rs`,
  `outpacket.rs`, `bpf.rs`, plus the redundant `types::cache::Blockdata` stub and the
  now-dead `KEYBLOCK_LEN` constant, and the `bpf` Cargo feature (removed from `default`
  too).
  - `blockdata.rs`: DNSSEC key/RR pooling was intentionally dropped — `dnssec.rs` stores
    signatures/keys/digests as plain `Vec<u8>`, which is upstream-behavior-equivalent
    (the C slab allocator is a fragmentation optimization, not observable protocol
    behavior). Do not resurrect this module to route DNSSEC storage through it.
  - `outpacket.rs`: ported upstream's `new_opt6`/`end_opt6` in-place TLV-patching
    pattern for DHCPv6 option building, but `dhcp6.rs`'s `build_option6`/
    `build_ia_na_option` independently reimplemented the same TLV logic via
    build-then-wrap `Vec<u8>` construction. Both produce identical wire bytes; keeping
    `dhcp6.rs`'s simpler approach and deleting the duplicate is not a parity loss.
  - `bpf.rs`: built Linux classic-BPF `sock_filter` programs with no upstream
    counterpart (`grep sock_filter original_dnsmasq_src` = zero hits) and no call site.
    Upstream `bpf.c` is BSD/Solaris-only routing-socket code gated on
    `HAVE_BSD_NETWORK`/`HAVE_SOLARIS_NETWORK`; its Linux analog is `netlink.rs`, already
    ported. Future audits should diff `bpf.c` against `netlink.rs`, not this module.

- [x] Removed the dead `tables.rs` module (issue #57): it claimed to port
  `tables.c` (BSD PF ipset support, gated `HAVE_BSD_IPSET` upstream) but every
  path — including the `#[cfg(target_os = "openbsd")]` branch — returned
  `Err(PfError::NotSupported)` without ever calling `ioctl` or touching
  `/dev/pf`. It also used non-upstream function names (`add_to_table`/
  `del_from_table` instead of `add_to_ipset`/`ipset_init`) and had zero
  callers anywhere in the codebase. Same disposition as `bpf.rs` (see above):
  BSD/PF is out of scope for this Linux-targeted port, and the Linux
  equivalent of upstream's `add_to_ipset`/`ipset_init` interface is already
  fully implemented and wired up in `ipset.rs` (netlink-based, called from
  `forward.rs` and `dnsmasq.rs`). Do not resurrect `tables.rs`; if BSD PF
  support is ever wanted, port `tables.c`'s ioctl sequence
  (`DIOCRADDTABLES`/`DIOCRADDADDRS`/`DIOCRDELADDRS`) fresh against the real
  `add_to_ipset`/`ipset_init` signatures, not the old stub's invented ones.

- [x] Align Cargo feature defaults with upstream config.h (issue #55).
  - Removed `dnssec` from default feature list (upstream config.h:206 leaves `HAVE_DNSSEC`
    commented out as it requires external crypto libraries).
  - Added `ipset` to default feature list (upstream config.h:190 enables `HAVE_IPSET` by default).
  - Added `script` feature to Cargo.toml and default list. `helper.rs` is now gated on both
    `feature = "dhcp"` AND `feature = "script"` (not just `dhcp`). Directives `--dhcp-script`
    and `--dhcp-luascript` return an error at config-parse time when `script` is disabled,
    matching upstream option.c:2390-2391.
  - `--dhcp-scriptuser` remains gated only on `feature = "dhcp"`, matching upstream option.c:2876-2878.
  - Verified: `cargo check --no-default-features` now compiles cleanly (was broken with 3 errors before).

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
