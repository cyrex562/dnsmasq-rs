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
    is still never set. `Daemon` also has no `umbrella_org`/`umbrella_asset`/
    `umbrella_device` fields yet (see the `umbrella` entry under "Unrecognized/no-op
    directives" below) — `add_umbrella_opt` takes them as plain parameters so it doesn't
    need those fields to be portable, but a real caller will need them threaded through
    once the outgoing-query path exists.
  - ipset kernel population is now wired end to end: `rfc1035::extract_addresses` matches the
    query name against `ExtractConfig::ipsets` (a local `domain_find_sets`, duplicating
    `forward::domain_find_sets`/`IpSet` — nothing constructs an `IpSet` from parsed config,
    so unifying the two types is still follow-up work) and reports every matched A/AAAA address
    via `ExtractOutcome::ipset_hits`; `forward::cache_upstream_reply` now calls
    `ipset::add_to_ipset` for each hit (feature = `ipset`, Linux only), which opens a
    `NETLINK_NETFILTER` socket and sends the `IPSET_CMD_ADD` built by the existing
    `ipset::build_ipset_msg`, mirroring `add_to_ipset()`/`new_add_to_ipset()`
    (`ipset.c:104-141,177-193`) fire-and-forget (no ACK is awaited, matching upstream). Off
    Linux or without the `ipset` feature, the match is still logged via `tracing::debug!` so it
    stays observable. Not ported: the pre-2.6.32 `SOL_IP`/`getsockopt` fallback (`old_kernel` in
    `ipset.c` — this crate tracks no `kernel_version` to gate it on) and reusing a single
    persistent socket across calls the way `ipset_init()` does (a socket is opened and closed
    per call here instead; correctness is unaffected, only efficiency).

    **nftset is explicitly out of scope**, and differently so than ipset: upstream's
    `add_to_nftset()` (`nftset.c:41-93`) does not build a raw netlink message at all — it shells
    out to `libnftables` (`nft_run_cmd_from_buffer()`) with a textual `add element <set> { <ip> }`
    command. That is an FFI dependency this crate does not have (no `libnftables`/`nftables`
    binding in `Cargo.toml`), so `nftset.rs`'s existing raw-`NEWSETELEM`-netlink builder does not
    actually match upstream's mechanism and could not be wired to real behavior without adding a
    new C library dependency — a materially bigger change than this ticket's scope. `nftset=`
    directive parsing is also still explicitly rejected
    (`option::apply_nftset_is_explicitly_unsupported`), so there is no config path that could
    reach it yet either; `ExtractConfig`/`ForwardConfig` carry `ipsets` only, matching what can
    actually be configured today.
  - `find_soa` (`rfc1035.rs`, port of `rfc1035.c:519-650`) does not apply DNSSEC TTL capping
    from a per-answer signature-validity array (`daemon->rr_status[i + ancount]`,
    `rfc1035.c:609-618`) — that array does not exist anywhere in the DNSSEC path yet
    (`grep rr_status` finds nothing outside upstream C), so capping it here in isolation would
    be unverifiable. It does now: verify the SOA's owner name is a byte suffix of the queried
    name before using it (`rfc1035.c:554-556`), and cache the SOA RR itself as `F_RR|F_KEYTAG`
    (`rfc1035.c:620`).
  - `log_txt` (`rfc1035.rs`, port of `rfc1035.c:653-682`) truncates each TXT string at its first
    non-printable byte and logs via `tracing::debug!` per string, called from
    `extract_addresses`'s TXT branch. C logs through its general `log_query()` facility, which
    this crate does not have (`grep -rn "fn log_query"` finds nothing outside
    `forward::log_query_mysockaddr`, an unrelated helper) — `answer_request`'s local-config TXT
    branch (`rfc1035.c`'s second `log_txt` call site, serving from cache/local data) does not
    call `log_txt` yet, so TXT answers built from `--txt-record` are not logged the way a
    forwarded TXT reply now is.
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
  - Upstream gates the resolv-file re-read on `OPT_NO_POLL` (`dnsmasq.c:1552`) because
    otherwise a periodic poll/inotify watch is expected to catch the change; this port
    has no such watch, so SIGHUP always re-reads regardless of `--no-poll`.
  - `--servers-file` re-read (`read_servers_file()`) and DHCP reload
    (`reread_dhcp`/`dhcp_read_ethers`/`lease_update_from_configs`/`rerun_scripts`) are not
    implemented — SIGHUP is DNS-only for now.
  - See "Reload staleness" below: `daemon.servers` is updated correctly, but the
    already-running forward task's `ForwardConfig` (upstream list, host-records, CNAMEs)
    is still a one-time snapshot, so a resolv-file-driven server-list change only takes
    effect on the next process start, not the next query.

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
    `SO_REUSEPORT`/`SO_REUSEADDR` gating, or PXE-port (4011) bind
    (`enable_pxe`/`daemon->pxefd` don't exist in this port at all). DHCP
    socket setup in `bind_listeners` is still a plain bind + `set_nonblocking`
    + optional `SO_BINDTODEVICE`.
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

- [ ] Issue #18 remaining DHCP/PXE directives: recognized and accepted by
  `apply_line` (`src/option.rs`) so a config carrying them no longer aborts
  startup, but their runtime behavior is not wired:
  - `dhcp-broadcast`, `dhcp-generate-names`, `dhcp-ignore-names`,
    `bootp-dynamic` (option.c:4660-4700, shared `dhcp_netid_list` case): the
    value is parsed and discarded. Upstream stores a tag-matched list
    (`daemon->force_broadcast`/`dhcp_gen_names`/`dhcp_ignore_names`/
    `bootp_dynamic`) consulted by the DHCPv4 reply path in `rfc2131.c`; none
    of those lists or their `dhcp.rs`/`rfc2131.rs` consumers exist yet.
  - `dhcp-proxy` (option.c:4703): value discarded. Upstream sets
    `daemon->override = 1` and collects `override_relays` IPv4 addresses;
    neither field exists on `Daemon`.
  - `dhcp-pxe-vendor` (option.c:4716): value discarded. Upstream builds a
    `dhcp_pxe_vendor` list matched against PXE client-vendor options.
  - `pxe-prompt` / `pxe-service` (option.c:4423,4461): value discarded.
    Upstream builds `dhcp_opt`/`pxe_service` entries that drive the PXE menu
    the DHCP/TFTP path serves; no PXE menu support exists in this port.
  - `conf-script` (option.c:2068): value discarded, and deliberately never
    executed. Upstream runs the referenced file as a program and reads config
    directives back from its stdout (`one_file(file, LOPT_CONF_SCRIPT)`).
    Executing an arbitrary external program from config parsing is a
    capability this port intentionally does not implement.
  - `umbrella` (option.c:2808): only the top-level `OPT_UMBRELLA` bit is set.
    The `deviceid:`/`orgid:`/`assetid:`/`userid:` sub-options are not parsed;
    `Daemon` has no `umbrella_device`/`umbrella_org`/`umbrella_asset`/
    `umbrella_user` fields yet. The option-payload side (`add_umbrella_opt`,
    `edns0.c:517-574`) is now ported as `edns0::add_umbrella_opt`/
    `add_edns0_config`, parameterized directly rather than reading `Daemon`, so
    parsing these sub-options and threading them through is the only work left
    to make `--umbrella orgid=...` etc. actually take effect — see the
    `edns0.c` entry above for what's already wired vs. not.
  Required tests: once each backing field/list exists, add parser tests plus
  a `dhcp.rs`/`rfc2131.rs` consumer test.
  Done when: each directive above either updates real `Daemon` state consumed
  by the DHCP/PXE runtime path, or remains explicitly listed here.

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
    `--domain` directive have a "no address" shorthand, and `--domain`'s own
    subnet form (`daemon->cond_domain`) is still unparsed (only the plain
    `domain=<suffix>` form works; see `src/option.rs`'s `"domain"` arm).
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
    and the `--domain` subnet-form parsing into `Daemon::cond_domain`
    (mentioned above) both land.
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
  Required tests: once addressed, add a `--domain` subnet-form test, a
  `synth-domain=...,<iface>` acceptance test, and a DHCP-request test where
  `bridge-interface`/`shared-network` change context selection.
  Done when: `--domain`'s subnet form populates `cond_domain` and is wired
  the same way `synth_domains` now is, and DHCP context matching consumes
  `bridges`/`shared_networks`.

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
