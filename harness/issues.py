"""Port issue corpus for dnsmasq-rs.

Generated from a five-agent gap audit of all 50 upstream files (2026-08-14).
Each entry becomes one GitHub issue. `key` is stable and is what `blocked_by`
references, so the harness can resolve dependencies without knowing issue
numbers at authoring time.
"""

UPSTREAM = "original_dnsmasq_src/dnsmasq-master/src"

# key, title, tier, risk, model, port_file, upstream_file, gaps[], acceptance[], blocked_by[], extra_labels[]
ISSUES = [
    # ─────────────────────────── TIER 0 — INTEGRATION ───────────────────────────
    dict(
        key="T0-1", tier=0, risk="high", model="opus",
        title="Wire local-data answering into the live query path",
        port_file="src/dnsmasq.rs, src/forward.rs", upstream_file=f"{UPSTREAM}/rfc1035.c",
        summary=(
            "`rfc1035::answer_request` (src/rfc1035.rs:835) and `LocalConfig` (:802) implement "
            "answering from `host-record`, `cname`, `txt-record`, `mx-host`, `srv-host`, and "
            "`ptr-record` config data, and are unit-tested. `src/forward.rs` contains zero "
            "references to either, and `dnsmasq::run_main_loop` spawns only the forwarding loop. "
            "Local data is parsed into `Daemon` and never consulted at runtime.\n\n"
            "This is why `parity/run-major.sh` fails 8/8 cases: the `dns/basic` fixture is pure "
            "local data under `no-resolv` with zero upstreams, so every query is handed to a "
            "forwarder with nowhere to send it and times out. Upstream answers all eight."
        ),
        gaps=[
            "`run_main_loop` never builds a `LocalConfig` from `Daemon` state",
            "`run_forward_loop` has no local-answer check before forwarding",
            "Queries for locally-configured names are forwarded instead of answered",
        ],
        acceptance=[
            "`./parity/run-major.sh` passes all 8 cases in the `dns/basic` fixture",
            "A query for a `host-record` name is answered without any upstream configured",
            "Local answering precedes forwarding, matching upstream order",
        ],
        blocked_by=[],
    ),
    dict(
        key="T0-2", tier=0, risk="high", model="opus",
        title="Wire the DNS cache into the forward path",
        port_file="src/forward.rs", upstream_file=f"{UPSTREAM}/forward.c",
        summary=(
            "The live path (`ForwardEngine::forward_query` / `handle_reply`) is a raw UDP relay: "
            "no cache lookup before forwarding, no cache insertion on reply. `cache::cache_reply` "
            "(which calls `extract_addresses`) has no callers outside its own unit tests, so "
            "`dnsmasq-rs` currently caches nothing at runtime despite a complete, tested cache."
        ),
        gaps=[
            "No cache lookup on the query path; every query is forwarded",
            "No `extract_addresses` / cache insertion on the reply path",
            "`cache::cache_reply` has zero non-test callers",
            "Negative caching and TTL expiry never exercised at runtime",
        ],
        acceptance=[
            "A repeated query is answered from cache without a second upstream query",
            "Cache entries respect upstream TTL and expire correctly",
            "Integration test asserts cache hit/miss counts across repeated queries",
        ],
        blocked_by=["T0-1"],
    ),
    dict(
        key="T0-3", tier=0, risk="high", model="opus",
        title="main.rs never calls daemonize, drop_privileges, or write_pid_file",
        port_file="src/main.rs, src/dnsmasq.rs", upstream_file=f"{UPSTREAM}/dnsmasq.c",
        summary=(
            "`daemonize()` (dnsmasq.rs:121), `drop_privileges()` (:61), and `write_pid_file()` "
            "(:83) are implemented and unit-tested, and `src/main.rs` calls none of them. The "
            "binary therefore always runs in the foreground as the invoking user and ignores "
            "`--user`, `--group`, and `--pid-file` entirely.\n\n"
            "Additionally `drop_privileges` is thinner than upstream (dnsmasq.c:740-815): no "
            "`setgroups(0, ...)` to strip supplementary groups, and no `PR_SET_KEEPCAPS` + "
            "`capset()` to retain CAP_NET_BIND_SERVICE across the setuid, which upstream needs "
            "to keep binding port 53 and opening raw sockets after dropping root."
        ),
        gaps=[
            "`main.rs` does not call `daemonize()`; `--no-daemon`/`-d` has no opposite",
            "`main.rs` does not call `drop_privileges()`; `--user`/`--group` are inert",
            "`main.rs` does not call `write_pid_file()`; `--pid-file` is inert",
            "`drop_privileges` omits `setgroups(0)` supplementary-group clearing",
            "`drop_privileges` omits capability retention across setuid",
        ],
        acceptance=[
            "Without `--no-daemon`, the process detaches from the controlling terminal",
            "`--user`/`--group` demonstrably change the running uid/gid",
            "`--pid-file` writes the correct pid",
            "Supplementary groups are cleared; a test asserts this where permissions allow",
            "Daemonization still happens before the tokio runtime starts (fork is not tokio-safe)",
        ],
        blocked_by=[],
    ),
    dict(
        key="T0-4", tier=0, risk="high", model="opus",
        title="Listeners ignore --interface / --listen-address and bind 0.0.0.0",
        port_file="src/dnsmasq.rs, src/network.rs", upstream_file=f"{UPSTREAM}/network.c",
        summary=(
            "`run_main_loop` binds exactly one UDP socket on `0.0.0.0:{port}` "
            "(dnsmasq.rs:286-293) regardless of configuration. The parser does capture "
            "`--interface`, `--except-interface`, and `--listen-address` into "
            "`daemon.if_names` / `if_except` / `if_addrs`, and `run_main_loop` never reads them.\n\n"
            "This is security-relevant: a config written to bind only a LAN interface will in "
            "practice listen on every interface. `network::create_listeners` and the "
            "`iface_allowed_v4`/`v6` helpers already exist but have no callers."
        ),
        gaps=[
            "One wildcard socket instead of one listener per configured address/interface",
            "`--interface` / `--except-interface` / `--listen-address` parsed but never applied",
            "`network::create_listeners` and `iface_allowed_*` have zero non-test callers",
            "No `--bind-interfaces` vs `--bind-dynamic` distinction",
        ],
        acceptance=[
            "With `--listen-address=127.0.0.1`, the daemon does not answer on other addresses",
            "`--interface`/`--except-interface` demonstrably include/exclude interfaces",
            "Listener creation goes through `network.rs` rather than an inline bind",
            "Capability-dependent assertions are gated so restricted environments do not fail",
        ],
        blocked_by=[],
    ),
    dict(
        key="T0-5", tier=0, risk="medium", model="sonnet",
        title="SIGHUP handler is a logging stub; reload functions are never called",
        port_file="src/main.rs, src/dnsmasq.rs", upstream_file=f"{UPSTREAM}/dnsmasq.c",
        summary=(
            "`main.rs:123-128` logs `\"SIGHUP: reloading configuration (stub — implement "
            "cache_reload here)\"` and does nothing else. `on_sighup()` (dnsmasq.rs:418) and "
            "`clear_cache_and_reload()` (:488) are implemented and tested but have zero callers "
            "outside their own file. The signal plumbing is half-built: `run_main_loop`'s "
            "internal handler (:384-389) does forward the signal to the channel that `main.rs` "
            "then stubs out."
        ),
        gaps=[
            "SIGHUP does not flush the cache",
            "SIGHUP does not re-read `/etc/hosts` or resolv files",
            "`on_sighup` / `clear_cache_and_reload` have zero non-test callers",
        ],
        acceptance=[
            "SIGHUP flushes the DNS cache",
            "SIGHUP re-reads hosts and resolv files",
            "Repeated SIGHUP is stable and idempotent",
            "Test covers a no-op reload leaving state consistent",
        ],
        blocked_by=["T0-2"],
    ),
    dict(
        key="T0-6", tier=0, risk="high", model="opus",
        title="No source-port randomization; two rival pending-query implementations",
        port_file="src/forward.rs", upstream_file=f"{UPSTREAM}/forward.c",
        summary=(
            "`run_forward_loop` binds a single socket at forward.rs:1229 (`0.0.0.0:0`) and reuses "
            "it for every outbound query. Random query ID without random source port is "
            "materially weaker spoofing resistance than upstream. `RandFdPool` / `RandomSocket` "
            "(:617-720) implement per-server randomized sockets and are tested, but "
            "`forward_query` sends on the shared `upstream_sock` instead.\n\n"
            "Separately, `forward.rs` contains two pending-query implementations: a faithful "
            "`FrecTable`/`Frec`/`FrecSrc` port of upstream `struct frec` with per-domain-group "
            "exhaustion limiting and multi-client dedup, which is dead code, and the simpler "
            "`ForwardTable`/`PendingQuery` that the live path uses and which has neither."
        ),
        gaps=[
            "All upstream queries share one source port",
            "`RandFdPool` has no live callers",
            "`FrecTable` (faithful) is dead; `ForwardTable` (simpler) is live",
            "No per-group frec exhaustion limiting or client dedup in the live path",
        ],
        acceptance=[
            "Outbound queries use varying source ports",
            "One pending-query implementation remains; the other is removed",
            "Per-group query-full limiting is exercised by a test",
            "Multiple clients querying the same name are deduplicated onto one upstream query",
        ],
        blocked_by=["T0-2"],
    ),
    dict(
        key="T0-7", tier=0, risk="high", model="opus",
        title="Wire process_reply into the reply path (rebind, bogus-wildcard, rrfilter, EDNS0)",
        port_file="src/forward.rs", upstream_file=f"{UPSTREAM}/forward.c",
        summary=(
            "`forward::process_reply` implements rebind checking and related reply processing but "
            "is never called from `run_forward_loop`/`handle_reply`. Its own doc comment records "
            "the gap: \"Full integration (EDNS0 stripping, bogus-wildcard detection, rrfilter, "
            "extract_addresses, DNSSEC validation) requires the relevant modules to be ported; "
            "those paths are marked as TODO below.\"\n\n"
            "Net effect: no rebind protection, no bogus-wildcard defense, no RR filtering, and no "
            "EDNS0 handling on replies at runtime."
        ),
        gaps=[
            "`process_reply` has no callers in the live reply path",
            "`--stop-dns-rebind` / rebind protection is inert",
            "`check_for_bogus_wildcard` never runs against replies",
            "`rrfilter::strip_dnssec_if_not_requested` and `filter_rr_types` have no live callers",
            "`edns0` add/strip never applied",
        ],
        acceptance=[
            "A reply containing a private address for a public name is rejected under rebind protection",
            "Bogus-wildcard addresses configured via `--bogus-nxdomain` are caught",
            "DNSSEC RRs are stripped when the client did not set DO",
            "Integration tests cover each path end to end",
        ],
        blocked_by=["T0-2"],
    ),
    dict(
        key="T0-8", tier=0, risk="high", model="opus",
        title="DHCPv4: lease store unwired and three message handlers unreachable",
        port_file="src/dhcp.rs, src/rfc2131.rs, src/lease.rs", upstream_file=f"{UPSTREAM}/rfc2131.c",
        summary=(
            "`dispatch_dhcp_with_meta` (dhcp.rs:454-466) increments a metric and returns `None` "
            "for Release, Decline, and Inform instead of calling `rfc2131::handle_release` "
            "(:196), `handle_decline` (:207), and `handle_inform` (:174) — all three are "
            "implemented and referenced only by their own unit tests.\n\n"
            "`src/lease.rs` (`LeaseDb`) has zero callers outside its own file. No lease is "
            "created on ACK, freed on RELEASE, or persisted to disk. DHCPv4 lease handling is "
            "effectively 0% functional at runtime regardless of `LeaseDb`'s own test coverage."
        ),
        gaps=[
            "Release/Decline/Inform silently dropped by dispatch",
            "`LeaseDb` has zero non-test callers; ACK records no lease",
            "No lease persistence to `--dhcp-leasefile`",
            "No re-offer avoidance across requests",
        ],
        acceptance=[
            "DISCOVER/OFFER/REQUEST/ACK creates a persisted lease",
            "RELEASE frees the lease; DECLINE marks the address unusable",
            "INFORM is answered without allocating an address",
            "Leases survive a restart via the lease file",
        ],
        blocked_by=[],
    ),

    # ─────────────────────── TIER 1 — CORRECTNESS / SECURITY ────────────────────
    dict(
        key="T1-1", tier=1, risk="high", model="opus", extra_labels=["security"],
        title="DNSSEC validate_rrset reports Secure without verifying any signature",
        port_file="src/dnssec.rs", upstream_file=f"{UPSTREAM}/dnssec.c",
        summary=(
            "`validate_rrset` (src/dnssec.rs:462-587) builds the correct RFC 4034 §6.2 signed-data "
            "blob, hashes it with SHA-256, then binds both the digest and the signature to "
            "throwaway names and discards them:\n\n"
            "```rust\n"
            "let _digest: Vec<u8> = { ... };\n"
            "let _signature = signature; // would be passed to RSA/ECDSA verify\n"
            "...\n"
            "return RrsetValidation::Secure { ttl, key_tag };\n"
            "```\n\n"
            "It never calls any verification routine and returns `Secure` unconditionally. A "
            "forged RRSIG with correct timing, labels, and structure but garbage signature bytes "
            "is reported Secure.\n\n"
            "Real, working verification already exists in `src/crypto.rs` (`verify_sig`, RSA / "
            "ECDSA / Ed25519, unit-tested). The two modules are simply not connected. This is "
            "latent today only because `dnssec.rs` has no live callers."
        ),
        gaps=[
            "`validate_rrset` discards the computed digest and the signature",
            "Unconditional `RrsetValidation::Secure` return at dnssec.rs:583",
            "`crypto::verify_sig` is never called from `dnssec.rs`",
            "Algorithm coverage limited to 8 and 13 (dnssec.rs:512) vs upstream 5,7,8,10,13,14,15,16",
        ],
        acceptance=[
            "`validate_rrset` calls `crypto::verify_sig` and returns Bogus on failure",
            "REQUIRED negative test: a valid RRSIG with corrupted signature bytes returns Bogus",
            "REQUIRED negative test: a signature from the wrong key returns Bogus",
            "Expired and not-yet-valid signatures return Bogus",
            "Supported algorithm set matches upstream, or unsupported ones are explicitly rejected rather than accepted",
        ],
        blocked_by=[],
    ),
    dict(
        key="T1-2", tier=1, risk="high", model="opus", extra_labels=["security"],
        title="crypto.rs: RsaSha1 verifies with SHA-256; GOST and Ed448 missing",
        port_file="src/crypto.rs", upstream_file=f"{UPSTREAM}/crypto.c",
        summary=(
            "`verify_sig` (src/crypto.rs:182-188) routes `DnssecAlgorithm::RsaSha1` to "
            "`RsaVerifyingKey<Sha256>`, so algorithm-5 signatures can never verify. This fails "
            "closed rather than open, so it is a correctness bug rather than a forgery risk — but "
            "it diverges from upstream's per-algorithm hash selection (crypto.c:153-204).\n\n"
            "Also missing: GOST (`dnsmasq_gostdsa_verify`, crypto.c:280-320, algorithm 12) and "
            "Ed448 (crypto.c:321-400, algorithm 16). `parse_dnskey` returns `UnsupportedAlgorithm` "
            "for Ed448 while `algo_digest_name` still advertises `\"null_hash\"` support for it — "
            "an internal inconsistency."
        ),
        gaps=[
            "RsaSha1 arm uses `RsaVerifyingKey<Sha256>` instead of Sha1",
            "GOST (algorithm 12) entirely absent",
            "Ed448 (algorithm 16) rejected by `parse_dnskey` but advertised by `algo_digest_name`",
        ],
        acceptance=[
            "Algorithm 5 signatures verify against a known-good test vector",
            "Advertised algorithm support matches what `parse_dnskey` actually accepts",
            "Unsupported algorithms are explicitly rejected, never silently treated as valid",
            "GOST/Ed448 either implemented or documented as unsupported with an explicit rejection path",
        ],
        blocked_by=[],
    ),
    dict(
        key="T1-3", tier=1, risk="medium", model="sonnet",
        title="check_for_bogus_wildcard matches only A records, never AAAA",
        port_file="src/rfc1035.rs", upstream_file=f"{UPSTREAM}/rfc1035.c",
        summary=(
            "`check_for_bogus_wildcard` (src/rfc1035.rs:1232) filters on `rtype == 1` only. "
            "Upstream `check_bad_address` (rfc1035.c:1340-1401) matches both `T_A` and `T_AAAA`, "
            "so IPv6 bogus-NXDOMAIN entries are silently never caught. The asymmetry is visible "
            "directly against `check_for_ignored_address` (:1275-1300), which is AAAA-aware.\n\n"
            "Separately, the negative entry is cached with the caller-supplied `local_ttl` "
            "(:1258) instead of the TTL extracted from the matched RR (rfc1035.c:1363-1364, used "
            "at :1415)."
        ),
        gaps=[
            "Only `rtype == 1` (A) is matched; AAAA is ignored",
            "Negative entry cached with `local_ttl` rather than the matched RR's TTL",
        ],
        acceptance=[
            "A `--bogus-nxdomain`-style IPv6 address in a reply is caught",
            "The cached negative entry uses the RR's TTL",
            "Tests cover both A and AAAA paths",
        ],
        blocked_by=[],
    ),
    dict(
        key="T1-4", tier=1, risk="high", model="opus",
        title="extract_addresses caches any RR type and cannot roll back a partial insert",
        port_file="src/rfc1035.rs, src/cache.rs", upstream_file=f"{UPSTREAM}/rfc1035.c",
        summary=(
            "Two related defects.\n\n"
            "**Unbounded caching.** `extract_addresses` (src/rfc1035.rs:627-813) caches every "
            "unrecognized RR type via its `_ => F_RR` / `_ => AllAddr::RrData` fallthrough. "
            "Upstream caches only `T_SRV`, `T_PTR`, or types explicitly listed on "
            "`daemon->cache_rr` (`rr_on_list`, rfc1035.c:800-804), and refuses to cache anything "
            "when the query itself was `T_CNAME`. `ExtractConfig` has no `cache_rr` field.\n\n"
            "**No rollback.** Upstream wraps a whole reply in `cache_start_insert()` / "
            "`cache_end_insert()` (rfc1035.c:711) and discards it on any bad-packet return. The "
            "Rust version calls `cache.insert(...)` per record immediately, so a malformed packet "
            "hit mid-CNAME-chain leaves earlier records permanently cached even though the "
            "function returns `BadPacket`."
        ),
        gaps=[
            "Any RR type is cached; no `cache_rr` allowlist exists",
            "`T_CNAME` queries do not suppress insertion as upstream requires",
            "No staged-insert/rollback equivalent to `cache_start_insert`/`cache_end_insert`",
            "Malformed replies can partially pollute the cache",
        ],
        acceptance=[
            "Only SRV, PTR, and allowlisted types are cached",
            "A reply that fails to parse mid-way inserts nothing",
            "Test asserts cache is unchanged after a `BadPacket` return",
        ],
        blocked_by=["T0-2"],
    ),
    dict(
        key="T1-5", tier=1, risk="high", model="opus",
        title="rrfilter drops upstream's compression-pointer safety pass",
        port_file="src/rrfilter.rs", upstream_file=f"{UPSTREAM}/rrfilter.c",
        summary=(
            "Upstream runs a two-pass `check_name()`/`check_rrs()` algorithm (rrfilter.c:23-160) "
            "*before* eliding any record, specifically to detect when a retained record's name "
            "uses DNS compression to point into a record about to be removed, and to abort "
            "safely. `filter_rr_types` (src/rrfilter.rs:40-103) has no equivalent and slices "
            "matched RRs out blindly. Its own doc comment states the assumption:\n\n"
            "> pointers that referred only to removed RRs are not rewritten (this is safe for the "
            "common cases — OPT and DNSSEC — that this function is used for)\n\n"
            "That is an assumption, not a proven invariant, and it is a wire-corruption risk with "
            "adversarial or unusual upstream replies.\n\n"
            "Also missing: the `RRFILTER_CONF`/`EDNS0`/`DNSSEC` mode distinction, RFC 8482 §4.3 "
            "filtering of `T_ANY` replies (rrfilter.c:216-223), the \"don't strip the DNSSEC RR "
            "matching the queried type\" exception (:212-214), `rrfilter_desc()` (:296-355), and "
            "`to_wire()`/`from_wire()` (:356-412) used for DNSSEC canonical form."
        ),
        gaps=[
            "No compression-pointer safety pass before elision",
            "No RFC 8482 ANY-query filtering mode",
            "No answer-type exception when stripping DNSSEC RRs",
            "`rrfilter_desc`, `to_wire`, `from_wire` missing",
        ],
        acceptance=[
            "A reply using compression into an elided RR is handled without corrupting the wire format",
            "Property test: filtering never produces an unparseable packet",
            "ANY-query replies are filtered per RFC 8482",
        ],
        blocked_by=[],
    ),
    dict(
        key="T1-6", tier=1, risk="high", model="opus",
        title="conntrack builds a CT_NEW set-message; upstream issues a GET query",
        port_file="src/conntrack.rs", upstream_file=f"{UPSTREAM}/conntrack.c",
        summary=(
            "Upstream `get_incoming_mark()` (conntrack.c:27-73) performs an nfnetlink **GET** "
            "query to read an existing connection's firewall mark, used at forward.c:116, 609, "
            "1445, 1823, and 2395 to propagate that mark onto outbound DNS forwarding.\n\n"
            "`src/conntrack.rs` instead builds an `IPCTNL_MSG_CT_NEW` (create/set) message — "
            "semantically the opposite operation — never sends it over any socket, and has no "
            "callers. This needs rebuilding as a GET-query plus response parse, not extending."
        ),
        gaps=[
            "`build_ctmark_msg` constructs a set-message where a get-query is required",
            "No socket is ever opened or message sent",
            "No response-parsing callback equivalent to conntrack.c:75-83",
            "No call sites in `forward.rs` for mark propagation",
        ],
        acceptance=[
            "A GET query reads the mark for an existing connection",
            "The mark is applied to the corresponding outbound query",
            "Capability-dependent tests are gated for restricted environments",
        ],
        blocked_by=["T0-6"],
    ),
    dict(
        key="T1-7", tier=1, risk="medium", model="sonnet",
        title="radv calc_lifetime and calc_interval implement different semantics than upstream",
        port_file="src/radv.rs", upstream_file=f"{UPSTREAM}/radv.c",
        summary=(
            "These are same-name, different-behavior ports rather than missing functions, which "
            "makes them invisible to any audit that matches on symbol names.\n\n"
            "Upstream `calc_interval` (radv.c:997-1011) clamps a single `ra->interval` to "
            "`[4,1800]` with default 600. Rust's `calc_interval(min, max)` (radv.rs:292-296) "
            "computes an unrelated min/max pair via a `0.33` ratio formula.\n\n"
            "Upstream `calc_lifetime` (radv.c:1013-1029) defaults to `3 × interval`, or clamps "
            "`ra->lifetime` to `[interval, 9000]` with 0 permitted to mean \"no default route\". "
            "Rust's (radv.rs:279-283) is `unwrap_or(default).min(65535)`.\n\n"
            "Neither takes an `RaInterfaceParam` like the faithfully-ported `calc_prio` "
            "(radv.rs:338-346) does."
        ),
        gaps=[
            "`calc_interval` does not clamp to [4,1800] or default to 600",
            "`calc_lifetime` does not default to 3x interval or clamp to [interval,9000]",
            "Lifetime 0 as \"no default route\" is not honored",
        ],
        acceptance=[
            "Both functions reproduce upstream clamp semantics exactly",
            "Boundary tests at 4, 1800, 9000, and 0",
            "Signatures take the RA interface parameters as upstream does",
        ],
        blocked_by=[],
    ),

    # ────────────────────────── TIER 2 — CONFIG PARITY ──────────────────────────
    dict(
        key="T2-1", tier=2, risk="medium", model="sonnet",
        title="dhcp-vendorclass is implemented under the invented key dhcp-vendor",
        port_file="src/option.rs", upstream_file=f"{UPSTREAM}/option.c",
        summary=(
            "`option.rs:1227` implements the directive under the key `\"dhcp-vendor\"`, which is "
            "not a dnsmasq directive. The real upstream name is `dhcp-vendorclass` (option table "
            "line 273, case 'U', ~option.c:4565). Any real config using "
            "`dhcp-vendorclass=set:tag,text` is rejected outright with `UnknownOption`.\n\n"
            "Verified: `grep -c '\"dhcp-vendorclass\"' src/option.rs` → 0, "
            "`grep -c '\"dhcp-vendor\"' src/option.rs` → 5."
        ),
        gaps=[
            "`dhcp-vendorclass` unrecognized",
            "Non-existent `dhcp-vendor` key accepted instead",
        ],
        acceptance=[
            "`dhcp-vendorclass=set:tag,text` parses and applies",
            "The invented `dhcp-vendor` key is removed or kept only as a documented alias",
            "Test asserts a real-world config line is accepted",
        ],
        blocked_by=[],
    ),
    dict(
        key="T2-2", tier=2, risk="medium", model="sonnet",
        title="domain-needed and other core directives are unrecognized and abort startup",
        port_file="src/option.rs", upstream_file=f"{UPSTREAM}/option.c",
        summary=(
            "Verified by running the binary:\n\n"
            "```\n"
            "$ dnsmasq-rs --conf-file t.conf   # t.conf contains: domain-needed\n"
            "Error: UnknownOption(\"domain-needed\", \"t.conf\", 1)  → exit 1\n"
            "```\n\n"
            "`domain-needed` (`-D`, `OPT_NODOTS_LOCAL`) is among the most commonly set dnsmasq "
            "directives and is frequently the first line of a real config. The "
            "`OPT_NODOTS_LOCAL` bit exists in `types/constants.rs` but is referenced nowhere.\n\n"
            "Also unrecognized: `keep-in-foreground` (`-k`, distinct from the implemented "
            "`no-daemon`/`-d`), `dhcp-broadcast`, `dhcp-duid`, `dhcp-generate-names`, "
            "`dhcp-ignore-names`, `dhcp-rapid-commit`, `dhcp-proxy`, `dhcp-pxe-vendor`, "
            "`bootp-dynamic`, `pxe-prompt`, `pxe-service`, `clear-on-reload`, `conf-script`, "
            "`umbrella`, `no-dhcpv4-interface`, `no-dhcpv6-interface`, `enable-ubus`, "
            "`dns-loop-detect`, `connmark-allowlist`, `connmark-allowlist-enable`, `log-malloc`."
        ),
        gaps=[
            "`domain-needed` unrecognized; `OPT_NODOTS_LOCAL` never set",
            "`keep-in-foreground` unrecognized",
            "~20 further directives unrecognized (listed above)",
            "Two synthetic non-upstream keys exist (`log-rotate`, `no-hosts6`) returning \"not implemented yet\"",
        ],
        acceptance=[
            "A config containing `domain-needed` starts successfully and suppresses forwarding of single-label queries",
            "Each listed directive either parses and applies, or is explicitly documented as unsupported in `tasks.md`",
            "Synthetic non-upstream keys are removed",
        ],
        blocked_by=[],
    ),
    dict(
        key="T2-3", tier=2, risk="medium", model="opus",
        title="DHCP tag subsystem: tag-if and dhcp-match are unparsed, engine already exists",
        port_file="src/option.rs, src/types/daemon.rs", upstream_file=f"{UPSTREAM}/option.c",
        summary=(
            "`run_tag_if()` (src/dhcp_common.rs:740) is fully implemented and unit-tested. "
            "Nothing in `option.rs` ever constructs a `TagIf` from a config line, so the feature "
            "is dead at runtime — the engine was built and the wiring was not.\n\n"
            "`dhcp-match` (LOPT_MATCH, option.c:4314) and `dhcp-name-match` (LOPT_NAME_MATCH, "
            ":4321) are likewise absent. These tag clients by option-60/vendor-class substring, "
            "generic option match, or PXE client detection. `daemon->dhcp_match` and "
            "`dhcp_name_match` have no Rust fields at all.\n\n"
            "Note this silently degrades any config relying on conditional tag logic rather than "
            "erroring where it should."
        ),
        gaps=[
            "`tag-if` unparsed; `run_tag_if` has no live caller",
            "`dhcp-match` and `dhcp-name-match` unparsed",
            "`Daemon` lacks `tag_if`, `dhcp_match`, `dhcp_match6`, `dhcp_name_match` fields",
        ],
        acceptance=[
            "`tag-if=set:a,tag:b,tag:c` parses and drives `run_tag_if` at runtime",
            "`dhcp-match` tags a client by vendor-class substring",
            "Integration test: a tagged client receives the tag-conditional option",
        ],
        blocked_by=["T0-8"],
    ),
    dict(
        key="T2-4", tier=2, risk="medium", model="sonnet",
        title="rev-server, synth-domain, shared-network, and bridge-interface unimplemented",
        port_file="src/option.rs, src/types/daemon.rs", upstream_file=f"{UPSTREAM}/option.c",
        summary=(
            "Four unrelated but similarly-shaped config gaps, each needing a parser plus a "
            "`Daemon` field:\n\n"
            "- `rev-server` (LOPT_REV_SERV, option.c:3161) — the modern, widely-used way to "
            "delegate reverse DNS by subnet. No fallback path exists.\n"
            "- `synth-domain` (LOPT_SYNTH, option.c:2622) — synthesized forward/reverse names for "
            "IP-embedded hostnames. Related: `src/domain.rs` has `synthesize_ipv4` but no "
            "`synthesize_ipv6`, and `CondDomain` has no `interface` or `prefixlen` field.\n"
            "- `shared-network` (LOPT_SHARED_NET, option.c:3709)\n"
            "- `bridge-interface` (LOPT_BRIDGE, option.c:3673)"
        ),
        gaps=[
            "`rev-server` unparsed; no `Daemon` field",
            "`synth-domain` unparsed; no cond-domain/synth field",
            "`shared-network` unparsed; no `shared_networks` field",
            "`bridge-interface` unparsed; no `bridges` field",
        ],
        acceptance=[
            "Each directive parses, applies, and affects runtime behavior",
            "`rev-server` delegates reverse lookups for the configured subnet",
            "Malformed forms are rejected with a clear error",
        ],
        blocked_by=[],
    ),
    dict(
        key="T2-5", tier=2, risk="high", model="opus",
        title="dhcp-relay is unparsed and relay_upstream4 is entirely absent",
        port_file="src/option.rs, src/rfc2131.rs", upstream_file=f"{UPSTREAM}/rfc2131.c",
        summary=(
            "`dhcp-relay` / `dhcp-split-relay` (LOPT_RELAY / LOPT_SPLIT_RELAY, option.c:4729) are "
            "unparsed, and `relay_upstream4()` (rfc2131.c:3058-3265, ~207 LOC) — the actual "
            "Layer-3 relay forwarding — has no Rust equivalent.\n\n"
            "Easy to mistake for implemented: `option.rs:3128` has a `parse_dhcp_relay_id` helper "
            "and `DhcpRelayIdRule` exists, but those serve `dhcp-circuitid`/`dhcp-remoteid`/"
            "`dhcp-subscrid` option-82 **tag matching**, which is a different feature. "
            "`Daemon.relay4`/`relay6` fields and a `DhcpRelay` type do exist "
            "(types/daemon.rs:159,164) — the data model is ahead of the parser here.\n\n"
            "Related gap in the same area: relay-agent-information option 82 capture and echo "
            "(`OPTION_AGENT_ID`, rfc2131.c:189-204, 1113-1132, 1721-1729) has zero references in "
            "`rfc2131.rs`, so the suboptions are used for config-time tag matching only and are "
            "never stored on the lease or echoed back in the reply."
        ),
        gaps=[
            "`dhcp-relay` / `dhcp-split-relay` unparsed despite `relay4`/`relay6` fields existing",
            "`relay_upstream4()` absent",
            "Option 82 agent-id never captured or echoed in replies",
        ],
        acceptance=[
            "`dhcp-relay=local,server` parses and populates `Daemon.relay4`",
            "A relayed DHCP request is forwarded upstream and the reply returned",
            "Option 82 is echoed back per RFC 3046",
        ],
        blocked_by=["T0-8"],
    ),
]


# ────────────────────────── TIER 3 — PER-FILE DEPTH ──────────────────────────
# (key, title, risk, model, port_file, upstream_basename, summary, gaps, acceptance)
_T3 = [
    ("rfc1035", "rfc1035.c depth: find_soa, local-domain checks, query logging", "high", "opus",
     "src/rfc1035.rs", "rfc1035.c",
     "Remaining per-file gaps after the integration work in T0-1/T0-7 and the correctness fixes in T1-3/T1-4.",
     ["`find_soa` replaced by `find_soa_minimum_ttl` (:599-619): no name/substring match verification (rfc1035.c:554-556), no caching of the SOA RR itself as `F_RR` (:559-625), no DNSSEC rr_status TTL capping (:609-618)",
      "`check_for_local_domain` (:1306-1314) omits interface-name records (`daemon->int_names`, rfc1035.c:1322-1324), `cache_find_non_terminal` (:1330-1331, exists in cache.rs but uncalled), and `is_name_synthetic` (:1333-1335)",
      "`extract_addresses` never populates ipset/nftset from extracted addresses (rfc1035.c:690-691, 1009, 1020)",
      "`report_addresses` (rfc1035.c:1148-1218) missing entirely",
      "`log_txt` (rfc1035.c:653-681) missing"],
     ["Each listed function matches upstream behavior for supported cases",
      "ipset/nftset receive extracted addresses where configured"]),

    ("cache", "cache.c depth: log_query sink and transactional insert", "medium", "sonnet",
     "src/cache.rs", "cache.c",
     "`log_query()` (cache.c:2311) is the most pervasively used function in the C codebase and has no Rust equivalent anywhere, so `--log-queries` produces nothing. `querystr`/`querystr_flags` (:711-733) exist as pure formatters with no logging sink behind them.",
     ["`log_query` has no equivalent; `--log-queries` is inert",
      "`cache_start_insert`/`cache_end_insert` staged-insert mechanism absent (see T1-4)",
      "`cache_make_stat` (cache.c:1906) absent, so `--stat-log` STAT TXT records are unavailable",
      "`is_outdated_cname_pointer` (cache.c:449-462) stale-CNAME-chain expiry not replicated"],
     ["`--log-queries` produces upstream-comparable output",
      "Cache statistics are queryable where upstream supports it"]),

    ("forward-depth", "forward.c depth: connection-mark filtering and outgoing marks", "medium", "sonnet",
     "src/forward.rs", "forward.c",
     "Remaining gaps after T0-6/T0-7.",
     ["`is_query_allowed_for_mark`/`answer_disallowed` (forward.c:1526-1567) SO_MARK-based ubus allowlist filtering absent",
      "`set_outgoing_mark` (forward.c:112-120) SO_MARK on outgoing sockets for policy routing absent"],
     ["Mark-based query filtering works where configured",
      "Capability-dependent tests are gated"]),

    ("domain", "domain.c: IPv6 name synthesis and interface-scoped conditional domains", "medium", "sonnet",
     "src/domain.rs", "domain.c",
     "`is_name_synthetic()` (domain.c:25-150) handles both `F_IPV4` and `F_IPV6`; Rust has only `synthesize_ipv4` (:51-90).",
     ["No `synthesize_ipv6`; AAAA-side `--synth-domain` resolution entirely missing",
      "`CondDomain` has no `interface`/address-list field, so the `c->interface` branch of `match_domain`/`match_domain6` (domain.c:220-227, 259-266) is unimplemented",
      "`match_domain6` (:208-216) collapses upstream's prefixlen-dependent branching (domain.c:267-279) into an always-low64 comparison; `CondDomain` has no `prefixlen` field, so any conditional IPv6 domain with a prefix shorter than /64 matches incorrectly"],
     ["AAAA synth-domain queries resolve",
      "Interface-scoped conditional domains work",
      "Prefixes shorter than /64 match correctly"]),

    ("domain-match", "domain-match.c: make_local_answer missing, breaking --address=", "high", "opus",
     "src/domain_match.rs", "domain-match.c",
     "`make_local_answer()` (domain-match.c:409-475) writes A/AAAA answer RRs into the reply for `--address=/domain/1.2.3.4`-style configs, including truncation and TC-bit handling. It has no Rust equivalent (verified: zero hits repo-wide). `is_local_answer` DOES exist (domain_match.rs:518) but the whole `domain_match` module has zero callers outside itself.\n\nNet effect: `--address=` and `--server=/domain/` local-literal answers do not work. This is one of the most common dnsmasq deployment patterns (ad-blocking, split-horizon).",
     ["`make_local_answer` missing entirely",
      "`is_local_answer` exists but has zero callers",
      "`domain_match` module has no callers outside itself"],
     ["`--address=/example.com/1.2.3.4` returns 1.2.3.4",
      "`--address=/example.com/` returns NODATA per upstream",
      "TC bit set correctly when the answer does not fit"]),

    ("edns0", "edns0.c: ECS echo verification and MAC/Umbrella options", "high", "opus",
     "src/edns0.rs", "edns0.c",
     "`check_source()` (edns0.c:445-488) validates that an ECS option echoed back in a reply matches what was sent — anti cache-poisoning. `check_source_subnet` (:215-223) is a different, narrower function that merely extracts an ECS address with no comparison role.",
     ["`check_source` has no equivalent; a spoofed/mismatched ECS echo is not caught",
      "`calc_subnet_opt` (edns0.c:350-444) missing; `build_ecs_payload` lacks the cacheability determination tied to peer/config",
      "`edns0_needs_mac` query-augmentation flow missing (only the base64 primitives `char64`/`encoder`/`mac_to_base64` are ported)",
      "`add_umbrella_opt` (edns0.c:517-574) missing"],
     ["A reply whose ECS echo does not match the query is rejected",
      "ECS cacheability flags match upstream"]),

    ("dhcp", "dhcp.c: ICMP conflict probe, /etc/ethers, socket setup", "high", "opus",
     "src/dhcp.rs", "dhcp.c",
     "The address-conflict probe is the notable one: `IcmpPinger::ping()` in dnsmasq.rs:592-623 is an explicit stub that always returns `false`, and `dhcp.rs` never calls it. The server can double-assign an address already in use.",
     ["`do_icmp_ping` (dhcp.c:769-923) not ported; `IcmpPinger::ping` always returns false and is uncalled",
      "`icmp_checksum` is implemented but dead — never used to build or send a real ICMP packet",
      "`make_fd`/`dhcp_init` (dhcp.c:36-129): no IP_PKTINFO/IP_MTU_DISCOVER/SO_REUSEPORT setup, no PXE port bind",
      "`dhcp_read_ethers` (dhcp.c:924-1090): `--read-ethers` is parsed and stored but never consumed",
      "`host_from_dns` (dhcp.c:1091-1124) missing",
      "`guess_range_netmask` (dhcp.c:568-753) missing",
      "`context_for_reply` (:193) collapses upstream's interface-aware context selection into first-match-or-first"],
     ["An in-use address is detected and not offered",
      "`--read-ethers` populates static host config",
      "Per-interface context selection matches upstream"]),

    ("dhcp-common", "dhcp-common.c: startup config logging and option_string formats", "low", "haiku",
     "src/dhcp_common.rs", "dhcp-common.c",
     "The tag/option-filter/pxe logic here is a genuinely faithful port (`option_filter`'s 4-phase logic and `match_netid_wild`'s negation/wildcard handling verified line-by-line). The gaps are diagnostic output.",
     ["`log_context` (dhcp-common.c:951-1044) and `log_relay` (:1045-1081) have no equivalent; startup diagnostics for dhcp-range/dhcp-relay are absent",
      "`option_string` (:827-950) simplified: only OT_ADDR_LIST/OT_NAME/OT_DEC/OT_TIME/hex; missing signed decimal, OT_STRING vs OT_NAME distinction, RFC3397 domain-search decompression, IPv6 address-list formatting",
      "Two `recv_dhcp_packet` definitions exist (:458, :566); confirm which compiles for the real feature build"],
     ["Startup logs dhcp-range and dhcp-relay config as upstream does",
      "`option_string` covers upstream's format branches"]),

    ("rfc2131", "rfc2131.c: BOOTP, LEASEQUERY, and PXE UEFI paths", "high", "opus",
     "src/rfc2131.rs", "rfc2131.c",
     "Remaining gaps after T0-8 wires up dispatch and T2-5 covers relay/option-82.",
     ["BOOTP support (`mess_type == 0`, rfc2131.c:564-694, ~130 LOC) missing: `dispatch_dhcp_with_meta` requires `get_message_type` to succeed (dhcp.rs:415), so any packet lacking option 53 is silently dropped rather than answered",
      "`DHCPLEASEQUERY` falls into the `_ => None` catch-all (dhcp.rs:467) despite the enum variant existing",
      "`apply_delay` (rfc2131.c:3035-3057) applied only to OFFERs (dhcp.rs:475), not ACKs",
      "`pxe_uefi_workaround` and full `pxe_opts` menu construction (rfc2131.c:2392-2556) not verified line-by-line"],
     ["A BOOTP client receives a valid reply",
      "LEASEQUERY is answered per RFC 4388",
      "Reply delay applies to both OFFER and ACK as upstream does"]),

    ("lease", "lease.c: atomic lease-file persistence and script hooks", "high", "opus",
     "src/lease.rs", "lease.c",
     "Depth work after T0-8 wires `LeaseDb` into the packet path.",
     ["`lease_update_file` (lease.c:278-496) uses atomic temp-file + rename + fsync; `write_to_file`/`load_from_file` (:449, :456) are simple path-based read/write with no crash-safety discipline",
      "`do_script_run` (lease.c:1216-1311) and `rerun_scripts` (:1203-1215): `rerun_scripts` exists but has no connection to `helper.rs`, so no dhcp-script hook fires",
      "`lease_ping_reply`, `lease_update_slaac`, `lease_find_interfaces`, `lease_make_duid` (lease.c:497-556) have no direct equivalents"],
     ["Lease file writes are atomic and survive a simulated crash mid-write",
      "dhcp-script hooks fire on lease add/old/del"]),

    ("helper", "helper.c: no forked, privilege-dropped script helper", "high", "opus",
     "src/helper.rs", "helper.c",
     "`src/helper.rs` is not a port of helper.c's design. Upstream forks a privilege-dropped child (setuid/setgid, rlimit fd capping, pipe-based binary protocol) to run `dhcp-script`; the Rust module defines a text newline-delimited wire format (helper.rs:55-115) bearing no resemblance to the C binary struct protocol, plus a `run_script()` (:191) that appears to invoke the script in-process.\n\nSecurity consequence: without the forked helper, script execution would run with dnsmasq's full privileges rather than the dropped uid/gid — a regression against upstream's design intent. Currently moot because nothing calls it.",
     ["`create_helper` (helper.c:79-692, ~600 LOC) has no equivalent",
      "No privilege separation for script execution",
      "Wire format diverges entirely from upstream's binary protocol",
      "No callers from `dhcp.rs`/`lease.rs`",
      "Lua scripting (`grab_extradata_lua`, helper.c:736-756) not ported — reasonable to deprioritize"],
     ["Scripts run in a forked child with dropped privileges",
      "Parent survives a script that hangs or crashes",
      "Test asserts the child's uid/gid differ from root where permissions allow"]),

    ("arp", "arp.c: cache never populated; no kernel-refresh glue or call sites", "high", "opus",
     "src/arp.rs", "arp.c",
     "The `ArpCache` state machine (New/Found/Mark/Empty, refresh cycle, eviction) is a faithful, tested port of the data-structure logic. But C's `find_mac()` (arp.c:107-208) triggers `iface_enumerate()` itself when stale (:152-181) and loops; Rust's `find_mac_cached()` (:188) is lookup-only and documents that it leaves kernel enumeration \"to the caller\" — and no caller exists.",
     ["`find_mac_cached` never triggers kernel enumeration, so the cache is never populated",
      "Upstream callers of `find_mac` — edns0.c (3 sites), dhcp6.c:338, tftp.c:470 — have no Rust equivalents",
      "`do_arp_script_run` (arp.c:210-240) exists but never fires"],
     ["The ARP cache populates from the kernel neighbor table",
      "EDNS0 MAC option and DHCPv6 MAC logging resolve real addresses"]),

    ("dhcp6", "dhcp6.c: no DHCPv6 server — init, socket loop, DUID, contexts, allocation", "high", "opus",
     "src/dhcp6.rs", "dhcp6.c",
     "`dispatch_dhcp6` (dhcp6.rs:137-178) is a stub returning empty-option Advertise/Reply regardless of input. There is no port-547 listener anywhere in the crate.",
     ["`dhcp6_init` (dhcp6.c:35-88): no socket bind, no ALL_SERVERS multicast join",
      "`dhcp6_packet` (:89-307): no receive/dispatch loop, relay detection, or context matching",
      "`get_client_mac` (:308-351) missing",
      "`complete_context6` (:352-473) missing, including the `IN6_IS_ADDR_ULA(local)` case at :370",
      "`address6_allocate` (:492-575): only the pure hash primitives (`sdbm_hash64`, `hash_to_addr6`) are ported; the allocation loop with collision/DECLINE retry is absent",
      "`make_duid`/`make_duid1` (:617-689) missing entirely; `handle_solicit`/`handle_request6` take `server_duid` as an opaque caller-supplied parameter with no generator",
      "`dhcp_construct_contexts` (:814-880) missing"],
     ["A DHCPv6 SOLICIT receives a real ADVERTISE with an allocated address",
      "DUID is generated and persisted",
      "Contexts are constructed from config plus live interface prefixes"]),

    ("rfc3315", "rfc3315.c: the ~1200-line DHCPv6 state machine is absent", "high", "opus",
     "src/rfc3315.rs", "rfc3315.c",
     "Wire-format TLV helpers, logging, and relay encode/decode are faithful. The state machine is not. `handle_solicit`/`handle_request6` fabricate a single hardcoded IA_NA with fixed lifetimes (3600/7200/1800/2880) regardless of client input or lease store, and should not be read as a working server.",
     ["`dhcp6_reply`/`dhcp6_maybe_relay`/`dhcp6_no_relay` (rfc3315.c:71-1301, ~1200 LOC): the entire per-message-type machine (SOLICIT/REQUEST/RENEW/REBIND/RELEASE/DECLINE/CONFIRM/INFOREQUEST, rapid-commit, reconfigure-accept, IA_PD prefix delegation) missing",
      "`add_options` (:1301-1534) missing, including ULA/link-local auto-prefix logic at :1342, 1360-1365",
      "`update_leases` (:1870-1986) missing; no lease-DB integration at all",
      "`config_valid`/`config_implies`/`check_address`/`mark_context_used`/`mark_config_used` (:1701-1822) missing",
      "Status codes DHCP6NOADDRS/NOBINDING/NOTONLINK/USEMULTI never produced; `status_success` always returns 0",
      "`relay_upstream6`/`relay_reply6` (:2145-2327) socket-level forwarding missing",
      "`check_ia`/`build_ia`/`end_ia`/`calculate_times` exist (:559-660) but have no callers besides tests"],
     ["Each DHCPv6 message type is handled per RFC 8415",
      "Leases are allocated from real contexts and persisted",
      "Failure status codes are returned where upstream returns them"]),

    ("radv", "radv.c: no ICMPv6 socket, send path, prefix construction, or timer", "high", "opus",
     "src/radv.rs", "radv.c",
     "`build_ra()` produces bytes and nothing sends them. See T1-7 for the separate mismatched-semantics defect in this file.",
     ["`ra_init` (radv.c:71-117): no raw ICMPv6 socket, ICMP6 filter, or hop-limit sockopt",
      "`icmp6_packet` (:141-256): no receive loop for Router/Neighbor Solicitations",
      "`send_ra`/`send_ra_alias`/`send_ra_to_aliases` (:257-578, 899-920): nothing transmits",
      "`add_prefixes` (:586-765): nothing populates `RaPrefix`/`RouterAdvertisement` from live interface state, including the ULA/link-local zero cases at :479-501 and `IN6_IS_ADDR_ULA(local)` at :714",
      "`periodic_ra` (:789-898): no timer loop; `new_timeout()` (:363-386) exists but nothing calls it periodically",
      "`iface_search` (:921-972) missing",
      "`ra_start_unsolicited` (:118-140) exists only as a struct-mutating method with no send path"],
     ["Unsolicited RAs are transmitted on the configured interval",
      "A Router Solicitation receives an RA",
      "Prefix options reflect live interface addresses"]),

    ("slaac", "slaac.c: address math present, all lease/kernel/DAD integration missing", "medium", "sonnet",
     "src/slaac.rs", "slaac.c",
     "Pure EUI-64/address-derivation math is present and correct.",
     ["`slaac_add_addrs` (slaac.c:25-118) missing; nothing ties `slaac_address`/`eui64_from_mac` to lease records",
      "`periodic_slaac` (:119-190) missing",
      "`slaac_ping_reply` (:191-213) missing; no ICMPv6 DAD integration",
      "`is_slaac_for`/`synthesize_slaac_addrs` are Rust-only helpers with no 1:1 C counterpart"],
     ["SLAAC addresses are derived from leases and tracked",
      "DAD probing works where permissions allow"]),

    ("netlink", "netlink.c: EPERM fallback divergence and no runtime integration", "medium", "sonnet",
     "src/netlink.rs", "netlink.c",
     "The most faithful of the networking files — real NETLINK_ROUTE socket creation, message parsing, ENOBUFS recovery, multicast group management. The gap is integration plus one semantic divergence.",
     ["`netlink_open` (:449-489) retries the no-multicast bind on ANY bind failure; upstream retries only when `errno == EPERM` (netlink.c:76)",
      "No caller opens a netlink socket or processes address-change events, so `newaddress()`-triggered interface re-scans never fire"],
     ["EPERM fallback matches upstream exactly",
      "Address-change events trigger interface re-enumeration at runtime"]),

    ("network", "network.c: iface_allowed drastically simplified; lifecycle functions missing", "high", "opus",
     "src/network.rs", "network.c",
     "Depth work after T0-4 wires listener creation. `iface_allowed` is the big one: 357 lines upstream vs a much narrower Rust pair.",
     ["`iface_allowed` (network.c:239-596, 357 LOC): Rust's `iface_allowed_v4`/`v6` (:838-957) implement only name allow/deny, loopback exclusion, a dhcp_except deny list, and a tftp allow list. Missing: bridge-interface alias resolution, IFACE_TENTATIVE/DAD flag skipping, deprecated-address handling, listen-address vs interface precedence, --auth-server special-casing, bind-dynamic vs bind-interfaces semantics",
      "`enumerate_interfaces` (:722-883): Rust's same-named function (:56-79) is a thin `if_addrs` wrapper that hardcodes `index: 0` and creates/destroys no listeners — a different, much smaller function reusing the name",
      "`release_listener` (:674-721), `warn_bound_listeners` (:1251-1275), `warn_wild_labels`, `warn_int_names`, `is_dad_listeners` all missing",
      "`join_multicast` (:1307-1366) missing",
      "`local_bind` (:1367-1456) missing — no SO_BINDTODEVICE/IP_PKTINFO source selection for outbound queries",
      "`allocate_sfd`/`pre_allocate_sfds` (:1457-1563) missing",
      "`check_servers` (:1564-1698) missing",
      "`reload_servers` (:1699-1777): only `parse_resolv_conf` (:988-1021) exists, which tokenizes nameserver lines without diffing, deduping, or triggering reload",
      "`newaddress` (:1778-1811) missing"],
     ["`iface_allowed` reproduces upstream's include/exclude precedence",
      "Interfaces appearing and disappearing create and release listeners",
      "`reload_servers` diffs against the live server list on SIGHUP"]),

    ("dnssec-depth", "dnssec.c: trust-chain orchestration and NSEC/NSEC3 proofs missing", "high", "opus",
     "src/dnssec.rs", "dnssec.c",
     "Depth work after T1-1 makes signature verification real. Roughly 1600 lines of orchestration remain.",
     ["`dnssec_validate_reply` (dnssec.c:1974-2331, ~358 LOC) — the top-level entry point — missing",
      "`zone_status` (:1881-1973) missing — no DS/DNSKEY walk to a trust anchor",
      "`dnssec_validate_by_ds` (:716-989) and `dnssec_validate_ds` (:990-1182) missing",
      "`prove_non_existence`/`_nsec`/`_nsec3`/`check_nsec3_coverage` (:1247-1880, ~570 LOC) — all NSEC/NSEC3 negative proofs — missing",
      "`get_rdata` (:159-221) and `setup_timestamp` (:68-113) missing; no boot-time clock sanity check"],
     ["A signed zone validates end to end from a configured trust anchor",
      "NSEC and NSEC3 negative proofs are verified",
      "A broken chain yields Bogus, not Secure"]),

    ("auth", "auth.c: answer_auth simplified against a synthetic data model", "high", "opus",
     "src/auth.rs", "auth.c",
     "Rust's `answer_auth` (auth.rs:179-343) answers from a flat, pre-supplied `LocalRecords` struct with no relationship to the real DNS cache, interface list, or DHCP lease table. Upstream's is ~816 lines.",
     ["No OPCODE != QUERY -> NOTIMP (auth.c:129-131)",
      "No qclass != C_IN rejection (:143-148)",
      "PTR reverse lookups against real interface addresses, `daemon->int_names`, and the DHCP/hosts cache with FQDN stripping (:173-274) missing",
      "CNAME-chain and wildcard-CNAME resolution (`cname_restart`/`cname_wildcard`) missing",
      "No SRV or NAPTR support",
      "No TCP truncation handling",
      "AXFR authorization/zone-transfer semantics missing",
      "`find_subnet`/`find_exclude`/`filter_zone` (:44-70) exist in Rust (:117-153) but are never called from `answer_auth`, which takes a single zone directly and skips zone selection and subnet exclusion",
      "`in_zone`'s `cut` output parameter (:72-98) dropped; Rust returns only a bool"],
     ["Authoritative answers come from real cache/lease/interface state",
      "AXFR is authorized per `--auth-peer`",
      "SRV and NAPTR records are served"]),

    ("tftp", "tftp.c: no sockets, no file I/O, no transfer table", "high", "opus",
     "src/tftp.rs", "tftp.c",
     "Packet framing, filename sanitization, and option-negotiation math are solid and tested. Everything that touches the OS is missing — there is no `UdpSocket` or `fs::` usage anywhere in the file.",
     ["`check_tftp_listeners` (tftp.c:621-751) missing — no connection accept, per-transfer socket allocation, or state-machine drive",
      "`tftp_request` (:44-537, ~490 LOC) missing — no file open with prefix/interface/subnet matching",
      "`check_tftp_fileperm` (:538-620) missing — no path/permission resolution or client-IP file-prefix substitution",
      "`get_block` (:905-1023): Rust's (:404) works on already-buffered data, not a live File",
      "`do_tftp_script_run` (:1024-1039) missing",
      "`free_transfer` and timeout retransmit logic missing; no active-transfer table with retry timers"],
     ["A real TFTP client can download a file end to end",
      "blksize/timeout/tsize negotiation works against real files",
      "Path traversal outside `--tftp-root` is rejected"]),

    ("dump", "dump.c: writer accumulates in memory and has no live hooks", "medium", "sonnet",
     "src/dump.rs", "dump.c",
     "The IPv4/IPv6/ICMP framing and checksum math (dump.c:131-303) is genuinely well reproduced in `frame_udp_ipv4`/`frame_udp_ipv6`/`frame_icmp_ipv4`/`frame_icmpv6` (:96-224). The I/O layer is not.",
     ["`dump_init` (dump.c:46-93): `PcapWriter::new` (:232) writes the header into an in-memory Vec; no File/OpenOptions usage anywhere in the file",
      "`dump_packet_udp`/`dump_packet_icmp` (:94-130) missing as named hooks, including the fd->address fallback via `getsockname()` (:112-119)",
      "Nothing calls `write_udp_packet`/`write_icmp_packet` from the live packet paths"],
     ["`--dump-file` produces a pcap readable by tcpdump/wireshark",
      "Query and reply packets appear in the dump"]),

    ("loop", "loop.c: no probe send loop or server-state integration", "medium", "sonnet",
     "src/loop_detect.rs", "loop.c",
     "Token encode/decode and hex round-trip logic look correct against LOOP_TEST_TYPE/LOOP_TEST_DOMAIN semantics.",
     ["`loop_send_probes` (loop.c:22-49) missing — no iteration over `daemon->servers`, no sendto",
      "`detect_loop` (:80-111) marks the offending server with SERV_LOOP and calls `check_servers(1)`; Rust's `check_loop_reply` (:128) only returns a matched token from a caller-supplied list and has no notion of Server flags",
      "No callers anywhere"],
     ["A looping upstream server is detected and disabled",
      "`--dns-loop-detect` works end to end"]),

    ("metrics", "metrics.c: clear_metrics drops per-server reset; label text diverges", "low", "haiku",
     "src/metrics/mod.rs", "metrics.c",
     "The strongest-integrated file in the audit — the enum ordering matches metrics.h exactly and the increment call sites are real. Two small gaps.",
     ["`clear_metrics` (metrics.c:56-73) resets the counters array AND walks `daemon->servers` resetting queries/failed_queries/retrys/nxdomain_replies/query_latency (:64-72). Rust (:63-67) only resets the array; the Server fields exist (types/server.rs:38-42) and no code path ever resets them",
      "`metric_name`/`get_metric_name` (metrics.c:19-54) is never called from anywhere — dead code — and its string values diverge from upstream (e.g. Rust `dhcpack`/`dhcpdecline` vs upstream's `dhcp_ack`/`dhcp_decline` style), which would be a wire-format mismatch once any exporter is wired up"],
     ["`clear_metrics` resets per-server statistics",
      "Metric label text matches upstream exactly"]),

    ("dbus", "dbus.c: stub with 4 of 15 methods and no bus connection", "high", "opus",
     "src/dbus.rs", "dbus.c",
     "Self-described \"D-Bus interface stub\" (dbus.rs:3), 101 lines against 1106 upstream. The `dbus` feature declares `dep:zbus` in Cargo.toml and `grep -rn zbus src/*.rs` finds zero usage.",
     ["`supported_methods()` (:34-36) lists 4 names; upstream has 15 (GetVersion, GetLoopServers, SetServers, SetServersEx, SetDomainServers, SetFilterWin2KOption, SetFilterA, SetFilterAAAA, SetLocaliseQueriesOption, SetBogusPrivOption, AddDhcpLease, DeleteDhcpLease, GetMetrics, GetServerMetrics, ClearCache) and none of the logic is implemented",
      "`dbus_init`/`set_dbus_listeners`/`check_dbus_listeners`/`add_watch`/`remove_watch` (dbus.c:118-158, 951-1053) missing entirely",
      "`dbus_read_servers`/`dbus_read_servers_ex` (:158-488) missing",
      "`dbus_add_lease`/`dbus_del_lease` (:523-703) and `emit_dbus_signal` (:1054-1106) missing",
      "`dbus_get_metrics`/`dbus_get_server_metrics` (:704-950) missing"],
     ["A real bus connection is established under the `dbus` feature",
      "Each upstream method is implemented or explicitly documented as unsupported",
      "Lease add/delete signals are emitted"]),

    ("ubus", "ubus.c: invented wire format incompatible with real libubus", "high", "opus",
     "src/ubus.rs", "ubus.c",
     "`encode_ubus_msg`/`decode_ubus_msg` (ubus.rs:29-60) implement a bespoke `\"object\\nmethod\\nkey=value\\n\"` plus 4-byte-length-prefix protocol. That is not a simplification of the real ubus `blob_attr` binary TLV format — it is a different, incompatible one, so it cannot interoperate with a real ubusd even once wired up.",
     ["`ubus_init`/`set_ubus_listeners`/`check_ubus_listeners` (ubus.c:106-337) missing, including libubus context creation, reconnect-on-disconnect, and conntrack-mark allowlist subscription",
      "`ubus_event_bcast` and the connmark-allowlist refused/resolved variants (:337-391) missing",
      "The encode/decode pair implements an invented protocol rather than blob_attr TLV",
      "HAVE_CONNTRACK-gated allowlist logic (ubus.c:30, 59, 203, 356) has no counterpart"],
     ["Messages use the real ubus blob_attr format",
      "A real ubusd accepts the connection and receives events",
      "DHCP lease events are broadcast"]),

    ("nftset", "nftset.c: wrong mechanism — raw netlink vs upstream's libnftables", "high", "opus",
     "src/nftset.rs", "nftset.c",
     "Upstream uses libnftables (`nft_ctx_new`, `nft_run_cmd_from_buffer` with `\"add element %s { %s }\"`) and opens no netlink socket itself. Rust hand-rolls raw nfnetlink TLVs with attribute numbers 1/2/3 self-labeled \"simplified\" (nftset.rs:67) that do not match real NFTA_* constants, and never sends them.\n\nExtending `build_nft_add_msg` is the wrong direction. A faithful port needs either FFI to libnftables or a spec-correct raw netlink client written from scratch.",
     ["`nftset_init` (nftset.c:31-39) has no equivalent",
      "`add_to_nftset` (:41-98) has no equivalent; no socket is ever opened",
      "Attribute type numbers do not correspond to real nftables netlink numbering",
      "No delete path — upstream's `remove` parameter selecting cmd_add vs cmd_del (:43) has no counterpart",
      "The `4 `/`6 ` set-name prefix stripping for `nftset=/domain/4#table.set,6#table.set` (:53-62) missing",
      "No error handling or logging of the libnftables error buffer (:82-95)"],
     ["Addresses are actually added to and removed from an nftables set",
      "Dual-family `4#`/`6#` syntax parses",
      "Failures are surfaced rather than silently dropped"]),

    ("ipset", "ipset.c: no socket, no send, no call sites", "high", "opus",
     "src/ipset.rs", "ipset.c",
     "Structurally the closer-to-correct of the two netlink modules — the ADD/DEL message direction is right, unlike conntrack.rs. But nothing sends it.",
     ["`ipset_init` (ipset.c:86-100) missing — no `socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)` or bind",
      "`add_to_ipset` (:192-214) public dispatcher missing; `build_ipset_msg` (:86) builds but never sends",
      "`old_add_to_ipset` (:151-188, kernels < 2.6.32) not ported — reasonable to mark explicitly N/A rather than silently omit",
      "No call sites anywhere; upstream calls `ipset_init` from dnsmasq.c:355 and adds addresses after each successful answer",
      "`parse_ipset_list` (:141) parses /proc/net/ip_set and has NO upstream counterpart — invented; document as such"],
     ["Resolved addresses are added to the configured ipset",
      "Capability-dependent tests are gated",
      "Invented functions are documented or removed"]),

    ("inotify", "inotify.c: only byte-parsing ported; watches never established", "medium", "sonnet",
     "src/inotify.rs", "inotify.c",
     "The module doc comment says it \"Mirrors the watch logic from dnsmasq's inotify.c\"; in fact only the byte-parsing helpers mirror anything. `parse_inotify_event`/`to_watch_event` have zero callers outside their own tests, and the crate's actual resolv.conf change detection is mtime polling (`dnsmasq::poll_resolv`, :534) regardless of whether the `inotify` feature is on.",
     ["`inotify_dnsmasq_init` (inotify.c:88-134) missing — no inotify_init1, no symlink following with MAXSYMLINKS guard (:107-114), no directory watches",
      "`set_dynamic_inotify` (:178-263) missing — no hostsdir/dhcp-hostsdir/dhcp-optsdir watches, no initial directory scan",
      "`inotify_check` (:265-370) missing — none of the cache_remove_uid/read_hostsfile/option_read_dynfile/dhcp_update_configs/lease_update_* cascade exists",
      "`--no-poll` has no real analog since resolv.conf detection always polls"],
     ["Changes to a watched hosts directory are picked up without SIGHUP",
      "`--no-poll` suppresses mtime polling",
      "The module doc comment matches what is implemented"]),

    ("log", "log.c: no real syslog output and no deadlock-avoidance queue", "medium", "sonnet",
     "src/log.rs", "log.c",
     "Reimplemented on `tracing` rather than porting the /dev/log Unix-socket protocol. The API shape is right; the wire behavior does not exist. Note this substitution is not harmless the way util.rs's SURF-PRNG-to-`rand` substitution is: it silently drops a deliberate deadlock protection.",
     ["No syslog crate dependency; `my_syslog` (:201) routes to tracing macros plus an optional file, so default syslog-to-/dev/log logging never happens",
      "The bounded async queue (log.c:23-28, 164-284, MAX_LOGS entries) exists specifically so that if syslogd blocks on a DNS lookup through dnsmasq, dnsmasq does not deadlock. `set_log_writer`/`check_log_writer` are documented no-ops (:258-268), removing that protection",
      "No reconnect-on-EPIPE/ECONNREFUSED/ENOTCONN logic (:221-276)",
      "`--log-facility` is parsed into `daemon.log_fac` but nothing calls openlog/syslog, so it is an accepted-but-ignored parameter"],
     ["Log output reaches the system syslog daemon by default",
      "`--log-facility` takes effect",
      "A blocked log sink cannot deadlock the daemon"]),

    ("util", "util.c: close_fds may close its own dirfd; kernel_version shells out", "low", "haiku",
     "src/util.rs", "util.c",
     "The most faithful file in the audit — nearly every function has a line-for-line equivalent with matching edge cases. Two small gaps.",
     ["`close_fds` (util.rs:435, upstream util.c:789-866): C explicitly excludes `dirfd(d)`, the fd used by the /proc/self/fd scan itself (:848). Rust (:445-462) has no equivalent and its comment admits \"we can't know it exactly, but it will be >= 3; just skip spares\" — it can close its own directory handle mid-iteration",
      "`kernel_version` (util.rs:569, upstream :906-921): C calls `uname(2)`. Rust spawns `Command::new(\"uname\")`, which costs a subprocess per call and silently returns 0.0.0 on musl/containers lacking the binary, where C's syscall never fails"],
     ["`close_fds` never closes the fd it is iterating with",
      "`kernel_version` uses the `uname` syscall directly"]),

    ("protocol-consts", "Protocol header completeness: status codes, ULA macros, RrType coverage", "low", "haiku",
     "src/dns_protocol/, src/dhcp6_protocol/, src/types/addr.rs",
     "dns-protocol.h, dhcp6-protocol.h, ip6addr.h",
     "Three small header-derived gaps grouped into one issue. `radv-protocol.h` is a complete 1:1 port with no gaps.",
     ["dhcp6-protocol.h:71-77: DHCP6SUCCESS/UNSPEC/NOADDRS/NOBINDING/NOTONLINK/USEMULTI have no Rust constants and are never referenced — consistent with rfc3315.rs never expressing a failure status",
      "ip6addr.h:24-27 `IN6_IS_ADDR_ULA_ZERO` and :29-32 `IN6_IS_ADDR_LINK_LOCAL_ZERO` have no Rust equivalent; needed by radv.c:479-501 and rfc3315.c:1342-1365. (`IN6_IS_ADDR_ULA` IS ported, as `network::is_ula_v6`, though it lives outside types/addr.rs)",
      "`RrType::from_u16` (dns_protocol/mod.rs:101-124) omits MD, MF, MB, MG, MR, MINFO, RP, AFSDB, RT, SIG, PX, NXT, KX, DNAME, TKEY, TSIG, MAILB — returns None where the variant exists"],
     ["All status codes and macros have Rust equivalents",
      "`RrType::from_u16` round-trips every declared variant"]),

    ("orphan-modules", "Decide the fate of orphaned modules: blockdata, outpacket, bpf", "low", "sonnet",
     "src/blockdata.rs, src/outpacket.rs, src/bpf.rs", "blockdata.c, outpacket.c, bpf.c",
     "Three modules that are complete or near-complete but referenced nowhere. Each needs a decision rather than more porting.\n\n`bpf.rs` is the odd one: upstream `bpf.c` is gated `#if defined(HAVE_BSD_NETWORK) || defined(HAVE_SOLARIS_NETWORK)` and implements BSD/Solaris routing-socket enumeration with no Linux relevance. Its true Linux analog is `netlink.rs`. `bpf.rs` instead builds classic-BPF `sock_filter` programs — a feature with no upstream counterpart at all (`grep sock_filter original_dnsmasq_src` returns zero hits) — and nothing applies them.",
     ["`blockdata.rs` is a complete, correct port with zero callers; decide whether DNSSEC key material should route through it or whether pooling was intentionally dropped in Rust",
      "`outpacket.rs` is complete with zero callers; wire into dhcp6.rs's packet building or document why not",
      "`bpf.rs` is unlabeled speculative code with no upstream justification and no call site; decide to use, document, or remove",
      "Future audits should compare bpf.c against netlink.rs, not bpf.rs"],
     ["Each module is either integrated or removed",
      "Any retained non-upstream code is documented as a deliberate addition"]),

    ("config-defaults", "Cargo feature defaults diverge from upstream config.h", "low", "haiku",
     "Cargo.toml", "config.h",
     "Feature-flag mapping is present and mostly mirrors HAVE_*. Numeric tuning constants were spot-checked against `Daemon::default` and found faithful (cachesize 150, ftabsize 150, max_logs 5, auth_ttl 600, soa_refresh 1200, soa_retry 180, soa_expiry 1209600).",
     ["Upstream defaults (config.h:185-192) enable HAVE_IPSET; Cargo.toml's default set omits `ipset`",
      "Cargo.toml enables `dnssec` by default; upstream leaves `HAVE_DNSSEC` commented out (config.h:206) since it needs an external crypto library",
      "No discrete `script` feature; helper.rs compiles unconditionally, so there is no way to build a script-free binary as config.h's NO_SCRIPT allows"],
     ["Default feature set matches upstream's default HAVE_* set, or divergences are documented",
      "A script-free build is possible"]),

    ("daemon-struct", "types/daemon.rs is missing fields for the unimplemented directives", "medium", "sonnet",
     "src/types/daemon.rs", "dnsmasq.h",
     "The OPT_* boolean-flag enum is essentially 1:1 (81/81 constants matched by name). The `struct daemon` port is partial, and the gap tracks the option.c gaps mechanically rather than being an independent modeling failure — closing T2-3/T2-4 requires adding these fields in tandem.",
     ["Missing from types/daemon.rs (vs dnsmasq.h:1167-1354): `tag_if`, `dhcp_match`, `dhcp_match6`, `dhcp_name_match`, `dhcp_pxe_vendors`, `pxe_services`, `shared_networks`, `bridges`, `synth_domains`/`cond_domain`, `umbrella_org`/`asset`/`device`, `override_relays`, `force_broadcast`, `bootp_dynamic`, `enable_pxe`, `doing_ra`, `doing_dhcp6`",
      "`relay4`/`relay6` DO exist (:159, :164) with a modeled DhcpRelay type, but nothing populates them — the data model is ahead of the parser"],
     ["Every field backing an implemented directive exists and is populated",
      "Fields are added alongside the parser work rather than ahead of it"]),

    ("tables", "tables.c: BSD PF ipset support is stubbed to always return NotSupported", "low", "sonnet",
     "src/tables.rs", "tables.c",
     "Upstream is BSD-PF ipset support gated `#if defined(HAVE_BSD_IPSET)` (tables.c:21), implementing real ioctl(2) calls against /dev/pf. The Rust port returns `Err(PfError::NotSupported)` on every platform — including inside the `#[cfg(target_os = \"openbsd\")]` branch (tables.rs:38-44), which is present but issues no ioctl.\n\nGiven dnsmasq-rs targets Linux (netlink, if-addrs), this is low practical priority — but it should be an explicit documented N/A rather than a silent always-error stub.",
     ["Entire ioctl-based table/address add/remove logic (tables.c:55-141) unimplemented",
      "The openbsd cfg branch exists but returns NotSupported without attempting anything"],
     ["Either real pf ioctl support, or an explicit documented decision that BSD is out of scope",
      "The misleading openbsd cfg branch is removed if BSD is out of scope"]),
]

for _t in _T3:
    ISSUES.append(dict(
        key=f"T3-{_t[0]}", tier=3, risk=_t[2], model=_t[3],
        title=_t[1], port_file=_t[4],
        upstream_file=" ,".join(f"{UPSTREAM}/{b.strip()}" for b in _t[5].split(",")),
        summary=_t[6], gaps=_t[7], acceptance=_t[8], blocked_by=[],
    ))
