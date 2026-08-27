# zones.d — Dynamic DNS Zone Directory — Design

Date: 2026-08-27
Status: Approved for planning
Repo: `cyrex562/dnsmasq-rs`

## Problem

`dnsmasq-rs` is a Rust port of upstream `dnsmasq`, targeting behavioral parity with the
supported feature set (see `CLAUDE.md`). This feature has **no upstream counterpart** — it is
a dnsmasq-rs-specific extension, filed as issue #177 during the "reload while running" (#128)
scoping discussion but explicitly deferred as architectural-scale work.

Today, local DNS answer data (`host-record`, `cname`, `txt-record`, `srv-host`, `mx-host`,
`naptr-record`, `ptr-record`, `address=/domain/ip`) can only be added via the main config file
or `conf-dir` — both read once at startup. Adding, editing, or removing a "zone's" worth of
local DNS records at runtime requires a full process restart. The user wants to organize and
load such records the way nginx organizes site configs (a directory of independent fragment
files) and the way BIND/CoreDNS load zones (files that can be added/changed without restarting
the whole server) — but reusing dnsmasq-rs's own existing directive syntax and config-parsing
pipeline, not a new RFC 1035 zone-file parser.

Issue #177 originally bundled this with a second, harder idea — `networks.d` for dynamically
adding whole DHCP pools. That idea is **out of scope for this spec** (see Non-goals) and will
be filed as its own follow-up issue once/if it gets its own design pass.

## Non-goals

- **`networks.d` / dynamic DHCP pools.** A new `dhcp-range` on an interface not already bound
  needs a new listening socket, and this codebase binds all sockets before dropping root
  privileges at startup (`main.rs`: `bind_listeners` before `drop_privileges_with`, both
  complete before the main loop or any reload machinery runs). That's a fundamentally
  different, harder problem than the DNS-only feature this spec covers, and was explicitly
  descoped by the user during brainstorming.
- **RFC 1035 zone-file format.** No `$ORIGIN`/`$TTL`/SOA-and-friends presentation-format
  parser. A zone file is dnsmasq-rs directive syntax; "one file = one zone" is an
  organizational convention, not a new content format.
- **BIND-style domain auto-scoping ($ORIGIN).** Records inside a zone file use the same
  fully-qualified names as anywhere else in dnsmasq-rs config. The filename carries no special
  parsing meaning.
- **Zone-of-authority semantics** (SOA records, zone transfers, NOTIFY, authoritative-vs-cache
  distinctions). "Zone" here means "an independently loadable file of local DNS answer
  directives," not a DNS-protocol concept. (dnsmasq-rs's existing `--auth-zone` machinery,
  where it exists, is unrelated and untouched by this feature.)
- **Arbitrary directives in a zone file.** Deliberately restricted to a fixed allowlist (see
  below) so a zone file cannot reconfigure listening addresses, DHCP behavior, logging, or
  anything outside "local DNS answer data."

## Directive & config surface

New repeatable directive: **`zones-dir=<path>`** (mirrors `--hostsdir`/`--dhcp-hostsdir`'s
existing multi-instance convention — it may be given more than once). Every file directly
inside each configured directory is a candidate zone file, subject to the same skip rules
`conf-dir` already uses: dotfiles and `~`-suffixed backup names are ignored; no required
extension.

## Allowed directives

A zone file may contain only:

- `host-record`
- `cname`
- `txt-record`
- `srv-host`
- `mx-host`
- `naptr-record`
- `ptr-record`
- `address` (the `=/domain/ip` local-answer form)

Any other directive encountered in a zone file is a parse error for that file (see Error
handling). Each allowed directive is dispatched to the **same per-directive parser function**
`option.rs`'s normal `apply_line` already uses — no new parsing code is written for this
feature, only a new, narrower dispatcher that accepts a fixed subset of keys and writes into a
different destination.

## Data model

```rust
/// Aggregate of local DNS answer data loaded from every currently-present
/// file across every configured `--zones-dir`. Rebuilt wholesale on any
/// change; never mutated incrementally. Field types match the corresponding
/// `Daemon`/`LocalData` fields exactly.
#[derive(Debug, Clone, Default)]
pub struct ZonesDRecords {
    pub host_records:        Vec<HostRecord>,
    pub cnames:               Vec<Cname>,
    pub txt_records:          Vec<TxtRecord>,
    pub mx_records:           Vec<MxSrvRecord>,   // mx-host and srv-host both land here
    pub naptr_records:        Vec<Naptr>,
    pub ptr_records:          Vec<PtrRecord>,
    pub address_server_list:  Vec<crate::types::server::Server>,
}
```

Lives at `Daemon.zones_d: ZonesDRecords`, plus `Daemon.zones_dirs: Vec<String>` (or reuses the
existing `HostsFile`-style dynamic-dir list shape already used for `--hostsdir`, if that type
fits without modification — an implementation-time decision, not a design one).

`ZonesDRecords` deliberately carries **no per-entry provenance tag**. Unlike the
`ConfigFlags::BANK` pattern (`reread_dhcp`, issue #175), which clears-and-re-derives only
flagged entries inside a Vec shared with directly-configured ones, `ZonesDRecords` is a wholly
separate aggregate that gets replaced in full on every rescan — there is nothing to
selectively retain, so no flag is needed. This was chosen over the flag-based approach
(Approach B, considered and rejected — see Alternatives) specifically to avoid touching
`HostRecord`/`TxtRecord`/`MxSrvRecord`/`NaptrRecord`/`PtrRecord`'s existing shapes.

## Loading model

On startup, and on any watched-directory change:

1. List every file directly inside every configured `--zones-dir`, applying the skip rules
   above.
2. For each remaining file, in isolation: parse it into `ConfigLine`s the normal way
   (`parse_config_text`), then dispatch each line through the new allowlist-restricted
   applier. A file that produces even one disallowed-directive or parse error is dropped
   entirely from this rescan (see Error handling) — partial application of a single bad file
   is not attempted.
3. Aggregate every successfully-parsed file's records into one fresh `ZonesDRecords`.
4. Replace `daemon.zones_d` with the fresh aggregate, wholesale.

This is a full rescan of the whole `zones-dir` set on any single-file change, not an
incremental per-file diff — matching the precedent already set by `--hostsdir` reload
(`cache::reload_hosts` flushes and rebuilds the entire `F_HOSTS` cache on any hit, not just the
changed file). Zone counts are expected to be small enough (local DNS answer data, not an
internet-scale zone set) that this is cheap in practice; if that assumption turns out wrong in
practice, a later optimization can special-case "exactly one file changed" without changing the
public shape of `ZonesDRecords`.

## Watch integration

Reuses `inotify.rs`'s existing dynamic-directory watch primitive — the same one already
watching `--hostsdir`/`dhcp-hostsdir`/`dhcp-optsdir` — rather than building new watch
infrastructure. `--zones-dir` registers as a new watched-directory kind alongside the existing
`AH_HOSTS`/`AH_DHCP_HST`/`AH_DHCP_OPT` cases; an `IN_CLOSE_WRITE`/`IN_MOVED_TO`/`IN_DELETE` hit
on a zones-dir triggers the rescan described above instead of `cache::load_hosts_file`. The
initial scan at startup (`set_dynamic_inotify`'s existing "watch then initial-scan" step) covers
zones-dir the same way it already does for `--hostsdir`.

## Merge point (reaching live query answering)

`dnsmasq::daemon_local_data(daemon: &Daemon) -> LocalData` is the single existing function that
builds the `LocalData` the forward loop answers queries from, called from `daemon_forward_config`
and re-invoked on every reload tick (issue #174's `SharedForwardConfig` plumbing already
delivers a fresh `LocalData` to the *live* forward loop every second; no new delivery mechanism
is needed for this feature). Each `zones_d` field is chained onto its directly-configured
counterpart at the point `daemon_local_data` currently does a plain `.clone()`:

```rust
host_records:  daemon.host_records.iter().chain(daemon.zones_d.host_records.iter()).cloned().collect(),
cnames:        daemon.cnames.iter().chain(daemon.zones_d.cnames.iter()).cloned().collect(),
txt_records:   txt_records.into_iter().chain(daemon.zones_d.txt_records.iter().cloned()).collect(),
mx_records:    daemon.mxnames.iter().chain(daemon.zones_d.mx_records.iter()).cloned().collect(),
naptr_records: daemon.naptr.iter().chain(daemon.zones_d.naptr_records.iter()).cloned().collect(),
ptr_records:   daemon.ptr.iter().chain(daemon.zones_d.ptr_records.iter()).cloned().collect(),
// address_server_list/address_servers: append zones_d's entries to literal_servers(daemon)'s
// output before ServerArray::build, same idea, one extra step since that field is
// function-derived rather than a plain clone.
```

No other part of the forward loop, cache, or reply path needs to know zones.d exists — from
`daemon_local_data`'s output onward, zone-sourced and directly-configured local data are
indistinguishable, which is the intended behavior (a zone-sourced `host-record` answers exactly
like any other).

## Error handling

- A zone file containing a disallowed directive, or a directive that fails to parse under its
  existing per-directive parser, is logged (file path + reason) and **excluded from the current
  aggregate** — not partially applied, not left at its last-good state. If a previously-good
  file is edited into a broken state, its records disappear from live answers until it's fixed.
  This was chosen deliberately over caching last-known-good content: the aggregate should always
  reflect what's actually parseable in the directory right now, not a stale mix.
- Other files in the same rescan are unaffected by one file's failure.
- A configured `--zones-dir` that doesn't exist or isn't readable is logged once (matching
  `inotify_dnsmasq_init`'s existing "log and continue" convention for a missing resolv
  directory) rather than treated as a fatal startup error.

## Alternatives considered

- **Approach B — tag-and-filter (`ConfigFlags::BANK`-style).** Add a "zone-sourced" flag
  directly to `HostRecord`/`TxtRecord`/`MxSrvRecord`/`NaptrRecord`/`PtrRecord` and push
  zones.d entries into the *same* Vecs `Daemon` already has, tagged; rescanning does
  `retain(|r| !r.flags.contains(ZONE_SOURCED))` then re-adds. Rejected because it requires
  adding a new field to five existing record-type structs (larger diff surface, touches code
  well outside this feature) for no benefit over Approach A once `daemon_local_data` is
  already the single merge point everything flows through.
- **Approach C — full re-resolve.** Re-run `resolve_config`/`normalize_config` against the
  main conf-file's lines plus every zone file's lines combined, on every zones.d change.
  Rejected: `normalize_config` performs one-time-style default-filling (DNSSEC fast-retry
  defaults, local-TTL fill-in) that isn't verified idempotent against already-normalized live
  state, and re-resolving the *entire* daemon configuration for a small, scoped directory
  change is disproportionate to what the feature needs.
- **BIND-style `$ORIGIN` auto-scoping and real zone-file format** were both raised and declined
  by the user during brainstorming — see Non-goals.

## Testing strategy

- Unit tests on the new allowlist dispatcher: each of the 8 allowed directives parses into the
  correct `ZonesDRecords` field; a disallowed directive (e.g. `dhcp-range`, `listen-address`)
  is rejected with a clear error; a malformed value for an allowed directive is rejected the
  same way its normal `apply_line` counterpart would be.
- Unit tests on the rescan/aggregation function: multiple valid files aggregate correctly; one
  bad file among several doesn't block the others; a file removed from the directory drops its
  records from the next aggregate; an empty/nonexistent `--zones-dir` produces an empty
  aggregate rather than an error.
- Integration test: real `--zones-dir` through `init_daemon_with`/`run_main_loop_with`
  startup, then a live add/edit/delete of a zone file via real inotify (mirroring the existing
  `--dhcp-hostsfile` reload integration tests), asserting DNS answers over loopback change
  accordingly with no restart and no explicit reload trigger needed.
