# networks.d — Dynamic DHCP Pool Directory — Design

Date: 2026-08-28
Status: Approved for planning
Repo: `cyrex562/dnsmasq-rs`

## Problem

Issue #182 (split from #177 during that issue's brainstorming): dnsmasq-rs's DHCP side has no
way to add a new `dhcp-range` pool at runtime without a full process restart, even though
issue #179 already made the *data* inside an existing pool (`dhcp-host`/`dhcp-option` entries)
live-reloadable. No upstream counterpart — this is a dnsmasq-rs-specific extension, following
the same "watched directory of directive-syntax fragment files" pattern issue #177's `zones.d`
already shipped for DNS.

The obstacle #177's brainstorming identified: a `dhcp-range` on an interface the daemon isn't
already listening on needs a new listening socket, and this codebase binds all sockets before
dropping root privileges at startup, before any reload machinery exists.

**Correction made during this issue's own brainstorming, worth recording:** that obstacle is
narrower than #177's Non-goals section implied. `daemon_dhcp_runtime` (`src/dnsmasq.rs:989`)
binds a *single* DHCPv4 socket, defaulting to the wildcard address `0.0.0.0:67` unless an
explicit `--interface=`/`--listen-address=` restricts it to a specific device via
`SO_BINDTODEVICE` (`bind_dhcp_socket_to_device`, called conditionally in `spawn_dhcp_task`).
When no such restriction is configured — the common case — the existing socket already
receives DHCP traffic from *every* local interface. Separately, a `dhcp-relay=`-reached pool
never needs a new local socket at all: relayed traffic arrives unicast at the server's existing
bound address regardless of which remote subnet the client is on. So "new pool needs a new
socket" is only true for a *directly-attached, non-relayed* subnet on an interface the existing
bind can't receive from — confirmed by the user during brainstorming as an accepted, inherent
limitation of direct (non-relay) DHCP, not an artifact of this port.

## Non-goals

- **A genuinely new local (non-relayed) subnet on an interface the existing socket bind can't
  receive from** — e.g. the daemon was started with `--interface=eth0` and a new pool targets
  `eth1`. This needs an actual new privileged socket bind, unavailable post-privilege-drop, and
  still requires a restart. Documented as a known, accepted limitation (see Problem).
- **DHCPv6 pools.** `parse_dhcp_range` (`option.rs:3880`) is IPv4-only (requires two parseable
  `Ipv4Addr`s); DHCPv6 range/prefix configuration is a separate concern with its own RA/prefix
  machinery, out of scope here.
- **RFC-format zone/network files.** Same as #177: a network fragment file is dnsmasq-rs
  directive syntax, not a new file format.
- **Reachability validation at load time.** A new pool for a subnet the daemon genuinely can't
  reach (interface down, wrong relay config, typo) is not detected or rejected at parse time —
  it simply never matches an arriving packet's subnet at dispatch, the same silent no-op a
  statically-configured unreachable pool already produces today. Building reachability
  detection that's actually correct (interfaces come and go; relays are deliberately off-link)
  is its own hard problem, not attempted here.
- **`dhcp-boot`, `dhcp-vendorclass`, `dhcp-userclass`, `dhcp-mac`, `tag-if`, and other
  DHCP-adjacent directives** not named in the allowlist below. Can be added to the allowlist
  later the same way any single directive was added to `zones.d`'s, if wanted — deliberately
  starting narrow (see the allowlist below) rather than including everything DHCP-adjacent
  `option.rs` supports.

## Directive & config surface

New repeatable directive: **`networks-dir=<path>`** (mirrors `--zones-dir`'s convention). Every
file directly inside each configured directory is a candidate "network" fragment file, subject
to the same skip rules `conf-dir`/`zones-dir` already use (dotfiles, `~`-suffixed backups
ignored; no required extension).

## Allowed directives

A network file may contain only:

- `dhcp-range` — the pool itself (`option::parse_dhcp_range`).
- `dhcp-relay` / `dhcp-split-relay` — relay associations (`option::parse_dhcp_relay`).
- `dhcp-host` — static reservations (`option::parse_dhcp_host`, already used by `zones.d`'s
  sibling subsystem, `reread_dhcp`'s bank-file reader from issue #175 — same parser, different
  destination).
- `dhcp-option` — options, typically tag-scoped to the new pool via `dhcp-range`'s `set:`
  netid (`option::parse_dhcp_option`).

Any other directive is a parse error for that file, handled the same way `zones.d` handles one
(see Error handling): the whole file is dropped from the current rescan, other files
unaffected.

## Data model

```rust
/// The DHCP-pool analog of `zones_d::ZonesDRecords` (issue #182, following
/// issue #177's pattern): everything a `--networks-dir` fragment file can
/// contribute. Rebuilt wholesale from every currently-present file across
/// every configured `--networks-dir` on any directory change.
#[derive(Debug, Clone, Default)]
pub struct NetworksDRecords {
    pub contexts:  Vec<crate::types::dhcp::DhcpContext>,
    pub relay4:    Vec<crate::types::dhcp::DhcpRelay>,
    pub configs:   Vec<crate::types::dhcp::DhcpConfig>,
    pub dhcp_opts: Vec<crate::types::dhcp::DhcpOpt>,
}
```

Unlike `zones.d`, this does **not** live on `Daemon` — `DhcpServerConfig`'s reload path is
already fully decoupled from `Daemon` (that decoupling is the point of issue #179's
`SharedDhcpReloadConfig`: `run_dhcp_loop` never touches `Daemon` directly). `NetworksDRecords`
is merged directly into `DhcpReloadConfig` (see Merge point) rather than needing its own
`Daemon` field and a second merge step the way `zones_d`'s did.

## Loading model

Same rescan semantics as `zones.d`'s, but wired differently (see Merge point for why): a pure
function, `fn networks_d_records(daemon: &Daemon) -> NetworksDRecords`, lists every file in
every `daemon.dynamic_dirs` entry flagged `DynDirFlags::NETWORKS` (skip-rules applied), parses
each file in isolation and whole-file-atomically (one bad directive or malformed value drops
that file entirely, not partially), and aggregates every successfully-parsed file's contents
into one fresh `NetworksDRecords` — no partial state, no incremental mutation. Directly
unit-testable given a `Daemon` with `dynamic_dirs` configured, the same way `zones_d`'s own
rescan function is tested. Unlike `zones_d::rescan_zones_dirs`, this isn't itself the thing
callers invoke on a directory change — `daemon_dhcp_reload_config` calls it as one step of
building a `DhcpReloadConfig` (see Merge point), so there's a single call site for both startup
and every reload trigger, rather than one function serving as its own top-level entry point
from multiple, easy-to-miss call sites.

## Relay `iface_index` fixup

`daemon_dhcp_runtime` (`src/dnsmasq.rs:989-1013`) does one piece of startup-only post-processing
on `daemon.relay4` that a live-added relay entry needs too: for each non-split-mode relay whose
`local_addr` matches the bound interface's address, it sets `relay.iface_index` — without it,
`relay_upstream4`'s `relay.iface_index != 0` dispatch guard never matches and the relay silently
never fires (`dhcp.c:669-673`'s `complete_context` equivalent). The reload path (see Merge
point) must call the same fixup — reusing `first_ipv4_listen_addr`/`first_bind_interface`
(`src/dnsmasq.rs`, currently private, need `pub(crate)`) against the *current* `Daemon` state,
not the value snapshotted at startup — for every relay in the merged `relay4` list, not just
ones sourced from `networks.d`, since `daemon.relay4` itself could also have changed via a
plain reload (issue #175's `reread_dhcp`-adjacent paths don't currently touch `relay4`, but the
fixup should run over the merged list regardless, for correctness independent of source).

## Merge point

Extends `DhcpReloadConfig` (`src/dnsmasq.rs`, issue #179) with two new fields:

```rust
pub struct DhcpReloadConfig {
    // ... existing configs, dhcp_opts, generation ...
    #[cfg(feature = "dhcp")]
    pub contexts: Vec<crate::types::dhcp::DhcpContext>,
    #[cfg(feature = "dhcp")]
    pub relay4:   Vec<crate::types::dhcp::DhcpRelay>,
}
```

`daemon_dhcp_reload_config` (`src/dnsmasq.rs`, issue #179) is the single function that builds a
fresh `DhcpReloadConfig` from `Daemon` — called from *both* `resolve_run_config` (startup,
before the forward/DHCP tasks ever spawn) and `clear_cache_and_reload` (every SIGHUP/API/DBus/
resolv-hit/conf-file-hit reload). Extending this one function to also fold in `networks_d_records
(daemon)`'s output (see Loading model) — start from `daemon.dhcp.clone()`/`daemon.relay4.clone()`
(today's statically-configured contexts/relays, preserving current behavior when no
`networks.d` is configured at all), extend with `networks_d_records(daemon)`'s
`contexts`/`relay4`/`configs`/`dhcp_opts` (parsed fresh on every call — same "always re-derive,
never cache" philosophy `daemon_dhcp_reload_config` already applies to
`daemon.dhcp_conf`/`dhcp_opts`), then run the `iface_index` fixup over the combined `relay4`
list — automatically covers *both* the startup case and every reload trigger with no separate
wiring. This deliberately avoids the class of bug `zones.d` had to patch after the fact
(issue #177's postmortem): `Daemon.zones_d` was built through two disconnected code paths
(`init_daemon_with`'s special early call for startup, `inotify_check`'s rescan for live
updates), which is exactly why the startup one had to be added separately once the gap was
found. Folding `networks.d` into the one function every DHCP-reload-config build already
funnels through sidesteps that whole failure mode from the start.

`run_dhcp_loop`'s existing reload tick (`src/dhcp.rs:1585`, issue #179) gains two lines
alongside its existing `cfg.configs = fresh.configs; cfg.dhcp_opts = fresh.dhcp_opts;`:

```rust
cfg.contexts = fresh.contexts;
cfg.relay4   = fresh.relay4;
```

No other part of `run_dhcp_loop`'s dispatch needs to change — `narrow_context`,
`relay_reply4`/`relay_upstream4`, and every other consumer of `cfg.contexts()`/`cfg.relay4`
already reads whatever's currently in `cfg`, since that's exactly the mechanism issue #179
built for `configs`/`dhcp_opts`.

`DhcpServerConfig`'s own top-level `pool_start`/`pool_end`/`server_ip` fields (the "primary
pool" fallback used only when `cfg.contexts()` is empty, via `synthetic_pool_context`) are
**not** touched by this reload — they stay startup-only, matching #179's existing comment
("pool bounds... startup-only... a reload must not touch"), since `cfg.contexts()` being
non-empty already bypasses that fallback entirely once any pool (static or `networks.d`-sourced)
exists.

## Watch integration

Reuses the same `inotify.rs` dynamic-directory watch as `zones.d` and `--hostsdir` before it —
a new `DynDirFlags::NETWORKS` watched-kind alongside `ZONES`/`HOSTS`/`DHCP_HST`/`DHCP_OPT`.

Unlike `zones.d`'s hit handling (which runs its rescan *synchronously inside* `inotify_check`,
since it only touches `&mut Daemon`/`&mut DnsCache` — locks the caller already holds),
`networks.d`'s rescan needs to lock `SharedDhcpReloadConfig`, a separate `Arc<Mutex<_>>` that
`inotify_check` (`fn inotify_check(daemon: &mut Daemon, cache: &mut DnsCache) -> InotifyHits`,
currently fully synchronous) has no access to and can't acquire without becoming `async` itself
— a much bigger, more invasive signature change than this feature needs. Instead, this follows
the *other* existing pattern already in this file — the one `hits.resolv`/`hits.conf_file` use:
`InotifyHits` gains a plain `networks_dir: bool` flag, set synchronously inside `inotify_check`
exactly like the other three hit flags (no new params, no `async`), and the actual rescan runs
in `watch_inotify_changes` *after* `inotify_check` returns, where an async context and every
shared handle (`daemon_handle`, `dhcp_reload`) already exist:

```rust
if hits.networks_dir {
    push_fresh_dhcp_reload_config(&daemon_handle, &dhcp_reload).await;
}
```

`push_fresh_dhcp_reload_config` is the `dhcp_reload` analog of `push_fresh_forward_config`
(issue #177's own live-reload-gap fix, `src/inotify.rs`): read-lock `daemon_handle`, call the
now-`networks.d`-aware `daemon_dhcp_reload_config(&d)` (see Merge point — this already includes
the current `networks.d` state, plus a `generation` bump matching every other write to this
struct, issue #180), release the read lock, then replace `*dhcp_reload.lock().await`. No
separate rescan function needed — the same builder both the startup path and every full reload
already use is already `networks.d`-aware. This is a genuinely *lighter* fix than `zones.d`'s
own `push_fresh_forward_config` needed to be: it's still deliberately *not* the full
`clear_cache_and_reload` (a `--networks-dir` is meant to be touched somewhat dynamically too,
and flushing the entire DNS cache plus rereading resolv/hosts on every DHCP pool edit would be
an unrelated, avoidable cost — same reasoning as `zones.d`'s), but unlike that fix, there's no
second bug class to guard against here, since `daemon_dhcp_reload_config` was never split
across two disconnected code paths the way `Daemon.zones_d` was.

## Error handling

Identical philosophy to `zones.d`: a bad network file is logged and dropped entirely from the
current rescan; other files in the same rescan are unaffected; a missing/unreadable
`--networks-dir` is logged once and skipped, not fatal.

## Alternatives considered

- **Folding this into `zones.d`'s own directory/directive**, widening its allowlist to also
  accept DHCP directives. Rejected: mixes two concerns the original issue's own naming
  (`zones.d` vs `networks.d`) already kept conceptually separate, and would couple DNS's #174
  reload tick to DHCP's #179 one for no benefit.
- **Fully rebuilding `DhcpDaemonRuntime`** (including `bind_addr`/the bound socket) on every
  `networks.d` change. Rejected: the bound socket is fundamentally startup-only for the life of
  `run_dhcp_loop` — recomputing it is both unnecessary (only `contexts`/`relay4` need to
  change) and contradicts this issue's own scope decision to explicitly exclude the
  new-socket case.
- **Solving the new-socket-for-a-new-local-interface case too** (e.g. retaining
  `CAP_NET_BIND_SERVICE` across the privilege drop, or re-exec-based re-privileging). Considered
  and explicitly descoped during brainstorming — see Non-goals.

## Testing strategy

- Unit tests on the new allowlist dispatcher (mirroring `zones_d::apply_zone_directive`'s test
  shape): each of the 4 allowed directives parses into the correct `NetworksDRecords` field; a
  disallowed directive is rejected; a malformed value is rejected.
- Unit tests on `networks_d_records`: multi-file aggregation, bad-file isolation, deleted-file
  removal, dotfile/backup skipping, missing-directory handling — same shape as
  `zones_d::rescan_zones_dirs`'s existing test suite.
- Unit test on `daemon_dhcp_reload_config`: with a `--networks-dir` configured, its output's
  `contexts`/`relay4`/`configs`/`dhcp_opts` include both the statically-configured entries and
  `networks_d_records`'s contribution.
- Unit test on the relay `iface_index` fixup: a `networks.d`-sourced non-split-mode relay whose
  `local_addr` matches the bound interface gets a nonzero `iface_index` after the merge; a
  split-mode relay is left untouched (matching `daemon_dhcp_runtime`'s existing behavior
  exactly).
- Integration test: real `--networks-dir` through `run_main_loop_with` startup, then a live
  add of a `dhcp-range` fragment file via real inotify, confirming a DHCPDISCOVER on the new
  pool's subnet gets an OFFER from it — with no restart, no SIGHUP — mirroring `zones.d`'s own
  live smoke test methodology (issue #177's postmortem: verify end-to-end with a real running
  loop, not just unit tests against `Daemon`/config-building functions in isolation, since that
  is exactly the class of gap `zones.d`'s own verification pass caught).
