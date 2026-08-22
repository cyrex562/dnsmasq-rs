# Parity Harness

This directory contains the container-backed parity harness for larger milestone validation runs.

Current scope:

- Phase 1: DNS parity only
- Two containers:
  - upstream `dnsmasq`
  - current `dnsmasq-rs`
- One host-side probe:
  - `cargo run --bin parity_probe`

The goal is to make major feature-set validation reproducible without requiring a third probe container or external Python packages.

## Layout

- `compose.major.yaml`
  Starts upstream and Rust dnsmasq instances on isolated host ports.

- `docker/`
  Container build definitions for the upstream and Rust services.

- `fixtures/dns/`
  DNS-only fixture sets, one directory per scenario. Each directory has a
  `dnsmasq.conf` and a `queries.txt` (`<name> <qtype>` per line); both
  daemons are started with the same config and probed with the same queries.
  - `basic/` — host/CNAME/TXT/MX/SRV/PTR records, one query per type.
  - `negative/` — NXDOMAIN and NODATA shape: unknown names, an unregistered
    subdomain of a known name, and a known name queried for a type it
    doesn't have.
  - `local-block/` — `--address=/domain/ip`, `--address=/domain/#` (NULL
    address), `--address=/domain/`/`--server=/domain/` with no address
    (block, NXDOMAIN), and `--address=/#/ip` (wildcard catch-all) versus a
    more specific `host-record` overriding the wildcard.
  - `cname-chain/` — a 3-hop CNAME chain terminating on an A record, plus a
    1-hop CNAME to a name with no data (NODATA past the alias).

- `run-major.sh`
  Builds the services, starts them, runs the probe against one fixture
  (`FIXTURE=<name>`, default `basic`), and reports mismatches.

- `run-suite.sh`
  Builds the services once, then runs every fixture directory under
  `fixtures/dns/` in turn, printing a pass/fail summary at the end. Use this
  to check parity broadly; use `run-major.sh` for one fixture at a time
  (e.g. while iterating on a fix).

## First Use

Run the whole suite:

```bash
./parity/run-suite.sh
```

Or a single fixture:

```bash
./parity/run-major.sh
```

Environment overrides:

- `FIXTURE=basic`
- `UPSTREAM_PORT=2053`
- `CANDIDATE_PORT=3053`
- `PARITY_STARTUP_WAIT_SECS=3`
- `KEEP_CONTAINERS=1`

Example:

```bash
UPSTREAM_PORT=2053 CANDIDATE_PORT=3053 ./parity/run-major.sh
```

## What This Does

1. Builds an upstream dnsmasq image from the vendored source tree.
2. Builds a `dnsmasq-rs` image from the current repository.
3. Starts both with the same fixture config mounted read-only.
4. Sends the same DNS queries to each.
5. Parses and normalizes replies using repo-local Rust code.
6. Fails if the normalized replies differ.

## Current Limitations

- This is a scaffold for milestone validation, not full CI yet.
- The initial fixture set is DNS-only.
- DHCP, DHCPv6, RA, and interface-sensitive behavior are intentionally out of scope for this first harness version.
- The current codebase is not expected to pass all future parity suites yet.

## Next Expansion Points

- Add fixtures for cache TTL decay and reload (`SIGHUP`) behavior — needs the
  probe to send repeated, time-spaced queries and compare TTL trends rather
  than a single snapshot; the current probe only does one query per case.
- Add a forwarding fixture — needs a third "fake upstream" container the
  `server=` directive can point at, since every fixture today is `no-resolv`
  (self-contained, no real network dependency).
- Add a DHCP harness with Docker capabilities such as `NET_ADMIN` and `NET_RAW`.
- Add a VM-backed lane only for cases that truly need fuller kernel or distro behavior.
