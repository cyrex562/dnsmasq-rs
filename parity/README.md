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

- `fixtures/dns/basic/`
  Initial DNS-only fixture set:
  - `dnsmasq.conf`
  - `queries.txt`
  - `hosts.empty`
  - `resolv.empty`

- `run-major.sh`
  Builds the services, starts them, runs the probe, and reports mismatches.

## First Use

Run:

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

- Add more DNS fixture directories for cache, reload, and forwarding behavior.
- Add a DHCP harness with Docker capabilities such as `NET_ADMIN` and `NET_RAW`.
- Add a VM-backed lane only for cases that truly need fuller kernel or distro behavior.
