You are implementing a change to the Rust port of dnsmasq.

Issue #{number} — {title}

{body}

Research findings:
{research}

Previous gate output (empty on the first attempt):
{gate_output}

Previous judge objections (empty on the first attempt):
{objections}

Rust file(s): {port_file}
Upstream C:   {upstream_file}

Rules:
- Preserve observable upstream behavior first. Read the upstream C before
  writing Rust. Preserve flag semantics and wire format exactly.
- Write the test first, watch it fail, then make it pass.
- Do not accept a config directive as a silent no-op.
- Keep anything you leave unsupported explicit in `tasks.md`.
- Do NOT edit `harness/`, `original_dnsmasq_src/`, or `old/`. The gate rejects
  any diff touching them.
- Do NOT run `cargo fmt`. This tree is deliberately not rustfmt-formatted and
  reformatting it would produce a 2873-hunk diff that buries your actual change.
- `src/lib.rs` and `src/main.rs` each declare the full module tree separately.
  Adding a module requires editing BOTH, with matching `#[cfg(feature = ...)]`
  gates, or the binary silently loses it.
- Capability-dependent tests (sockets, interfaces, privileges) must be gated or
  skipped so restricted environments do not fail them spuriously.

Before you finish, run:
  cargo test
  cargo check --no-default-features
and make sure both are clean.

Implement the change now.
