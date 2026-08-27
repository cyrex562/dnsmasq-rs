# agents.md

## Project Context

This repository is a Rust port of the upstream `dnsmasq` binary. The goal is behavioral parity for the supported feature set, not merely compiling modules with similar names.

Primary references:

- Upstream C source: not vendored in this repo (removed, issue #169 — this project is a
  derivative work of GPL-licensed dnsmasq; see `NOTICE.md`) — clone
  `http://thekelleys.org.uk/git/dnsmasq.git` externally to read it, do not re-vendor it
- Earlier Rust attempt: `old/`
- Central tracker: `tasks.md`
- Project overview and test expectations: `CLAUDE.md`

The `old/` tree is reference-only.

## Core Rule

Port observable behavior first. Do not claim progress from line counts, module presence, or broad API similarity alone. A port is only complete when the Rust implementation behaves like upstream under unit, property-based, and black-box parity tests.

## Agent Roles

### Porting Agent

Goal:

- Translate upstream behavior into safe Rust while preserving semantics.

Process:

1. Read the upstream C implementation for the target behavior.
2. Read the current Rust module and identify gaps, simplifications, and stubs.
3. Port the next coherent behavior slice end to end.
4. Add or update tests before marking the slice complete.
5. Verify the behavior with the strongest available test layer:
   - unit tests
   - property tests where invariants apply
   - parity fixtures if the behavior is externally observable

Priority areas:

1. `src/option.rs`
2. `src/dnsmasq.rs` and `src/main.rs`
3. Runtime listener and socket behavior in `src/network.rs`, `src/forward.rs`, and `src/dhcp_common.rs`
4. Config-driven DHCP and local DNS data behavior
5. Remaining feature-gated integrations

### Testing Agent

Goal:

- Prove that the Rust port matches upstream behavior and remains robust under malformed input.

Process:

1. Identify the behavior under test and whether it is internal logic or externally observable.
2. Prefer the strongest useful test form:
   - unit tests for deterministic logic
   - property tests for parsers, encoders, invariants, and panic-freedom
   - black-box parity tests for executable behavior
3. Add regression coverage for every bug or parity mismatch found.
4. Keep environment-sensitive tests isolated from pure logic tests.

Required test patterns:

- Happy path
- Boundary or edge cases
- Invalid or malformed input
- Error path if `Result` is returned
- Property tests for protocol parsing or roundtrip invariants where applicable
- Fixture-based parity tests for user-visible behavior

### Review Agent

Goal:

- Check correctness against upstream behavior, not only Rust style.

Review checklist:

- Does the Rust implementation preserve the same observable semantics as upstream?
- Were any edge cases silently simplified?
- Are config directives either implemented correctly or rejected clearly?
- Are feature gates correct and complete?
- Are capability-dependent tests isolated so restricted environments do not create false failures?
- Is every parity bug backed by regression coverage?

## Porting Rules

- C `union` maps to Rust `enum` or a typed wrapper.
- C null pointer maps to `Option<T>`.
- C globals map to explicit shared state, but that shared state must not invent new semantics.
- C `#ifdef HAVE_X` maps to `#[cfg(feature = "x")]`.
- C allocation patterns map to ownership-based Rust types.
- Prefer safe Rust. Introduce `unsafe` only when required by the platform boundary and keep it tightly scoped.

Additional rules for this repo:

- Do not silently drop upstream behavior because the Rust shape is cleaner.
- Preserve flag semantics and wire-format behavior exactly unless there is an explicit documented deviation.
- Keep naming traceable to upstream where that improves reviewability.
- When refactoring, keep a direct path back to the upstream behavior for reviewers.

## Config Parser Rules

- `src/option.rs` is a parity-critical module.
- A directive is not complete until:
  - it parses valid forms
  - it rejects invalid forms clearly
  - it mutates daemon state correctly
  - it affects runtime behavior correctly where applicable
  - it has directive-level tests and integration coverage

- Never accept a directive as a placeholder no-op unless that no-op is explicitly documented and tracked in `tasks.md`.

## Testing Requirements

Every new behavior slice should add:

- Unit tests for deterministic logic
- Error-path tests for malformed input or invalid state
- Property tests for parsers, roundtrips, invariants, or panic-freedom where appropriate
- A regression test when fixing a bug

For externally visible behavior, add parity-oriented tests when possible:

- same fixture config
- same query or packet input
- compare normalized behavior against upstream dnsmasq

## Environment-Sensitive Tests

Some tests in this repo require socket operations, interface enumeration, bind-to-device behavior, or other capabilities that may fail in restricted environments.

Rules:

- Pure logic tests must stay deterministic and capability-independent.
- Capability-dependent tests must be clearly separated, gated, skipped, or made expectation-aware.
- Do not use restricted-environment failures as evidence that the implementation is wrong.
- Do not leave permission-sensitive tests written as unconditional logic tests.

## Completion Standard

Do not mark work complete because a module exists or because many tests pass.

A behavior is complete when:

- the implementation matches upstream for the supported case
- the code is safe and reviewable
- unit and property tests cover the behavior
- externally visible behavior is covered by parity fixtures where applicable
- unsupported cases are explicitly documented
