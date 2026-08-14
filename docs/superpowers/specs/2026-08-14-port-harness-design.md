# Autonomous Port Harness — Design

Date: 2026-08-14
Status: Approved for planning
Repo: `cyrex562/dnsmasq-rs`

## Problem

`dnsmasq-rs` needs a 100% behavioral port of upstream dnsmasq (50 files, ~44k LOC C). The
work is highly parallelizable across files but each file needs the same repeated sequence:
understand the upstream behavior, implement it in Rust, prove it did not regress anything,
and prove it is actually complete rather than plausibly complete.

Doing that by hand for ~46 work items is the bottleneck. This spec defines two things:

- **Project A** — a gap-audited GitHub issue corpus, roughly one issue per upstream file.
- **Project B** — an autonomous harness that consumes those issues and lands merged PRs.

Project A is the input to Project B and is built first.

## Non-goals

- Replacing GitHub Actions CI. The gate runs locally, by explicit choice.
- Multi-provider model routing. The pool is Claude tiers only.
- Parallel issue execution. v1 is strictly serial.
- Porting behavior upstream does not have. Parity is the target, not improvement.

## Baseline reality

These facts constrain the design and were measured, not assumed:

| Fact | Impact |
|---|---|
| `cargo test` — 3019 tests, 0 failures | Test count and pass state are usable gate signals |
| `cargo check --no-default-features` failed (3 errors in `option.rs`) | Fixed as prep work; feature-gate leakage is a live bug class the gate must catch |
| `cargo fmt --check` — 2873 diff hunks | The tree is deliberately not rustfmt-formatted. **`fmt` cannot be a gate stage.** |
| `cargo clippy --all-targets` — 198 warnings, 0 errors | `-D warnings` is impossible. Gate uses a **count ratchet** against baseline. |
| No branch protection, no workflows | Auto-merge is unimpeded; the harness is the only gate, so post-merge verification is mandatory |
| docker 29.1.3 + compose present | The `parity/` probe can be a real gate stage |
| `claude` 2.1.233 | Headless `claude -p` is available for stage execution |
| **`parity/run-major.sh` fails at baseline** — `dnsmasq-rs` answers no query in the `dns/basic` fixture | Parity **cannot** be a pass/fail gate stage. It becomes a per-case ratchet, and fixing it is issue #1 |

Measured baseline (recorded in `harness/baseline.json`):

| Feature set | Tests passed | Clippy warnings |
|---|---|---|
| default | 3019 | 198 |
| `--all-features` | 3059 | 200 |
| `--no-default-features` | 1613 | 145 |

### The baseline parity failure

`rfc1035::answer_request` (`src/rfc1035.rs:835`) and `LocalConfig` (`:802`) implement local-data
answering and are unit-tested for host records, MX, TXT, and CAA. But `src/forward.rs` contains
no reference to either, and `dnsmasq::run_main_loop` spawns only the forwarding loop. Local data
is parsed into `Daemon` and never consulted at runtime.

The `dns/basic` fixture is pure local data (`host-record`, `cname`, `txt-record`, `mx-host`,
`srv-host`, `ptr-record`) under `no-resolv` with zero upstreams, so every query is handed to a
forwarder with nowhere to send it and times out. Upstream answers all eight cases; the candidate
answers none.

This is the project's own warning made concrete — 3019 passing tests alongside a binary that
cannot answer a query from its own config file. It is the strongest available argument for
gating on executable behavior rather than test counts, and it is the first issue the harness
should be pointed at.

## Project A — Gap audit and issue corpus

### File mapping

41 `.c` files map mostly 1:1 to Rust modules (`arp.c` → `src/arp.rs`). The 9 headers do not:

- `dnsmasq.h` → `src/types/*`
- `dns-protocol.h`, `dhcp-protocol.h`, `dhcp6-protocol.h`, `radv-protocol.h` → `src/*_protocol/`
- `metrics.h` → `src/metrics/`
- `config.h` → Cargo features
- `ip6addr.h` → `src/types/addr.rs`

The corpus is therefore ~41 per-file port issues plus ~5 cross-cutting issues:

1. Feature-gate leakage sweep (the `--no-default-features` bug class)
2. `lib.rs` / `main.rs` module-tree duplication
3. Parity fixture expansion beyond `dns/basic`
4. SIGHUP reload — replace the `main.rs` stub with real behavior
5. CLI/config-file unification behind one normalization pipeline

### Audit method

Five read-only subagents, ~10 files each. Per file each reports:

- Exported C functions vs. their Rust equivalents: present, missing, or **silently simplified**
- Concrete gaps with upstream line references
- Risk tier (pure logic / config-driven / runtime-and-socket)
- Suggested model tier

Results are normalized and deduplicated before any issue is filed. Files already at parity get
a short verify-and-close issue rather than being skipped — "looks done" has already proven
unreliable in this tree in both directions.

### Issue format

Human-readable prose, followed by a fenced `harness` block the script parses:

````
```harness
port-file: src/option.rs
upstream-file: original_dnsmasq_src/dnsmasq-master/src/option.c
risk: high
model-tier: opus
gate-profile: full+parity
```
````

Gaps are an enumerated checklist in the prose body. Labels: `port`, `risk:{low,medium,high}`,
`tier:{haiku,sonnet,opus}`, `parked`, `needs-human`.

## Project B — The harness

### Shape

Python 3, stdlib only, at `harness/`:

```
harness/
  harness.py        # CLI + cycle state machine
  gate.sh           # the local CI substitute
  baseline.json     # measured baseline the gate compares against
  stages/*.md       # one prompt template per stage, tunable without touching code
  state/            # per-cycle JSON records
```

Invocation: `./harness/harness.py run --max-issues N`.

Prompts live in files, not in Python string literals, so stage behavior can be tuned and
diffed independently of the orchestration logic.

### Cycle state machine

1. **SELECT** — highest-priority open `port` issue that is not `parked`/`needs-human`
2. **RESEARCH** — sonnet, read-only tools: upstream C vs. current Rust, emits gap analysis JSON
3. **ROUTE** — deterministic Python (see below)
4. **DESIGN** — opus, `risk:high` only; skipped otherwise
5. **IMPLEMENT** — routed model, inside a dedicated git worktree, TDD instruction in prompt
6. **GATE** — `gate.sh`; failure loops back to IMPLEMENT with raw output
7. **REVIEW** — sonnet, sees the diff only
8. **FIX** — apply blocking review findings
9. **JUDGE** — opus, fresh context (see below)
10. **PR** — push branch, `gh pr create` with the judge report attached
11. **MERGE** — `gh pr merge --squash --delete-branch`
12. **POST-MERGE VERIFY** — re-run gate on master; red → auto-revert, reopen, `needs-human`
13. **RECORD** — write the cycle record; update baseline if counts legitimately grew

Each cycle lands as one squashed commit, so a bad merge is a one-command revert.

### Model routing

Routing is a deterministic table in Python, **not** a model call — it is cheaper, auditable,
diffable, and tunable from accumulated cycle data. A model choosing the model costs a call and
cannot be reviewed.

| Condition | Model |
|---|---|
| `risk:low` and gap count < 5 | haiku |
| `risk:medium` | sonnet |
| `risk:high`, or file in {`option.rs`, `forward.rs`, `dnssec.rs`, `network.rs`, `rfc1035.rs`} | opus |
| Research stage | sonnet |
| Review stage | sonnet |
| Judge stage | opus (always) |

On retry, the implement model escalates one tier.

### The gate

`gate.sh`, fail-fast, emits JSON:

1. `cargo check --all-features`
2. `cargo check --no-default-features`
3. `cargo build`
4. `cargo test` — 0 failures **and** test count >= baseline
5. `cargo clippy --all-targets` — warning count <= baseline, per feature set
6. `./parity/run-major.sh` — DNS-touching issues only, as a **per-case ratchet**: the set of
   fixture cases that pass must not shrink. It cannot be pass/fail because zero cases pass today.
7. Forbidden-path check — the diff must not touch `harness/`, `original_dnsmasq_src/`, or `old/`

`fmt` is deliberately absent (see Baseline reality).

Gate-failure retries have their own budget, separate from the judge's retry budget.

### Judge independence

The judge is its own `claude -p` invocation whose context is exactly:

- the issue body
- the final diff
- the raw gate JSON
- the upstream C file

It never sees the implementer's or reviewer's narrative. A judge that reads the
implementer's summary grades the story instead of the code.

Verdict: `complete` or `incomplete` with specific reasons.

### Failure policy

On `incomplete`, the implementer retries with the judge's specific objections, up to twice.
Still failing → label `needs-human`, drop the worktree, post the judge report to the issue,
continue to the next issue. The loop never blocks on one hard file.

## Risks

**Test count as a gate has a false positive.** A legitimate refactor can reduce test count.
Mitigation: the judge may approve a decrease with written justification rather than the gate
hard-failing.

**The harness lives in the repo it edits.** A cycle could otherwise rewrite its own rules.
Mitigation: the forbidden-path gate stage.

**The `lib.rs` / `main.rs` duplication is a trap for every implement stage** — adding a module
requires editing both files with matching `cfg` gates, or the binary silently loses it.
Mitigation: this instruction lives in the implement prompt template until the duplication issue
is itself resolved.

**Auto-merge with no branch protection.** Mitigation: post-merge verify with auto-revert
(step 12), which is what makes unattended merging defensible here.

## Prep work

- [x] Fix `--no-default-features` gate leakage in `src/option.rs` (3 compile errors, plus 13
      test failures the compile error had been hiding)
- [x] Capture `harness/baseline.json` — test and clippy counts per feature set
- [x] Establish parity baseline — `dns/basic` fails 8/8 cases; root cause recorded above
- [ ] Create labels and the issue template
- [ ] Run the 50-file gap audit and file the corpus

## Open decision

The parity ratchet needs a per-case pass/fail record, which `parity_probe` does not currently
emit — it prints human-readable `ok` / `mismatch` lines and exits non-zero on any mismatch.
Adding a `--json` output mode to `src/bin/parity_probe.rs` is a small prerequisite for the gate.
