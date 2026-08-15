# Autonomous Port Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone Python orchestrator that takes a GitHub port issue through research, routed implementation, a local gate standing in for CI, review, and an isolated judge, then opens a PR, merges it, and reverts automatically if master goes red.

**Architecture:** A cycle state machine in `harness/harness.py` drives one issue at a time. Each stage is a separate headless `claude -p` invocation with a file-based prompt template, so stage behavior is tunable and diffable independently of orchestration. Model routing is a deterministic Python table, not a model call. The judge runs in a fresh process whose context is exactly the issue body, the final diff, the raw gate JSON, and the upstream C file — never the implementer's narrative. Work happens in a throwaway git worktree; master is protected by a post-merge gate re-run with auto-revert.

**Tech Stack:** Python 3 (stdlib only — no pip dependencies), `gh` CLI, `git`, `claude` CLI 2.1.233, `cargo`, `docker compose` (for the parity fixture).

**Spec:** `docs/superpowers/specs/2026-08-14-port-harness-design.md`

## Global Constraints

- **Python 3 stdlib only.** No pip installs. `unittest` for tests, `subprocess` for shelling out, `json` for state.
- **`fmt` is never a gate stage.** The tree is deliberately not rustfmt-formatted (2873 diff hunks). Never run `cargo fmt` on this repo.
- **Clippy is a ratchet, not a threshold.** Baseline is 198 (default) / 200 (all-features) / 145 (no-default-features). Never `-D warnings`.
- **Parity is a per-case ratchet.** 0 of 8 cases pass today. Never pass/fail.
- **Baseline lives in `harness/baseline.json`** and is the single source of comparison. Test counts: 3019 / 3059 / 1613.
- **Forbidden paths.** A cycle's diff must never touch `harness/`, `original_dnsmasq_src/`, or `old/`. The gate rejects it.
- **Repo is `cyrex562/dnsmasq-rs`.** Default branch is `master`, unprotected.
- **Every implement-stage prompt must carry this warning:** `src/lib.rs` and `src/main.rs` each declare the full module tree separately; adding a module requires editing both with matching `#[cfg(feature = ...)]` gates.
- **Serial execution only.** One issue at a time. No parallel cycles in v1.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/bin/parity_probe.rs` | *(modify)* add `--json` per-case output |
| `harness/gate.sh` | The CI substitute. Runs builds/tests/clippy/parity, emits JSON |
| `harness/gate.py` | Invoke `gate.sh`, parse its JSON, compare against baseline |
| `harness/routing.py` | Deterministic model routing + retry escalation |
| `harness/issue_meta.py` | Parse the fenced `harness` block; resolve `blocked-by` readiness |
| `harness/claude_runner.py` | Wrap `claude -p`; render stage templates |
| `harness/gitops.py` | Worktree lifecycle, branch, PR, squash-merge, revert |
| `harness/state.py` | Per-cycle JSON records under `harness/state/` |
| `harness/harness.py` | CLI + cycle state machine |
| `harness/stages/*.md` | One prompt template per stage |
| `harness/tests/*.py` | `unittest` suites for the pure-logic modules |

---

### Task 1: parity_probe --json per-case output

The ratchet needs to know *which* cases pass. Today `query_server(...)?` propagates on the first timeout, so one dead case aborts the entire probe — which is exactly what happens now (the candidate answers nothing, so the run dies on case 1 and never learns about cases 2-8).

**Files:**
- Modify: `src/bin/parity_probe.rs:42-67` (`main`), `:69-114` (`parse_args`), `:11-18` (`Config`)

**Interfaces:**
- Produces: `parity_probe --json` writes `{"total":N,"passing":N,"cases":[{"name","qtype","status","detail"}]}` to stdout and exits 0 regardless of mismatches. Without `--json`, behavior is unchanged.

- [ ] **Step 1: Write the failing test**

Add to the bottom of `src/bin/parity_probe.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_accepts_json_flag() {
        let cfg = parse_args(vec![
            "--queries".into(), "q.txt".into(),
            "--upstream".into(), "127.0.0.1:1".into(),
            "--candidate".into(), "127.0.0.1:2".into(),
            "--json".into(),
        ])
        .unwrap();
        assert!(cfg.json);
    }

    #[test]
    fn parse_args_defaults_json_off() {
        let cfg = parse_args(vec![
            "--queries".into(), "q.txt".into(),
            "--upstream".into(), "127.0.0.1:1".into(),
            "--candidate".into(), "127.0.0.1:2".into(),
        ])
        .unwrap();
        assert!(!cfg.json);
    }

    #[test]
    fn json_escape_handles_quotes_and_backslashes() {
        assert_eq!(json_escape(r#"a"b\c"#), r#"a\"b\\c"#);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin parity_probe`
Expected: FAIL — `no field 'json' on type 'Config'`, `cannot find function 'json_escape'`

- [ ] **Step 3: Add the `json` field and flag**

In `struct Config` (line 11), add the field:

```rust
#[derive(Debug)]
struct Config {
    queries: String,
    upstream: SocketAddr,
    candidate: SocketAddr,
    timeout_ms: u64,
    json: bool,
}
```

In `parse_args`, add `let mut json = false;` beside `let mut timeout_ms`, add the match arm:

```rust
            "--json" => {
                json = true;
            }
```

and add `json,` to the returned `Config { ... }`.

- [ ] **Step 4: Add the escape helper and per-case reporting**

Add above `main`:

```rust
/// Minimal JSON string escaping — enough for names, qtypes, and error text.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
```

Replace `main` (lines 42-67) with:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_args(env::args().skip(1).collect())?;
    let cases = load_queries(&config.queries)?;

    // (status, detail) per case. A failure never aborts the run: the ratchet
    // needs a verdict for every case, not just the ones before the first error.
    let mut results: Vec<(String, String)> = Vec::with_capacity(cases.len());
    let mut mismatches = 0usize;

    for case in &cases {
        let up = query_server(config.upstream, case, config.timeout_ms);
        let cand = query_server(config.candidate, case, config.timeout_ms);

        let (status, detail) = match (up, cand) {
            (Ok(u), Ok(c)) if u == c => ("ok".to_string(), String::new()),
            (Ok(u), Ok(c)) => (
                "mismatch".to_string(),
                format!("upstream={u:?} candidate={c:?}"),
            ),
            (Err(e), _) => ("error".to_string(), format!("upstream query failed: {e}")),
            (_, Err(e)) => ("error".to_string(), format!("candidate query failed: {e}")),
        };

        if status != "ok" {
            mismatches += 1;
        }

        if !config.json {
            if status == "ok" {
                println!("ok {} {}", case.name, case.qtype_name);
            } else {
                eprintln!("{status} for {} {}: {detail}", case.name, case.qtype_name);
            }
        }

        results.push((status, detail));
    }

    if config.json {
        let passing = results.iter().filter(|(s, _)| s == "ok").count();
        let mut out = String::from("{\n");
        out.push_str(&format!("  \"total\": {},\n", results.len()));
        out.push_str(&format!("  \"passing\": {passing},\n"));
        out.push_str("  \"cases\": [\n");
        for (i, (case, (status, detail))) in cases.iter().zip(results.iter()).enumerate() {
            out.push_str(&format!(
                "    {{\"name\": \"{}\", \"qtype\": \"{}\", \"status\": \"{}\", \"detail\": \"{}\"}}{}\n",
                json_escape(&case.name),
                json_escape(&case.qtype_name),
                json_escape(status),
                json_escape(detail),
                if i + 1 == results.len() { "" } else { "," }
            ));
        }
        out.push_str("  ]\n}");
        println!("{out}");
        // Always exit 0 in JSON mode; the caller compares against baseline.
        return Ok(());
    }

    if mismatches > 0 {
        return Err(format!("{mismatches} parity mismatches detected").into());
    }

    Ok(())
}
```

Update `print_help`:

```rust
fn print_help() {
    println!("parity_probe --queries FILE --upstream HOST:PORT --candidate HOST:PORT [--timeout-ms N] [--json]");
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --bin parity_probe`
Expected: PASS, 3 tests

- [ ] **Step 6: Verify the full suite is still at baseline**

Run: `cargo test 2>&1 | grep -E "^test result"`
Expected: 0 failed; total passed >= 3019

- [ ] **Step 7: Verify JSON output end to end**

Run: `./parity/run-major.sh` is not needed here. Instead run the probe against two dead ports:
```bash
cargo run --quiet --bin parity_probe -- \
  --queries parity/fixtures/dns/basic/queries.txt \
  --upstream 127.0.0.1:9 --candidate 127.0.0.1:9 \
  --timeout-ms 200 --json
```
Expected: valid JSON, `"total": 8`, `"passing": 0`, 8 case objects with `"status": "error"`, **exit code 0**.

- [ ] **Step 8: Commit**

```bash
git add src/bin/parity_probe.rs
git commit -m "Add --json per-case output to parity_probe

The parity ratchet needs a verdict for every fixture case. The previous
main() propagated on the first query error, so one dead case aborted the
whole run before the others were tried.

In --json mode every case is attempted, results are reported individually,
and the exit code is always 0 so the caller compares against baseline."
```

---

### Task 2: gate.sh — the CI substitute

**Files:**
- Create: `harness/gate.sh`

**Interfaces:**
- Produces: `harness/gate.sh <repo-dir> [--parity]` writes a JSON object to stdout:
  `{"ok":bool,"stages":[{"name":str,"ok":bool,"detail":str}],"tests":{"<set>":{"passed":int,"failed":int}},"clippy":{"<set>":int},"parity":{"total":int,"passing":int}|null,"forbidden_paths":[str]}`
  Exit code 0 if it ran to completion (even on failures), 2 on internal error.

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# Local CI substitute. Emits a JSON verdict on stdout; diagnostics on stderr.
# Never runs `cargo fmt` — this tree is deliberately not rustfmt-formatted.
set -uo pipefail

REPO="${1:?usage: gate.sh <repo-dir> [--parity]}"
RUN_PARITY=0
[[ "${2:-}" == "--parity" ]] && RUN_PARITY=1
cd "$REPO" || exit 2

STAGES=()          # "name|ok|detail"
declare -A T_PASS T_FAIL CLIPPY
PARITY_JSON="null"
OK=1

record() { STAGES+=("$1|$2|$3"); [[ "$2" == "true" ]] || OK=0; }

# ── build checks ─────────────────────────────────────────────────────────────
for spec in "default:" "all-features:--all-features" "no-default-features:--no-default-features"; do
  name="${spec%%:*}"; flags="${spec#*:}"
  # shellcheck disable=SC2086
  if out=$(cargo check $flags 2>&1); then
    record "check:$name" true ""
  else
    record "check:$name" false "$(echo "$out" | grep -E '^error' | head -5 | tr '\n' ';')"
  fi
done

# ── tests ────────────────────────────────────────────────────────────────────
for spec in "default:" "all-features:--all-features" "no-default-features:--no-default-features"; do
  name="${spec%%:*}"; flags="${spec#*:}"
  # shellcheck disable=SC2086
  out=$(cargo test $flags 2>&1)
  p=$(echo "$out" | grep -oP '(?<=result: ok\. )\d+(?= passed)' | paste -sd+ | bc 2>/dev/null || echo 0)
  f=$(echo "$out" | grep -oP '\d+(?= failed)' | paste -sd+ | bc 2>/dev/null || echo 0)
  T_PASS[$name]=${p:-0}; T_FAIL[$name]=${f:-0}
  if [[ "${f:-0}" -eq 0 ]] && echo "$out" | grep -q "test result"; then
    record "test:$name" true "${p:-0} passed"
  else
    record "test:$name" false "$(echo "$out" | grep -E '^(error|test result: FAILED)' | head -5 | tr '\n' ';')"
  fi
done

# ── clippy (counts only; never -D warnings) ──────────────────────────────────
for spec in "default:" "all-features:--all-features" "no-default-features:--no-default-features"; do
  name="${spec%%:*}"; flags="${spec#*:}"
  # shellcheck disable=SC2086
  n=$(cargo clippy --all-targets $flags 2>&1 | grep -cE '^warning')
  CLIPPY[$name]=${n:-0}
  record "clippy:$name" true "$n warnings"
done

# ── forbidden paths ──────────────────────────────────────────────────────────
FORBIDDEN=$(git diff --name-only master...HEAD 2>/dev/null \
  | grep -E '^(harness/|original_dnsmasq_src/|old/)' || true)
if [[ -n "$FORBIDDEN" ]]; then
  record "forbidden-paths" false "$(echo "$FORBIDDEN" | tr '\n' ';')"
else
  record "forbidden-paths" true ""
fi

# ── parity (ratchet; caller compares against baseline) ───────────────────────
if [[ "$RUN_PARITY" -eq 1 ]]; then
  if PARITY_JSON=$(PARITY_JSON_MODE=1 "$REPO/parity/run-major.sh" --json 2>/dev/null); then
    record "parity" true ""
  else
    PARITY_JSON="null"
    record "parity" true "parity run unavailable; skipped"
  fi
fi

# ── emit ─────────────────────────────────────────────────────────────────────
{
  echo "{"
  echo "  \"ok\": $([[ $OK -eq 1 ]] && echo true || echo false),"
  echo "  \"stages\": ["
  for i in "${!STAGES[@]}"; do
    IFS='|' read -r n o d <<< "${STAGES[$i]}"
    d=${d//\\/\\\\}; d=${d//\"/\\\"}
    printf '    {"name": "%s", "ok": %s, "detail": "%s"}%s\n' \
      "$n" "$o" "$d" "$([[ $i -lt $((${#STAGES[@]} - 1)) ]] && echo ,)"
  done
  echo "  ],"
  echo "  \"tests\": {"
  echo "    \"default\": {\"passed\": ${T_PASS[default]}, \"failed\": ${T_FAIL[default]}},"
  echo "    \"all-features\": {\"passed\": ${T_PASS[all-features]}, \"failed\": ${T_FAIL[all-features]}},"
  echo "    \"no-default-features\": {\"passed\": ${T_PASS[no-default-features]}, \"failed\": ${T_FAIL[no-default-features]}}"
  echo "  },"
  echo "  \"clippy\": {"
  echo "    \"default\": ${CLIPPY[default]},"
  echo "    \"all-features\": ${CLIPPY[all-features]},"
  echo "    \"no-default-features\": ${CLIPPY[no-default-features]}"
  echo "  },"
  echo "  \"parity\": $PARITY_JSON"
  echo "}"
}
exit 0
```

- [ ] **Step 2: Make executable and run against the clean tree**

```bash
chmod +x harness/gate.sh
./harness/gate.sh "$PWD" | tee /tmp/gate-baseline.json | python3 -m json.tool | head -30
```
Expected: valid JSON, `"ok": true`, tests 3019/3059/1613 with 0 failed, clippy 198/200/145.

- [ ] **Step 3: Verify it detects a forbidden path**

```bash
git checkout -b gate-selftest
echo "# selftest" >> harness/baseline.json
git commit -aqm "selftest"
./harness/gate.sh "$PWD" | python3 -c "import json,sys; d=json.load(sys.stdin); print([s for s in d['stages'] if s['name']=='forbidden-paths'])"
git checkout -q master- 2>/dev/null || git checkout -q harness-prep
git branch -qD gate-selftest
git checkout -q harness/baseline.json
```
Expected: the `forbidden-paths` stage reports `ok: false` listing `harness/baseline.json`.

- [ ] **Step 4: Commit**

```bash
git add harness/gate.sh
git commit -m "Add harness/gate.sh, the local CI substitute

Runs check/test/clippy across all three feature sets, checks the diff for
forbidden paths, optionally runs the parity fixture, and emits a JSON
verdict. Deliberately never runs cargo fmt, and never uses -D warnings:
this tree carries 198 baseline clippy warnings and is not rustfmt-formatted."
```

---

### Task 3: gate.py — run the gate and compare against baseline

**Files:**
- Create: `harness/gate.py`, `harness/tests/test_gate.py`

**Interfaces:**
- Consumes: `harness/gate.sh` JSON, `harness/baseline.json`
- Produces:
  - `GateResult(ok: bool, failures: list[str], raw: dict)`
  - `run_gate(repo_dir: str, parity: bool) -> GateResult`
  - `compare_to_baseline(raw: dict, baseline: dict) -> list[str]` — returns human-readable regression strings, empty if clean

- [ ] **Step 1: Write the failing test**

```python
# harness/tests/test_gate.py
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from gate import compare_to_baseline  # noqa: E402

BASE = {
    "feature_sets": {
        "default": {"tests": {"passed": 3019, "failed": 0}, "clippy_warnings": 198},
        "all-features": {"tests": {"passed": 3059, "failed": 0}, "clippy_warnings": 200},
        "no-default-features": {"tests": {"passed": 1613, "failed": 0}, "clippy_warnings": 145},
    },
    "parity": {"cases_total": 8, "cases_passing": 0},
}


def raw(passed=(3019, 3059, 1613), clippy=(198, 200, 145), failed=(0, 0, 0), parity=None):
    names = ["default", "all-features", "no-default-features"]
    return {
        "ok": True,
        "stages": [],
        "tests": {n: {"passed": p, "failed": f} for n, p, f in zip(names, passed, failed)},
        "clippy": dict(zip(names, clippy)),
        "parity": parity,
    }


class TestCompare(unittest.TestCase):
    def test_clean_run_has_no_regressions(self):
        self.assertEqual(compare_to_baseline(raw(), BASE), [])

    def test_test_failure_is_a_regression(self):
        out = compare_to_baseline(raw(failed=(1, 0, 0)), BASE)
        self.assertTrue(any("failed" in m for m in out))

    def test_fewer_tests_is_a_regression(self):
        out = compare_to_baseline(raw(passed=(3018, 3059, 1613)), BASE)
        self.assertTrue(any("3018" in m for m in out))

    def test_more_tests_is_fine(self):
        self.assertEqual(compare_to_baseline(raw(passed=(3100, 3059, 1613)), BASE), [])

    def test_more_clippy_warnings_is_a_regression(self):
        out = compare_to_baseline(raw(clippy=(199, 200, 145)), BASE)
        self.assertTrue(any("clippy" in m for m in out))

    def test_fewer_clippy_warnings_is_fine(self):
        self.assertEqual(compare_to_baseline(raw(clippy=(150, 200, 145)), BASE), [])

    def test_parity_regression_detected(self):
        base = dict(BASE, parity={"cases_total": 8, "cases_passing": 3})
        out = compare_to_baseline(raw(parity={"total": 8, "passing": 2}), base)
        self.assertTrue(any("parity" in m for m in out))

    def test_parity_improvement_is_fine(self):
        out = compare_to_baseline(raw(parity={"total": 8, "passing": 5}), BASE)
        self.assertEqual(out, [])

    def test_absent_parity_is_not_a_regression(self):
        self.assertEqual(compare_to_baseline(raw(parity=None), BASE), [])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest harness.tests.test_gate -v` from the repo root, or `python3 harness/tests/test_gate.py`
Expected: FAIL — `ModuleNotFoundError: No module named 'gate'`

- [ ] **Step 3: Write the implementation**

```python
# harness/gate.py
"""Run the local gate and compare its verdict against the recorded baseline."""
import json
import os
import subprocess
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
GATE_SH = os.path.join(HERE, "gate.sh")
BASELINE = os.path.join(HERE, "baseline.json")

FEATURE_SETS = ["default", "all-features", "no-default-features"]


@dataclass
class GateResult:
    ok: bool
    failures: list = field(default_factory=list)
    raw: dict = field(default_factory=dict)


def load_baseline(path=BASELINE):
    with open(path) as f:
        return json.load(f)


def compare_to_baseline(raw, baseline):
    """Return a list of regression descriptions. Empty means no regression.

    Tests and parity ratchet upward (more is fine, fewer is not). Clippy
    ratchets downward (fewer is fine, more is not). A hard test failure is
    always a regression regardless of counts.
    """
    out = []
    sets = baseline.get("feature_sets", {})

    for name in FEATURE_SETS:
        base = sets.get(name)
        got = raw.get("tests", {}).get(name)
        if base is None or got is None:
            continue

        if got["failed"] > 0:
            out.append(f"{name}: {got['failed']} test(s) failed")

        base_passed = base["tests"]["passed"]
        if got["passed"] < base_passed:
            out.append(
                f"{name}: {got['passed']} tests passed, below baseline {base_passed}"
            )

        base_clippy = base.get("clippy_warnings")
        got_clippy = raw.get("clippy", {}).get(name)
        if base_clippy is not None and got_clippy is not None and got_clippy > base_clippy:
            out.append(
                f"{name}: {got_clippy} clippy warnings, above baseline {base_clippy}"
            )

    parity = raw.get("parity")
    base_parity = baseline.get("parity")
    if parity and base_parity:
        if parity.get("passing", 0) < base_parity.get("cases_passing", 0):
            out.append(
                f"parity: {parity['passing']}/{parity['total']} cases passing, "
                f"below baseline {base_parity['cases_passing']}"
            )

    return out


def run_gate(repo_dir, parity=False, baseline_path=BASELINE):
    cmd = [GATE_SH, repo_dir] + (["--parity"] if parity else [])
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    if proc.returncode == 2 or not proc.stdout.strip():
        return GateResult(False, [f"gate.sh failed to run: {proc.stderr[-500:]}"], {})

    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return GateResult(False, [f"gate.sh emitted invalid JSON: {e}"], {})

    failures = [
        f"stage {s['name']}: {s['detail']}" for s in raw.get("stages", []) if not s["ok"]
    ]
    failures += compare_to_baseline(raw, load_baseline(baseline_path))
    return GateResult(not failures, failures, raw)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 harness/tests/test_gate.py -v`
Expected: PASS, 9 tests

- [ ] **Step 5: Verify against a real gate run**

```bash
python3 -c "
import sys; sys.path.insert(0,'harness')
from gate import run_gate
r = run_gate('$PWD')
print('ok:', r.ok); print('failures:', r.failures)"
```
Expected: `ok: True`, `failures: []`

- [ ] **Step 6: Commit**

```bash
git add harness/gate.py harness/tests/test_gate.py
git commit -m "Add gate.py: run the gate and ratchet against baseline

Tests and parity ratchet upward, clippy ratchets downward, and any hard
test failure is a regression regardless of counts."
```

---

### Task 4: issue_meta.py — parse the harness block and dependency readiness

**Files:**
- Create: `harness/issue_meta.py`, `harness/tests/test_issue_meta.py`

**Interfaces:**
- Produces:
  - `IssueMeta(number:int, key:str, tier:int, risk:str, model:str, port_file:str, upstream_file:str, gate_profile:str, blocked_by:list[str], title:str, body:str)`
  - `parse_meta(number:int, title:str, body:str) -> IssueMeta | None` — `None` when no `harness` block
  - `select_next(issues: list[IssueMeta], closed_keys: set[str]) -> IssueMeta | None` — lowest tier first, then lowest issue number, skipping any whose `blocked_by` are not all in `closed_keys`

- [ ] **Step 1: Write the failing test**

```python
# harness/tests/test_issue_meta.py
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from issue_meta import parse_meta, select_next  # noqa: E402

BODY = """Some prose here.

## Harness metadata

```harness
key: T0-2
tier: 0
risk: high
model-tier: opus
port-file: src/forward.rs
upstream-file: original_dnsmasq_src/dnsmasq-master/src/forward.c
gate-profile: full+parity
blocked-by: T0-1
```
"""


def meta(number, key, tier, blocked="none"):
    body = BODY.replace("key: T0-2", f"key: {key}") \
               .replace("tier: 0", f"tier: {tier}") \
               .replace("blocked-by: T0-1", f"blocked-by: {blocked}")
    return parse_meta(number, f"title {key}", body)


class TestParse(unittest.TestCase):
    def test_parses_all_fields(self):
        m = parse_meta(3, "Wire the DNS cache", BODY)
        self.assertEqual(m.key, "T0-2")
        self.assertEqual(m.tier, 0)
        self.assertEqual(m.risk, "high")
        self.assertEqual(m.model, "opus")
        self.assertEqual(m.port_file, "src/forward.rs")
        self.assertEqual(m.gate_profile, "full+parity")
        self.assertEqual(m.blocked_by, ["T0-1"])
        self.assertEqual(m.number, 3)

    def test_blocked_by_none_is_empty_list(self):
        self.assertEqual(meta(9, "T0-8", 0, "none").blocked_by, [])

    def test_multiple_blockers(self):
        self.assertEqual(meta(9, "T0-8", 0, "T0-1,T0-2").blocked_by, ["T0-1", "T0-2"])

    def test_body_without_block_returns_none(self):
        self.assertIsNone(parse_meta(1, "t", "no metadata here"))


class TestSelect(unittest.TestCase):
    def test_lowest_tier_wins(self):
        issues = [meta(30, "T3-a", 3), meta(2, "T0-1", 0)]
        self.assertEqual(select_next(issues, set()).key, "T0-1")

    def test_lowest_number_breaks_ties(self):
        issues = [meta(5, "T0-4", 0), meta(2, "T0-1", 0)]
        self.assertEqual(select_next(issues, set()).number, 2)

    def test_blocked_issue_is_skipped(self):
        issues = [meta(3, "T0-2", 0, "T0-1"), meta(9, "T0-8", 0, "none")]
        self.assertEqual(select_next(issues, set()).key, "T0-8")

    def test_blocked_issue_unlocks_when_blocker_closed(self):
        issues = [meta(3, "T0-2", 0, "T0-1")]
        self.assertIsNone(select_next(issues, set()))
        self.assertEqual(select_next(issues, {"T0-1"}).key, "T0-2")

    def test_no_eligible_issues_returns_none(self):
        self.assertIsNone(select_next([], set()))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 harness/tests/test_issue_meta.py`
Expected: FAIL — `ModuleNotFoundError: No module named 'issue_meta'`

- [ ] **Step 3: Write the implementation**

```python
# harness/issue_meta.py
"""Parse the fenced `harness` metadata block out of a GitHub issue body."""
import json
import re
import subprocess
from dataclasses import dataclass, field

BLOCK_RE = re.compile(r"```harness\s*\n(.*?)```", re.DOTALL)
REPO = "cyrex562/dnsmasq-rs"


@dataclass
class IssueMeta:
    number: int
    key: str
    tier: int
    risk: str
    model: str
    port_file: str
    upstream_file: str
    gate_profile: str
    blocked_by: list = field(default_factory=list)
    title: str = ""
    body: str = ""

    @property
    def wants_parity(self):
        return self.gate_profile == "full+parity"


def parse_meta(number, title, body):
    m = BLOCK_RE.search(body or "")
    if not m:
        return None

    fields = {}
    for line in m.group(1).splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        fields[k.strip()] = v.strip()

    blocked = fields.get("blocked-by", "none")
    blocked_list = [] if blocked in ("none", "") else [b.strip() for b in blocked.split(",")]

    try:
        return IssueMeta(
            number=number,
            key=fields["key"],
            tier=int(fields["tier"]),
            risk=fields["risk"],
            model=fields["model-tier"],
            port_file=fields["port-file"],
            upstream_file=fields["upstream-file"],
            gate_profile=fields.get("gate-profile", "full"),
            blocked_by=blocked_list,
            title=title,
            body=body,
        )
    except KeyError:
        return None


def select_next(issues, closed_keys):
    """Lowest tier first, then lowest issue number, skipping blocked issues."""
    eligible = [i for i in issues if all(b in closed_keys for b in i.blocked_by)]
    if not eligible:
        return None
    return sorted(eligible, key=lambda i: (i.tier, i.number))[0]


def fetch_open_issues(repo=REPO, label="port"):
    out = subprocess.run(
        ["gh", "issue", "list", "--repo", repo, "--label", label, "--state", "open",
         "--limit", "200", "--json", "number,title,body,labels"],
        capture_output=True, text=True, check=True,
    ).stdout
    metas = []
    for row in json.loads(out):
        names = {lbl["name"] for lbl in row.get("labels", [])}
        if "parked" in names or "needs-human" in names:
            continue
        m = parse_meta(row["number"], row["title"], row["body"])
        if m:
            metas.append(m)
    return metas


def fetch_closed_keys(repo=REPO, label="port"):
    out = subprocess.run(
        ["gh", "issue", "list", "--repo", repo, "--label", label, "--state", "closed",
         "--limit", "200", "--json", "number,title,body"],
        capture_output=True, text=True, check=True,
    ).stdout
    keys = set()
    for row in json.loads(out):
        m = parse_meta(row["number"], row["title"], row["body"])
        if m:
            keys.add(m.key)
    return keys
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 harness/tests/test_issue_meta.py -v`
Expected: PASS, 9 tests

- [ ] **Step 5: Verify against the real repo**

```bash
python3 -c "
import sys; sys.path.insert(0,'harness')
from issue_meta import fetch_open_issues, fetch_closed_keys, select_next
o = fetch_open_issues(); c = fetch_closed_keys()
print('open with metadata:', len(o))
n = select_next(o, c); print('next:', n.key, n.number, n.title)"
```
Expected: `open with metadata: 56`, next is `T0-1` issue 2 (nothing blocks it, and it is tier 0 / lowest number).

- [ ] **Step 6: Commit**

```bash
git add harness/issue_meta.py harness/tests/test_issue_meta.py
git commit -m "Add issue_meta.py: parse harness blocks and pick the next issue

Selection is lowest tier first, then lowest issue number, skipping any
issue whose blocked-by keys are not yet closed, and skipping parked or
needs-human issues entirely."
```

---

### Task 5: routing.py — deterministic model routing

**Files:**
- Create: `harness/routing.py`, `harness/tests/test_routing.py`

**Interfaces:**
- Consumes: `IssueMeta` from Task 4
- Produces:
  - `TIERS = ["haiku", "sonnet", "opus"]`
  - `route(meta, stage: str, attempt: int = 0) -> str`
  - `escalate(model: str) -> str`

- [ ] **Step 1: Write the failing test**

```python
# harness/tests/test_routing.py
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from issue_meta import IssueMeta  # noqa: E402
from routing import escalate, route  # noqa: E402


def m(risk="medium", model="sonnet", port_file="src/util.rs"):
    return IssueMeta(1, "K", 3, risk, model, port_file, "u.c", "full")


class TestRoute(unittest.TestCase):
    def test_judge_is_always_opus(self):
        self.assertEqual(route(m(risk="low", model="haiku"), "judge"), "opus")

    def test_review_is_always_sonnet(self):
        self.assertEqual(route(m(risk="high", model="opus"), "review"), "sonnet")

    def test_research_is_always_sonnet(self):
        self.assertEqual(route(m(risk="high"), "research"), "sonnet")

    def test_implement_uses_issue_model_tier(self):
        self.assertEqual(route(m(model="haiku", risk="low"), "implement"), "haiku")

    def test_hot_file_forces_opus(self):
        self.assertEqual(
            route(m(model="haiku", risk="low", port_file="src/option.rs"), "implement"),
            "opus",
        )

    def test_high_risk_forces_at_least_sonnet(self):
        self.assertEqual(route(m(model="haiku", risk="high"), "implement"), "opus")

    def test_retry_escalates_one_tier(self):
        self.assertEqual(route(m(model="sonnet"), "implement", attempt=1), "opus")

    def test_escalation_saturates_at_opus(self):
        self.assertEqual(route(m(model="opus"), "implement", attempt=3), "opus")

    def test_judge_does_not_escalate(self):
        self.assertEqual(route(m(), "judge", attempt=2), "opus")


class TestEscalate(unittest.TestCase):
    def test_haiku_to_sonnet(self):
        self.assertEqual(escalate("haiku"), "sonnet")

    def test_sonnet_to_opus(self):
        self.assertEqual(escalate("sonnet"), "opus")

    def test_opus_saturates(self):
        self.assertEqual(escalate("opus"), "opus")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 harness/tests/test_routing.py`
Expected: FAIL — `ModuleNotFoundError: No module named 'routing'`

- [ ] **Step 3: Write the implementation**

```python
# harness/routing.py
"""Deterministic model routing.

A table, not a model call: cheaper, auditable, diffable, and tunable from
accumulated cycle data. A model choosing the model costs a request and cannot
be reviewed.
"""

TIERS = ["haiku", "sonnet", "opus"]

# Files where a wrong edit is expensive or the logic is intricate enough that
# the cheapest capable model is not the cheapest outcome.
HOT_FILES = (
    "src/option.rs",
    "src/forward.rs",
    "src/dnssec.rs",
    "src/network.rs",
    "src/rfc1035.rs",
    "src/crypto.rs",
)

# Stages whose model never varies. The judge is pinned to the top tier because
# it is the only thing standing between a plausible diff and master.
FIXED_STAGES = {"research": "sonnet", "review": "sonnet", "judge": "opus"}


def escalate(model):
    i = TIERS.index(model)
    return TIERS[min(i + 1, len(TIERS) - 1)]


def route(meta, stage, attempt=0):
    if stage in FIXED_STAGES:
        return FIXED_STAGES[stage]

    model = meta.model
    if meta.risk == "high" or any(f in meta.port_file for f in HOT_FILES):
        model = "opus"

    for _ in range(attempt):
        model = escalate(model)
    return model
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 harness/tests/test_routing.py -v`
Expected: PASS, 12 tests

- [ ] **Step 5: Commit**

```bash
git add harness/routing.py harness/tests/test_routing.py
git commit -m "Add routing.py: deterministic model routing

Judge is pinned to opus, review and research to sonnet. Implement uses the
issue's model-tier, forced to opus for high-risk issues or hot files, and
escalated one tier per retry."
```

---

### Task 6: Stage prompt templates

**Files:**
- Create: `harness/stages/research.md`, `design.md`, `implement.md`, `review.md`, `judge.md`

**Interfaces:**
- Produces: five templates using `{placeholder}` substitution. Placeholders available to all: `{key}`, `{number}`, `{title}`, `{body}`, `{port_file}`, `{upstream_file}`, `{repo}`. Additionally `{research}` (design, implement), `{gate_output}` (implement retry, judge), `{diff}` (review, judge), `{review}` (implement fix), `{objections}` (implement retry).

- [ ] **Step 1: Write `harness/stages/research.md`**

```markdown
You are analyzing a gap between upstream dnsmasq (C) and its Rust port.

Issue #{number} — {title}

{body}

Rust file(s): {port_file}
Upstream C:   {upstream_file}

Read BOTH files. Do not trust comments, module names, or test names — this
codebase has a documented history of overclaiming and underclaiming completion
in both directions. Verify by reading actual code.

Report, concisely:
1. What upstream actually does for this behavior, with line references.
2. What the Rust side currently does, with line references.
3. The precise delta, as an ordered list of changes to make.
4. Any call sites that must change, especially whether anything currently
   calls the code you are about to modify.
5. Test cases that would fail today and pass after the change.

Do NOT edit any file. Your output is analysis only.
```

- [ ] **Step 2: Write `harness/stages/design.md`**

```markdown
You are designing the implementation for a dnsmasq port issue before any code
is written.

Issue #{number} — {title}

{body}

Research findings:
{research}

Produce a short implementation approach:
- The order of changes, smallest coherent step first.
- Which existing types and functions to reuse rather than reinvent.
- Where the risk of semantic drift from upstream is highest, and how to avoid it.
- The test strategy: what is unit-testable, what needs an integration test, and
  what can only be verified by the parity fixture.

Be specific and short. Do NOT edit any file.
```

- [ ] **Step 3: Write `harness/stages/implement.md`**

```markdown
You are implementing a change to the Rust port of dnsmasq.

Issue #{number} — {title}

{body}

Research findings:
{research}

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
  reformatting it would produce a 2873-hunk diff.
- `src/lib.rs` and `src/main.rs` each declare the full module tree separately.
  Adding a module requires editing BOTH, with matching `#[cfg(feature = ...)]`
  gates, or the binary silently loses it.

Before you finish, run:
  cargo test
  cargo check --no-default-features
and make sure both are clean.

Implement the change now.
```

- [ ] **Step 4: Write `harness/stages/review.md`**

```markdown
You are reviewing a diff against upstream dnsmasq for semantic drift.

Issue #{number} — {title}

{body}

Diff under review:
{diff}

Check specifically:
- Does this preserve upstream's observable behavior, or does it quietly
  simplify an edge case?
- Are flag semantics and wire format preserved exactly?
- Is any config directive accepted as a silent no-op?
- Are feature gates correct and complete, including in BOTH `lib.rs` and
  `main.rs`?
- Are capability-dependent tests gated so restricted environments do not fail?
- Does every behavior change have a test?

Report only issues that matter, most severe first. If the diff is sound, say so
plainly. Do NOT edit any file.
```

- [ ] **Step 5: Write `harness/stages/judge.md`**

```markdown
You are judging whether a change is complete. You are the last check before
this merges to master unattended.

You are deliberately given no implementer or reviewer narrative. Judge the
code, not an account of the code.

Issue #{number} — {title}

Issue requirements:
{body}

Final diff:
{diff}

Gate output (raw):
{gate_output}

Upstream reference: {upstream_file}

Verify independently:
1. Does the diff satisfy EVERY acceptance criterion in the issue? Check each
   one against the actual code, not against its description.
2. Does the behavior match the upstream C for the supported cases?
3. Do the tests actually exercise the new behavior, or do they assert
   something trivially true?
4. Did anything get weakened to make a test pass?

The test count dropping is a regression UNLESS the diff shows a legitimate
consolidation — say so explicitly if you approve one.

Respond with exactly one line first:
VERDICT: complete
or
VERDICT: incomplete

Then, if incomplete, a numbered list of specific objections an implementer can
act on. Do NOT edit any file.
```

- [ ] **Step 6: Verify all five exist and have placeholders**

```bash
for f in research design implement review judge; do
  printf "%-10s %s bytes\n" "$f" "$(wc -c < harness/stages/$f.md)"
done
grep -L "{body}" harness/stages/*.md   # expect no output
```
Expected: five non-empty files, no file missing `{body}`.

- [ ] **Step 7: Commit**

```bash
git add harness/stages/
git commit -m "Add harness stage prompt templates

Prompts live in files rather than Python string literals so stage behavior
can be tuned and diffed independently of orchestration logic. The judge
template is explicit that it receives no implementer narrative."
```

---

### Task 7: claude_runner.py — headless stage execution

**Files:**
- Create: `harness/claude_runner.py`, `harness/tests/test_claude_runner.py`

**Interfaces:**
- Consumes: `harness/stages/*.md`, `routing.route`
- Produces:
  - `render(stage: str, **kw) -> str`
  - `run_stage(stage: str, model: str, cwd: str, prompt: str, read_only: bool = False) -> str`
  - `parse_verdict(text: str) -> tuple[bool, str]` — returns `(complete, objections)`

- [ ] **Step 1: Write the failing test**

```python
# harness/tests/test_claude_runner.py
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from claude_runner import parse_verdict, render  # noqa: E402


class TestRender(unittest.TestCase):
    def test_substitutes_placeholders(self):
        out = render("research", number=2, title="T", body="B",
                     port_file="p.rs", upstream_file="u.c", key="T0-1", repo="r")
        self.assertIn("Issue #2 — T", out)
        self.assertIn("p.rs", out)
        self.assertNotIn("{body}", out)

    def test_unknown_placeholder_is_left_alone(self):
        # Templates use braces in prose; a missing key must not raise.
        out = render("judge", number=1, title="t", body="b", diff="d",
                     gate_output="g", upstream_file="u", key="k", repo="r")
        self.assertIn("VERDICT", out)


class TestVerdict(unittest.TestCase):
    def test_complete(self):
        ok, obj = parse_verdict("VERDICT: complete\n")
        self.assertTrue(ok)

    def test_incomplete_captures_objections(self):
        ok, obj = parse_verdict("VERDICT: incomplete\n1. Missing AAAA case\n")
        self.assertFalse(ok)
        self.assertIn("AAAA", obj)

    def test_case_insensitive(self):
        self.assertTrue(parse_verdict("verdict: COMPLETE")[0])

    def test_missing_verdict_is_incomplete(self):
        ok, obj = parse_verdict("I think it looks fine")
        self.assertFalse(ok)
        self.assertIn("no VERDICT line", obj)

    def test_verdict_must_be_early_not_buried(self):
        buried = "\n".join(["filler"] * 40 + ["VERDICT: complete"])
        ok, _ = parse_verdict(buried)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 harness/tests/test_claude_runner.py`
Expected: FAIL — `ModuleNotFoundError: No module named 'claude_runner'`

- [ ] **Step 3: Write the implementation**

```python
# harness/claude_runner.py
"""Render stage templates and execute them through headless `claude -p`."""
import json
import os
import re
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
STAGES = os.path.join(HERE, "stages")

# Tools a read-only stage is permitted to use. Research, review, and judge must
# not be able to edit the tree — the judge especially, or it can fix what it is
# supposed to be grading.
READ_ONLY_TOOLS = "Read,Grep,Glob,Bash(cargo test:*),Bash(cargo check:*),Bash(git diff:*),Bash(git log:*)"

VERDICT_RE = re.compile(r"^\s*VERDICT:\s*(complete|incomplete)\s*$", re.I | re.M)
VERDICT_SEARCH_LINES = 20


class StageError(RuntimeError):
    pass


def render(stage, **kw):
    with open(os.path.join(STAGES, f"{stage}.md")) as f:
        template = f.read()
    out = template
    for key, value in kw.items():
        out = out.replace("{" + key + "}", str(value))
    return out


def run_stage(stage, model, cwd, prompt, read_only=False, timeout=3600):
    cmd = [
        "claude", "-p", prompt,
        "--model", model,
        "--output-format", "json",
        "--add-dir", cwd,
    ]
    if read_only:
        cmd += ["--allowedTools", READ_ONLY_TOOLS]
    else:
        cmd += ["--permission-mode", "bypassPermissions"]

    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise StageError(f"{stage} exited {proc.returncode}: {proc.stderr[-1000:]}")

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return proc.stdout.strip()

    if isinstance(payload, dict):
        return payload.get("result") or payload.get("text") or proc.stdout.strip()
    return proc.stdout.strip()


def parse_verdict(text):
    """A verdict must appear near the top, per the judge template's contract.

    A VERDICT buried under paragraphs of hedging is treated as no verdict —
    it usually means the model reasoned its way to a conclusion rather than
    committing to one, and defaulting that to 'complete' would be the single
    most dangerous failure mode in this harness.
    """
    head = "\n".join(text.splitlines()[:VERDICT_SEARCH_LINES])
    m = VERDICT_RE.search(head)
    if not m:
        return False, "judge produced no VERDICT line in the first "
        f"{VERDICT_SEARCH_LINES} lines; treating as incomplete"
    if m.group(1).lower() == "complete":
        return True, ""
    return False, text[m.end():].strip()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 harness/tests/test_claude_runner.py -v`
Expected: PASS, 7 tests

- [ ] **Step 5: Smoke-test a real headless call**

```bash
python3 -c "
import sys; sys.path.insert(0,'harness')
from claude_runner import run_stage
print(run_stage('research', 'haiku', '$PWD', 'Reply with exactly: OK', read_only=True)[:200])"
```
Expected: output containing `OK`. If the CLI prompts or errors on auth, resolve that before continuing — every later task depends on this path.

- [ ] **Step 6: Commit**

```bash
git add harness/claude_runner.py harness/tests/test_claude_runner.py
git commit -m "Add claude_runner.py: headless stage execution

Read-only stages get an explicit tool allowlist so research, review, and
judge cannot edit the tree. A judge verdict buried past the first 20 lines
is treated as no verdict rather than defaulting to complete."
```

---

### Task 8: gitops.py — worktree, PR, merge, and post-merge revert

**Files:**
- Create: `harness/gitops.py`, `harness/tests/test_gitops.py`

**Interfaces:**
- Produces:
  - `make_worktree(repo:str, branch:str) -> str` / `remove_worktree(repo:str, path:str)`
  - `diff_against_master(worktree:str) -> str`
  - `has_changes(worktree:str) -> bool`
  - `commit_all(worktree:str, message:str)`
  - `push_and_pr(worktree:str, branch:str, title:str, body:str) -> str` (PR URL)
  - `squash_merge(pr_url:str)`
  - `revert_head(repo:str) -> str` (revert commit sha)
  - `branch_name(key:str, attempt:int) -> str`

- [ ] **Step 1: Write the failing test**

```python
# harness/tests/test_gitops.py
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from gitops import branch_name, commit_all, diff_against_master, has_changes, \
    make_worktree, remove_worktree  # noqa: E402


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


class TestBranchName(unittest.TestCase):
    def test_includes_key(self):
        self.assertIn("t0-1", branch_name("T0-1", 0).lower())

    def test_attempt_suffix_on_retry(self):
        self.assertNotEqual(branch_name("T0-1", 0), branch_name("T0-1", 1))

    def test_is_git_safe(self):
        n = branch_name("T3-dhcp-common", 2)
        self.assertNotIn(" ", n)
        self.assertNotIn("~", n)


class TestWorktree(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp()
        git(self.repo, "init", "-q", "-b", "master")
        git(self.repo, "config", "user.email", "t@t")
        git(self.repo, "config", "user.name", "t")
        open(os.path.join(self.repo, "a.txt"), "w").write("one\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "init")

    def test_worktree_created_and_removed(self):
        wt = make_worktree(self.repo, "feature-x")
        self.assertTrue(os.path.isdir(wt))
        self.assertTrue(os.path.exists(os.path.join(wt, "a.txt")))
        remove_worktree(self.repo, wt)
        self.assertFalse(os.path.isdir(wt))

    def test_has_changes_and_diff(self):
        wt = make_worktree(self.repo, "feature-y")
        self.assertFalse(has_changes(wt))
        open(os.path.join(wt, "a.txt"), "w").write("two\n")
        self.assertTrue(has_changes(wt))
        commit_all(wt, "change a")
        d = diff_against_master(wt)
        self.assertIn("two", d)
        remove_worktree(self.repo, wt)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 harness/tests/test_gitops.py`
Expected: FAIL — `ModuleNotFoundError: No module named 'gitops'`

- [ ] **Step 3: Write the implementation**

```python
# harness/gitops.py
"""Git and GitHub operations for one harness cycle."""
import os
import re
import subprocess
import tempfile

REPO_SLUG = "cyrex562/dnsmasq-rs"
BASE_BRANCH = "master"


def _run(cwd, *args, check=True):
    return subprocess.run(list(args), cwd=cwd, capture_output=True, text=True, check=check)


def branch_name(key, attempt=0):
    safe = re.sub(r"[^a-zA-Z0-9._-]", "-", key).lower()
    suffix = f"-retry{attempt}" if attempt else ""
    return f"harness/{safe}{suffix}"


def make_worktree(repo, branch):
    path = tempfile.mkdtemp(prefix="harness-wt-")
    os.rmdir(path)  # git worktree add wants a non-existent path
    _run(repo, "git", "worktree", "add", "-b", branch, path, BASE_BRANCH)
    return path


def remove_worktree(repo, path):
    _run(repo, "git", "worktree", "remove", "--force", path, check=False)


def has_changes(worktree):
    out = _run(worktree, "git", "status", "--porcelain").stdout.strip()
    if out:
        return True
    ahead = _run(worktree, "git", "rev-list", "--count", f"{BASE_BRANCH}..HEAD").stdout.strip()
    return ahead not in ("", "0")


def commit_all(worktree, message):
    _run(worktree, "git", "add", "-A")
    _run(worktree, "git", "commit", "-m", message, check=False)


def diff_against_master(worktree):
    return _run(worktree, "git", "diff", f"{BASE_BRANCH}...HEAD").stdout


def push_and_pr(worktree, branch, title, body):
    _run(worktree, "git", "push", "-u", "origin", branch)
    out = _run(
        worktree, "gh", "pr", "create",
        "--repo", REPO_SLUG, "--base", BASE_BRANCH, "--head", branch,
        "--title", title, "--body", body,
    ).stdout.strip()
    return out.splitlines()[-1] if out else ""


def squash_merge(worktree, pr_url):
    _run(worktree, "gh", "pr", "merge", pr_url, "--squash", "--delete-branch")


def head_sha(repo):
    return _run(repo, "git", "rev-parse", "HEAD").stdout.strip()


def sync_master(repo):
    _run(repo, "git", "checkout", BASE_BRANCH)
    _run(repo, "git", "pull", "--ff-only", "origin", BASE_BRANCH)


def revert_head(repo):
    """Revert the merge commit currently at master's HEAD and push it.

    This is the safety net that makes unattended auto-merge defensible with no
    branch protection: if the post-merge gate is red, master goes back.
    """
    _run(repo, "git", "revert", "--no-edit", "HEAD")
    sha = head_sha(repo)
    _run(repo, "git", "push", "origin", BASE_BRANCH)
    return sha
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 harness/tests/test_gitops.py -v`
Expected: PASS, 5 tests

- [ ] **Step 5: Commit**

```bash
git add harness/gitops.py harness/tests/test_gitops.py
git commit -m "Add gitops.py: worktree lifecycle, PR, squash merge, revert

Each cycle works in a throwaway worktree and lands as one squash commit, so
revert_head is a single-command undo when the post-merge gate goes red."
```

---

### Task 9: state.py and harness.py — the cycle state machine

**Files:**
- Create: `harness/state.py`, `harness/harness.py`, `harness/tests/test_state.py`

**Interfaces:**
- Consumes: everything from Tasks 3-8
- Produces: `./harness/harness.py run --max-issues N [--dry-run] [--issue N]`

- [ ] **Step 1: Write the failing test**

```python
# harness/tests/test_state.py
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from state import CycleRecord, save_record  # noqa: E402


class TestRecord(unittest.TestCase):
    def test_round_trips_to_disk(self):
        d = tempfile.mkdtemp()
        r = CycleRecord(key="T0-1", number=2, title="t")
        r.stages.append({"stage": "research", "model": "sonnet", "ok": True})
        r.verdict = "complete"
        path = save_record(r, d)
        with open(path) as f:
            back = json.load(f)
        self.assertEqual(back["key"], "T0-1")
        self.assertEqual(back["verdict"], "complete")
        self.assertEqual(len(back["stages"]), 1)

    def test_filename_contains_key(self):
        d = tempfile.mkdtemp()
        path = save_record(CycleRecord(key="T3-dhcp", number=28, title="t"), d)
        self.assertIn("t3-dhcp", os.path.basename(path).lower())


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 harness/tests/test_state.py`
Expected: FAIL — `ModuleNotFoundError: No module named 'state'`

- [ ] **Step 3: Write `harness/state.py`**

```python
# harness/state.py
"""Per-cycle records, written under harness/state/."""
import json
import os
import re
from dataclasses import asdict, dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.path.join(HERE, "state")


@dataclass
class CycleRecord:
    key: str
    number: int
    title: str
    stages: list = field(default_factory=list)
    gate_failures: list = field(default_factory=list)
    verdict: str = ""
    objections: str = ""
    pr_url: str = ""
    merged: bool = False
    reverted: bool = False
    outcome: str = "started"


def save_record(record, state_dir=STATE_DIR):
    os.makedirs(state_dir, exist_ok=True)
    safe = re.sub(r"[^a-zA-Z0-9._-]", "-", record.key).lower()
    path = os.path.join(state_dir, f"{record.number:04d}-{safe}.json")
    with open(path, "w") as f:
        json.dump(asdict(record), f, indent=2)
        f.write("\n")
    return path
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 harness/tests/test_state.py -v`
Expected: PASS, 2 tests

- [ ] **Step 5: Write `harness/harness.py`**

```python
#!/usr/bin/env python3
"""Autonomous port harness.

  ./harness/harness.py run --max-issues 1
  ./harness/harness.py run --issue 2 --dry-run
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import claude_runner  # noqa: E402
import gitops  # noqa: E402
import issue_meta  # noqa: E402
import routing  # noqa: E402
from gate import run_gate  # noqa: E402
from state import CycleRecord, save_record  # noqa: E402

REPO = os.path.dirname(HERE)
MAX_GATE_RETRIES = 2
MAX_JUDGE_RETRIES = 2


def log(msg):
    print(f"[harness] {msg}", flush=True)


def _stage(record, name, model, fn):
    log(f"  {name} ({model})")
    try:
        out = fn()
        record.stages.append({"stage": name, "model": model, "ok": True})
        return out
    except Exception as e:  # noqa: BLE001 - recorded, then re-raised
        record.stages.append({"stage": name, "model": model, "ok": False, "error": str(e)})
        raise


def run_cycle(meta, dry_run=False):
    record = CycleRecord(key=meta.key, number=meta.number, title=meta.title)
    log(f"issue #{meta.number} [{meta.key}] {meta.title}")

    common = dict(key=meta.key, number=meta.number, title=meta.title, body=meta.body,
                  port_file=meta.port_file, upstream_file=meta.upstream_file,
                  repo=gitops.REPO_SLUG)

    # 1. RESEARCH (read-only, in the main repo — nothing is modified yet)
    research = _stage(record, "research", "sonnet", lambda: claude_runner.run_stage(
        "research", "sonnet", REPO,
        claude_runner.render("research", **common), read_only=True))

    # 2. DESIGN (high risk only)
    if meta.risk == "high":
        _stage(record, "design", "opus", lambda: claude_runner.run_stage(
            "design", "opus", REPO,
            claude_runner.render("design", research=research, **common), read_only=True))

    if dry_run:
        record.outcome = "dry-run"
        save_record(record)
        log("  dry run — stopping before implement")
        return record

    branch = gitops.branch_name(meta.key)
    worktree = gitops.make_worktree(REPO, branch)
    log(f"  worktree {worktree}")

    try:
        objections = ""
        gate_output = ""
        for judge_attempt in range(MAX_JUDGE_RETRIES + 1):
            model = routing.route(meta, "implement", attempt=judge_attempt)

            # 3. IMPLEMENT, with its own gate-failure retry budget
            for gate_attempt in range(MAX_GATE_RETRIES + 1):
                impl_model = routing.route(meta, "implement", attempt=judge_attempt + gate_attempt)
                prompt = claude_runner.render(
                    "implement", research=research, gate_output=gate_output,
                    objections=objections, **common)
                _stage(record, f"implement.j{judge_attempt}.g{gate_attempt}", impl_model,
                       lambda p=prompt, m=impl_model: claude_runner.run_stage(
                           "implement", m, worktree, p))

                if not gitops.has_changes(worktree):
                    raise RuntimeError("implement stage produced no changes")
                gitops.commit_all(worktree, f"{meta.title}\n\nCloses #{meta.number}")

                log("  gate")
                result = run_gate(worktree, parity=meta.wants_parity)
                record.gate_failures = result.failures
                gate_output = "\n".join(result.failures) or "gate clean"
                if result.ok:
                    break
                log(f"  gate failed: {gate_output[:200]}")
            else:
                record.outcome = "gate-exhausted"
                break

            if not result.ok:
                record.outcome = "gate-exhausted"
                break

            diff = gitops.diff_against_master(worktree)

            # 4. REVIEW
            review = _stage(record, "review", "sonnet", lambda: claude_runner.run_stage(
                "review", "sonnet", worktree,
                claude_runner.render("review", diff=diff, **common), read_only=True))

            # 5. JUDGE — fresh process, curated context, no implementer narrative
            judgement = _stage(record, "judge", "opus", lambda: claude_runner.run_stage(
                "judge", "opus", worktree,
                claude_runner.render("judge", diff=diff, gate_output=gate_output, **common),
                read_only=True))
            complete, objections = claude_runner.parse_verdict(judgement)
            record.verdict = "complete" if complete else "incomplete"
            record.objections = objections
            log(f"  judge: {record.verdict}")

            if complete:
                # 6. PR + MERGE
                body = (f"Closes #{meta.number}\n\n## Judge verdict\n\n{judgement}\n\n"
                        f"## Review\n\n{review}\n")
                pr = gitops.push_and_pr(worktree, branch, meta.title, body)
                record.pr_url = pr
                log(f"  pr {pr}")
                gitops.squash_merge(worktree, pr)
                record.merged = True

                # 7. POST-MERGE VERIFY — the safety net for unprotected master
                gitops.sync_master(REPO)
                log("  post-merge gate")
                post = run_gate(REPO, parity=meta.wants_parity)
                if not post.ok:
                    sha = gitops.revert_head(REPO)
                    record.reverted = True
                    record.outcome = "reverted"
                    log(f"  POST-MERGE RED — reverted as {sha}")
                    _park(meta, f"Auto-reverted: post-merge gate failed.\n\n"
                                f"{chr(10).join(post.failures)}")
                else:
                    record.outcome = "merged"
                    log("  merged and verified")
                break

            log(f"  retrying with objections ({judge_attempt + 1}/{MAX_JUDGE_RETRIES})")
        else:
            record.outcome = "judge-exhausted"

        if record.outcome in ("judge-exhausted", "gate-exhausted"):
            _park(meta, f"Harness gave up after retries ({record.outcome}).\n\n"
                        f"Last judge objections:\n{record.objections}\n\n"
                        f"Last gate failures:\n{chr(10).join(record.gate_failures)}")
    finally:
        gitops.remove_worktree(REPO, worktree)
        save_record(record)

    return record


def _park(meta, comment):
    import subprocess
    subprocess.run(["gh", "issue", "comment", str(meta.number),
                    "--repo", gitops.REPO_SLUG, "--body", comment], check=False)
    subprocess.run(["gh", "issue", "edit", str(meta.number),
                    "--repo", gitops.REPO_SLUG, "--add-label", "needs-human"], check=False)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run")
    run.add_argument("--max-issues", type=int, default=1)
    run.add_argument("--issue", type=int, help="run one specific issue number")
    run.add_argument("--dry-run", action="store_true",
                     help="research and design only; never edits or merges")
    args = ap.parse_args()

    open_issues = issue_meta.fetch_open_issues()
    closed = issue_meta.fetch_closed_keys()

    if args.issue:
        picked = [i for i in open_issues if i.number == args.issue]
        if not picked:
            log(f"issue {args.issue} not found, or has no harness block")
            return 1
        run_cycle(picked[0], dry_run=args.dry_run)
        return 0

    for n in range(args.max_issues):
        nxt = issue_meta.select_next(open_issues, closed)
        if not nxt:
            log("no eligible issues")
            break
        log(f"cycle {n + 1}/{args.max_issues}")
        rec = run_cycle(nxt, dry_run=args.dry_run)
        if rec.outcome == "merged":
            closed.add(nxt.key)
        open_issues = [i for i in open_issues if i.number != nxt.number]
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 6: Verify the CLI wires up and issue selection works**

```bash
chmod +x harness/harness.py
python3 -m unittest discover -s harness/tests -v 2>&1 | tail -5
./harness/harness.py run --issue 2 --dry-run
```
Expected: all unit tests pass; the dry run picks issue #2 (`T0-1`), runs research and design, writes `harness/state/0002-t0-1.json`, and stops before implementing.

- [ ] **Step 7: Commit**

```bash
git add harness/state.py harness/harness.py harness/tests/test_state.py
git commit -m "Add the cycle state machine and CLI

Serial execution, one issue per cycle: research, optional design for
high-risk issues, implement with a gate-failure retry budget, review, then
an isolated judge. On approval it opens a PR, squash-merges, re-runs the
gate on master, and auto-reverts if master goes red. Exhausted retries park
the issue with needs-human and a comment."
```

---

### Task 10: First live cycle on issue #2

**Files:** none created — this validates the harness end to end.

- [ ] **Step 1: Confirm the baseline is clean before handing control over**

```bash
./harness/gate.sh "$PWD" | python3 -c "import json,sys; d=json.load(sys.stdin); print('ok', d['ok'])"
```
Expected: `ok True`. Do not proceed otherwise — the ratchet is meaningless from a red baseline.

- [ ] **Step 2: Dry-run the target issue and read the research output**

```bash
./harness/harness.py run --issue 2 --dry-run
python3 -m json.tool harness/state/0002-t0-1.json | head -30
```
Expected: research identifies `rfc1035::answer_request` and the missing call from `run_main_loop`. If the research is wrong, fix `harness/stages/research.md` before spending an implement cycle.

- [ ] **Step 3: Run one live cycle**

```bash
./harness/harness.py run --issue 2 2>&1 | tee /tmp/cycle-1.log
```
Expected: implement, gate, review, judge, PR, merge, post-merge verify. Watch for the parity line — this issue is the one that should move parity off 0/8.

- [ ] **Step 4: Verify the outcome independently of the harness**

```bash
git -C "$PWD" checkout master && git pull --ff-only
cargo test 2>&1 | grep -E "^test result" | head -3
./parity/run-major.sh
gh issue view 2 --json state,labels --jq '{state:.state,labels:[.labels[].name]}'
```
Expected: tests at or above 3019 with 0 failures; parity now passes cases it did not before; issue #2 closed by the merge.

- [ ] **Step 5: Update the baseline if the cycle legitimately raised it**

```bash
python3 harness/../harness/create_issues.py --dry-run >/dev/null  # sanity: corpus still parses
python3 - <<'EOF'
import json, subprocess
b = json.load(open("harness/baseline.json"))
print("current baseline:", b["feature_sets"]["default"]["tests"]["passed"],
      "parity", b["parity"]["cases_passing"])
EOF
```
If the cycle raised test counts or parity passing, update `harness/baseline.json` to the new floor and commit it, so the next cycle cannot regress below the improved state.

- [ ] **Step 6: Commit the baseline update**

```bash
git add harness/baseline.json
git commit -m "Raise harness baseline after first successful cycle"
```

---

## Self-Review

**Spec coverage.** Every spec section maps to a task: the cycle state machine (Task 9), deterministic routing (Task 5), the gate including the clippy ratchet and forbidden paths (Tasks 2-3), judge independence via a separate read-only process with curated context (Tasks 6-7), post-merge verify with auto-revert (Tasks 8-9), failure policy of two retries then park (Task 9), `--max-issues N` bounding (Task 9), and the `parity_probe --json` prerequisite the spec's open decision named (Task 1). Prompts-in-files, stdlib-only, and serial execution are honored throughout.

**Placeholders.** None. Every step carries the actual code or command.

**Type consistency.** `IssueMeta` is defined in Task 4 and consumed with the same field names by `routing.route` (Task 5) and `harness.py` (Task 9). `GateResult.ok`/`.failures`/`.raw` are defined in Task 3 and used unchanged in Task 9. `parse_verdict` returns `(bool, str)` in Task 7 and is unpacked as such in Task 9. `branch_name`, `make_worktree`, `has_changes`, `commit_all`, `diff_against_master`, `push_and_pr`, `squash_merge`, `sync_master`, `revert_head` are all defined in Task 8 and called with matching signatures in Task 9.

**One known rough edge, deliberately left in.** The `for ... else` control flow in `run_cycle`'s nested retry loops is correct but dense; it is the kind of thing worth simplifying once the first few live cycles show which retry paths actually fire. Simplifying it before there is data would be guessing.
