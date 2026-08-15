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


def parity_is_usable(parity):
    """True when a parity document actually says something about the candidate.

    If every case failed because the UPSTREAM container never answered, the run
    tells us nothing about our own binary — the fixture infrastructure was not
    ready. Treating that as "0 cases passing" would manufacture a false
    regression as soon as the baseline rises above zero, which is exactly the
    failure mode that would make the ratchet untrustworthy.
    """
    if not parity:
        return False
    cases = parity.get("cases") or []
    if not cases:
        return False
    return not all(
        c.get("status") == "error" and "upstream query failed" in (c.get("detail") or "")
        for c in cases
    )


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
    if base_parity and parity_is_usable(parity):
        if parity.get("passing", 0) < base_parity.get("cases_passing", 0):
            out.append(
                f"parity: {parity['passing']}/{parity['total']} cases passing, "
                f"below baseline {base_parity['cases_passing']}"
            )

    return out


def run_gate(repo_dir, parity=False, baseline_path=BASELINE):
    cmd = [GATE_SH, repo_dir] + (["--parity"] if parity else [])
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
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
