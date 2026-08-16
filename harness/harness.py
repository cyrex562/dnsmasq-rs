#!/usr/bin/env python3
"""Autonomous port harness.

  ./harness/harness.py run --max-issues 1
  ./harness/harness.py run --issue 2 --dry-run
  ./harness/harness.py next
"""
import argparse
import os
import subprocess
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

# Gate failures and judge rejections have separate budgets: a diff that will
# not compile is a different problem from one that compiles but misses the
# point, and burning the judge budget on build errors would waste the
# expensive stage.
MAX_GATE_RETRIES = 2
MAX_JUDGE_RETRIES = 2


def log(msg):
    print(f"[harness] {msg}", flush=True)


# Stage outputs are stored so a cycle can be audited after the fact — whether
# the research actually understood the issue, what the judge objected to.
# Truncated because a diff-heavy review can run long and these records are
# meant to stay readable.
MAX_STORED_OUTPUT = 20000


def _parity_line(raw):
    p = (raw or {}).get("parity")
    if not p:
        return "parity: not run"
    return f"parity: {p.get('passing', 0)}/{p.get('total', 0)} cases"


def summarize_gate(result):
    """Render the gate's actual numbers, not just its failures.

    A passing gate used to be reported to the judge as the bare string
    "gate clean". The judge is asked to verify acceptance criteria like
    "parity passes 8/8" — and was handed no parity data to check it against,
    which the first live cycle's judge correctly objected to. The ratchet only
    fails on regression below baseline, so a clean gate proves nothing about
    improvement; the numbers have to travel with it.
    """
    raw = result.raw or {}
    lines = ["status: " + ("clean" if result.ok else "FAILED")]

    tests = raw.get("tests") or {}
    for name, t in tests.items():
        lines.append(f"tests[{name}]: {t.get('passed', 0)} passed, {t.get('failed', 0)} failed")

    clippy = raw.get("clippy") or {}
    for name, n in clippy.items():
        lines.append(f"clippy[{name}]: {n} warnings")

    lines.append(_parity_line(raw))
    p = raw.get("parity")
    if p:
        for c in p.get("cases", []):
            lines.append(f"  parity case {c['name']} {c['qtype']}: {c['status']}"
                         + (f" ({c['detail'][:120]})" if c.get("detail") else ""))

    if result.failures:
        lines.append("failures:")
        lines.extend(f"  - {f}" for f in result.failures)

    return "\n".join(lines)


def _record_stage(record, name, model, fn):
    log(f"  {name} ({model})")
    try:
        out = fn()
    except Exception as e:  # noqa: BLE001 — recorded, then re-raised
        record.stages.append({"stage": name, "model": model, "ok": False, "error": str(e)})
        raise
    text = out if isinstance(out, str) else str(out)
    record.stages.append({
        "stage": name,
        "model": model,
        "ok": True,
        "output": text[:MAX_STORED_OUTPUT],
        "truncated": len(text) > MAX_STORED_OUTPUT,
    })
    return out


def _implement_until_gate_passes(meta, record, worktree, common, research,
                                 objections, base_attempt):
    """Run implement/gate until the gate is clean or the budget is spent.

    Returns (GateResult, gate_output) on success, or (None, gate_output) if the
    retry budget was exhausted.
    """
    gate_output = ""
    for gate_attempt in range(MAX_GATE_RETRIES + 1):
        model = routing.route(meta, "implement", attempt=base_attempt + gate_attempt)
        prompt = claude_runner.render(
            "implement", research=research, gate_output=gate_output,
            objections=objections, **common)
        _record_stage(
            record, f"implement.j{base_attempt}.g{gate_attempt}", model,
            lambda p=prompt, m=model: claude_runner.run_stage("implement", m, worktree, p))

        if not gitops.has_changes(worktree):
            raise RuntimeError("implement stage produced no changes")
        gitops.commit_all(worktree, f"{meta.title}\n\nCloses #{meta.number}")

        log("  gate")
        result = run_gate(worktree, parity=meta.wants_parity)
        record.gate_failures = result.failures
        gate_output = summarize_gate(result)
        if result.ok:
            log(f"  gate clean | {_parity_line(result.raw)}")
            return result, gate_output
        log(f"  gate failed: {'; '.join(result.failures)[:200]}")

    return None, gate_output


def _merge_and_verify(meta, record, worktree, branch, judgement, review):
    body = (f"Closes #{meta.number}\n\n"
            f"## Judge verdict\n\n{judgement}\n\n"
            f"## Review\n\n{review}\n")
    pr = gitops.push_and_pr(worktree, branch, meta.title, body)
    record.pr_url = pr
    log(f"  pr {pr}")

    gitops.squash_merge(worktree, pr)
    record.merged = True
    _verify_or_revert(meta, record)


def _verify_or_revert(meta, record):
    """The safety net for an unprotected master: verify what actually landed.

    Nothing may skip this once a merge has happened. It runs from the normal
    path and again from the cycle's error handler, because the first live cycle
    proved that an exception raised *after* a successful merge silently bypasses
    verification and leaves master unchecked.
    """
    gitops.sync_master(REPO)
    log("  post-merge gate")
    post = run_gate(REPO, parity=meta.wants_parity)
    if post.ok:
        record.outcome = "merged"
        log("  merged and verified")
        return

    sha = gitops.revert_head(REPO)
    record.reverted = True
    record.outcome = "reverted"
    log(f"  POST-MERGE RED — reverted as {sha}")
    _park(meta, "Auto-reverted: the post-merge gate failed on master.\n\n"
                + "\n".join(post.failures))


def run_cycle(meta, dry_run=False):
    record = CycleRecord(key=meta.key, number=meta.number, title=meta.title)
    log(f"issue #{meta.number} [{meta.key}] {meta.title}")

    common = dict(key=meta.key, number=meta.number, title=meta.title, body=meta.body,
                  port_file=meta.port_file, upstream_file=meta.upstream_file,
                  repo=gitops.REPO_SLUG)

    research = _record_stage(record, "research", "sonnet", lambda: claude_runner.run_stage(
        "research", "sonnet", REPO,
        claude_runner.render("research", **common), read_only=True))

    if meta.risk == "high":
        design_model = routing.route(meta, "design")
        _record_stage(record, "design", design_model, lambda: claude_runner.run_stage(
            "design", design_model, REPO,
            claude_runner.render("design", research=research, **common), read_only=True))

    if dry_run:
        record.outcome = "dry-run"
        save_record(record)
        log("  dry run — stopping before implement")
        return record

    branch = gitops.branch_name(meta.key)
    worktree = gitops.make_worktree(REPO, branch)
    log(f"  worktree {worktree}")

    objections = ""
    try:
        for judge_attempt in range(MAX_JUDGE_RETRIES + 1):
            result, gate_output = _implement_until_gate_passes(
                meta, record, worktree, common, research, objections, judge_attempt)
            if result is None:
                record.outcome = "gate-exhausted"
                break

            diff = gitops.diff_against_master(worktree)

            review = _record_stage(record, "review", "sonnet", lambda: claude_runner.run_stage(
                "review", "sonnet", worktree,
                claude_runner.render("review", diff=diff, **common), read_only=True))

            # Fresh process, curated context, no implementer or reviewer narrative.
            judge_model = routing.route(meta, "judge")
            judgement = _record_stage(record, "judge", judge_model, lambda: claude_runner.run_stage(
                "judge", judge_model, worktree,
                claude_runner.render("judge", diff=diff, gate_output=gate_output, **common),
                read_only=True))

            complete, objections = claude_runner.parse_verdict(judgement)
            record.verdict = "complete" if complete else "incomplete"
            record.objections = objections
            log(f"  judge: {record.verdict}")

            if complete:
                _merge_and_verify(meta, record, worktree, branch, judgement, review)
                break

            if judge_attempt < MAX_JUDGE_RETRIES:
                log(f"  retrying with objections ({judge_attempt + 1}/{MAX_JUDGE_RETRIES})")
        else:
            record.outcome = "judge-exhausted"

        if record.outcome in ("judge-exhausted", "gate-exhausted"):
            # Push the abandoned work before the worktree is destroyed. Several
            # rounds of converging effort are worth more to whoever picks the
            # issue up than a clean branch list is.
            pushed = gitops.push_branch(worktree, branch)
            record.parked_branch = branch if pushed else ""
            _park(meta, f"Harness gave up after retries ({record.outcome}).\n\n"
                        + (f"Work so far is pushed to `{branch}`.\n\n" if pushed else "")
                        + f"Last judge objections:\n{record.objections or 'none'}\n\n"
                        + "Last gate failures:\n"
                        + ("\n".join(record.gate_failures) or "none"))
    except Exception as e:  # noqa: BLE001
        record.outcome = f"error: {e}"
        log(f"  ERROR {e}")
        # A merge may have landed before the failure. Verification is the only
        # thing protecting an unprotected master, so it must survive any
        # exception raised after the merge — not just the ones we predicted.
        if record.pr_url and not record.reverted:
            try:
                if gitops.pr_state(REPO, record.pr_url) == "MERGED":
                    record.merged = True
                    log("  merge landed despite the error — verifying anyway")
                    _verify_or_revert(meta, record)
            except Exception as verify_err:  # noqa: BLE001
                log(f"  POST-MERGE VERIFICATION FAILED TO RUN: {verify_err}")
                record.outcome = f"unverified-merge: {verify_err}"
    finally:
        gitops.remove_worktree(REPO, worktree)
        # Only after the worktree is gone, or the branch is still checked out
        # and deletion fails.
        if record.merged:
            gitops.delete_remote_branch(REPO, branch)
        save_record(record)

    return record


def _park(meta, comment):
    subprocess.run(["gh", "issue", "comment", str(meta.number),
                    "--repo", gitops.REPO_SLUG, "--body", comment], check=False)
    subprocess.run(["gh", "issue", "edit", str(meta.number),
                    "--repo", gitops.REPO_SLUG, "--add-label", "needs-human"], check=False)


def cmd_next(_args):
    open_issues = issue_meta.fetch_open_issues()
    closed = issue_meta.fetch_closed_keys()
    nxt = issue_meta.select_next(open_issues, closed)
    if not nxt:
        log("no eligible issues")
        return 1
    print(f"{nxt.key}  #{nxt.number}  risk={nxt.risk}  "
          f"model={routing.route(nxt, 'implement')}  parity={nxt.wants_parity}")
    print(f"  {nxt.title}")
    return 0


def cmd_run(args):
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


def main():
    ap = argparse.ArgumentParser(description="Autonomous dnsmasq port harness")
    sub = ap.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="run one or more cycles")
    run.add_argument("--max-issues", type=int, default=1)
    run.add_argument("--issue", type=int, help="run one specific issue number")
    run.add_argument("--dry-run", action="store_true",
                     help="research and design only; never edits, commits, or merges")
    run.set_defaults(func=cmd_run)

    nxt = sub.add_parser("next", help="show which issue would run next")
    nxt.set_defaults(func=cmd_next)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
