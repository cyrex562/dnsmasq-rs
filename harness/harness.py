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


def _record_stage(record, name, model, fn):
    log(f"  {name} ({model})")
    try:
        out = fn()
    except Exception as e:  # noqa: BLE001 — recorded, then re-raised
        record.stages.append({"stage": name, "model": model, "ok": False, "error": str(e)})
        raise
    record.stages.append({"stage": name, "model": model, "ok": True})
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
        gate_output = "\n".join(result.failures) or "gate clean"
        if result.ok:
            return result, gate_output
        log(f"  gate failed: {gate_output[:200]}")

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

    # The safety net for an unprotected master: verify what actually landed.
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
        _record_stage(record, "design", "opus", lambda: claude_runner.run_stage(
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
            judgement = _record_stage(record, "judge", "opus", lambda: claude_runner.run_stage(
                "judge", "opus", worktree,
                claude_runner.render("judge", diff=diff, gate_output=gate_output, **common),
                read_only=True))

            complete, objections = claude_runner.parse_verdict(judgement)
            record.verdict = "complete" if complete else "incomplete"
            record.objections = objections
            log(f"  judge: {record.verdict}")

            if complete:
                _merge_and_verify(meta, record, worktree, branch, judgement, review)
                break

            log(f"  retrying with objections ({judge_attempt + 1}/{MAX_JUDGE_RETRIES})")
        else:
            record.outcome = "judge-exhausted"

        if record.outcome in ("judge-exhausted", "gate-exhausted"):
            _park(meta, f"Harness gave up after retries ({record.outcome}).\n\n"
                        f"Last judge objections:\n{record.objections or 'none'}\n\n"
                        f"Last gate failures:\n" + ("\n".join(record.gate_failures) or "none"))
    except Exception as e:  # noqa: BLE001
        record.outcome = f"error: {e}"
        log(f"  ERROR {e}")
    finally:
        gitops.remove_worktree(REPO, worktree)
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
