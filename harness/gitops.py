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
    """Create a throwaway worktree for one cycle, branched fresh from master.

    Uses `-B`, not `-b`: re-running an issue that was parked or interrupted
    would otherwise collide with the branch its previous attempt left behind
    and fail before doing any work. Resetting is safe because a cycle always
    starts from master anyway, and parked work is preserved on the remote by
    push_branch before the worktree is destroyed.
    """
    path = tempfile.mkdtemp(prefix="harness-wt-")
    os.rmdir(path)  # `git worktree add` wants a non-existent path
    _run(repo, "git", "worktree", "add", "-B", branch, path, BASE_BRANCH)
    return path


def remove_worktree(repo, path):
    _run(repo, "git", "worktree", "remove", "--force", path, check=False)


def has_changes(worktree):
    """True if the worktree differs from master, uncommitted or committed."""
    if _run(worktree, "git", "status", "--porcelain").stdout.strip():
        return True
    ahead = _run(worktree, "git", "rev-list", "--count",
                 f"{BASE_BRANCH}..HEAD").stdout.strip()
    return ahead not in ("", "0")


def commit_all(worktree, message):
    _run(worktree, "git", "add", "-A")
    _run(worktree, "git", "commit", "-m", message, check=False)


def diff_against_master(worktree):
    return _run(worktree, "git", "diff", f"{BASE_BRANCH}...HEAD").stdout


def push_and_pr(worktree, branch, title, body):
    # --force-with-lease, because the cycle owns this branch name: a previous
    # parked or interrupted attempt may have pushed to it, and a plain push is
    # then rejected as non-fast-forward. Cycle 4 lost an approved, gate-clean
    # diff that way — the judge had already returned complete. The lease still
    # protects against clobbering a push we have not seen.
    _run(worktree, "git", "push", "--force-with-lease", "-u", "origin", branch)
    out = _run(
        worktree, "gh", "pr", "create",
        "--repo", REPO_SLUG, "--base", BASE_BRANCH, "--head", branch,
        "--title", title, "--body", body,
    ).stdout.strip()
    return out.splitlines()[-1] if out else ""


def pr_state(worktree, pr_url):
    return _run(worktree, "gh", "pr", "view", pr_url, "--repo", REPO_SLUG,
                "--json", "state", "--jq", ".state", check=False).stdout.strip()


def squash_merge(worktree, pr_url):
    """Squash-merge a PR, deciding success by the PR's state rather than gh's
    exit code.

    `gh pr merge --delete-branch` exits non-zero when branch deletion fails
    even though the merge itself succeeded — and deletion reliably fails while
    the branch is still checked out in the cycle's worktree. Trusting the exit
    code once caused a successful merge to raise, which unwound the cycle past
    the post-merge gate and left an unverified merge on master. The safety net
    must not be skippable by a cleanup failure.

    Branch deletion is handled separately, after the worktree is gone.
    """
    proc = _run(worktree, "gh", "pr", "merge", pr_url, "--squash", check=False)
    state = pr_state(worktree, pr_url)
    if state != "MERGED":
        raise RuntimeError(
            f"merge failed (pr state={state or 'unknown'}): "
            f"{(proc.stderr or proc.stdout).strip()[:500]}"
        )
    return state


def push_branch(worktree, branch):
    """Push a branch without opening a PR. Returns True on success.

    Used to preserve abandoned work when an issue is parked: several rounds of
    converging effort are worth more to whoever picks the issue up than a tidy
    branch list is. Best-effort — failing to preserve work must not turn a park
    into an error.
    """
    proc = _run(worktree, "git", "push", "-u", "origin", branch, check=False)
    return proc.returncode == 0


def delete_remote_branch(repo, branch):
    """Best-effort cleanup. Never raises: a leftover branch is untidy, not unsafe."""
    _run(repo, "git", "push", "origin", "--delete", branch, check=False)


def head_sha(repo):
    return _run(repo, "git", "rev-parse", "HEAD").stdout.strip()


def sync_master(repo):
    _run(repo, "git", "checkout", BASE_BRANCH)
    _run(repo, "git", "pull", "--ff-only", "origin", BASE_BRANCH)


def revert_head(repo):
    """Revert whatever is at master's HEAD and push it.

    This is the safety net that makes unattended auto-merge defensible with an
    unprotected master: if the post-merge gate is red, master goes back. Each
    cycle lands as a single squash commit, so this is a one-command undo.
    """
    _run(repo, "git", "revert", "--no-edit", "HEAD")
    sha = head_sha(repo)
    _run(repo, "git", "push", "origin", BASE_BRANCH)
    return sha
