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
    os.rmdir(path)  # `git worktree add` wants a non-existent path
    _run(repo, "git", "worktree", "add", "-b", branch, path, BASE_BRANCH)
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
    """Revert whatever is at master's HEAD and push it.

    This is the safety net that makes unattended auto-merge defensible with an
    unprotected master: if the post-merge gate is red, master goes back. Each
    cycle lands as a single squash commit, so this is a one-command undo.
    """
    _run(repo, "git", "revert", "--no-edit", "HEAD")
    sha = head_sha(repo)
    _run(repo, "git", "push", "origin", BASE_BRANCH)
    return sha
