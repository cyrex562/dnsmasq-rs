import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import gitops  # noqa: E402
from gitops import (branch_name, commit_all, diff_against_master, has_changes,  # noqa: E402
                    make_worktree, remove_worktree, squash_merge)


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


class TestBranchName(unittest.TestCase):
    def test_includes_key(self):
        self.assertIn("t0-1", branch_name("T0-1", 0).lower())

    def test_attempt_suffix_on_retry(self):
        self.assertNotEqual(branch_name("T0-1", 0), branch_name("T0-1", 1))

    def test_is_git_safe(self):
        n = branch_name("T3-dhcp-common", 2)
        for bad in (" ", "~", "^", ":", "?", "*", "["):
            self.assertNotIn(bad, n)

    def test_sanitizes_unusual_keys(self):
        n = branch_name("T3/weird key", 0)
        self.assertNotIn(" ", n)
        self.assertTrue(n.startswith("harness/"))


class TestWorktree(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp()
        git(self.repo, "init", "-q", "-b", "master")
        git(self.repo, "config", "user.email", "t@t")
        git(self.repo, "config", "user.name", "t")
        with open(os.path.join(self.repo, "a.txt"), "w") as f:
            f.write("one\n")
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
        with open(os.path.join(wt, "a.txt"), "w") as f:
            f.write("two\n")
        self.assertTrue(has_changes(wt))
        commit_all(wt, "change a")
        self.assertTrue(has_changes(wt))  # committed but ahead of master
        d = diff_against_master(wt)
        self.assertIn("two", d)
        remove_worktree(self.repo, wt)

    def test_untouched_worktree_reports_no_changes(self):
        wt = make_worktree(self.repo, "feature-z")
        self.assertFalse(has_changes(wt))
        self.assertEqual(diff_against_master(wt).strip(), "")
        remove_worktree(self.repo, wt)


class TestSquashMerge(unittest.TestCase):
    """Regression: the first live cycle merged successfully, but
    `gh pr merge --delete-branch` exited 1 because the branch was still checked
    out in the worktree. squash_merge raised, the cycle unwound past the
    post-merge gate, and an unverified merge sat on master. Success must be
    decided by PR state, not by gh's exit code."""

    def setUp(self):
        self._run = gitops._run
        self._calls = []

    def tearDown(self):
        gitops._run = self._run

    def _fake(self, merge_rc=1, state="MERGED"):
        class R:
            def __init__(self, stdout="", stderr="", rc=0):
                self.stdout, self.stderr, self.returncode = stdout, stderr, rc

        def fake(cwd, *args, check=True):
            self._calls.append(args)
            if "merge" in args:
                if merge_rc and check:
                    raise AssertionError("merge must be called with check=False")
                return R(stderr="failed to delete branch", rc=merge_rc)
            if "view" in args:
                return R(stdout=state)
            return R()

        gitops._run = fake

    def test_merge_succeeds_when_gh_exits_nonzero_but_pr_is_merged(self):
        self._fake(merge_rc=1, state="MERGED")
        self.assertEqual(squash_merge("/tmp", "url"), "MERGED")

    def test_merge_raises_when_pr_is_not_merged(self):
        self._fake(merge_rc=1, state="OPEN")
        with self.assertRaises(RuntimeError):
            squash_merge("/tmp", "url")

    def test_merge_does_not_pass_delete_branch(self):
        self._fake(merge_rc=0, state="MERGED")
        squash_merge("/tmp", "url")
        merge_call = [c for c in self._calls if "merge" in c][0]
        self.assertNotIn("--delete-branch", merge_call)


if __name__ == "__main__":
    unittest.main()
