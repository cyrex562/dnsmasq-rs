import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from gitops import (branch_name, commit_all, diff_against_master, has_changes,  # noqa: E402
                    make_worktree, remove_worktree)


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


if __name__ == "__main__":
    unittest.main()
