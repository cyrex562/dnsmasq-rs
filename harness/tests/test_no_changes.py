import os
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import harness as h  # noqa: E402
from issue_meta import IssueMeta  # noqa: E402


def m():
    return IssueMeta(12, "T1-3", 1, "medium", "sonnet", "src/rfc1035.rs", "u.c", "full")


class TestNoChangesNeeded(unittest.TestCase):
    """Regression: issue #12's implementer correctly found the described bug
    already fixed (by unrelated prior cycles rewriting the same file) and made
    no edits. The harness raised a bare RuntimeError, recorded nothing on the
    issue, and left no trace beyond a local state file."""

    def test_carries_the_implementer_output(self):
        e = h.NoChangesNeeded("my reasoning here")
        self.assertEqual(e.output, "my reasoning here")
        self.assertIn("no changes", str(e))


class TestFlagNoChanges(unittest.TestCase):
    def test_posts_comment_and_labels_without_closing(self):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)

            class R:
                pass
            return R()

        with patch("subprocess.run", fake_run):
            h._flag_no_changes(m(), "the bug is already fixed, see rfc1035.rs:1339")

        joined = [" ".join(c) for c in calls]
        self.assertTrue(any("comment" in c and "12" in c for c in joined))
        self.assertTrue(any("verify-and-close" in c for c in joined))
        # The issue itself must never be closed by this path — only commented
        # and labeled. "gh issue close ..." would be its own distinct command.
        self.assertFalse(any(c[:3] == ["gh", "issue", "close"] for c in calls))

    def test_comment_includes_the_reasoning_verbatim(self):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)

            class R:
                pass
            return R()

        with patch("subprocess.run", fake_run):
            h._flag_no_changes(m(), "SPECIFIC REASONING TEXT")

        bodies = [c[c.index("--body") + 1] for c in calls if "--body" in c]
        self.assertTrue(any("SPECIFIC REASONING TEXT" in b for b in bodies))

    def test_comment_flags_the_claim_as_unverified(self):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)

            class R:
                pass
            return R()

        with patch("subprocess.run", fake_run):
            h._flag_no_changes(m(), "reasoning")

        bodies = [c[c.index("--body") + 1] for c in calls if "--body" in c]
        self.assertTrue(any("unverified" in b.lower() for b in bodies))


class TestParkLabelIsConfigurable(unittest.TestCase):
    def test_default_label_is_needs_human(self):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)

            class R:
                pass
            return R()

        with patch("subprocess.run", fake_run):
            h._park(m(), "some comment")

        joined = [" ".join(c) for c in calls]
        self.assertTrue(any("needs-human" in c for c in joined))

    def test_custom_label_overrides_default(self):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)

            class R:
                pass
            return R()

        with patch("subprocess.run", fake_run):
            h._park(m(), "some comment", label="verify-and-close")

        joined = [" ".join(c) for c in calls]
        self.assertTrue(any("verify-and-close" in c for c in joined))
        self.assertFalse(any("needs-human" in c for c in joined))


class TestHeartbeat(unittest.TestCase):
    """Long stages (implement, judge, gate) ran 10-30+ minutes with zero
    output, which read identically to a hang from the operator's side."""

    def test_stop_function_halts_the_thread(self):
        h.HEARTBEAT_SECS = 0.05
        try:
            stop = h._heartbeat("test-stage")
            time.sleep(0.12)
            stop()
            n_threads_before = threading.active_count()
            time.sleep(0.12)
            n_threads_after = threading.active_count()
            self.assertLessEqual(n_threads_after, n_threads_before)
        finally:
            h.HEARTBEAT_SECS = 60

    def test_emits_at_least_one_liveness_line(self):
        h.HEARTBEAT_SECS = 0.05
        lines = []
        try:
            with patch("builtins.print", lambda *a, **k: lines.append(a[0] if a else "")):
                stop = h._heartbeat("test-stage")
                time.sleep(0.15)
                stop()
        finally:
            h.HEARTBEAT_SECS = 60
        self.assertTrue(any("still running" in ln and "test-stage" in ln for ln in lines))


class TestLogFile(unittest.TestCase):
    """A stable, tailable path so the operator can watch progress directly
    (`tail -f harness/state/harness.log`) instead of asking for a status
    check on every long stage."""

    def test_log_path_is_stable_and_under_harness_state(self):
        self.assertTrue(h.LOG_FILE.endswith(os.path.join("state", "harness.log")))

    def test_log_writes_to_the_file(self):
        with tempfile.TemporaryDirectory() as d:
            fake_path = os.path.join(d, "harness.log")
            orig = h.LOG_FILE
            h.LOG_FILE = fake_path
            try:
                h.log("distinctive test message")
            finally:
                h.LOG_FILE = orig
            with open(fake_path) as f:
                content = f.read()
            self.assertIn("distinctive test message", content)


if __name__ == "__main__":
    unittest.main()
