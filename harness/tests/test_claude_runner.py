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

    def test_unused_kwargs_are_harmless(self):
        out = render("research", number=1, title="t", body="b", port_file="p",
                     upstream_file="u", key="k", repo="r", unused="x")
        self.assertNotIn("unused", out)

    def test_missing_kwarg_leaves_placeholder_rather_than_raising(self):
        out = render("research", number=1, title="t")
        self.assertIn("{body}", out)

    def test_judge_template_renders(self):
        out = render("judge", number=1, title="t", body="b", diff="d",
                     gate_output="g", upstream_file="u")
        self.assertIn("VERDICT", out)
        self.assertNotIn("{diff}", out)


class TestVerdict(unittest.TestCase):
    def test_complete(self):
        ok, obj = parse_verdict("VERDICT: complete\n")
        self.assertTrue(ok)
        self.assertEqual(obj, "")

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

    def test_verdict_buried_past_the_head_does_not_count(self):
        buried = "\n".join(["filler"] * 40 + ["VERDICT: complete"])
        ok, obj = parse_verdict(buried)
        self.assertFalse(ok)
        self.assertIn("no VERDICT line", obj)

    def test_verdict_within_head_still_counts(self):
        text = "\n".join(["preamble", "more"] + ["VERDICT: complete"])
        self.assertTrue(parse_verdict(text)[0])

    def test_empty_output_is_incomplete(self):
        self.assertFalse(parse_verdict("")[0])


class TestPermissions(unittest.TestCase):
    """The implement stage runs unattended on a developer machine. It must not
    get arbitrary shell by default."""

    def test_write_tools_exclude_network_and_destructive_commands(self):
        from claude_runner import WRITE_TOOLS
        for banned in ("curl", "wget", "rm:", "sudo", "ssh", "pip", "npm"):
            self.assertNotIn(banned, WRITE_TOOLS)

    def test_write_tools_cover_what_implement_needs(self):
        from claude_runner import WRITE_TOOLS
        for needed in ("Write", "Edit", "Bash(cargo:*)", "Bash(git:*)"):
            self.assertIn(needed, WRITE_TOOLS)

    def test_read_only_tools_grant_no_write_capability(self):
        from claude_runner import READ_ONLY_TOOLS
        for banned in ("Write", "Edit", "Bash(git commit", "Bash(git add"):
            self.assertNotIn(banned, READ_ONLY_TOOLS)


if __name__ == "__main__":
    unittest.main()
