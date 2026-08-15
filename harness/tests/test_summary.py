import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gate import GateResult  # noqa: E402
import harness as h  # noqa: E402

RAW = {
    "tests": {"default": {"passed": 3033, "failed": 0}},
    "clippy": {"default": 198},
    "parity": {"total": 8, "passing": 8,
               "cases": [{"name": "host.test", "qtype": "A", "status": "ok", "detail": ""}]},
}


class TestSummarizeGate(unittest.TestCase):
    """A clean gate must carry its numbers. The judge verifies criteria like
    'parity passes 8/8' and previously received only the string 'gate clean'."""

    def test_clean_gate_includes_test_counts(self):
        s = h.summarize_gate(GateResult(True, [], RAW))
        self.assertIn("3033 passed", s)

    def test_clean_gate_includes_parity_totals(self):
        s = h.summarize_gate(GateResult(True, [], RAW))
        self.assertIn("parity: 8/8", s)

    def test_clean_gate_includes_per_case_parity(self):
        s = h.summarize_gate(GateResult(True, [], RAW))
        self.assertIn("host.test A: ok", s)

    def test_clean_gate_is_not_just_the_words_gate_clean(self):
        s = h.summarize_gate(GateResult(True, [], RAW))
        self.assertNotEqual(s.strip(), "gate clean")
        self.assertGreater(len(s.splitlines()), 3)

    def test_failures_are_listed(self):
        s = h.summarize_gate(GateResult(False, ["default: 199 clippy warnings"], RAW))
        self.assertIn("FAILED", s)
        self.assertIn("199 clippy", s)

    def test_missing_parity_says_not_run(self):
        s = h.summarize_gate(GateResult(True, [], {"tests": {}, "clippy": {}}))
        self.assertIn("parity: not run", s)


if __name__ == "__main__":
    unittest.main()
