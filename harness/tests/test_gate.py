import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from gate import compare_to_baseline, parity_is_usable  # noqa: E402

BASE = {
    "feature_sets": {
        "default": {"tests": {"passed": 3019, "failed": 0}, "clippy_warnings": 198},
        "all-features": {"tests": {"passed": 3059, "failed": 0}, "clippy_warnings": 200},
        "no-default-features": {"tests": {"passed": 1613, "failed": 0}, "clippy_warnings": 145},
    },
    "parity": {"cases_total": 8, "cases_passing": 0},
}


def raw(passed=(3019, 3059, 1613), clippy=(198, 200, 145), failed=(0, 0, 0), parity=None):
    names = ["default", "all-features", "no-default-features"]
    return {
        "ok": True,
        "stages": [],
        "tests": {n: {"passed": p, "failed": f} for n, p, f in zip(names, passed, failed)},
        "clippy": dict(zip(names, clippy)),
        "parity": parity,
    }


def parity_doc(statuses, details=None):
    details = details or ["" for _ in statuses]
    cases = [
        {"name": f"c{i}", "qtype": "A", "status": s, "detail": d}
        for i, (s, d) in enumerate(zip(statuses, details))
    ]
    return {
        "total": len(cases),
        "passing": sum(1 for s in statuses if s == "ok"),
        "cases": cases,
    }


class TestCompare(unittest.TestCase):
    def test_clean_run_has_no_regressions(self):
        self.assertEqual(compare_to_baseline(raw(), BASE), [])

    def test_test_failure_is_a_regression(self):
        out = compare_to_baseline(raw(failed=(1, 0, 0)), BASE)
        self.assertTrue(any("failed" in m for m in out))

    def test_fewer_tests_is_a_regression(self):
        out = compare_to_baseline(raw(passed=(3018, 3059, 1613)), BASE)
        self.assertTrue(any("3018" in m for m in out))

    def test_more_tests_is_fine(self):
        self.assertEqual(compare_to_baseline(raw(passed=(3100, 3059, 1613)), BASE), [])

    def test_more_clippy_warnings_is_a_regression(self):
        out = compare_to_baseline(raw(clippy=(199, 200, 145)), BASE)
        self.assertTrue(any("clippy" in m for m in out))

    def test_fewer_clippy_warnings_is_fine(self):
        self.assertEqual(compare_to_baseline(raw(clippy=(150, 200, 145)), BASE), [])

    def test_parity_regression_detected(self):
        base = dict(BASE, parity={"cases_total": 8, "cases_passing": 3})
        out = compare_to_baseline(raw(parity=parity_doc(["ok", "ok", "mismatch"])), base)
        self.assertTrue(any("parity" in m for m in out))

    def test_parity_improvement_is_fine(self):
        out = compare_to_baseline(raw(parity=parity_doc(["ok"] * 5)), BASE)
        self.assertEqual(out, [])

    def test_absent_parity_is_not_a_regression(self):
        self.assertEqual(compare_to_baseline(raw(parity=None), BASE), [])


class TestParityUsable(unittest.TestCase):
    """A parity run where the UPSTREAM container never answered tells us
    nothing about the candidate. Counting it as 0 passing would manufacture a
    false regression the moment the baseline rises above zero."""

    def test_all_upstream_failures_is_not_usable(self):
        doc = parity_doc(
            ["error"] * 3,
            ["upstream query failed: timeout"] * 3,
        )
        self.assertFalse(parity_is_usable(doc))

    def test_candidate_failures_are_usable(self):
        doc = parity_doc(
            ["error"] * 3,
            ["candidate query failed: timeout"] * 3,
        )
        self.assertTrue(parity_is_usable(doc))

    def test_mixed_results_are_usable(self):
        doc = parity_doc(["ok", "mismatch"], ["", "differs"])
        self.assertTrue(parity_is_usable(doc))

    def test_none_is_not_usable(self):
        self.assertFalse(parity_is_usable(None))

    def test_unusable_parity_is_skipped_in_comparison(self):
        base = dict(BASE, parity={"cases_total": 8, "cases_passing": 5})
        doc = parity_doc(["error"] * 8, ["upstream query failed: x"] * 8)
        self.assertEqual(compare_to_baseline(raw(parity=doc), base), [])


if __name__ == "__main__":
    unittest.main()
