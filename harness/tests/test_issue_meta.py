import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from issue_meta import parse_meta, select_next  # noqa: E402

BODY = """Some prose here.

## Harness metadata

```harness
key: T0-2
tier: 0
risk: high
model-tier: opus
port-file: src/forward.rs
upstream-file: original_dnsmasq_src/dnsmasq-master/src/forward.c
gate-profile: full+parity
blocked-by: T0-1
```
"""


def meta(number, key, tier, blocked="none"):
    body = (BODY.replace("key: T0-2", f"key: {key}")
                .replace("tier: 0", f"tier: {tier}")
                .replace("blocked-by: T0-1", f"blocked-by: {blocked}"))
    return parse_meta(number, f"title {key}", body)


class TestParse(unittest.TestCase):
    def test_parses_all_fields(self):
        m = parse_meta(3, "Wire the DNS cache", BODY)
        self.assertEqual(m.key, "T0-2")
        self.assertEqual(m.tier, 0)
        self.assertEqual(m.risk, "high")
        self.assertEqual(m.model, "opus")
        self.assertEqual(m.port_file, "src/forward.rs")
        self.assertEqual(m.gate_profile, "full+parity")
        self.assertEqual(m.blocked_by, ["T0-1"])
        self.assertEqual(m.number, 3)

    def test_wants_parity_reflects_gate_profile(self):
        self.assertTrue(parse_meta(3, "t", BODY).wants_parity)
        plain = BODY.replace("gate-profile: full+parity", "gate-profile: full")
        self.assertFalse(parse_meta(3, "t", plain).wants_parity)

    def test_blocked_by_none_is_empty_list(self):
        self.assertEqual(meta(9, "T0-8", 0, "none").blocked_by, [])

    def test_multiple_blockers(self):
        self.assertEqual(meta(9, "T0-8", 0, "T0-1,T0-2").blocked_by, ["T0-1", "T0-2"])

    def test_body_without_block_returns_none(self):
        self.assertIsNone(parse_meta(1, "t", "no metadata here"))

    def test_block_missing_required_field_returns_none(self):
        broken = BODY.replace("key: T0-2\n", "")
        self.assertIsNone(parse_meta(1, "t", broken))

    def test_none_body_returns_none(self):
        self.assertIsNone(parse_meta(1, "t", None))


class TestSelect(unittest.TestCase):
    def test_lowest_tier_wins(self):
        issues = [meta(30, "T3-a", 3), meta(2, "T0-1", 0)]
        self.assertEqual(select_next(issues, set()).key, "T0-1")

    def test_lowest_number_breaks_ties(self):
        issues = [meta(5, "T0-4", 0), meta(2, "T0-1", 0)]
        self.assertEqual(select_next(issues, set()).number, 2)

    def test_blocked_issue_is_skipped(self):
        issues = [meta(3, "T0-2", 0, "T0-1"), meta(9, "T0-8", 0, "none")]
        self.assertEqual(select_next(issues, set()).key, "T0-8")

    def test_blocked_issue_unlocks_when_blocker_closed(self):
        issues = [meta(3, "T0-2", 0, "T0-1")]
        self.assertIsNone(select_next(issues, set()))
        self.assertEqual(select_next(issues, {"T0-1"}).key, "T0-2")

    def test_partially_satisfied_blockers_still_block(self):
        issues = [meta(9, "T0-8", 0, "T0-1,T0-2")]
        self.assertIsNone(select_next(issues, {"T0-1"}))
        self.assertEqual(select_next(issues, {"T0-1", "T0-2"}).key, "T0-8")

    def test_no_eligible_issues_returns_none(self):
        self.assertIsNone(select_next([], set()))


if __name__ == "__main__":
    unittest.main()
