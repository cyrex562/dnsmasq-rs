import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from issue_meta import IssueMeta  # noqa: E402
from routing import escalate, route  # noqa: E402


def m(risk="medium", model="sonnet", port_file="src/util.rs"):
    return IssueMeta(1, "K", 3, risk, model, port_file, "u.c", "full")


class TestRoute(unittest.TestCase):
    def test_judge_is_always_opus(self):
        self.assertEqual(route(m(risk="low", model="haiku"), "judge"), "opus")

    def test_review_is_always_sonnet(self):
        self.assertEqual(route(m(risk="high", model="opus"), "review"), "sonnet")

    def test_research_is_always_sonnet(self):
        self.assertEqual(route(m(risk="high"), "research"), "sonnet")

    def test_implement_uses_issue_model_tier(self):
        self.assertEqual(route(m(model="haiku", risk="low"), "implement"), "haiku")

    def test_hot_file_forces_opus(self):
        self.assertEqual(
            route(m(model="haiku", risk="low", port_file="src/option.rs"), "implement"),
            "opus",
        )

    def test_hot_file_matches_within_a_multi_file_list(self):
        meta = m(model="haiku", risk="low", port_file="src/dnsmasq.rs, src/forward.rs")
        self.assertEqual(route(meta, "implement"), "opus")

    def test_high_risk_forces_opus(self):
        self.assertEqual(route(m(model="haiku", risk="high"), "implement"), "opus")

    def test_retry_escalates_one_tier(self):
        self.assertEqual(route(m(model="sonnet"), "implement", attempt=1), "opus")

    def test_haiku_escalates_to_sonnet_on_first_retry(self):
        self.assertEqual(route(m(model="haiku", risk="low"), "implement", attempt=1), "sonnet")

    def test_escalation_saturates_at_opus(self):
        self.assertEqual(route(m(model="opus"), "implement", attempt=3), "opus")

    def test_judge_does_not_escalate(self):
        self.assertEqual(route(m(), "judge", attempt=2), "opus")

    def test_review_does_not_escalate(self):
        self.assertEqual(route(m(), "review", attempt=2), "sonnet")


class TestEscalate(unittest.TestCase):
    def test_haiku_to_sonnet(self):
        self.assertEqual(escalate("haiku"), "sonnet")

    def test_sonnet_to_opus(self):
        self.assertEqual(escalate("sonnet"), "opus")

    def test_opus_saturates(self):
        self.assertEqual(escalate("opus"), "opus")


if __name__ == "__main__":
    unittest.main()
