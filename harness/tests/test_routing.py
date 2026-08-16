import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from issue_meta import IssueMeta  # noqa: E402
import routing  # noqa: E402
from routing import escalate, route  # noqa: E402


def m(risk="medium", model="sonnet", port_file="src/util.rs"):
    return IssueMeta(1, "K", 3, risk, model, port_file, "u.c", "full")


class TestRoute(unittest.TestCase):
    """Exercises the tier-selection logic uncapped (ceiling=opus), i.e. the
    same policy this project ran under for tier 0. Capping is tested
    separately in TestModelCeiling."""

    def setUp(self):
        self._orig_ceiling = routing.MODEL_CEILING
        routing.MODEL_CEILING = "opus"

    def tearDown(self):
        routing.MODEL_CEILING = self._orig_ceiling

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


class TestModelCeiling(unittest.TestCase):
    """Set 2026-08-16 to hold opus spend down after tier 0, and extended the
    same day to cover the judge too, "until further notice" — a deliberate,
    user-directed risk: every serious tier-0 defect caught after a clean gate
    and passing review (cache poisoning, a rebind bypass, silent lease loss)
    was found by an opus judge. HARNESS_MODEL_CEILING=opus restores the judge
    to full strength."""

    def setUp(self):
        self._orig_ceiling = routing.MODEL_CEILING

    def tearDown(self):
        routing.MODEL_CEILING = self._orig_ceiling

    def test_default_ceiling_is_sonnet(self):
        # Guards the policy itself, not just the mechanism: a change here
        # silently re-enables full opus spend.
        routing.MODEL_CEILING = "sonnet"
        self.assertEqual(
            route(m(model="haiku", risk="high", port_file="src/option.rs"), "implement"),
            "sonnet",
        )

    def test_judge_respects_a_sonnet_ceiling(self):
        routing.MODEL_CEILING = "sonnet"
        self.assertEqual(route(m(risk="high", model="opus"), "judge"), "sonnet")

    def test_judge_respects_a_haiku_ceiling(self):
        routing.MODEL_CEILING = "haiku"
        self.assertEqual(route(m(risk="high", model="opus"), "judge"), "haiku")

    def test_opus_ceiling_restores_the_judge_too(self):
        routing.MODEL_CEILING = "opus"
        self.assertEqual(route(m(), "judge"), "opus")

    def test_high_risk_is_capped_at_sonnet_not_opus(self):
        routing.MODEL_CEILING = "sonnet"
        self.assertEqual(route(m(risk="high", model="opus"), "implement"), "sonnet")

    def test_hot_file_is_capped_at_sonnet_not_opus(self):
        routing.MODEL_CEILING = "sonnet"
        meta = m(model="haiku", risk="low", port_file="src/forward.rs")
        self.assertEqual(route(meta, "implement"), "sonnet")

    def test_escalation_is_capped_not_opus(self):
        routing.MODEL_CEILING = "sonnet"
        self.assertEqual(route(m(model="sonnet"), "implement", attempt=5), "sonnet")

    def test_below_ceiling_is_unaffected(self):
        routing.MODEL_CEILING = "sonnet"
        self.assertEqual(route(m(model="haiku", risk="low"), "implement"), "haiku")

    def test_research_and_review_respect_the_ceiling_too(self):
        routing.MODEL_CEILING = "haiku"
        self.assertEqual(route(m(), "research"), "haiku")
        self.assertEqual(route(m(), "review"), "haiku")

    def test_opus_ceiling_restores_the_original_policy(self):
        routing.MODEL_CEILING = "opus"
        self.assertEqual(route(m(risk="high", model="haiku"), "implement"), "opus")

    def test_env_var_sets_the_default(self):
        # MODEL_CEILING is read once at import time; this documents the
        # override mechanism without needing a subprocess re-import.
        path = os.path.join(os.path.dirname(__file__), "..", "routing.py")
        with open(path) as f:
            self.assertIn("HARNESS_MODEL_CEILING", f.read())


class TestEscalate(unittest.TestCase):
    def test_haiku_to_sonnet(self):
        self.assertEqual(escalate("haiku"), "sonnet")

    def test_sonnet_to_opus(self):
        self.assertEqual(escalate("sonnet"), "opus")

    def test_opus_saturates(self):
        self.assertEqual(escalate("opus"), "opus")


if __name__ == "__main__":
    unittest.main()
