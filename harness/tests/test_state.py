import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from state import CycleRecord, save_record  # noqa: E402


class TestRecord(unittest.TestCase):
    def test_round_trips_to_disk(self):
        d = tempfile.mkdtemp()
        r = CycleRecord(key="T0-1", number=2, title="t")
        r.stages.append({"stage": "research", "model": "sonnet", "ok": True})
        r.verdict = "complete"
        path = save_record(r, d)
        with open(path) as f:
            back = json.load(f)
        self.assertEqual(back["key"], "T0-1")
        self.assertEqual(back["verdict"], "complete")
        self.assertEqual(len(back["stages"]), 1)

    def test_filename_contains_key_and_number(self):
        d = tempfile.mkdtemp()
        path = save_record(CycleRecord(key="T3-dhcp", number=28, title="t"), d)
        base = os.path.basename(path).lower()
        self.assertIn("t3-dhcp", base)
        self.assertIn("0028", base)

    def test_defaults_are_safe(self):
        r = CycleRecord(key="K", number=1, title="t")
        self.assertFalse(r.merged)
        self.assertFalse(r.reverted)
        self.assertEqual(r.outcome, "started")

    def test_current_stage_defaults_empty(self):
        r = CycleRecord(key="K", number=1, title="t")
        self.assertEqual(r.current_stage, "")

    def test_current_stage_round_trips_to_disk(self):
        d = tempfile.mkdtemp()
        r = CycleRecord(key="T0-1", number=2, title="t")
        r.current_stage = "judge (sonnet)"
        path = save_record(r, d)
        with open(path) as f:
            back = json.load(f)
        self.assertEqual(back["current_stage"], "judge (sonnet)")


if __name__ == "__main__":
    unittest.main()
