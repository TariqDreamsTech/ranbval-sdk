"""Adaptive-aggregation sampler: first use sends, repeats are counted and aggregated."""

import unittest

from ranbval_sdk.telemetry.sampling import AdaptiveSampler


class TestAdaptiveSampler(unittest.TestCase):
    def test_first_seen_sends_repeats_aggregate(self):
        s = AdaptiveSampler(flush_interval_sec=9999)  # no auto-flush during the test
        self.assertEqual(s.decide("A"), 1)  # first use → full event
        for _ in range(9):
            self.assertEqual(s.decide("A"), 0)  # repeats → counted, not sent
        self.assertEqual(s.decide("B"), 1)  # new credential → full event
        pending = dict(s.flush_pending())
        self.assertEqual(pending.get("A"), 9)  # 9 repeats aggregated
        self.assertNotIn("B", pending)  # single use, nothing pending
        self.assertEqual(s.flush_pending(), [])  # cleared after flush


if __name__ == "__main__":
    unittest.main()
