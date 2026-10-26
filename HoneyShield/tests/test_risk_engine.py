import unittest
from datetime import datetime, timedelta, timezone

from risk_engine import score_from_failures


class RiskEngineTests(unittest.TestCase):
    def make_events(self, offsets, fingerprints):
        start = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
        return [
            {
                "event_at": (start + timedelta(seconds=offset)).isoformat(timespec="milliseconds"),
                "username_fingerprint": fingerprint,
            }
            for offset, fingerprint in zip(offsets, fingerprints)
        ]

    def test_regular_diverse_burst_reaches_high_risk(self):
        events = self.make_events([0, 0.82, 1.61, 2.42], ["a", "b", "c", "d"])
        score, band, reasons = score_from_failures(events)
        self.assertEqual(score, 70)
        self.assertEqual(band, "HIGH")
        self.assertTrue(any("short interval" in reason for reason in reasons))
        self.assertTrue(any("username fingerprints" in reason for reason in reasons))
        self.assertTrue(any("regular request cadence" in reason for reason in reasons))

    def test_single_typo_or_normal_retry_remains_low(self):
        events = self.make_events([0, 18], ["demo-fingerprint", "demo-fingerprint"])
        score, band, reasons = score_from_failures(events)
        self.assertEqual(score, 0)
        self.assertEqual(band, "LOW")
        self.assertTrue(reasons)

    def test_threshold_is_configurable(self):
        events = self.make_events([0, 0.82, 1.61, 2.42], ["a", "b", "c", "d"])
        score, band, _ = score_from_failures(events, threshold=75)
        self.assertEqual(score, 70)
        self.assertEqual(band, "ELEVATED")

    def test_score_is_capped_at_one_hundred(self):
        events = self.make_events([0, 0.8, 1.6, 2.4, 3.2], ["same"] * 5)
        score, band, _ = score_from_failures(events)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)
        self.assertIn(band, {"LOW", "ELEVATED", "HIGH"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
