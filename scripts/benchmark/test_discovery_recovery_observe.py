from pathlib import Path
import runpy
import unittest

assess = runpy.run_path(str(Path(__file__).with_name("discovery-recovery-observe.py")))["assess"]


def sample(at, remaining, completed, failures=0):
    return {"elapsed": at, "ready_status": "ready", "pipeline": {"status": "delayed", "consumers": [{"status": "running"}], "lanes": [{
        "lane": "realtime", "started_at": "same", "status": "delayed", "remaining_events": remaining,
        "completed_segments": completed, "retries": failures, "timeout_failures": failures}]}}


class RecoveryObservationTest(unittest.TestCase):
    def test_two_bad_windows_prevent_scaleup_despite_backlog_decrease(self):
        result = assess([sample(0, 1000, 0), sample(300, 900, 98, 2), sample(600, 800, 196, 4)], "consume-one", 600)
        self.assertFalse(result["passed"])
        self.assertIn("timeout_rate_above_one_percent_two_windows", result["reasons"])

    def test_short_observation_does_not_pass(self):
        self.assertIn("observation_incomplete", assess([sample(0, 100, 0), sample(60, 50, 1)], "consume-one", 1800)["reasons"])

    def test_passive_requires_every_window_to_decrease(self):
        samples = [sample(i * 900, 10000 - i * 100, i * 2) for i in range(9)]
        self.assertTrue(assess(samples, "passive", 7200)["passed"])
        samples[-1]["pipeline"]["lanes"][0]["remaining_events"] += 200
        self.assertFalse(assess(samples, "passive", 7200)["passed"])


if __name__ == "__main__":
    unittest.main()
