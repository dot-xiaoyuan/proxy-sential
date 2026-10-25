import json
from pathlib import Path
import runpy
import tempfile
import unittest

verify = runpy.run_path(str(Path(__file__).with_name("verify-service-expectations.py")))["verify"]


class ServiceExpectationsTest(unittest.TestCase):
    def test_stopped_is_preserved_and_missing_consumer_detected(self):
        with tempfile.TemporaryDirectory() as root:
            config = Path(root) / "config"
            config.mkdir()
            (config / "service-expectations.json").write_text(json.dumps({
                "proxy-sentinel-discovery.service": "running",
                "proxy-sentinel-passive-discovery.service": "stopped"}))
            result = verify(root, lambda _: "inactive")
            self.assertFalse(result["passed"])
            self.assertFalse(result["services"][0]["matches"])
            self.assertTrue(result["services"][1]["matches"])

    def test_missing_intent_is_reported_not_inferred_from_enablement(self):
        with tempfile.TemporaryDirectory() as root:
            result = verify(root, lambda _: "inactive")
            self.assertFalse(result["expectations_complete"])
            self.assertEqual(result["services"][0]["expected"], "unspecified")


if __name__ == "__main__":
    unittest.main()
