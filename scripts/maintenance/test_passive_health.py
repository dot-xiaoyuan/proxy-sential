import datetime
import json
import tempfile
import unittest
from pathlib import Path

import passive_health as health


class AlertTests(unittest.TestCase):
    def test_quiet_chart_vs_unmerged_writes(self):
        metrics = dict(table="activity_chart_facts_5m_v3", merges=0, inserts=0,
                       max_partition_parts=20, delay_at=1000)
        self.assertEqual(health.chart_alerts(metrics), [])
        self.assertIn("writes_without_merges", health.chart_alerts(dict(metrics, inserts=3)))
        self.assertIn("partition_part_pressure", health.chart_alerts(dict(metrics, max_partition_parts=800)))

    def test_cumulative_errors_and_current_conditions(self):
        self.assertEqual(health.status({"http": 200, "components": {"stats": "ready"}}, [],
                                       {"failed": 0}, {"available": 21, "total": 100}), [])
        self.assertEqual(set(health.status({"http": 503, "components": {"stats": "delayed"}}, ["db.service"],
                                           {"failed": 3}, {"available": 19, "total": 100})),
                         {"readyz", "failed_units", "archive_retry_exhausted", "disk_free_below_20_percent"})
        self.assertEqual(set(health.status({"http": 200}, [], {"failed": 0}, {"available": 8, "total": 100},
                                           max_watermark_lag_seconds=1200)),
                         {"disk_free_below_10_percent", "source_watermark_lag_high"})

    def test_watermark_lag_and_atomic_snapshot(self):
        now = datetime.datetime(2026, 11, 26, 12, 0, 0, tzinfo=datetime.timezone.utc)
        rows = [
            {"source_event_type": "capwap", "cursor_timestamp": "2026-11-26T11:58:00+00:00"},
            {"source_event_type": "mdns", "cursor_timestamp": "2026-11-26T11:40:00+00:00"},
        ]
        self.assertEqual(health.watermark_lag_seconds(rows, now), 1200)
        self.assertEqual(rows[0]["lag_seconds"], 120)
        self.assertEqual(rows[1]["lag_seconds"], 1200)
        with tempfile.TemporaryDirectory() as tmp:
            snap = Path(tmp) / "passive-health" / "latest.json"
            health.write_snapshot(str(snap), {"alerts": [], "max_watermark_lag_seconds": 120})
            self.assertEqual(json.loads(snap.read_text(encoding="utf-8"))["max_watermark_lag_seconds"], 120)


if __name__ == "__main__":
    unittest.main()
