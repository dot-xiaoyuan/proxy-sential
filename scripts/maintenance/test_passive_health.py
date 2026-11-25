import unittest

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

if __name__ == "__main__":
    unittest.main()
