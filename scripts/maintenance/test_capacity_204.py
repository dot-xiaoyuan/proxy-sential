import datetime
import json
from pathlib import Path
import tempfile
import unittest

import capacity_204 as cap


class CapacityTests(unittest.TestCase):
    def test_rate_uses_elapsed_seconds_and_splits_on_reset_or_gap(self):
        before = {"wal_bytes": 10, "stats_reset": "a"}
        after = {"wal_bytes": 70, "stats_reset": "a"}
        self.assertEqual(cap.wal_rate(before, after, 30), 2)
        self.assertIsNone(cap.wal_rate(before, dict(after, stats_reset="b"), 30))
        self.assertIsNone(cap.wal_rate(after, before, 30))
        self.assertEqual(cap.local_day({"sampled_at": "2026-11-24T17:00:00Z"}), datetime.date(2026, 11, 25))

    def test_no_delta_over_missing_date(self):
        left = {"sampled_at": "2026-11-22T00:00:00Z"}
        right = {"sampled_at": "2026-11-24T00:00:00Z"}
        self.assertEqual(cap.interval(left, right)["status"], "missing_day")

    def test_storage_responsibility(self):
        self.assertEqual(cap.retention("ch:passive_discovery_raw_archive"), "archive")
        self.assertEqual(cap.retention("pg:public.passive_archive_rows"), "archive")
        self.assertEqual(cap.retention("pg:public.passive_hardware_changes"), "hot_history")
        self.assertEqual(cap.retention("ch:activity_chart_facts_5m_v3"), "other")

    def test_seven_samples_preserve_hot_and_archive_horizons_and_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            for i in range(7):
                stamp = f"2026-11-{10+i}T02:00:00+00:00"
                pg = {"schemaname": "public", "relname": "passive_hardware_changes",
                      "relid": "1" if i < 3 else "2", "total_bytes": i*2,
                      "heap_bytes": i, "index_bytes": i, "n_tup_upd": i, "n_tup_hot_upd": i}
                sample = {"sampled_at": stamp, "wal": [{"wal_bytes": i*86400, "stats_reset": None}],
                          "database": [{"stats_reset": None}], "pg_tables": [pg], "errors": {},
                          "ch_partitions": [{"table": "passive_discovery_raw_archive", "bytes": i*5}],
                          "disk": {"total": 10000, "available": 5000}}
                (folder / f"capacity-{stamp[:10]}.json").write_text(json.dumps(sample))
            result = cap.report(folder)
            self.assertEqual(result["intervals"][2]["pg_updates"]["public.passive_hardware_changes"]["status"],
                             "new_relation_or_counter_reset")
            self.assertEqual(result["intervals"][0]["wal_bytes_per_second"], 1)
            self.assertEqual(result["hot_history_extra_30d_bytes"], 60)
            self.assertEqual(result["archive_extra_365d_bytes"], 1825)
            self.assertEqual(result["extra_bytes_above_reserve_after_hot_and_archive"], 1115)
