import datetime as dt
import importlib.util
from pathlib import Path
import unittest
from unittest import mock


PATH = Path(__file__).with_name("storage-window-baseline.py")
SPEC = importlib.util.spec_from_file_location("storage_window_baseline", PATH)
BASELINE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASELINE)
UTC = dt.timezone.utc


def period(start, key="passive-discovery/epoch-a", capture=100, projected=80):
    return {
        "kind": "periodic", "_window_start": start, "_at": start + dt.timedelta(seconds=30),
        "capture_accepted": {key: {"segments": 2, "events": capture, "source_bytes": 1200}},
        "sink_acks": {key: {"body_segments": 2, "body_events": 90,
                            "search_segments": 2, "search_events": 90,
                            "eventbus_segments": 0, "eventbus_events": 0}},
        "projection_writes": {key: {"segments": 1, "events": projected,
                                    "fresh_events": projected - 5,
                                    "pg_fact_rows": 20, "pg_state_rows": 10}},
        "durable_backlog": {"segments": 50, "reserved_bytes": 200_000},
        "queues": {"projection": {"depth": 48, "capacity": 8192}},
    }


def snapshot(at, wal, commits, parts):
    return {
        "started_at": at.isoformat(), "finished_at": at.isoformat(),
        "wal": {"wal_bytes": wal, "wal_records": wal // 100, "stats_reset": "fixed"},
        "database": {"xact_commit": commits, "xact_rollback": 1, "stats_reset": "fixed"},
        "parts": [{"table": "stream_event_search", "parts": parts, "bytes_on_disk": parts * 1000}],
        "merge_counters": [{"event": name, "value": wal // 1000} for name in (
            "Merge", "MergeSourceParts", "MergedRows", "MergedUncompressedBytes", "MergeExecuteMilliseconds")],
        "probe_intervals": {name: {"from": at.isoformat(), "to": at.isoformat()}
                            for name in ("wal", "database", "parts", "merges")},
    }


class StorageWindowBaselineTests(unittest.TestCase):
    def setUp(self):
        self.start = dt.datetime(2026, 11, 12, 3, 0, 0, tzinfo=UTC)
        self.records = [period(self.start), period(self.start + dt.timedelta(seconds=30))]
        self.before = snapshot(self.start + dt.timedelta(seconds=1), 1000, 100, 10)
        self.after = snapshot(self.start + dt.timedelta(seconds=61), 7000, 160, 12)

    def test_reports_source_cost_and_separates_system_wide_counters(self):
        result = BASELINE.build_report("passive-discovery", "epoch-a", self.records,
                                       self.before, self.after)
        self.assertEqual(result["source_metrics"]["accepted_standard_events"], 200)
        self.assertEqual(result["source_metrics"]["clickhouse_confirmed_body_events"], 180)
        self.assertEqual(result["source_metrics"]["per_1000_projected_events"]["pg_fact_rows_per_1000_projected_events"], 250)
        self.assertEqual(result["source_metrics"]["per_1000_projected_events"]["pg_state_rows_per_1000_projected_events"], 125)
        self.assertEqual(result["system_wide"]["pg_wal_bytes"], 6000)
        self.assertEqual(result["system_wide"]["clickhouse_parts"][0]["parts_after"], 12)
        self.assertEqual(result["system_wide"]["clickhouse_merge_counters"]["Merge"], 6)
        self.assertIn("throughput", result["interpretation"])
        self.assertIn("raw_dpi_input_events", result["unavailable"])

    def test_rejects_discontinuous_metrics_or_reset_counters(self):
        self.records[1]["_window_start"] += dt.timedelta(seconds=5)
        with self.assertRaisesRegex(BASELINE.ProbeError, "gap or process restart"):
            BASELINE.build_report("passive-discovery", "epoch-a", self.records,
                                  self.before, self.after)
        self.records[1]["_window_start"] -= dt.timedelta(seconds=5)
        self.after["wal"]["stats_reset"] = "changed"
        with self.assertRaisesRegex(BASELINE.ProbeError, "reset"):
            BASELINE.build_report("passive-discovery", "epoch-a", self.records,
                                  self.before, self.after)

    def test_rejects_old_release_and_misaligned_samples(self):
        del self.records[0]["capture_accepted"]
        with self.assertRaisesRegex(BASELINE.ProbeError, "lacks capture_accepted"):
            BASELINE.build_report("passive-discovery", "epoch-a", self.records,
                                  self.before, self.after)
        self.records[0]["capture_accepted"] = period(self.start)["capture_accepted"]
        self.after["probe_intervals"]["wal"]["to"] = (self.start + dt.timedelta(seconds=75)).isoformat()
        with self.assertRaisesRegex(BASELINE.ProbeError, "eight seconds"):
            BASELINE.build_report("passive-discovery", "epoch-a", self.records,
                                  self.before, self.after)

    def test_recent_metric_parser_ignores_shutdown_and_limits_json(self):
        record = {"kind": "periodic", "window_start": self.start.isoformat(),
                  "at": (self.start + dt.timedelta(seconds=30)).isoformat()}
        line = "prefix passive stream metrics " + __import__("json").dumps(record)
        with mock.patch.object(BASELINE, "command", return_value=line + "\npassive stream metrics {\"kind\":\"shutdown\"}"):
            rows = BASELINE.recent_metrics(self.start)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["_at"], self.start + dt.timedelta(seconds=30))

    def test_open_euler_python_parses_go_nanosecond_timestamp(self):
        self.assertEqual(BASELINE.parse_stamp("2026-11-12T04:29:23.391039934Z"),
                         dt.datetime(2026, 11, 12, 4, 29, 23, 391039, tzinfo=UTC))


if __name__ == "__main__":
    unittest.main()
