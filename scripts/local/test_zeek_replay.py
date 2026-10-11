import datetime as dt
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "zeek_replay", Path(__file__).with_name("zeek_replay.py")
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def write_lines(path, items):
    with path.open("w", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")


def epoch_of(stamp):
    return module.parse_rfc3339(stamp)


class EventTime(unittest.TestCase):
    def test_epoch_string_and_number(self):
        self.assertEqual(module.event_time({"ts": 100.5}), 100.5)
        self.assertEqual(module.event_time({"ts": "100.5"}), 100.5)

    def test_rfc3339_with_fraction_and_offset(self):
        expected = dt.datetime(2026, 10, 11, tzinfo=dt.timezone.utc).timestamp()
        self.assertEqual(module.event_time({"timestamp": "2026-10-11T00:00:00Z"}), expected)
        self.assertEqual(
            module.event_time({"timestamp": "2026-10-11T08:00:00.500000+08:00"}),
            expected + 0.5,
        )

    def test_missing_and_boolean_are_not_times(self):
        self.assertIsNone(module.event_time({"other": 1}))
        self.assertIsNone(module.event_time({"ts": True}))
        self.assertIsNone(module.event_time("not-an-object"))


class Offset(unittest.TestCase):
    def test_offset_anchors_newest_event(self):
        self.assertEqual(module.compute_offset(400.0, 1000.0), 600.0)

    def test_zero_offset_when_newest_is_now(self):
        self.assertEqual(module.compute_offset(1000.0, 1000.0), 0.0)


class Scan(unittest.TestCase):
    def test_scan_reports_range_and_malformed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "conn.log"
            with path.open("w", encoding="utf-8") as handle:
                handle.write(json.dumps({"ts": 300.0}) + "\n")
                handle.write("{not json\n")
                handle.write(json.dumps({"ts": 100.0}) + "\n")
                handle.write(json.dumps({"uid": "x"}) + "\n")
            result = module.scan_file(path)
            self.assertEqual(result["lines"], 3)
            self.assertEqual(result["malformed"], 1)
            self.assertEqual(result["without_time"], 1)
            self.assertEqual(epoch_of(result["oldest_ts"]), 100.0)
            self.assertEqual(epoch_of(result["newest_ts"]), 300.0)


class Shift(unittest.TestCase):
    def test_shift_preserves_order_span_and_key_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "dhcp.log"
            write_lines(
                source,
                [
                    {"ts": 100.25, "mac": "aa:bb", "host_name": "a"},
                    {"ts": 160.5, "mac": "cc:dd", "host_name": "b"},
                ],
            )
            before = module.scan_file(source)
            output = root / "shifted" / "dhcp.log"
            result = module.shift_file(source, output, 1000.0)
            after = module.scan_file(output)

            self.assertEqual(result["shifted"], 2)
            self.assertAlmostEqual(
                epoch_of(after["oldest_ts"]) - epoch_of(before["oldest_ts"]), 1000.0, places=6
            )
            self.assertAlmostEqual(
                epoch_of(after["newest_ts"]) - epoch_of(before["newest_ts"]), 1000.0, places=6
            )
            span_before = epoch_of(before["newest_ts"]) - epoch_of(before["oldest_ts"])
            span_after = epoch_of(after["newest_ts"]) - epoch_of(after["oldest_ts"])
            self.assertAlmostEqual(span_before, span_after, places=6)

            first = json.loads(output.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(list(first.keys()), ["ts", "mac", "host_name"])
            self.assertEqual(first["mac"], "aa:bb")

    def test_shift_handles_rfc3339_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "ttl.jsonl"
            write_lines(source, [{"timestamp": "2026-10-11T00:00:00Z", "source": "packet-sidecar"}])
            output = root / "shifted.jsonl"
            module.shift_file(source, output, 60.0)
            item = json.loads(output.read_text(encoding="utf-8").strip())
            self.assertEqual(item["timestamp"], "2026-10-11T00:01:00Z")

    def test_shift_keeps_non_json_lines_and_counts_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "mixed.log"
            source.write_text("#separator \\x09\n{bad json\n", encoding="utf-8")
            output = root / "out.log"
            result = module.shift_file(source, output, 5.0)
            self.assertEqual(result["passthrough"], 1)
            self.assertEqual(result["malformed"], 1)
            self.assertEqual(output.read_text(encoding="utf-8"), "#separator \\x09\n{bad json\n")


class Manifest(unittest.TestCase):
    def test_manifest_skips_empty_and_reports_sha(self):
        with tempfile.TemporaryDirectory() as tmp:
            replay = Path(tmp) / "replay"
            replay.mkdir()
            write_lines(replay / "dhcp.log", [{"ts": 200.0}, {"ts": 260.0}])
            (replay / "proxy_transactions.log").write_text("", encoding="utf-8")
            (replay / "manifest.json").write_text("{}", encoding="utf-8")

            output = replay / "manifest.json"
            manifest = module.build_manifest(
                input_dir=replay,
                output=output,
                source_host="root@192.168.0.30",
                source_dir="/opt/proxy-sentinel/data/zeek/logs/current",
                sensor_id="office-30",
                time_shift_seconds=0.0,
                anchor_now=1000.0,
                skipped=["proxy_transactions.log"],
            )

            self.assertEqual([item["name"] for item in manifest["files"]], ["dhcp.log"])
            self.assertEqual(manifest["lines"], 2)
            self.assertEqual(manifest["skipped"], ["proxy_transactions.log"])
            self.assertEqual(len(manifest["files"][0]["sha256"]), 64)
            self.assertEqual(manifest["sensor_id"], "office-30")
            self.assertAlmostEqual(manifest["span_seconds"], 60.0, places=6)
            self.assertTrue(output.exists())
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["lines"], 2)


if __name__ == "__main__":
    unittest.main()
