import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("activate-clickhouse-system-logs-inplace.py")
spec = importlib.util.spec_from_file_location("ch_inplace", SCRIPT)
maintenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(maintenance)


def table(name, uuid, ttl=False):
    suffix = " TTL event_date + toIntervalDay(7) SETTINGS ttl_only_drop_parts = 1" if ttl else " SETTINGS index_granularity = 8192"
    return {"name": name, "uuid": uuid, "engine": "MergeTree", "partition_key": "toYYYYMM(event_date)",
            "create_table_query": "CREATE TABLE system." + name + " (event_date Date) ENGINE = MergeTree ORDER BY event_date" + suffix}


OLD_UUIDS = {"query_log": "11111111-1111-1111-1111-111111111111",
             "text_log": "22222222-2222-2222-2222-222222222222"}
NEW_UUIDS = {"query_log": "33333333-3333-3333-3333-333333333333",
             "text_log": "44444444-4444-4444-4444-444444444444"}


class InPlaceSystemLogTest(unittest.TestCase):
    def test_live_ttl_requires_exact_seven_days_and_part_only_setting(self):
        self.assertTrue(maintenance.has_live_ttl(table("query_log", "u", True)["create_table_query"]))
        for ddl in (table("query_log", "u", True)["create_table_query"].replace("toIntervalDay(7)", "toIntervalDay(14)"),
                    table("query_log", "u", True)["create_table_query"].replace("ttl_only_drop_parts = 1", "ttl_only_drop_parts = 0"),
                    table("query_log", "u", False)["create_table_query"]):
            self.assertFalse(maintenance.has_live_ttl(ddl))

    def test_release_identity_checks_commit_checksum_and_recovery_help(self):
        cli_source = Path(__file__).parents[2] / "cmd/stream-repair/main.go"
        self.assertIn(maintenance.EXPECTED_HELP, cli_source.read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "releases" / "2026.11.13-abcd1234"
            release.mkdir(parents=True)
            (release / "bin").mkdir()
            (release / "bin/stream-repair").write_bytes(b"repair")
            digest = maintenance.sha256(release / "bin/stream-repair")
            (release / "SHA256SUMS").write_text(digest + "  ./bin/stream-repair\n")
            commit = "abcd1234" + "0" * 32
            (release / "release-manifest.json").write_text(json.dumps({"version": release.name, "git_commit": commit,
                                                                         "git_worktree_modified": False, "os": "linux", "arch": "amd64"}))
            (root / "current").symlink_to(release)
            with mock.patch.object(maintenance, "ROOT", root), mock.patch.object(maintenance, "CURRENT", root / "current"):
                with mock.patch.object(maintenance.subprocess, "run", return_value=mock.Mock(stdout="", stderr=maintenance.EXPECTED_HELP)):
                    self.assertEqual(maintenance.release_identity(commit, digest)["repair_sha256"], digest)
                old_help = "repair a settled source-backed or journal-backed standard-event archive with scoped row proof"
                with mock.patch.object(maintenance.subprocess, "run", return_value=mock.Mock(stdout="", stderr=old_help)):
                    with self.assertRaisesRegex(maintenance.SafetyError, "lacks settled scoped"):
                        maintenance.release_identity(commit, digest)
                with mock.patch.object(maintenance.subprocess, "run", return_value=mock.Mock(stdout="", stderr=maintenance.EXPECTED_HELP)):
                    with self.assertRaisesRegex(maintenance.SafetyError, "commit changed"):
                        maintenance.release_identity("f" * 40, digest)

    def test_policy_copy_refuses_different_existing_file(self):
        def command(args, **_):
            if args[:4] == ["docker", "exec", maintenance.CONTAINER, "test"]:
                return None
            raise AssertionError("must not copy")

        with mock.patch.object(maintenance, "container_file_hash", return_value="f" * 64), \
             mock.patch.object(maintenance, "command", side_effect=command):
            with self.assertRaisesRegex(maintenance.SafetyError, "already differs"):
                maintenance.install_container_policy("a" * 64)

    def test_policy_identity_accepts_only_staged_seven_day_diagnostic_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "deploy/clickhouse").mkdir(parents=True)
            template = root / "deploy/clickhouse/production-query-log-retention.xml"
            template.write_text("<clickhouse><query_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></query_log></clickhouse>")
            policy = root / "production-system-logs.xml"
            source = Path(__file__).parents[2] / "deploy/clickhouse/production-system-logs.xml"
            body = source.read_text().replace("</clickhouse>", "<query_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></query_log></clickhouse>")
            policy.write_text(body)
            policy.with_name("query-log-retention.staged").write_text(maintenance.sha256(template) + "\n")
            with mock.patch.object(maintenance, "POLICY", policy), mock.patch.object(maintenance, "CURRENT", root):
                digest = maintenance.policy_identity(None)["sha256"]
                self.assertEqual(digest, maintenance.sha256(policy))
                policy.write_text(body.replace("</clickhouse>", "<users><default><password>bad</password></default></users></clickhouse>"))
                with self.assertRaisesRegex(maintenance.SafetyError, "unexpected root"):
                    maintenance.policy_identity(None)

    def test_apply_stops_merges_before_policy_and_alter_then_keeps_old_tables(self):
        with tempfile.TemporaryDirectory() as directory:
            before = {name: table(name, OLD_UUIDS[name]) for name in maintenance.TABLES}
            final = {name: table(name, OLD_UUIDS[name], True) for name in maintenance.TABLES}
            calls = []

            def stop(names):
                calls.append(("stop", tuple(names)))

            def install(_sha):
                calls.append(("install",))

            def query(sql):
                calls.append(("sql", sql))
                return []

            with mock.patch.object(maintenance, "STATE", Path(directory) / "state.json"), \
                 mock.patch.object(maintenance, "application_ready"), \
                 mock.patch.object(maintenance, "system_tables", side_effect=[before, before, final, final]), \
                 mock.patch.object(maintenance, "stop_log_merges", side_effect=stop), \
                 mock.patch.object(maintenance, "install_container_policy", side_effect=install), \
                 mock.patch.object(maintenance, "container_identity", return_value={"id": "a" * 64, "started_at": "now"}), \
                 mock.patch.object(maintenance, "container_file_hash", return_value="b" * 64), \
                 mock.patch.object(maintenance, "ch_query", side_effect=query), \
                 mock.patch.object(maintenance.time, "sleep"):
                with contextlib.redirect_stdout(io.StringIO()):
                    maintenance.apply({"commit": "c" * 40}, {"sha256": "b" * 64}, {"id": "a" * 64, "started_at": "now"})
                state = json.loads((Path(directory) / "state.json").read_text())
            self.assertEqual(state["status"], "active")
            self.assertEqual(calls[0][0], "stop")
            self.assertEqual(calls[1][0], "install")
            sql = [call[1] for call in calls if call[0] == "sql"]
            self.assertEqual(sql[0], "SYSTEM RELOAD CONFIG")
            self.assertEqual(sum("MODIFY TTL" in item for item in sql), 2)
            self.assertTrue(all("materialize_ttl_after_modify = 0" in item for item in sql if "MODIFY TTL" in item))
            self.assertEqual(sum("ttl_only_drop_parts = 1" in item for item in sql), 2)

    def test_apply_fails_closed_if_old_log_table_disappears(self):
        with tempfile.TemporaryDirectory() as directory:
            before = {name: table(name, OLD_UUIDS[name]) for name in maintenance.TABLES}
            final = {name: table(name, NEW_UUIDS[name], True) for name in maintenance.TABLES}
            with mock.patch.object(maintenance, "STATE", Path(directory) / "state.json"), \
                 mock.patch.object(maintenance, "application_ready"), \
                 mock.patch.object(maintenance, "system_tables", side_effect=[before, before, final, final]), \
                 mock.patch.object(maintenance, "stop_log_merges"), \
                 mock.patch.object(maintenance, "install_container_policy"), \
                 mock.patch.object(maintenance, "container_identity", return_value={"id": "a" * 64, "started_at": "now"}), \
                 mock.patch.object(maintenance, "ch_query", return_value=[]), \
                 mock.patch.object(maintenance.time, "sleep"):
                with self.assertRaisesRegex(maintenance.SafetyError, "original log table is not retained"):
                    maintenance.apply({"commit": "c" * 40}, {"sha256": "b" * 64}, {"id": "a" * 64, "started_at": "now"})
                self.assertEqual(json.loads((Path(directory) / "state.json").read_text())["status"], "needs_review")


if __name__ == "__main__":
    unittest.main()
