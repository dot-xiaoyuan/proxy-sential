import contextlib
import datetime as dt
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("converge-clickhouse-system-logs.py")
spec = importlib.util.spec_from_file_location("system_log_cleanup", SCRIPT)
cleanup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cleanup)


def part(name, first, last, size):
    return {
        "name": name,
        "partition": name[:6],
        "bytes_on_disk": size,
        "rows": 10,
        "min_date": first,
        "max_date": last,
    }


class SystemLogCleanupTest(unittest.TestCase):
    def test_only_named_log_tables_and_numeric_legacy_suffixes_are_allowed(self):
        self.assertEqual(cleanup.base_log_table("text_log_0"), "text_log")
        self.assertEqual(cleanup.base_log_table("query_log_12"), "query_log")
        for table in ("text_log_backup", "query_log_0;DROP TABLE system.events", "events", "query_log_1234567"):
            with self.subTest(table=table), self.assertRaisesRegex(cleanup.SafetyError, "not allowlisted"):
                cleanup.base_log_table(table)

    def test_only_fully_expired_parts_fit_within_limits(self):
        cutoff = dt.date(2026, 11, 5)
        parts = [
            part("202610_1_1_0", "2026-10-31", "2026-10-31", 6),
            part("202611_2_2_0", "2026-11-01", "2026-11-03", 10),
            part("202611_3_3_0", "2026-11-02", "2026-11-08", 100),
            part("202611_4_4_0", "2026-11-09", "2026-11-09", 50),
        ]
        chosen, eligible_bytes, mixed = cleanup.plan_parts(parts, cutoff, 2, 12)
        self.assertEqual([row["name"] for row in chosen], ["202610_1_1_0"])
        self.assertEqual(eligible_bytes, 16)
        self.assertEqual(mixed, 1)

    def test_apply_stops_on_unready_application_before_reading_parts(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.xml"
            policy.write_text("<clickhouse><text_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></text_log></clickhouse>")

            def command(args, **_):
                if "{{.State.Running}}" in args:
                    return "true"
                if "{{json .Mounts}}" in args:
                    return "[]"
                raise AssertionError(f"unexpected command: {args}")

            with mock.patch.object(cleanup, "run_command", side_effect=command), mock.patch.object(cleanup, "server_ready", return_value=(False, "503")):
                with self.assertRaisesRegex(cleanup.SafetyError, "readyz is 503"):
                    cleanup.main(["--apply", "--policy-file", str(policy)], query_factory=lambda _: lambda _sql: (_ for _ in ()).throw(AssertionError("SQL must not run")))

    def test_query_log_apply_requires_upgraded_recovery_before_any_access(self):
        with mock.patch.object(cleanup, "run_command", side_effect=AssertionError("Docker must not be called")):
            with self.assertRaisesRegex(cleanup.SafetyError, "query_log remains protected"):
                cleanup.main(["--apply", "--table", "query_log"])

    def test_query_log_template_is_staged_without_claiming_live_activation(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.xml"
            template = Path(directory) / "query-log.xml"
            policy.write_text("<clickhouse>\n    <!-- Keep this comment. -->\n    <text_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></text_log>\n</clickhouse>\n")
            template.write_text("<clickhouse><query_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></query_log></clickhouse>")
            self.assertEqual(cleanup.stage_query_log_policy(policy, template, apply=False), (True, True))
            self.assertIsNone(cleanup.policy_retention_days(policy, "query_log"))
            self.assertEqual(cleanup.stage_query_log_policy(policy, template, apply=True), (True, True))
            self.assertEqual(cleanup.policy_retention_days(policy, "query_log"), 7)
            self.assertIn("<!-- Keep this comment. -->", policy.read_text())
            self.assertTrue(cleanup.query_log_marker(policy).is_file())
            self.assertEqual(cleanup.stage_query_log_policy(policy, template, apply=True), (False, False))

    def test_installer_only_preserves_query_log_ttl_with_explicit_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.xml"
            template = root / "query-log.xml"
            output = root / "production-system-logs.xml"
            base.write_text("<clickhouse><text_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></text_log></clickhouse>")
            template.write_text("<clickhouse><query_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></query_log></clickhouse>")
            output.write_text("<clickhouse><query_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></query_log></clickhouse>")
            self.assertFalse(cleanup.materialize_staged_policy(base, template, output, apply=True))
            self.assertIsNone(cleanup.policy_retention_days(output, "query_log"))
            cleanup.stage_query_log_policy(output, template, apply=True)
            self.assertTrue(cleanup.materialize_staged_policy(base, template, output, apply=True))
            self.assertEqual(cleanup.policy_retention_days(output, "query_log"), 7)

    def test_materialize_cli_never_contacts_docker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.xml"
            template = root / "query-log.xml"
            output = root / "production-system-logs.xml"
            base.write_text("<clickhouse><text_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></text_log></clickhouse>")
            template.write_text("<clickhouse><query_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></query_log></clickhouse>")
            with mock.patch.object(cleanup, "run_command", side_effect=AssertionError("installer must not contact Docker")):
                with contextlib.redirect_stdout(io.StringIO()) as result:
                    status = cleanup.main(["--materialize-staged-policy", "--apply", "--base-policy", str(base), "--query-log-template", str(template), "--policy-file", str(output)])
            self.assertEqual(status, 0)
            self.assertIn('"explicit_query_log_marker": false', result.getvalue())
            self.assertIsNone(cleanup.policy_retention_days(output, "query_log"))

    def test_query_log_cleanup_refuses_unmounted_or_unapplied_ttl(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.xml"
            template = Path(directory) / "query-log.xml"
            policy.write_text("<clickhouse><query_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></query_log></clickhouse>")
            template.write_text("<clickhouse><query_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></query_log></clickhouse>")
            cleanup.query_log_marker(policy).write_text(cleanup.template_digest(template) + "\n")
            calls = []

            def command(args, **_):
                if "{{.State.Running}}" in args:
                    return "true"
                if "{{json .Mounts}}" in args:
                    return "[]"
                raise AssertionError(f"unexpected command: {args}")

            def query(sql):
                calls.append(sql)
                if "FROM system.tables" in sql:
                    return [{"engine": "MergeTree", "partition_key": "toYYYYMM(event_date)", "ttl_position": 0}]
                raise AssertionError(f"cleanup reached unsafe query: {sql}")

            with mock.patch.object(cleanup, "run_command", side_effect=command), mock.patch.object(cleanup, "server_ready", return_value=(True, "200")):
                with self.assertRaisesRegex(cleanup.SafetyError, "TTL is not active"):
                    cleanup.main(["--apply", "--table", "query_log", "--recovery-independent", "--policy-file", str(policy), "--query-log-template", str(template)], query_factory=lambda _: query)
            self.assertEqual(len(calls), 1)

    def test_legacy_query_log_waits_for_active_table_ttl(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.xml"
            template = Path(directory) / "query-log.xml"
            policy.write_text("<clickhouse><query_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></query_log></clickhouse>")
            template.write_text("<clickhouse><query_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></query_log></clickhouse>")
            cleanup.query_log_marker(policy).write_text(cleanup.template_digest(template) + "\n")
            calls = []

            def command(args, **_):
                if "{{.State.Running}}" in args:
                    return "true"
                if "{{json .Mounts}}" in args:
                    return '[{"Type":"bind","Source":"' + str(policy) + '","Destination":"/etc/clickhouse-server/config.d/production-system-logs.xml"}]'
                raise AssertionError(f"unexpected command: {args}")

            def query(sql):
                calls.append(sql)
                if "FROM system.tables" in sql and "name='query_log_0'" in sql:
                    return [{"engine": "MergeTree", "partition_key": "toYYYYMM(event_date)", "ttl_position": 0}]
                if "FROM system.tables" in sql and "name='query_log'" in sql:
                    return [{"engine": "MergeTree", "partition_key": "toYYYYMM(event_date)", "ttl_position": 0}]
                raise AssertionError(f"cleanup reached unsafe query: {sql}")

            with mock.patch.object(cleanup, "run_command", side_effect=command), mock.patch.object(cleanup, "server_ready", return_value=(True, "200")):
                with self.assertRaisesRegex(cleanup.SafetyError, "TTL is not active"):
                    cleanup.main(["--apply", "--table", "query_log_0", "--recovery-independent", "--policy-file", str(policy), "--query-log-template", str(template)], query_factory=lambda _: query)
            self.assertEqual(len(calls), 2)
            self.assertFalse(any("DROP PART" in sql for sql in calls))

    def test_unstaged_legacy_query_log_is_protected_even_if_live_ttl_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.xml"
            template = Path(directory) / "query-log.xml"
            policy.write_text("<clickhouse><query_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></query_log></clickhouse>")
            template.write_text("<clickhouse><query_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></query_log></clickhouse>")

            def command(args, **_):
                if "{{.State.Running}}" in args:
                    return "true"
                if "{{json .Mounts}}" in args:
                    return '[{"Type":"bind","Source":"' + str(policy) + '","Destination":"/etc/clickhouse-server/config.d/production-system-logs.xml"}]'
                raise AssertionError(f"unexpected command: {args}")

            def query(sql):
                if "FROM system.tables" in sql:
                    return [{"engine": "MergeTree", "partition_key": "toYYYYMM(event_date)", "ttl_position": 100}]
                raise AssertionError(f"cleanup reached unsafe query: {sql}")

            with mock.patch.object(cleanup, "run_command", side_effect=command), mock.patch.object(cleanup, "server_ready", return_value=(True, "200")):
                with self.assertRaisesRegex(cleanup.SafetyError, "explicit staged marker"):
                    cleanup.main(["--apply", "--table", "query_log_0", "--recovery-independent", "--policy-file", str(policy), "--query-log-template", str(template)], query_factory=lambda _: query)

    def test_apply_rechecks_the_immutable_part_before_dropping(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.xml"
            policy.write_text("<clickhouse><text_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></text_log></clickhouse>")
            old = part("202610_1_1_0", "2026-10-30", "2026-10-31", 1024)
            changed = {**old, "max_date": "2026-11-12"}
            queries = []

            def query(sql):
                queries.append(sql)
                if "FROM system.tables" in sql:
                    return [{"engine": "MergeTree", "partition_key": "toYYYYMM(event_date)", "ttl_position": 0}]
                if "FROM system.parts" in sql and "AND name=" in sql:
                    return [changed]
                if "FROM system.parts" in sql:
                    return [old]
                raise AssertionError(f"unsafe SQL: {sql}")

            def command(args, **_):
                if args[:2] == ["docker", "inspect"] and "{{.State.Running}}" in args:
                    return "true"
                if args[:2] == ["docker", "inspect"] and "{{json .Mounts}}" in args:
                    return "[]"
                raise AssertionError(f"unexpected command: {args}")

            with mock.patch.object(cleanup, "run_command", side_effect=command), mock.patch.object(cleanup, "server_ready", return_value=(True, "200")):
                with contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(cleanup.SafetyError, "part changed after planning"):
                        cleanup.main(["--apply", "--policy-file", str(policy)], query_factory=lambda _: query)
            self.assertFalse(any("DROP PART" in sql for sql in queries))


if __name__ == "__main__":
    unittest.main()
