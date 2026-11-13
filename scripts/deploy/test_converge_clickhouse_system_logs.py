import contextlib
import datetime as dt
import importlib.util
import io
import json
import tempfile
import unittest
import urllib.error
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

    def test_operations_exception_needs_only_timeout_and_other_components_ready(self):
        components = {name: {"status": "ready"} for name in (
            "storage", "collector", "authentication", "identity_ingest", "identity_pipeline", "inventory_projection", "discovery_pipeline",
        )}
        components["authentication_oidc"] = {"status": "disabled"}
        components["operations"] = {"status": "unavailable", "error": "timeout: context deadline exceeded"}
        body = {"status": "not_ready", "components": components}
        self.assertTrue(cleanup.operations_only_degraded_payload(body))
        for broken in (
            {**body, "status": "ready"},
            {**body, "components": {**components, "storage": {"status": "delayed"}}},
            {**body, "components": {**components, "operations": {"status": "unavailable", "error": "database unavailable"}}},
            {**body, "components": {name: value for name, value in components.items() if name != "identity_ingest"}},
        ):
            with self.subTest(broken=broken):
                self.assertFalse(cleanup.operations_only_degraded_payload(broken))

    def test_operations_exception_reads_bounded_503_response(self):
        components = {name: {"status": "ready"} for name in (
            "storage", "collector", "authentication", "identity_ingest", "discovery_pipeline",
        )}
        components["operations"] = {"status": "unavailable", "error": "timeout: context deadline exceeded"}
        body = json.dumps({"status": "not_ready", "components": components}).encode()
        response = urllib.error.HTTPError("http://readyz", 503, "Service Unavailable", None, io.BytesIO(body))
        with mock.patch.object(cleanup.urllib.request, "urlopen", side_effect=response):
            self.assertTrue(cleanup.operations_only_degraded("http://readyz"))
        self.assertTrue(response.closed)

    def test_unready_response_is_closed(self):
        response = urllib.error.HTTPError("http://readyz", 503, "Service Unavailable", None, io.BytesIO(b"{}"))
        with mock.patch.object(cleanup.urllib.request, "urlopen", side_effect=response):
            self.assertEqual(cleanup.server_ready("http://readyz"), (False, "503"))
        self.assertTrue(response.closed)

    def test_operations_exception_drops_one_bounded_expired_text_log_part(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.xml"
            policy.write_text("<clickhouse><text_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></text_log></clickhouse>")
            old = part("202610_1_1_0", "2026-10-30", "2026-10-30", 2 * 1024**3)
            queries = []
            checks = []

            def command(args, **_):
                if "{{.State.Running}}" in args:
                    return "true"
                if "{{json .Mounts}}" in args:
                    return "[]"
                raise AssertionError(f"unexpected command: {args}")

            def query(sql):
                queries.append(sql)
                if "FROM system.tables" in sql:
                    return [{"engine": "MergeTree", "partition_key": "toYYYYMM(event_date)", "ttl_position": 0}]
                if "FROM system.parts" in sql and "AND name=" in sql:
                    return [] if any("DROP PART" in item for item in queries) else [old]
                if "FROM system.parts" in sql:
                    return [old]
                if "DROP PART" in sql:
                    return []
                raise AssertionError(f"unexpected SQL: {sql}")

            def degraded(_url):
                checks.append(True)
                return True

            with mock.patch.object(cleanup, "run_command", side_effect=command), \
                 mock.patch.object(cleanup, "server_ready", return_value=(False, "503")), \
                 mock.patch.object(cleanup, "operations_only_degraded", side_effect=degraded):
                with contextlib.redirect_stdout(io.StringIO()) as result:
                    status = cleanup.main([
                        "--apply", "--table", "text_log", "--allow-operations-degraded",
                        "--max-parts", "1", "--max-bytes", str(4 * 1024**3), "--policy-file", str(policy),
                    ], query_factory=lambda _: query)
            self.assertEqual(status, 0)
            self.assertEqual(len(checks), 2)
            self.assertEqual(sum("DROP PART" in item for item in queries), 1)
            self.assertIn('"operations_degraded_exception": true', result.getvalue())

    def test_operations_exception_rechecks_before_drop(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.xml"
            policy.write_text("<clickhouse><text_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></text_log></clickhouse>")
            old = part("202610_1_1_0", "2026-10-30", "2026-10-30", 2 * 1024**3)

            def command(args, **_):
                if "{{.State.Running}}" in args:
                    return "true"
                if "{{json .Mounts}}" in args:
                    return "[]"
                raise AssertionError(f"unexpected command: {args}")

            def query(sql):
                if "FROM system.tables" in sql:
                    return [{"engine": "MergeTree", "partition_key": "toYYYYMM(event_date)", "ttl_position": 0}]
                if "FROM system.parts" in sql and "AND name=" not in sql:
                    return [old]
                raise AssertionError(f"DROP or recheck must not run after health changed: {sql}")

            with mock.patch.object(cleanup, "run_command", side_effect=command), \
                 mock.patch.object(cleanup, "server_ready", return_value=(False, "503")), \
                 mock.patch.object(cleanup, "operations_only_degraded", side_effect=[True, False]):
                with contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(cleanup.SafetyError, "readiness changed"):
                        cleanup.main([
                            "--apply", "--table", "text_log", "--allow-operations-degraded",
                            "--max-parts", "1", "--max-bytes", str(4 * 1024**3), "--policy-file", str(policy),
                        ], query_factory=lambda _: query)

    def test_operations_exception_rejects_other_tables_or_unbounded_work(self):
        for options in (["--table", "query_log"], ["--max-parts", "2"], ["--max-bytes", str(5 * 1024**3)], ["--stage-query-log-policy"]):
            with self.subTest(options=options), mock.patch.object(cleanup, "run_command", side_effect=AssertionError("Docker must not be called")):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    cleanup.main(["--allow-operations-degraded", *options])

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

    def test_staging_policy_is_allowed_while_application_is_degraded(self):
        # Staging only edits a host file which is not mounted by the running
        # container. The readiness gate belongs to live DROP PART operations.
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.xml"
            template = Path(directory) / "query-log.xml"
            policy.write_text("<clickhouse><text_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></text_log></clickhouse>")
            template.write_text("<clickhouse><query_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></query_log></clickhouse>")

            def command(args, **_):
                if "{{.State.Running}}" in args:
                    return "true"
                if "{{json .Mounts}}" in args:
                    return "[]"
                raise AssertionError(f"unexpected command: {args}")

            with mock.patch.object(cleanup, "run_command", side_effect=command), mock.patch.object(cleanup, "server_ready", return_value=(False, "503")):
                with contextlib.redirect_stdout(io.StringIO()) as result:
                    status = cleanup.main([
                        "--apply", "--stage-query-log-policy", "--recovery-independent",
                        "--policy-file", str(policy), "--query-log-template", str(template),
                    ], query_factory=lambda _: lambda _sql: (_ for _ in ()).throw(AssertionError("SQL must not run")))
            self.assertEqual(status, 0)
            self.assertEqual(cleanup.policy_retention_days(policy, "query_log"), 7)
            self.assertTrue(cleanup.query_log_marker(policy).is_file())
            self.assertIn('"query_log_ttl_activated": false', result.getvalue())

    def test_staging_policy_waits_for_readiness_if_file_is_live_mounted(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.xml"
            template = Path(directory) / "query-log.xml"
            policy.write_text("<clickhouse><text_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></text_log></clickhouse>")
            template.write_text("<clickhouse><query_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></query_log></clickhouse>")

            def command(args, **_):
                if "{{.State.Running}}" in args:
                    return "true"
                if "{{json .Mounts}}" in args:
                    return '[{"Type":"bind","Source":"' + str(policy) + '","Destination":"/etc/clickhouse-server/config.d/production-system-logs.xml"}]'
                raise AssertionError(f"unexpected command: {args}")

            with mock.patch.object(cleanup, "run_command", side_effect=command), mock.patch.object(cleanup, "server_ready", return_value=(False, "503")):
                with self.assertRaisesRegex(cleanup.SafetyError, "readyz is 503"):
                    cleanup.main([
                        "--apply", "--stage-query-log-policy", "--recovery-independent",
                        "--policy-file", str(policy), "--query-log-template", str(template),
                    ], query_factory=lambda _: lambda _sql: (_ for _ in ()).throw(AssertionError("SQL must not run")))
            self.assertIsNone(cleanup.policy_retention_days(policy, "query_log"))
            self.assertFalse(cleanup.query_log_marker(policy).exists())

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

    def test_unmounted_live_ttl_requires_exact_seven_days_and_part_only_cleanup(self):
        valid = "CREATE TABLE system.query_log (event_date Date) ENGINE = MergeTree ORDER BY event_date TTL event_date + toIntervalDay(7) SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1 COMMENT 'system log'"
        self.assertTrue(cleanup.has_exact_seven_day_ttl(valid))
        for ddl in (
            valid.replace("toIntervalDay(7)", "toIntervalDay(14)"),
            valid.replace("ttl_only_drop_parts = 1", "ttl_only_drop_parts = 0"),
            valid.replace(", ttl_only_drop_parts = 1", ""),
            "CREATE TABLE system.query_log (event_date Date COMMENT 'TTL event_date + toIntervalDay(7)') ENGINE = MergeTree ORDER BY event_date SETTINGS ttl_only_drop_parts = 1",
        ):
            with self.subTest(ddl=ddl):
                self.assertFalse(cleanup.has_exact_seven_day_ttl(ddl))

    def test_unmounted_live_ttl_allows_only_bounded_fully_expired_query_log_part(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.xml"
            template = Path(directory) / "query-log.xml"
            policy.write_text("<clickhouse><query_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></query_log></clickhouse>")
            template.write_text(policy.read_text())
            cleanup.query_log_marker(policy).write_text(cleanup.template_digest(template) + "\n")
            old = part("202001_1_1_0", "2020-01-01", "2020-01-01", 1024)
            mixed = part("202611_2_2_0", "2026-11-02", "2026-11-12", 2048)
            ddl = "CREATE TABLE system.query_log (event_date Date) ENGINE = MergeTree ORDER BY event_date TTL event_date + toIntervalDay(7) SETTINGS ttl_only_drop_parts = 1"
            state = Path(directory) / "inplace-state.json"
            digest = cleanup.hashlib.sha256(policy.read_bytes()).hexdigest()
            state.write_text(json.dumps({"status": "active", "merges": "stopped_pending_cleanup",
                                         "policy": {"sha256": digest},
                                         "live_ddl_sha256": {"query_log": cleanup.hashlib.sha256(ddl.encode()).hexdigest()},
                                         "container": {"id": "a" * 64, "started_at": "2026-11-13T00:00:00Z"}}))
            queries = []

            def command(args, **_):
                if "{{.State.Running}}" in args:
                    return "true"
                if "{{json .Mounts}}" in args:
                    return "[]"
                if "{{.Id}} {{.State.StartedAt}}" in args:
                    return "a" * 64 + " 2026-11-13T00:00:00Z"
                if args[:3] == ["docker", "exec", "proxy-sentinel-clickhouse"]:
                    return digest + " " + cleanup.INPLACE_CONTAINER_POLICY
                raise AssertionError(f"unexpected command: {args}")

            def query(sql):
                queries.append(sql)
                if "FROM system.tables" in sql:
                    return [{"engine": "MergeTree", "partition_key": "toYYYYMM(event_date)", "ttl_position": 90, "create_table_query": ddl}]
                if "FROM system.parts" in sql and "AND name=" in sql:
                    return [] if any("DROP PART" in item for item in queries) else [old]
                if "FROM system.parts" in sql:
                    return [old, mixed]
                if "DROP PART" in sql:
                    return []
                raise AssertionError(f"unexpected SQL: {sql}")

            with mock.patch.object(cleanup, "INPLACE_STATE", state), mock.patch.object(cleanup, "run_command", side_effect=command), mock.patch.object(cleanup, "server_ready", return_value=(True, "200")):
                with contextlib.redirect_stdout(io.StringIO()) as result:
                    cleanup.main(["--apply", "--table", "query_log", "--recovery-independent",
                                  "--allow-unmounted-live-ttl", "--max-parts", "1", "--max-bytes", "4096",
                                  "--policy-file", str(policy), "--query-log-template", str(template)],
                                 query_factory=lambda _: query)
            self.assertTrue(any("DROP PART '202001_1_1_0'" in item for item in queries))
            self.assertFalse(any("DROP PART '202611_2_2_0'" in item for item in queries))
            self.assertIn('"unmounted_live_ttl_exception": true', result.getvalue())

    def test_unmounted_live_ttl_refuses_different_live_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.xml"
            template = Path(directory) / "query-log.xml"
            policy.write_text("<clickhouse><query_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></query_log></clickhouse>")
            template.write_text(policy.read_text())
            cleanup.query_log_marker(policy).write_text(cleanup.template_digest(template) + "\n")
            queries = []

            def command(args, **_):
                return "true" if "{{.State.Running}}" in args else "[]"

            def query(sql):
                queries.append(sql)
                if "FROM system.tables" in sql:
                    return [{"engine": "MergeTree", "partition_key": "toYYYYMM(event_date)", "ttl_position": 90,
                             "create_table_query": "CREATE TABLE system.query_log (event_date Date) ENGINE = MergeTree ORDER BY event_date TTL event_date + toIntervalDay(14) SETTINGS ttl_only_drop_parts = 1"}]
                raise AssertionError(f"cleanup reached unsafe SQL: {sql}")

            with mock.patch.object(cleanup, "run_command", side_effect=command), mock.patch.object(cleanup, "server_ready", return_value=(True, "200")):
                with self.assertRaisesRegex(cleanup.SafetyError, "exact live seven-day TTL"):
                    cleanup.main(["--apply", "--table", "query_log", "--recovery-independent",
                                  "--allow-unmounted-live-ttl", "--max-bytes", "4096", "--policy-file", str(policy),
                                  "--query-log-template", str(template)], query_factory=lambda _: query)
            self.assertEqual(len(queries), 1)
            self.assertFalse(any("DROP PART" in item for item in queries))

    def test_unmounted_live_ttl_rejects_unbounded_defaults_before_database_access(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            cleanup.main(["--apply", "--table", "query_log", "--recovery-independent", "--allow-unmounted-live-ttl"],
                         query_factory=lambda _: lambda _sql: (_ for _ in ()).throw(AssertionError("SQL must not run")))
        self.assertEqual(error.exception.code, 2)

    def test_unmounted_cleanup_requires_the_same_live_activation_state(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(cleanup, "INPLACE_STATE", Path(directory) / "missing.json"), \
                 mock.patch.object(cleanup, "run_command", side_effect=AssertionError("must not contact Docker")):
                with self.assertRaisesRegex(cleanup.SafetyError, "activation state is missing"):
                    cleanup.verify_inplace_activation("proxy-sentinel-clickhouse", Path(directory) / "policy.xml", "DDL")

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
