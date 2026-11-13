import contextlib
import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("tune-clickhouse-runtime-log-level.py")
spec = importlib.util.spec_from_file_location("ch_log_level", SCRIPT)
change = importlib.util.module_from_spec(spec)
spec.loader.exec_module(change)


CONTAINER = {"id": "a" * 64, "started_at": "2026-11-13T09:20:00Z"}
TABLES = {name: {"uuid": name, "ddl_sha256": "b" * 64} for name in ("query_log", "text_log")}
SNIPPET_SHA = hashlib.sha256(change.SNIPPET).hexdigest()


class RuntimeLogLevelTest(unittest.TestCase):
    def test_snippet_changes_only_the_root_logger_level(self):
        self.assertEqual(change.SNIPPET.decode(),
                         "<clickhouse>\n    <logger><level>information</level></logger>\n</clickhouse>\n")
        for forbidden in ("query_log", "text_log", "ttl", "drop", "merge", "password"):
            self.assertNotIn(forbidden, change.SNIPPET.decode().lower())

    def test_apply_verifies_runtime_rows_without_table_ddl_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            sql = []
            with mock.patch.object(change, "STATE", Path(directory) / "state.json"), \
                 mock.patch.object(change, "preflight", return_value=(CONTAINER, TABLES)), \
                 mock.patch.object(change, "install_snippet"), \
                 mock.patch.object(change, "ch_query", side_effect=lambda query: sql.append(query) or []), \
                 mock.patch.object(change, "config_value", return_value="information"), \
                 mock.patch.object(change, "verify_metadata"), \
                 mock.patch.object(change, "clickhouse_time_ms", return_value=1794560000000), \
                 mock.patch.object(change, "query_count", side_effect=[100, 175]), \
                 mock.patch.object(change, "noisy_logs_since", return_value=0), \
                 mock.patch.object(change.time, "sleep"):
                with contextlib.redirect_stdout(io.StringIO()):
                    change.apply(CONTAINER["id"], SNIPPET_SHA)
            state = json.loads((Path(directory) / "state.json").read_text())
            self.assertEqual(state["status"], "active")
            self.assertEqual(state["observed_queries"], 75)
            self.assertEqual(sql, ["SYSTEM RELOAD CONFIG", "SYSTEM FLUSH LOGS text_log"])

    def test_apply_rolls_back_when_trace_persists_after_reload(self):
        with tempfile.TemporaryDirectory() as directory:
            removed = []

            def config(key, **_):
                return "trace" if removed else "information"

            with mock.patch.object(change, "STATE", Path(directory) / "state.json"), \
                 mock.patch.object(change, "preflight", return_value=(CONTAINER, TABLES)), \
                 mock.patch.object(change, "install_snippet"), \
                 mock.patch.object(change, "remove_snippet", side_effect=lambda digest: removed.append(digest)), \
                 mock.patch.object(change, "ch_query", return_value=[]), \
                 mock.patch.object(change, "config_value", side_effect=config), \
                 mock.patch.object(change, "verify_metadata"), \
                 mock.patch.object(change, "clickhouse_time_ms", return_value=1794560000000), \
                 mock.patch.object(change, "query_count", side_effect=[100, 175]), \
                 mock.patch.object(change, "noisy_logs_since", return_value=3), \
                 mock.patch.object(change.time, "sleep"):
                with self.assertRaisesRegex(change.SafetyError, "trace_or_debug=3"):
                    change.apply(CONTAINER["id"], SNIPPET_SHA)
            self.assertEqual(removed, [SNIPPET_SHA])
            self.assertEqual(json.loads((Path(directory) / "state.json").read_text())["status"], "rolled_back")

    def test_apply_refuses_changed_container_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(change, "STATE", Path(directory) / "state.json"), \
                 mock.patch.object(change, "preflight", return_value=(CONTAINER, TABLES)), \
                 mock.patch.object(change, "install_snippet", side_effect=AssertionError("must not mutate")):
                with self.assertRaisesRegex(change.SafetyError, "planned container or snippet changed"):
                    change.apply("c" * 64, SNIPPET_SHA)

    def test_apply_recovers_when_install_reports_error_after_target_was_written(self):
        with tempfile.TemporaryDirectory() as directory:
            removed = []
            with mock.patch.object(change, "STATE", Path(directory) / "state.json"), \
                 mock.patch.object(change, "preflight", return_value=(CONTAINER, TABLES)), \
                 mock.patch.object(change, "install_snippet", side_effect=change.SafetyError("copy verification failed")), \
                 mock.patch.object(change, "container_file_hash", return_value=SNIPPET_SHA), \
                 mock.patch.object(change, "remove_snippet", side_effect=lambda digest: removed.append(digest)), \
                 mock.patch.object(change, "config_value", return_value="trace"), \
                 mock.patch.object(change, "verify_metadata"):
                with self.assertRaisesRegex(change.SafetyError, "copy verification failed"):
                    change.apply(CONTAINER["id"], SNIPPET_SHA)
            self.assertEqual(removed, [SNIPPET_SHA])
            self.assertEqual(json.loads((Path(directory) / "state.json").read_text())["status"], "rolled_back")

    def test_rollback_removes_only_matching_snippet_from_same_container(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text(json.dumps({"status": "active", "old_level": "trace", "container": CONTAINER,
                                         "tables": TABLES, "snippet_sha256": SNIPPET_SHA}))
            removed = []
            with mock.patch.object(change, "STATE", state), \
                 mock.patch.object(change, "container_identity", return_value=CONTAINER), \
                 mock.patch.object(change, "container_file_hash", return_value=SNIPPET_SHA), \
                 mock.patch.object(change, "remove_snippet", side_effect=lambda digest: removed.append(digest)), \
                 mock.patch.object(change, "config_value", return_value="trace"), \
                 mock.patch.object(change, "verify_metadata"):
                with contextlib.redirect_stdout(io.StringIO()):
                    change.rollback()
            self.assertEqual(removed, [SNIPPET_SHA])
            self.assertEqual(json.loads(state.read_text())["status"], "rolled_back")

    def test_rollback_refuses_changed_snippet(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text(json.dumps({"status": "active", "old_level": "trace", "container": CONTAINER,
                                         "tables": TABLES, "snippet_sha256": SNIPPET_SHA}))
            with mock.patch.object(change, "STATE", state), \
                 mock.patch.object(change, "container_identity", return_value=CONTAINER), \
                 mock.patch.object(change, "container_file_hash", return_value="c" * 64), \
                 mock.patch.object(change, "remove_snippet", side_effect=AssertionError("must not remove")):
                with self.assertRaisesRegex(change.SafetyError, "config changed"):
                    change.rollback()

    def test_rollback_marks_review_if_reload_fails_after_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text(json.dumps({"status": "active", "old_level": "trace", "container": CONTAINER,
                                         "tables": TABLES, "snippet_sha256": SNIPPET_SHA}))
            with mock.patch.object(change, "STATE", state), \
                 mock.patch.object(change, "container_identity", return_value=CONTAINER), \
                 mock.patch.object(change, "container_file_hash", return_value=SNIPPET_SHA), \
                 mock.patch.object(change, "remove_snippet", side_effect=change.SafetyError("reload failed")):
                with self.assertRaisesRegex(change.SafetyError, "reload failed"):
                    change.rollback()
            self.assertEqual(json.loads(state.read_text())["status"], "needs_review")

    def test_preflight_refuses_console_or_logger_override(self):
        values = {"logger.level": "trace", "text_log.level": "trace", "logger.log": "/var/log/clickhouse-server.log",
                  "logger.console": "true", "logger.console_log_level": None, "logger.use_syslog": None, "logger.levels": None}
        with mock.patch.object(change, "container_identity", return_value=CONTAINER), \
             mock.patch.object(change, "ready"), \
             mock.patch.object(change, "ch_query", return_value=[{"value": change.EXPECTED_VERSION}]), \
             mock.patch.object(change, "config_value", side_effect=lambda key, **_: values[key]), \
             mock.patch.object(change, "container_file_hash", return_value=None), \
             mock.patch.object(change, "table_fingerprints", side_effect=AssertionError("must stop before table scan")):
            with self.assertRaisesRegex(change.SafetyError, "logger.console is configured"):
                change.preflight()


if __name__ == "__main__":
    unittest.main()
