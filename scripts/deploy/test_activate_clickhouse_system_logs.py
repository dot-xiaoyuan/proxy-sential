"""Safety checks for the one-shot ClickHouse system-log maintenance tool."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("activate-clickhouse-system-logs.py")
SPEC = importlib.util.spec_from_file_location("clickhouse_system_log_maintenance", SCRIPT)
maintenance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(maintenance)


def source() -> dict:
    return {
        "Name": "/proxy-sentinel-clickhouse",
        "Id": "old-container-id",
        "Image": "sha256:old-image-id",
        "State": {"Status": "running", "Health": {"Status": "healthy"}},
        "Config": {
            "Image": "example/clickhouse@sha256:" + "a" * 64,
            "Env": ["CLICKHOUSE_USER=reader", "CLICKHOUSE_PASSWORD=top-secret"],
            "Entrypoint": ["/entrypoint.sh"], "Cmd": None, "User": "", "WorkingDir": "",
            "Hostname": "old-host", "ExposedPorts": {"8123/tcp": {}, "9000/tcp": {}, "9009/tcp": {}},
            "Labels": {"com.clickhouse.build.version": "25.9.2.1"},
            "Healthcheck": {"Test": ["CMD-SHELL", 'clickhouse-client --password "$CLICKHOUSE_PASSWORD" --query "SELECT 1"'],
                            "Interval": 10_000_000_000, "Timeout": 5_000_000_000, "Retries": 18},
        },
        "HostConfig": {
            "Binds": sorted(maintenance.EXPECTED_BINDS), "Mounts": None, "VolumesFrom": None,
            "PortBindings": maintenance.EXPECTED_PORTS, "NetworkMode": "default",
            "NanoCpus": 12_000_000_000, "Memory": 24 * 1024**3, "MemorySwap": 32 * 1024**3,
            "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0}, "AutoRemove": False,
            "Ulimits": [{"Name": "nofile", "Hard": 262144, "Soft": 262144}],
            "LogConfig": {"Type": "json-file", "Config": {"max-file": "5", "max-size": "20m"}},
            "ShmSize": 67108864, "IpcMode": "shareable", "Runtime": "runc",
        },
        "NetworkSettings": {"Networks": {"bridge": {}}},
        "Mounts": [
            {"Source": "/opt/proxy-sentinel/data/db/clickhouse/data", "Destination": "/var/lib/clickhouse", "RW": True},
            {"Source": "/opt/proxy-sentinel/data/db/clickhouse/logs", "Destination": "/var/log/clickhouse-server", "RW": True},
        ],
    }


class ActivateClickHouseSystemLogsTest(unittest.TestCase):
    def test_run_argv_keeps_resources_and_binds_without_secret_on_argv(self) -> None:
        args = maintenance.run_argv(source(), Path("/run/private-env"))
        self.assertEqual(args[-1], source()["Config"]["Image"])
        self.assertEqual(args[args.index("--cpus") + 1], "12.0")
        self.assertEqual(args[args.index("--memory") + 1], str(24 * 1024**3))
        self.assertEqual(args[args.index("--restart") + 1], "unless-stopped")
        self.assertEqual(args[args.index("--env-file") + 1], "/run/private-env")
        self.assertEqual({args[i + 1] for i, value in enumerate(args[:-1]) if value == "--volume"}, maintenance.EXPECTED_BINDS)
        self.assertIn("readonly", args[args.index("--mount") + 1])
        self.assertNotIn("top-secret", " ".join(args))

    def test_changed_data_bind_is_rejected_before_mutation(self) -> None:
        current = source()
        current["HostConfig"]["Binds"] = ["/tmp/other:/var/lib/clickhouse"]
        with mock.patch.object(maintenance, "command", return_value=json.dumps([{"Id": current["Image"]}])):
            with self.assertRaisesRegex(maintenance.MaintenanceError, "storage binds changed"):
                maintenance.check_source(current)

    def test_rollback_preserves_old_container_and_never_removes_volumes(self) -> None:
        state = {"old_name": "proxy-sentinel-clickhouse-rollback-test", "old_id": "old-container-id"}
        containers = {
            state["old_name"]: {"Id": "old-container-id", "State": {"Status": "exited"}},
            maintenance.NAME: {"Id": "new-container-id", "State": {"Status": "exited"}},
        }
        calls = []

        def fake_command(args, timeout=30):
            calls.append(args)
            if args[:2] == ["docker", "rm"]:
                del containers[maintenance.NAME]
            elif args[:2] == ["docker", "rename"]:
                containers[maintenance.NAME] = containers.pop(state["old_name"])
            elif args[:2] == ["docker", "start"]:
                containers[maintenance.NAME]["State"] = {"Status": "running", "Health": {"Status": "healthy"}}
            return ""

        with mock.patch.object(maintenance, "inspect", side_effect=lambda name: containers.get(name)), \
                mock.patch.object(maintenance, "command", side_effect=fake_command), \
                mock.patch.object(maintenance, "save_state"):
            maintenance.rollback(state)
        self.assertIn(["docker", "rm", maintenance.NAME], calls)
        self.assertFalse(any("-v" in call or "--volumes" in call for call in calls))
        self.assertEqual(containers[maintenance.NAME]["Id"], state["old_id"])

    def test_rollback_refuses_to_remove_new_when_old_is_missing(self) -> None:
        state = {"old_name": "proxy-sentinel-clickhouse-rollback-test", "old_id": "old-container-id"}
        with mock.patch.object(maintenance, "inspect", side_effect=lambda name: None if name == state["old_name"] else {"Id": "new-container-id"}), \
                mock.patch.object(maintenance, "command") as run:
            with self.assertRaisesRegex(maintenance.MaintenanceError, "refusing to remove"):
                maintenance.rollback(state)
            run.assert_not_called()

    def test_go_timestamp_with_nanoseconds_parses_on_old_python(self) -> None:
        parsed = maintenance.utc_time("2026-11-13T08:45:19.916916840Z")
        self.assertEqual(parsed.microsecond, 916916)

    def test_policy_must_include_all_nine_seven_day_ttls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "production-system-logs.xml"
            body = "<clickhouse>" + "".join(
                f"<{name}><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></{name}>"
                for name in maintenance.LOG_TABLES
            ) + "</clickhouse>"
            path.write_text(body)
            path.with_name("query-log-retention.staged").write_text("staged")
            self.assertEqual(len(maintenance.policy_hash(path)), 64)
            path.write_text(body.replace("INTERVAL 7 DAY", "INTERVAL 1 DAY", 1))
            with self.assertRaisesRegex(maintenance.MaintenanceError, "seven days"):
                maintenance.policy_hash(path)


if __name__ == "__main__":
    unittest.main()
