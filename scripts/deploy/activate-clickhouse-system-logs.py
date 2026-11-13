#!/usr/bin/env python3
"""One-shot, reversible ClickHouse system-log TTL activation on the 184 host.

Default is a read-only plan. --apply requires the observed image ID and policy
hash. The stopped original container is retained under a rollback name. This
script never removes a volume or a system-log table.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path


NAME = "proxy-sentinel-clickhouse"
POLICY = Path("/opt/proxy-sentinel/data/db/clickhouse/config.d/production-system-logs.xml")
TEMPLATE = Path("/opt/proxy-sentinel/current/deploy/clickhouse/production-query-log-retention.xml")
MOUNT = "/etc/clickhouse-server/config.d/production-system-logs.xml"
STATE = Path("/opt/proxy-sentinel/data/db/clickhouse/system-log-maintenance-state.json")
JOURNAL = Path("/var/lib/proxy-sentinel/discovery-fresh-20261030T154207Z")
CAPTURE_STATS = Path("/var/lib/proxy-sentinel/discovery-spool/stream-capture-stats/capture.stats")
EXPECTED_BINDS = {
    "/opt/proxy-sentinel/data/db/clickhouse/data:/var/lib/clickhouse",
    "/opt/proxy-sentinel/data/db/clickhouse/logs:/var/log/clickhouse-server",
}
EXPECTED_PORTS = {
    "8123/tcp": [{"HostIp": "127.0.0.1", "HostPort": "28123"}],
    "9000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "29000"}],
}
EXPECTED_ENV = {
    "PROXY_SENTINEL_PASSIVE_DURABLE_BUFFER_SEGMENTS": "8192",
    "PROXY_SENTINEL_PASSIVE_DURABLE_BUFFER_BYTES": str(32 * 1024**3),
    "PROXY_SENTINEL_PASSIVE_DURABLE_MIN_FREE_BYTES": str(100 * 1024**3),
}
SEGMENT_BYTES = 4 * 1024**2
DRAIN_RESERVE = 258
MAX_BACKLOG = 1000
MIN_FREE = 100 * 1024**3 + DRAIN_RESERVE * SEGMENT_BYTES + 32 * 1024**3 + 10 * 1024**3
LOG_TABLES = ("query_log", "text_log", "part_log", "trace_log", "query_views_log",
              "processors_profile_log", "metric_log", "asynchronous_metric_log", "query_metric_log")


class MaintenanceError(RuntimeError):
    pass


def command(argv: list[str], timeout: int = 30) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        # Never echo an argv, environment value, or Docker error containing one.
        raise MaintenanceError(f"{argv[0]} failed with exit code {result.returncode}")
    return result.stdout.strip()


def inspect(name: str) -> dict | None:
    result = subprocess.run(["docker", "inspect", name], capture_output=True, text=True, timeout=15, check=False)
    if result.returncode:
        return None
    rows = json.loads(result.stdout)
    return rows[0] if len(rows) == 1 else None


def ch_query(container: str, sql: str, timeout: int = 35) -> str:
    return command(["docker", "exec", container, "sh", "-c",
                    'exec clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --database "$CLICKHOUSE_DB" --query "$1"',
                    "sh", sql], timeout=timeout)


def utc_time(raw: str) -> dt.datetime:
    # 184 uses Python 3.7, which rejects Go's 7-9 digit fractional seconds.
    normalized = re.sub(r"(\.\d{6})\d+", r"\1", raw.replace("Z", "+00:00"))
    return dt.datetime.fromisoformat(normalized)


def policy_hash(path: Path = POLICY) -> str:
    if not path.is_file() or path.is_symlink():
        raise MaintenanceError("staged policy is missing or a symlink")
    root = ET.parse(path).getroot()
    if root.tag != "clickhouse":
        raise MaintenanceError("staged policy root is invalid")
    for table in LOG_TABLES:
        if root.findtext(f"{table}/ttl", default="").strip() != "event_date + INTERVAL 7 DAY DELETE":
            raise MaintenanceError(f"staged {table} TTL is not seven days")
    marker = path.with_name("query-log-retention.staged")
    if not marker.is_file():
        raise MaintenanceError("query-log retention marker is missing")
    if path == POLICY:
        if not TEMPLATE.is_file() or marker.read_text().strip() != hashlib.sha256(TEMPLATE.read_bytes()).hexdigest():
            raise MaintenanceError("query-log retention marker does not match the deployed template")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def env_map(items: list[str]) -> dict[str, str]:
    parsed = {}
    for item in items:
        if "=" not in item or "\n" in item or "\r" in item:
            raise MaintenanceError("container has an env value unsuitable for an env file")
        key, value = item.split("=", 1)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) or key in parsed:
            raise MaintenanceError("container environment has an invalid or repeated key")
        parsed[key] = value
    return parsed


def check_source(source: dict, expected_image_id: str | None = None) -> None:
    config, host = source["Config"], source["HostConfig"]
    if source["Name"] != "/" + NAME or source["State"]["Status"] != "running":
        raise MaintenanceError("source ClickHouse container is not running under the expected name")
    if source["State"].get("Health", {}).get("Status") != "healthy":
        raise MaintenanceError("source ClickHouse container is not healthy")
    if expected_image_id and source["Image"] != expected_image_id:
        raise MaintenanceError("ClickHouse image ID changed after planning")
    if "@sha256:" not in config["Image"]:
        raise MaintenanceError("ClickHouse image is not pinned by digest")
    image = json.loads(command(["docker", "image", "inspect", config["Image"]]))[0]
    if image["Id"] != source["Image"]:
        raise MaintenanceError("pinned ClickHouse image is not local or differs from the running image")
    if set(host.get("Binds") or []) != EXPECTED_BINDS or host.get("Mounts") or host.get("VolumesFrom"):
        raise MaintenanceError("ClickHouse storage binds changed; refusing to rebuild")
    if host.get("PortBindings") != EXPECTED_PORTS or host.get("NetworkMode") != "default":
        raise MaintenanceError("ClickHouse ports or network changed")
    if list(source["NetworkSettings"]["Networks"]) != ["bridge"]:
        raise MaintenanceError("ClickHouse network attachments changed")
    if host.get("NanoCpus") != 12_000_000_000 or host.get("Memory") != 24 * 1024**3 or host.get("MemorySwap") != 32 * 1024**3:
        raise MaintenanceError("ClickHouse CPU or memory limits changed")
    if host.get("RestartPolicy", {}).get("Name") != "unless-stopped" or host.get("AutoRemove"):
        raise MaintenanceError("ClickHouse restart policy changed")
    if host.get("Ulimits") != [{"Name": "nofile", "Hard": 262144, "Soft": 262144}]:
        raise MaintenanceError("ClickHouse nofile limit changed")
    if host.get("LogConfig") != {"Type": "json-file", "Config": {"max-file": "5", "max-size": "20m"}}:
        raise MaintenanceError("ClickHouse Docker log policy changed")
    if (host.get("Privileged") or host.get("ReadonlyRootfs") or host.get("CapAdd") or host.get("CapDrop")
            or host.get("SecurityOpt") or host.get("Devices") or host.get("DeviceRequests") or host.get("Tmpfs")
            or host.get("ExtraHosts") or host.get("Links") or host.get("Dns") or host.get("DnsOptions")
            or host.get("DnsSearch") or host.get("Sysctls") or host.get("PidsLimit") or host.get("Init")):
        raise MaintenanceError("ClickHouse has unhandled Docker host options")
    if config.get("Entrypoint") != ["/entrypoint.sh"] or config.get("Cmd") is not None or config.get("User") or config.get("WorkingDir"):
        raise MaintenanceError("ClickHouse entrypoint or command changed")
    health = config.get("Healthcheck") or {}
    if health.get("Test", [None])[0] != "CMD-SHELL" or len(health.get("Test", [])) != 2:
        raise MaintenanceError("ClickHouse healthcheck changed")
    env_map(config["Env"])


def passive_status() -> dict:
    pid = int(command(["systemctl", "show", "proxy-sentinel-discovery.service", "-p", "MainPID", "--value"]))
    if pid <= 0:
        raise MaintenanceError("passive capture is not running")
    actual = env_map(Path(f"/proc/{pid}/environ").read_bytes().decode().split("\0")[:-1])
    if any(actual.get(key) != value for key, value in EXPECTED_ENV.items()):
        raise MaintenanceError("passive durable buffer is not active in the running process")
    line = command(["journalctl", "-u", "proxy-sentinel-discovery.service", "-g", "passive stream metrics",
                    "-r", "-n", "1", "--no-pager", "-o", "cat"])
    marker = "passive stream metrics "
    if marker not in line:
        raise MaintenanceError("passive metrics are unavailable")
    metric = json.loads(line.split(marker, 1)[1])
    if (dt.datetime.now(dt.timezone.utc) - utc_time(metric["at"])).total_seconds() > 90:
        raise MaintenanceError("passive metrics are stale")
    backlog = metric.get("durable_backlog") or {}
    if backlog.get("limit_segments") != 8192 or backlog.get("segments", MAX_BACKLOG + 1) > MAX_BACKLOG or backlog.get("pause_reason"):
        raise MaintenanceError("passive backlog is close to the maintenance guard or paused")
    if any((metric.get("queues") or {}).get(lane, {}).get("capacity") != 8192 for lane in ("archive", "search", "projection")):
        raise MaintenanceError("passive lane queues are not in durable mode")
    capture = json.loads(CAPTURE_STATS.read_text())
    if (dt.datetime.now(dt.timezone.utc) - utc_time(capture["updated_at"])).total_seconds() > 90:
        raise MaintenanceError("passive capture statistics are stale")
    free = shutil.disk_usage(JOURNAL).free
    if free < MIN_FREE:
        raise MaintenanceError("disk lacks a full passive buffer and ten GiB of extra headroom")
    return {"pid": pid, "backlog": backlog["segments"], "pause_count": backlog.get("pause_count", 0),
            "capture_full_count": capture["capture_queue"]["full_count"], "free_bytes": free,
            "capture_updated_at": capture["updated_at"]}


def check_passive(baseline: dict) -> dict:
    now = passive_status()
    if now["pid"] != baseline["pid"] or now["pause_count"] != baseline["pause_count"] or now["capture_full_count"] != baseline["capture_full_count"]:
        raise MaintenanceError("passive capture restarted, paused, or filled its packet queue")
    return now


def run_argv(source: dict, env_file: Path) -> list[str]:
    config, host = source["Config"], source["HostConfig"]
    health = config["Healthcheck"]
    argv = ["docker", "run", "-d", "--name", NAME, "--env-file", str(env_file),
            "--cpus", str(host["NanoCpus"] / 1_000_000_000), "--memory", str(host["Memory"]),
            "--memory-swap", str(host["MemorySwap"]), "--restart", host["RestartPolicy"]["Name"],
            "--network", host["NetworkMode"], "--ulimit", "nofile=262144:262144",
            "--log-driver", host["LogConfig"]["Type"], "--shm-size", str(host["ShmSize"]),
            "--ipc", host["IpcMode"], "--runtime", host["Runtime"],
            "--hostname", config["Hostname"], "--entrypoint", config["Entrypoint"][0],
            "--health-cmd", health["Test"][1], "--health-interval", f'{health["Interval"]}ns',
            "--health-timeout", f'{health["Timeout"]}ns', "--health-retries", str(health["Retries"])]
    if health.get("StartPeriod"):
        argv += ["--health-start-period", f'{health["StartPeriod"]}ns']
    for key, value in sorted(host["LogConfig"]["Config"].items()):
        argv += ["--log-opt", f"{key}={value}"]
    for bind in sorted(host["Binds"]):
        argv += ["--volume", bind]
    argv += ["--mount", f"type=bind,src={POLICY},dst={MOUNT},readonly"]
    for port, bindings in sorted(host["PortBindings"].items()):
        for binding in bindings:
            argv += ["--publish", f'{binding["HostIp"]}:{binding["HostPort"]}:{port}']
    for port in sorted(config.get("ExposedPorts") or {}):
        argv += ["--expose", port]
    for key, value in sorted((config.get("Labels") or {}).items()):
        argv += ["--label", f"{key}={value}"]
    argv.append(config["Image"])
    return argv


def save_state(payload: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".ch-maintenance-", dir=STATE.parent)
    try:
        with os.fdopen(fd, "w") as out:
            os.fchmod(out.fileno(), 0o600)
            json.dump(payload, out, sort_keys=True)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, STATE)
        directory = os.open(STATE.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def wait_healthy(name: str, baseline: dict, seconds: int) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        check_passive(baseline)
        container = inspect(name)
        if container is None or container["State"]["Status"] == "exited":
            raise MaintenanceError("new ClickHouse container is absent or exited")
        if container["State"].get("Health", {}).get("Status") == "healthy":
            return
        time.sleep(5)
    raise MaintenanceError("ClickHouse healthcheck timed out")


def stop_old_log_merges(baseline: dict) -> None:
    # Rotation leaves the large old tables under _0 without the new TTL. Keep
    # them idle until the separate, bounded expired-part cleaner can run.
    rows = ch_query(NAME, "SELECT name FROM system.tables WHERE database = 'system' AND name IN ('query_log_0', 'text_log_0') FORMAT TabSeparatedRaw")
    names = set(rows.splitlines())
    if names != {"query_log_0", "text_log_0"}:
        raise MaintenanceError("old query_log/text_log did not rotate to _0")
    for table in ("query_log_0", "text_log_0"):
        ch_query(NAME, f"SYSTEM STOP MERGES system.{table}")
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        count = int(ch_query(NAME, "SELECT count() FROM system.merges WHERE database = 'system' AND table IN ('query_log_0', 'text_log_0') FORMAT TabSeparatedRaw"))
        if count == 0:
            return
        check_passive(baseline)
        time.sleep(3)
    raise MaintenanceError("old system-log merges did not cancel after rotation")


def verify_new(source: dict, baseline: dict) -> None:
    current = inspect(NAME)
    if current is None or current["Image"] != source["Image"]:
        raise MaintenanceError("new ClickHouse image differs from the old image")
    old, new = source["HostConfig"], current["HostConfig"]
    for key in ("NanoCpus", "Memory", "MemorySwap", "RestartPolicy", "PortBindings", "Ulimits", "LogConfig", "NetworkMode", "ShmSize", "IpcMode", "Runtime"):
        if old.get(key) != new.get(key):
            raise MaintenanceError(f"new ClickHouse {key} differs from the old container")
    if env_map(source["Config"]["Env"]) != env_map(current["Config"]["Env"]):
        raise MaintenanceError("new ClickHouse environment differs from the old container")
    mounts = {(m["Source"], m["Destination"], m["RW"]) for m in current["Mounts"]}
    expected = {(m["Source"], m["Destination"], m["RW"]) for m in source["Mounts"]}
    if mounts != expected | {(str(POLICY), MOUNT, False)}:
        raise MaintenanceError("new ClickHouse bind mounts or read-only policy mount differ")
    if current["Config"].get("Healthcheck") != source["Config"].get("Healthcheck"):
        raise MaintenanceError("new ClickHouse healthcheck differs")
    ch_query(NAME, "SYSTEM FLUSH LOGS query_log, text_log", timeout=60)
    rows = ch_query(NAME, "SELECT name, create_table_query FROM system.tables WHERE database = 'system' AND name IN ('query_log', 'text_log', 'query_log_0', 'text_log_0') FORMAT JSONEachRow")
    tables = {item["name"]: item["create_table_query"] for item in map(json.loads, rows.splitlines())}
    for table in ("query_log", "text_log"):
        ddl = tables.get(table, "")
        if not re.search(r"\bTTL\s+event_date\s*\+\s*(?:toIntervalDay\(7\)|INTERVAL\s+7\s+DAY)", ddl, re.IGNORECASE):
            raise MaintenanceError(f"new {table} does not have a seven-day TTL")
        if table + "_0" not in tables:
            raise MaintenanceError(f"old {table} was not retained as _0")
    check_passive(baseline)


def rollback(state: dict, baseline: dict | None = None) -> None:
    old_name, old_id = state["old_name"], state["old_id"]
    old = inspect(old_name)
    original = inspect(NAME)
    if old is not None and old["Id"] != old_id:
        raise MaintenanceError("rollback container ID differs; refusing to remove any container")
    if old is None and (original is None or original["Id"] != old_id):
        raise MaintenanceError("original ClickHouse container is missing; refusing to remove the new container")
    if original is not None and original["Id"] != old_id:
        if original["State"]["Status"] == "running":
            command(["docker", "stop", "--time", "60", NAME], timeout=90)
        command(["docker", "rm", NAME], timeout=30)  # Never use -v.
    if old is not None:
        command(["docker", "rename", old_name, NAME])
        original = inspect(NAME)
    if original is None or original["Id"] != old_id:
        raise MaintenanceError("original ClickHouse container is missing; manual recovery required")
    if original["State"]["Status"] != "running":
        command(["docker", "start", NAME], timeout=90)
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        current = inspect(NAME)
        if current and current["State"].get("Health", {}).get("Status") == "healthy":
            if baseline:
                check_passive(baseline)
            save_state({**state, "status": "rolled_back"})
            print("Rollback complete: original container is healthy; old data binds were retained.")
            return
        time.sleep(5)
    raise MaintenanceError("original ClickHouse container did not become healthy after rollback")


def apply(source: dict, image_id: str, policy_sha: str) -> None:
    if STATE.exists():
        raise MaintenanceError("a prior maintenance state file exists; inspect it before another apply")
    check_source(source, image_id)
    if policy_hash() != policy_sha:
        raise MaintenanceError("staged policy hash changed after planning")
    baseline = passive_status()
    old_id = source["Id"]
    old_name = NAME + "-rollback-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if inspect(old_name) is not None:
        raise MaintenanceError("rollback container name already exists")
    state = {"old_name": old_name, "old_id": old_id, "image_id": image_id, "policy_sha256": policy_sha,
             "started_at": dt.datetime.now(dt.timezone.utc).isoformat(), "status": "preparing"}
    print(f"Preflight passed: image={image_id}, policy={policy_sha}, passive backlog={baseline['backlog']}, free={baseline['free_bytes']} bytes")
    ch_query(NAME, "SYSTEM STOP MERGES system.query_log")
    stopped = True
    try:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            count = int(ch_query(NAME, "SELECT count() FROM system.merges WHERE database = 'system' AND table = 'query_log' FORMAT TabSeparatedRaw"))
            if count == 0:
                break
            check_passive(baseline)
            time.sleep(3)
        else:
            raise MaintenanceError("query_log merge did not cancel within 90 seconds")
        ch_query(NAME, "SYSTEM FLUSH LOGS query_log, text_log", timeout=60)
        check_passive(baseline)
        save_state(state)
        print("query_log merge stopped; stopping the old container")
        command(["docker", "stop", "--time", "60", NAME], timeout=90)
        save_state({**state, "status": "old_stopped"})
        command(["docker", "rename", NAME, old_name])
        save_state({**state, "status": "old_renamed"})
        fd, env_path = tempfile.mkstemp(prefix=".clickhouse-env-", dir="/run")
        try:
            with os.fdopen(fd, "w") as out:
                os.fchmod(out.fileno(), 0o600)
                for key, value in env_map(source["Config"]["Env"]).items():
                    out.write(f"{key}={value}\n")
                out.flush()
                os.fsync(out.fileno())
            command(run_argv(source, Path(env_path)), timeout=90)
        finally:
            os.unlink(env_path)
        save_state({**state, "status": "new_started"})
        print("New container started; waiting for health and TTL verification")
        wait_healthy(NAME, baseline, 180)
        stop_old_log_merges(baseline)
        verify_new(source, baseline)
        save_state({**state, "status": "active"})
        print(f"Activation verified. Original container retained as {old_name}; no volumes or old logs removed.")
    except BaseException as exc:
        print(f"Activation failed: {type(exc).__name__}: {exc}; rolling back", file=sys.stderr)
        try:
            rollback(state, baseline)
        except BaseException as rollback_error:
            print(f"Automatic rollback failed: {type(rollback_error).__name__}: {rollback_error}; use --rollback after inspection", file=sys.stderr)
        raise
    finally:
        if stopped and inspect(NAME) is not None and inspect(NAME)["Id"] == old_id and inspect(NAME)["State"]["Status"] == "running":
            try:
                ch_query(NAME, "SYSTEM START MERGES system.query_log")
            except Exception:
                print("Could not restart query_log merges on the original container", file=sys.stderr)


def interrupted(signum: int, _frame: object) -> None:
    raise MaintenanceError(f"received signal {signum}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--apply", action="store_true", help="activate policy with automatic rollback")
    group.add_argument("--rollback", action="store_true", help="restore the retained original container")
    parser.add_argument("--expected-image-id", help="full image ID observed in a prior plan")
    parser.add_argument("--expected-policy-sha256", help="policy digest observed in a prior plan")
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    if os.geteuid() != 0:
        raise MaintenanceError("run as root on 184")
    if args.rollback:
        if not STATE.is_file():
            raise MaintenanceError("maintenance state file is missing")
        rollback(json.loads(STATE.read_text()))
        return 0
    source = inspect(NAME)
    if source is None:
        raise MaintenanceError("ClickHouse container is absent")
    check_source(source, args.expected_image_id if args.apply else None)
    digest = policy_hash()
    passive = passive_status()
    print(json.dumps({"mode": "apply" if args.apply else "plan", "container": NAME, "container_id": source["Id"],
                      "image_ref": source["Config"]["Image"], "image_id": source["Image"], "policy_sha256": digest,
                      "policy_path": str(POLICY), "storage_binds": sorted(source["HostConfig"]["Binds"]),
                      "ports": source["HostConfig"]["PortBindings"], "cpu_nano": source["HostConfig"]["NanoCpus"],
                      "memory_bytes": source["HostConfig"]["Memory"], "memory_swap_bytes": source["HostConfig"]["MemorySwap"],
                      "env_keys": sorted(env_map(source["Config"]["Env"])), "passive": passive}, sort_keys=True))
    if not args.apply:
        return 0
    if not args.expected_image_id or not args.expected_policy_sha256:
        raise MaintenanceError("--apply requires both expected image ID and policy SHA256")
    apply(source, args.expected_image_id, args.expected_policy_sha256)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (MaintenanceError, subprocess.TimeoutExpired, OSError, ValueError, ET.ParseError) as error:
        print(f"Maintenance aborted: {type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(1)
