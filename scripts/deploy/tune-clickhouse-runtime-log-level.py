#!/usr/bin/env python3
"""Reduce ClickHouse Trace/Debug logging in place, with a checked rollback.

This changes only logger.level to information in the existing container.
It does not change text_log/query_log DDL, TTL, parts, merges or the container.
The default operation is a read-only plan. --apply requires the exact planned
container ID and snippet hash; --rollback restores the prior trace level.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path


ROOT = Path("/opt/proxy-sentinel")
CONTAINER = "proxy-sentinel-clickhouse"
CONFIG = "/etc/clickhouse-server/config.xml"
TARGET = "/etc/clickhouse-server/config.d/proxy-sentinel-runtime-log-level.xml"
STAGED = TARGET + ".staged"
STATE = ROOT / "data/db/clickhouse/runtime-log-level-state.json"
SNIPPET = b"<clickhouse>\n    <logger><level>information</level></logger>\n</clickhouse>\n"
MIN_FREE = 143 * 1024**3
EXPECTED_VERSION = "25.9.2.1"


class SafetyError(RuntimeError):
    pass


def command(args: list[str], *, timeout: int = 30, allow_failure: bool = False) -> str | None:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        if allow_failure:
            return None
        # Docker or ClickHouse errors can contain sensitive configuration.
        raise SafetyError(f"{args[0]} failed with exit status {result.returncode}")
    return result.stdout.strip()


def ch_query(sql: str) -> list[dict]:
    output = command(["docker", "exec", CONTAINER, "sh", "-c",
                      'exec clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --database "$CLICKHOUSE_DB" --query "$1"',
                      "sh", sql], timeout=30)
    return [json.loads(line) for line in output.splitlines() if line]


def config_value(key: str, *, required: bool = True) -> str | None:
    if key not in ("logger.level", "text_log.level", "logger.log", "logger.console",
                   "logger.console_log_level", "logger.use_syslog", "logger.levels"):
        raise SafetyError("config key is not allowlisted")
    value = command(["docker", "exec", CONTAINER, "clickhouse", "extract-from-config",
                     f"--config-file={CONFIG}", "--key", key], timeout=15, allow_failure=not required)
    if required and not value:
        raise SafetyError(f"required config key {key} is absent")
    return value


def container_identity(expected_id: str | None = None, expected_started: str | None = None) -> dict:
    rows = json.loads(command(["docker", "inspect", CONTAINER], timeout=20))
    if len(rows) != 1:
        raise SafetyError("ClickHouse container inspection is ambiguous")
    source = rows[0]
    state = source["State"]
    if (source.get("Name") != "/" + CONTAINER or state.get("Status") != "running"
            or state.get("Health", {}).get("Status") != "healthy"):
        raise SafetyError("ClickHouse container is not healthy")
    if expected_id is not None and source["Id"] != expected_id:
        raise SafetyError("ClickHouse container ID changed")
    if expected_started is not None and state.get("StartedAt") != expected_started:
        raise SafetyError("ClickHouse restarted during log-level maintenance")
    mounts = {(item["Source"], item["Destination"], item["RW"]) for item in source["Mounts"]}
    if mounts != {
        (str(ROOT / "data/db/clickhouse/data"), "/var/lib/clickhouse", True),
        (str(ROOT / "data/db/clickhouse/logs"), "/var/log/clickhouse-server", True),
    }:
        raise SafetyError("ClickHouse mounts changed; this path applies only to the existing container")
    if shutil.disk_usage(ROOT).free < MIN_FREE:
        raise SafetyError("disk lacks the protected passive buffer and maintenance headroom")
    return {"id": source["Id"], "started_at": state["StartedAt"]}


def ready() -> None:
    try:
        with urllib.request.urlopen("http://127.0.0.1:18080/readyz", timeout=3) as response:
            if response.status != 200:
                raise SafetyError("application /readyz is not 200")
    except (OSError, TimeoutError) as exc:
        raise SafetyError("application /readyz is unavailable") from exc


def table_fingerprints() -> dict[str, dict]:
    rows = ch_query("SELECT name,uuid,create_table_query FROM system.tables "
                    "WHERE database='system' AND name IN ('query_log','text_log') FORMAT JSONEachRow")
    if {row["name"] for row in rows} != {"query_log", "text_log"}:
        raise SafetyError("query_log or text_log is absent")
    return {row["name"]: {"uuid": row["uuid"],
                               "ddl_sha256": hashlib.sha256(row["create_table_query"].encode()).hexdigest()}
            for row in rows}


def query_count() -> int:
    rows = ch_query("SELECT value FROM system.events WHERE event='Query' FORMAT JSONEachRow")
    if len(rows) != 1:
        raise SafetyError("ClickHouse query counter is unavailable")
    return int(rows[0]["value"])


def clickhouse_time_ms() -> int:
    rows = ch_query("SELECT toUnixTimestamp64Milli(now64(3)) AS value FORMAT JSONEachRow")
    if len(rows) != 1:
        raise SafetyError("ClickHouse time is unavailable")
    return int(rows[0]["value"])


def noisy_logs_since(epoch_ms: int) -> int:
    rows = ch_query(
        "SELECT countIf(toString(level) IN ('Trace','Debug')) AS value FROM system.text_log "
        f"WHERE event_date >= today() - 1 AND event_time_microseconds >= fromUnixTimestamp64Milli({epoch_ms}) FORMAT JSONEachRow"
    )
    if len(rows) != 1:
        raise SafetyError("recent text_log levels are unavailable")
    return int(rows[0]["value"])


def container_file_hash(path: str) -> str | None:
    if command(["docker", "exec", CONTAINER, "test", "-L", path], allow_failure=True) is not None:
        raise SafetyError("runtime log-level path is a symlink")
    if command(["docker", "exec", CONTAINER, "test", "-e", path], allow_failure=True) is None:
        return None
    output = command(["docker", "exec", CONTAINER, "sha256sum", path])
    match = re.fullmatch(r"([0-9a-f]{64})\s+.+", output)
    if match is None:
        raise SafetyError("container checksum output is malformed")
    return match.group(1)


def save_state(payload: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix=".runtime-log-level-", dir=STATE.parent)
    try:
        with os.fdopen(fd, "w") as target:
            os.fchmod(target.fileno(), 0o600)
            json.dump(payload, target, sort_keys=True)
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        os.replace(path, STATE)
        directory = os.open(STATE.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(path):
            os.unlink(path)


def install_snippet() -> None:
    if container_file_hash(TARGET) is not None or container_file_hash(STAGED) is not None:
        raise SafetyError("runtime log-level config already exists")
    fd, path = tempfile.mkstemp(prefix="ch-runtime-log-level-", suffix=".xml")
    try:
        with os.fdopen(fd, "wb") as source:
            source.write(SNIPPET)
            source.flush()
            os.fsync(source.fileno())
        os.chmod(path, 0o644)
        command(["docker", "cp", path, f"{CONTAINER}:{STAGED}"], timeout=30)
        if container_file_hash(STAGED) != hashlib.sha256(SNIPPET).hexdigest():
            raise SafetyError("staged runtime config hash differs")
        command(["docker", "exec", CONTAINER, "mv", STAGED, TARGET])
        if container_file_hash(TARGET) != hashlib.sha256(SNIPPET).hexdigest():
            raise SafetyError("installed runtime config hash differs")
    finally:
        os.unlink(path)


def remove_snippet(expected_hash: str) -> None:
    if container_file_hash(TARGET) != expected_hash:
        raise SafetyError("runtime config changed; refusing to remove it")
    command(["docker", "exec", CONTAINER, "rm", TARGET])
    ch_query("SYSTEM RELOAD CONFIG")


def verify_metadata(container: dict, tables: dict) -> None:
    container_identity(container["id"], container["started_at"])
    if table_fingerprints() != tables:
        raise SafetyError("system log table metadata changed during log-level maintenance")
    ready()


def preflight() -> tuple[dict, dict]:
    container = container_identity()
    ready()
    version = ch_query("SELECT version() AS value FORMAT JSONEachRow")
    if len(version) != 1 or version[0]["value"] != EXPECTED_VERSION:
        raise SafetyError("ClickHouse version differs from the verified source behavior")
    if config_value("logger.level") != "trace" or config_value("text_log.level") != "trace":
        raise SafetyError("runtime logging baseline differs from trace")
    if not config_value("logger.log"):
        raise SafetyError("file logger is absent; root level may not control text_log as expected")
    for key in ("logger.console", "logger.console_log_level", "logger.use_syslog", "logger.levels"):
        if config_value(key, required=False) is not None:
            raise SafetyError(f"{key} is configured; review root logger threshold")
    if container_file_hash(TARGET) is not None or container_file_hash(STAGED) is not None:
        raise SafetyError("runtime log-level config already exists")
    return container, table_fingerprints()


def apply(expected_id: str, expected_hash: str) -> None:
    if STATE.exists():
        raise SafetyError("prior runtime log-level state exists; inspect it first")
    container, tables = preflight()
    if container["id"] != expected_id or hashlib.sha256(SNIPPET).hexdigest() != expected_hash:
        raise SafetyError("planned container or snippet changed")
    state = {"status": "preparing", "at": dt.datetime.now(dt.timezone.utc).isoformat(),
             "container": container, "tables": tables, "snippet_sha256": expected_hash,
             "old_level": "trace", "new_level": "information"}
    save_state(state)
    installed = False
    try:
        install_snippet()
        installed = True
        ch_query("SYSTEM RELOAD CONFIG")
        if config_value("logger.level") != "information":
            raise SafetyError("merged config did not select information")
        verify_metadata(container, tables)
        barrier = clickhouse_time_ms()
        before = query_count()
        time.sleep(20)
        ch_query("SYSTEM FLUSH LOGS text_log")
        observed_queries = query_count() - before
        noisy = noisy_logs_since(barrier)
        if observed_queries < 50 or noisy != 0:
            raise SafetyError(f"runtime logger validation failed: queries={observed_queries}, trace_or_debug={noisy}")
        verify_metadata(container, tables)
        save_state({**state, "status": "active", "observed_queries": observed_queries,
                    "trace_or_debug_after_reload": noisy})
        print(f"Runtime logger is information; {observed_queries} queries and no new Trace/Debug rows observed. No table or container changed.")
    except BaseException as exc:
        try:
            if installed or container_file_hash(TARGET) == expected_hash:
                remove_snippet(expected_hash)
                if config_value("logger.level") != "trace":
                    raise SafetyError("trace level was not restored")
                verify_metadata(container, tables)
                save_state({**state, "status": "rolled_back", "error_type": type(exc).__name__})
            else:
                if container_file_hash(STAGED) == expected_hash:
                    command(["docker", "exec", CONTAINER, "rm", STAGED])
                save_state({**state, "status": "needs_review", "error_type": type(exc).__name__})
        except BaseException as rollback_error:
            save_state({**state, "status": "needs_review", "error_type": type(exc).__name__,
                        "rollback_error_type": type(rollback_error).__name__})
            raise SafetyError("runtime log-level update and automatic rollback both failed") from rollback_error
        raise


def rollback() -> None:
    if not STATE.is_file() or STATE.is_symlink():
        raise SafetyError("runtime log-level state is missing")
    state = json.loads(STATE.read_text())
    if state.get("status") != "active" or state.get("old_level") != "trace":
        raise SafetyError("runtime log-level state is not active")
    container = state["container"]
    container_identity(container["id"], container["started_at"])
    if container_file_hash(TARGET) != state.get("snippet_sha256"):
        raise SafetyError("runtime log-level config changed")
    try:
        remove_snippet(state["snippet_sha256"])
        if config_value("logger.level") != "trace":
            raise SafetyError("trace level was not restored")
        verify_metadata(container, state["tables"])
        save_state({**state, "status": "rolled_back", "rolled_back_at": dt.datetime.now(dt.timezone.utc).isoformat()})
        print("Runtime logger restored to trace; system log tables and container are unchanged.")
    except BaseException as exc:
        save_state({**state, "status": "needs_review", "rollback_error_type": type(exc).__name__})
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--apply", action="store_true")
    operation.add_argument("--rollback", action="store_true")
    parser.add_argument("--expected-container-id")
    parser.add_argument("--expected-snippet-sha256")
    args = parser.parse_args()
    if args.rollback:
        rollback()
        return 0
    if args.apply:
        if (not re.fullmatch(r"[0-9a-f]{64}", args.expected_container_id or "") or
                not re.fullmatch(r"[0-9a-f]{64}", args.expected_snippet_sha256 or "")):
            parser.error("--apply requires planned container ID and snippet SHA256")
        apply(args.expected_container_id, args.expected_snippet_sha256)
        return 0
    container, tables = preflight()
    print(json.dumps({"mode": "plan", "container": container, "current_logger_level": "trace",
                      "text_log_level": "trace", "snippet_sha256": hashlib.sha256(SNIPPET).hexdigest(),
                      "system_log_tables": tables, "existing_state": STATE.exists()}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (SafetyError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"runtime ClickHouse log-level maintenance stopped: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
