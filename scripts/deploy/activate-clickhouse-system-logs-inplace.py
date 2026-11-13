#!/usr/bin/env python3
"""Activate bounded ClickHouse diagnostic-log TTL without stopping the container.

Default is read-only. --apply requires a verified release and exact container,
policy and stream-repair hashes. It copies the staged host policy into the
existing container's writable config layer for its next restart, then alters
the two live log tables with background merges stopped. It never drops a part.
Use converge-clickhouse-system-logs.py for separate, bounded expired-part work.
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
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path("/opt/proxy-sentinel")
CURRENT = ROOT / "current"
POLICY = ROOT / "data/db/clickhouse/config.d/production-system-logs.xml"
CONTAINER = "proxy-sentinel-clickhouse"
CONTAINER_POLICY = "/etc/clickhouse-server/config.d/production-system-logs.xml"
CONTAINER_POLICY_TMP = CONTAINER_POLICY + ".staged"
STATE = ROOT / "data/db/clickhouse/system-log-inplace-state.json"
MIN_FREE = 143 * 1024**3
EXPECTED_HELP = "journal-backed standard-event archive with scoped row proof"
TABLES = ("query_log", "text_log")
POLICY_LOG_TABLES = (
    "query_log", "text_log", "part_log", "trace_log", "query_views_log",
    "processors_profile_log", "metric_log", "asynchronous_metric_log", "query_metric_log",
)


class SafetyError(RuntimeError):
    pass


def command(args: list[str], timeout: int = 30, *, allow_failure: bool = False) -> str | None:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        if allow_failure:
            return None
        # Docker errors can include paths or environment values. Do not print them.
        raise SafetyError(f"{args[0]} failed with exit status {result.returncode}")
    return result.stdout.strip()


def ch_query(sql: str) -> list[dict]:
    output = command(["docker", "exec", CONTAINER, "sh", "-c",
                      'exec clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --database "$CLICKHOUSE_DB" --query "$1"',
                      "sh", sql], timeout=45)
    return [json.loads(line) for line in output.splitlines() if line]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def valid_digest(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{64}", value))


def release_identity(expected_commit: str | None, expected_repair_sha256: str | None) -> dict:
    release = CURRENT.resolve(strict=True)
    if release.parent != (ROOT / "releases").resolve():
        raise SafetyError("current does not resolve to a release directory")
    manifest = json.loads((release / "release-manifest.json").read_text())
    commit = manifest.get("git_commit", "")
    if (not re.fullmatch(r"[0-9a-f]{40}", commit) or manifest.get("git_worktree_modified") is not False
            or manifest.get("os") != "linux" or manifest.get("arch") != "amd64"
            or not manifest.get("version", "").endswith(commit[:8]) or release.name != manifest["version"]):
        raise SafetyError("release manifest is not a clean Linux amd64 commit")
    repair = release / "bin/stream-repair"
    repair_sha = sha256(repair)
    sums = (release / "SHA256SUMS").read_text().splitlines()
    if sums.count(repair_sha + "  ./bin/stream-repair") != 1:
        raise SafetyError("stream-repair differs from the release checksum manifest")
    help_result = subprocess.run([str(repair), "--help"], capture_output=True, text=True, timeout=5, check=False)
    if EXPECTED_HELP not in help_result.stdout + help_result.stderr:
        raise SafetyError("deployed stream-repair lacks journal-backed scoped recovery")
    if expected_commit is not None and commit != expected_commit:
        raise SafetyError("release commit changed after planning")
    if expected_repair_sha256 is not None and repair_sha != expected_repair_sha256:
        raise SafetyError("stream-repair binary changed after planning")
    return {"commit": commit, "repair_sha256": repair_sha, "release": release.name}


def policy_identity(expected_hash: str | None) -> dict:
    if not POLICY.is_file() or POLICY.is_symlink():
        raise SafetyError("staged host policy is missing or is a symlink")
    digest = sha256(POLICY)
    if expected_hash is not None and digest != expected_hash:
        raise SafetyError("host policy changed after planning")
    root = ET.parse(POLICY).getroot()
    if root.tag != "clickhouse" or root.attrib or sorted(child.tag for child in root) != sorted(("logger",) + POLICY_LOG_TABLES):
        raise SafetyError("staged host policy has an unexpected root")
    for table in POLICY_LOG_TABLES:
        node = root.find(table)
        allowed = {"ttl", "level"} if table == "text_log" else {"ttl"}
        if (node is None or node.attrib or len(node) != len(allowed)
                or {child.tag for child in node} != allowed or any(child.attrib for child in node)):
            raise SafetyError(f"staged {table} has an unexpected option")
        if node.findtext("ttl", default="").strip() != "event_date + INTERVAL 7 DAY DELETE":
            raise SafetyError(f"staged {table} TTL is not seven days")
    if root.findtext("text_log/level") != "information":
        raise SafetyError("staged text_log level changed")
    logger = root.find("logger")
    if (logger is None or logger.attrib or len(logger) != 3 or {child.tag for child in logger} != {"level", "size", "count"}
            or logger.findtext("level") != "information" or logger.findtext("size") != "100M"
            or logger.findtext("count") != "5"):
        raise SafetyError("staged logger policy changed")
    template = CURRENT / "deploy/clickhouse/production-query-log-retention.xml"
    marker = POLICY.with_name("query-log-retention.staged")
    if not template.is_file() or not marker.is_file() or marker.read_text().strip() != sha256(template):
        raise SafetyError("query_log recovery-independent retention marker differs from this release")
    return {"sha256": digest}


def container_identity(expected_id: str | None) -> dict:
    rows = json.loads(command(["docker", "inspect", CONTAINER], timeout=20))
    if len(rows) != 1:
        raise SafetyError("ClickHouse container inspection is ambiguous")
    source = rows[0]
    if (source.get("Name") != "/" + CONTAINER or source["State"].get("Status") != "running"
            or source["State"].get("Health", {}).get("Status") != "healthy"):
        raise SafetyError("ClickHouse container is not healthy under the expected name")
    if expected_id is not None and source["Id"] != expected_id:
        raise SafetyError("ClickHouse container ID changed after planning")
    mounts = {(m["Source"], m["Destination"], m["RW"]) for m in source["Mounts"]}
    expected = {
        (str(ROOT / "data/db/clickhouse/data"), "/var/lib/clickhouse", True),
        (str(ROOT / "data/db/clickhouse/logs"), "/var/log/clickhouse-server", True),
    }
    if mounts != expected:
        raise SafetyError("ClickHouse mounts changed; this in-place path applies only to the existing 184 container")
    if shutil.disk_usage(ROOT).free < MIN_FREE:
        raise SafetyError("disk lacks the protected passive buffer and maintenance headroom")
    return {"id": source["Id"], "started_at": source["State"]["StartedAt"]}


def application_ready() -> None:
    try:
        with urllib.request.urlopen("http://127.0.0.1:18080/readyz", timeout=3) as response:
            if response.status != 200:
                raise SafetyError("application is not ready")
    except (OSError, TimeoutError) as exc:
        raise SafetyError("application /readyz is unavailable") from exc


def system_tables() -> dict[str, dict]:
    rows = ch_query(
        "SELECT name,uuid,engine,partition_key,create_table_query FROM system.tables "
        "WHERE database='system' AND (name IN ('query_log','text_log') OR "
        "match(name, '^(query_log|text_log)_[0-9]{1,6}$')) FORMAT JSONEachRow"
    )
    return {row["name"]: row for row in rows}


def validate_table(table: dict, name: str) -> None:
    if table["engine"] != "MergeTree" or table["partition_key"] != "toYYYYMM(event_date)":
        raise SafetyError(f"system.{name} has an unexpected schema")


def has_live_ttl(ddl: str) -> bool:
    engine = re.search(r"\bENGINE\s*=\s*MergeTree\b", ddl, re.IGNORECASE)
    if engine is None:
        return False
    tail = ddl[engine.end():]
    return bool(re.search(r"\bTTL\s+event_date\s*\+\s*(?:toIntervalDay\(7\)|INTERVAL\s+7\s+DAY)(?:\s+DELETE)?(?=\s+(?:SETTINGS|COMMENT)|\s*$)", tail, re.IGNORECASE)) and \
        bool(re.search(r"\bttl_only_drop_parts\s*=\s*1\b", tail, re.IGNORECASE))


def stop_log_merges(names: list[str]) -> None:
    for name in names:
        if not re.fullmatch(r"(?:query_log|text_log)(?:_[0-9]{1,6})?", name):
            raise SafetyError("unexpected system log table name")
        ch_query(f"SYSTEM STOP MERGES system.{name}")
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        rows = ch_query("SELECT name FROM system.merges WHERE database='system' AND "
                        "match(table, '^(query_log|text_log)(_[0-9]{1,6})?$') LIMIT 1 FORMAT JSONEachRow")
        if not rows:
            return
        time.sleep(3)
    raise SafetyError("system log merge did not stop within 90 seconds")


def container_file_hash(path: str) -> str | None:
    exists = command(["docker", "exec", CONTAINER, "test", "-e", path], allow_failure=True)
    if exists is None:
        return None
    result = command(["docker", "exec", CONTAINER, "sha256sum", path])
    match = re.fullmatch(r"([0-9a-f]{64})\s+.+", result)
    if match is None:
        raise SafetyError("container policy checksum output is malformed")
    return match.group(1)


def install_container_policy(expected_sha: str) -> None:
    for path in (CONTAINER_POLICY, CONTAINER_POLICY_TMP):
        if command(["docker", "exec", CONTAINER, "test", "-L", path], allow_failure=True) is not None:
            raise SafetyError("container policy path is a symlink")
    current = container_file_hash(CONTAINER_POLICY)
    if current == expected_sha:
        return
    if current is not None or container_file_hash(CONTAINER_POLICY_TMP) is not None:
        raise SafetyError("container policy already differs or a staged copy remains")
    command(["docker", "cp", str(POLICY), f"{CONTAINER}:{CONTAINER_POLICY_TMP}"], timeout=30)
    if container_file_hash(CONTAINER_POLICY_TMP) != expected_sha:
        raise SafetyError("copied container policy hash differs")
    command(["docker", "exec", CONTAINER, "mv", CONTAINER_POLICY_TMP, CONTAINER_POLICY])
    if container_file_hash(CONTAINER_POLICY) != expected_sha:
        raise SafetyError("installed container policy hash differs")


def save_state(payload: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix=".ch-inplace-", dir=STATE.parent)
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


def apply(release: dict, policy: dict, container: dict) -> None:
    if STATE.exists():
        raise SafetyError("prior in-place maintenance state exists; inspect before another apply")
    application_ready()
    before = system_tables()
    for name in TABLES:
        if name not in before:
            raise SafetyError(f"system.{name} is absent")
        validate_table(before[name], name)
        if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", before[name]["uuid"]):
            raise SafetyError(f"system.{name} has no stable table UUID")
    state = {"status": "preparing", "at": dt.datetime.now(dt.timezone.utc).isoformat(),
             "release": release, "policy": policy, "container": container,
             "old_uuids": {name: before[name]["uuid"] for name in TABLES},
             "merges": "stopped_pending_cleanup"}
    stop_log_merges(sorted(before))
    save_state(state)
    try:
        install_container_policy(policy["sha256"])
        time.sleep(5)  # Detect a live config reload/rotation before altering.
        if container_identity(container["id"])["started_at"] != container["started_at"]:
            raise SafetyError("ClickHouse restarted while staging the policy")
        after_copy = system_tables()
        stop_log_merges(sorted(after_copy))
        for name in TABLES:
            table = after_copy.get(name)
            if table is None:
                raise SafetyError(f"system.{name} disappeared after policy staging")
            validate_table(table, name)
            if not has_live_ttl(table["create_table_query"]):
                ch_query(f"ALTER TABLE system.{name} MODIFY SETTING ttl_only_drop_parts = 1")
                ch_query(f"ALTER TABLE system.{name} MODIFY TTL event_date + INTERVAL 7 DAY DELETE SETTINGS materialize_ttl_after_modify = 0")
        final = system_tables()
        stop_log_merges(sorted(final))
        for name in TABLES:
            if name not in final or not has_live_ttl(final[name]["create_table_query"]):
                raise SafetyError(f"system.{name} live seven-day part-only TTL was not verified")
            old_uuid = before[name]["uuid"]
            if old_uuid not in {row["uuid"] for key, row in final.items() if key == name or key.startswith(name + "_")}:
                raise SafetyError(f"system.{name} original log table is not retained")
        if container_file_hash(CONTAINER_POLICY) != policy["sha256"]:
            raise SafetyError("persistent container policy changed after activation")
        application_ready()
        save_state({**state, "status": "active", "live_uuids": {name: final[name]["uuid"] for name in TABLES},
                    "live_ddl_sha256": {name: hashlib.sha256(final[name]["create_table_query"].encode()).hexdigest() for name in TABLES}})
        print("In-place seven-day TTL verified for query_log and text_log. Merges remain stopped for bounded part cleanup; no old log part was removed.")
    except BaseException as exc:
        save_state({**state, "status": "needs_review", "error_type": type(exc).__name__})
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--expected-release-commit")
    parser.add_argument("--expected-stream-repair-sha256")
    parser.add_argument("--expected-container-id")
    parser.add_argument("--expected-policy-sha256")
    args = parser.parse_args()
    if args.apply and (not re.fullmatch(r"[0-9a-f]{40}", args.expected_release_commit or "") or
                       not all(valid_digest(value or "") for value in (args.expected_stream_repair_sha256,
                                                                          args.expected_container_id,
                                                                          args.expected_policy_sha256))):
        parser.error("--apply requires the exact planned release commit, stream-repair SHA256, container ID and policy SHA256")
    release = release_identity(args.expected_release_commit, args.expected_stream_repair_sha256)
    policy = policy_identity(args.expected_policy_sha256)
    container = container_identity(args.expected_container_id)
    application_ready()
    existing_policy = container_file_hash(CONTAINER_POLICY)
    if existing_policy not in (None, policy["sha256"]):
        raise SafetyError("container config already contains a different policy")
    tables = system_tables()
    for name in TABLES:
        if name not in tables:
            raise SafetyError(f"system.{name} is absent")
        validate_table(tables[name], name)
    print(json.dumps({"mode": "apply" if args.apply else "plan", "release": release,
                      "policy_sha256": policy["sha256"], "container": container,
                      "container_policy_present": existing_policy == policy["sha256"],
                      "live_ttl": {name: has_live_ttl(tables[name]["create_table_query"]) for name in TABLES},
                      "existing_state": STATE.exists(), "merges_left_stopped_until_cleanup": True}, sort_keys=True))
    if args.apply:
        apply(release, policy, container)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (SafetyError, OSError, ValueError, ET.ParseError, subprocess.TimeoutExpired) as exc:
        print(f"in-place system-log activation stopped: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
