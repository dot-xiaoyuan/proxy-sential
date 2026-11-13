#!/usr/bin/env python3
"""Plan or remove a small number of fully expired ClickHouse system-log parts.

Run on the storage host. The default is read-only; --apply never recreates a
container or rewrites a mixed-age part. query_log requires an additional
assertion that the deployed recovery path no longer reads it.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable


LOG_TABLES = (
    "text_log",
    "query_log",
    "part_log",
    "trace_log",
    "query_views_log",
    "processors_profile_log",
    "metric_log",
    "asynchronous_metric_log",
    "query_metric_log",
)
LOG_TABLE_NAME = re.compile(r"^(" + "|".join(re.escape(table) for table in LOG_TABLES) + r")(?:_[0-9]{1,6})?$")
PART_NAME = re.compile(r"^[0-9]{6}_[0-9]+_[0-9]+_[0-9]+(?:_[0-9]+)?$")
CONTAINER_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
DEFAULT_POLICY = Path("/opt/proxy-sentinel/data/db/clickhouse/config.d/production-system-logs.xml")
DEFAULT_QUERY_LOG_TEMPLATE = Path("/opt/proxy-sentinel/current/deploy/clickhouse/production-query-log-retention.xml")
INPLACE_STATE = Path("/opt/proxy-sentinel/data/db/clickhouse/system-log-inplace-state.json")
INPLACE_CONTAINER_POLICY = "/etc/clickhouse-server/config.d/production-system-logs.xml"
DEFAULT_MAX_BYTES = 16 * 1024**3
OPERATIONS_DEGRADED_MAX_BYTES = 4 * 1024**3


class SafetyError(RuntimeError):
    pass


def run_command(args: list[str], *, timeout: int = 30) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise SafetyError(f"command failed ({result.returncode}): {args[0]} {args[1]}: {result.stderr.strip()[:500]}")
    return result.stdout.strip()


def clickhouse_query(container: str, sql: str) -> list[dict[str, Any]]:
    # The SQL is passed as an argv value, not interpolated into a shell. The
    # credentials are read inside the container and never appear in output.
    output = run_command([
        "docker", "exec", container, "sh", "-c",
        'exec clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --database "$CLICKHOUSE_DB" --query "$1"',
        "sh", sql,
    ])
    return [json.loads(line) for line in output.splitlines() if line]


def server_ready(url: str) -> tuple[bool, str]:
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            return response.status == 200, str(response.status)
    except urllib.error.HTTPError as exc:
        exc.close()
        return False, str(exc.code)
    except (urllib.error.URLError, TimeoutError) as exc:
        return False, type(exc).__name__


def operations_only_degraded_payload(body: Any) -> bool:
    if not isinstance(body, dict) or body.get("status") != "not_ready":
        return False
    components = body.get("components")
    if not isinstance(components, dict):
        return False
    operations = components.get("operations")
    if not isinstance(operations, dict) or operations.get("status") != "unavailable" or \
            "timeout" not in str(operations.get("error", "")).lower():
        return False
    required = ("storage", "collector", "authentication", "identity_ingest", "discovery_pipeline")
    if any(not isinstance(components.get(name), dict) or components[name].get("status") != "ready" for name in required):
        return False
    for name, item in components.items():
        if name != "operations" and (not isinstance(item, dict) or item.get("status") not in ("ready", "disabled")):
            return False
    return True


def operations_only_degraded(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=3):
            return False
    except urllib.error.HTTPError as exc:
        if exc.code != 503:
            exc.close()
            return False
        try:
            raw = exc.read(65537)
        finally:
            exc.close()
    except (urllib.error.URLError, TimeoutError):
        return False
    if len(raw) > 65536:
        return False
    try:
        return operations_only_degraded_payload(json.loads(raw))
    except (UnicodeDecodeError, ValueError):
        return False


def policy_retention_days(path: Path, table: str) -> int | None:
    if not path.is_file():
        return None
    root = ET.parse(path).getroot()
    ttl = root.findtext(f"{table}/ttl", default="")
    match = re.fullmatch(r"\s*event_date\s*\+\s*INTERVAL\s+(\d+)\s+DAY\s+DELETE\s*", ttl, re.IGNORECASE)
    return int(match.group(1)) if match else None


def atomic_write(path: Path, content: str, mode: int) -> None:
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, prefix=".system-log-policy-", delete=False) as temporary:
        temporary_path = Path(temporary.name)
        try:
            os.fchmod(temporary.fileno(), mode)
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        except BaseException:
            temporary_path.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary_path, path)
        directory_fd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary_path.unlink(missing_ok=True)


def query_log_marker(policy: Path) -> Path:
    return policy.with_name("query-log-retention.staged")


def base_log_table(table: str) -> str:
    match = LOG_TABLE_NAME.fullmatch(table)
    if match is None:
        raise SafetyError(f"system-log table is not allowlisted: {table!r}")
    return match.group(1)


def has_exact_seven_day_ttl(ddl: str) -> bool:
    # An unmounted host policy proves nothing about the active table. Require
    # the exact live retention rule and part-only cleanup before allowing an
    # exceptional in-place maintenance pass.
    engine = re.search(r"\bENGINE\s*=\s*MergeTree\b", ddl, re.IGNORECASE)
    if engine is None:
        return False
    return bool(re.search(
        r"\bTTL\s+event_date\s*\+\s*(?:toIntervalDay\(7\)|INTERVAL\s+7\s+DAY)(?:\s+DELETE)?(?=\s+(?:SETTINGS|COMMENT)|\s*$)",
        ddl[engine.end():], re.IGNORECASE,
    )) and bool(re.search(r"\bttl_only_drop_parts\s*=\s*1\b", ddl[engine.end():], re.IGNORECASE))


def verify_inplace_activation(container: str, policy: Path, active_query_log_ddl: str) -> None:
    if not INPLACE_STATE.is_file() or INPLACE_STATE.is_symlink():
        raise SafetyError("in-place activation state is missing")
    state = json.loads(INPLACE_STATE.read_text())
    if state.get("status") != "active" or state.get("merges") != "stopped_pending_cleanup":
        raise SafetyError("in-place activation is not verified active")
    expected_policy = hashlib.sha256(policy.read_bytes()).hexdigest()
    if (state.get("policy", {}).get("sha256") != expected_policy or
            state.get("live_ddl_sha256", {}).get("query_log") != hashlib.sha256(active_query_log_ddl.encode()).hexdigest()):
        raise SafetyError("in-place policy or live query_log DDL changed")
    identity = run_command(["docker", "inspect", "--format", "{{.Id}} {{.State.StartedAt}}", container]).split()
    if len(identity) != 2 or identity != [state.get("container", {}).get("id"), state.get("container", {}).get("started_at")]:
        raise SafetyError("ClickHouse restarted or changed after in-place activation")
    configured = run_command(["docker", "exec", container, "sha256sum", INPLACE_CONTAINER_POLICY]).split()
    if len(configured) != 2 or configured[0] != expected_policy or configured[1] != INPLACE_CONTAINER_POLICY:
        raise SafetyError("persistent container policy differs after in-place activation")


def template_digest(template: Path) -> str:
    if policy_retention_days(template, "query_log") != 7:
        raise SafetyError(f"query_log retention template is missing or is not seven days: {template}")
    return hashlib.sha256(template.read_bytes()).hexdigest()


def with_query_log_ttl(original: str) -> str:
    root = ET.fromstring(original)
    if root.find("query_log") is not None:
        raise SafetyError("base policy has a query_log section; inspect it manually before staging")
    closing = re.search(r"</clickhouse>\s*$", original)
    if closing is None:
        raise SafetyError("base policy has no closing clickhouse element")
    updated = original[: closing.start()] + "    <query_log><ttl>event_date + INTERVAL 7 DAY DELETE</ttl></query_log>\n" + original[closing.start() :]
    ET.fromstring(updated)
    return updated


def stage_query_log_policy(policy: Path, template: Path, *, apply: bool) -> tuple[bool, bool]:
    digest = template_digest(template)
    if not policy.is_file():
        raise SafetyError(f"base ClickHouse policy is missing: {policy}")
    current = policy_retention_days(policy, "query_log")
    if current is not None and current != 7:
        raise SafetyError(f"base policy already has a different query_log TTL: {current} days")
    marker = query_log_marker(policy)
    marker_changed = not marker.is_file() or marker.read_text().strip() != digest
    policy_changed = current != 7
    if not apply:
        return policy_changed, marker_changed
    if policy_changed:
        atomic_write(policy, with_query_log_ttl(policy.read_text()), policy.stat().st_mode & 0o777)
    if marker_changed:
        atomic_write(marker, digest + "\n", 0o644)
    return policy_changed, marker_changed


def materialize_staged_policy(base: Path, template: Path, output: Path, *, apply: bool) -> bool:
    if not base.is_file():
        raise SafetyError(f"release base policy is missing: {base}")
    digest = template_digest(template)
    marker = query_log_marker(output)
    staged = marker.is_file()
    if staged and marker.read_text().strip() != digest:
        raise SafetyError("staged query_log marker does not match the release template; revalidate and restage")
    original = base.read_text()
    if policy_retention_days(base, "query_log") is not None:
        raise SafetyError("release base policy must not enable query_log TTL by default")
    updated = with_query_log_ttl(original) if staged else original
    if apply:
        atomic_write(output, updated, 0o644)
    return staged


def plan_parts(parts: list[dict[str, Any]], cutoff: dt.date, max_parts: int, max_bytes: int) -> tuple[list[dict[str, Any]], int, int]:
    candidates = []
    mixed_parts = 0
    for part in parts:
        if not PART_NAME.fullmatch(str(part.get("name", ""))):
            raise SafetyError(f"unexpected part name: {part.get('name')!r}")
        partition = str(part.get("partition", ""))
        if not re.fullmatch(r"[0-9]{6}", partition):
            raise SafetyError(f"unexpected monthly partition: {partition!r}")
        first = dt.date.fromisoformat(part["min_date"])
        last = dt.date.fromisoformat(part["max_date"])
        if first > last or not part["name"].startswith(partition + "_"):
            raise SafetyError(f"part date or partition mismatch: {part['name']}")
        if first < cutoff <= last:
            mixed_parts += 1
        if last < cutoff:
            candidates.append(part)
    candidates.sort(key=lambda part: (part["max_date"], int(part["bytes_on_disk"]), part["name"]))
    chosen: list[dict[str, Any]] = []
    used_bytes = 0
    for part in candidates:
        size = int(part["bytes_on_disk"])
        if size <= 0 or size > max_bytes - used_bytes:
            continue
        chosen.append(part)
        used_bytes += size
        if len(chosen) >= max_parts:
            break
    return chosen, sum(int(part["bytes_on_disk"]) for part in candidates), mixed_parts


def inspect_parts(query: Callable[[str], list[dict[str, Any]]], table: str) -> list[dict[str, Any]]:
    rows = query(
        "SELECT name,partition,bytes_on_disk,rows,min_date,max_date FROM system.parts "
        f"WHERE database='system' AND table='{table}' AND active=1 "
        "ORDER BY max_date,bytes_on_disk,name LIMIT 1001 FORMAT JSONEachRow"
    )
    if len(rows) > 1000:
        raise SafetyError("more than 1000 active parts; inspect the table before planning cleanup")
    return rows


def main(argv: list[str] | None = None, *, query_factory: Callable[[str], Callable[[str], list[dict[str, Any]]]] = lambda container: lambda sql: clickhouse_query(container, sql)) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--table", default="text_log", help="allowlisted system log, optionally followed by a numeric legacy suffix")
    parser.add_argument("--retain-days", type=int, default=7)
    parser.add_argument("--max-parts", type=int, default=1)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--container", default="proxy-sentinel-clickhouse")
    parser.add_argument("--policy-file", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--query-log-template", type=Path, default=DEFAULT_QUERY_LOG_TEMPLATE)
    parser.add_argument("--base-policy", type=Path)
    parser.add_argument("--readyz", default="http://127.0.0.1:18080/readyz")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--recovery-independent", action="store_true", help="assert the running recovery code no longer requires system.query_log")
    parser.add_argument("--allow-operations-degraded", action="store_true", help="only for one <=4 GiB fully expired text_log part when operations alone times out")
    parser.add_argument("--stage-query-log-policy", action="store_true", help="stage query_log TTL in the host policy without restarting ClickHouse")
    parser.add_argument("--materialize-staged-policy", action="store_true", help="installer-only: refresh host policy from the release and an existing explicit marker")
    parser.add_argument("--allow-unmounted-live-ttl", action="store_true", help="allow bounded query_log cleanup after an in-place live TTL ALTER; the staged host policy will take effect only on a future container recreation")
    args = parser.parse_args(argv)
    base_table = base_log_table(args.table)
    query_log_table = base_table == "query_log"
    if args.retain_days < 7 or not 1 <= args.max_parts <= 10 or not 1 <= args.max_bytes <= 64 * 1024**3:
        parser.error("retain-days must be >=7, max-parts 1..10, max-bytes 1..64 GiB")
    if not CONTAINER_NAME.fullmatch(args.container):
        parser.error("invalid container name")
    if args.allow_operations_degraded and (args.table != "text_log" or args.stage_query_log_policy or
                                           args.materialize_staged_policy or args.max_parts != 1 or
                                           args.max_bytes > OPERATIONS_DEGRADED_MAX_BYTES):
        parser.error("operations exception allows only text_log, one part and at most 4 GiB")
    if args.allow_unmounted_live_ttl and (not query_log_table or not args.recovery_independent or
                                          args.stage_query_log_policy or args.materialize_staged_policy):
        parser.error("unmounted live TTL exception requires query_log cleanup with --recovery-independent")
    if args.apply and args.allow_unmounted_live_ttl and (args.max_parts != 1 or args.max_bytes > 4 * 1024**3):
        parser.error("unmounted live TTL cleanup allows one part and at most 4 GiB per invocation")
    if args.materialize_staged_policy:
        if args.base_policy is None or args.stage_query_log_policy:
            parser.error("--materialize-staged-policy requires --base-policy and cannot stage a new policy")
        staged = materialize_staged_policy(args.base_policy, args.query_log_template, args.policy_file, apply=args.apply)
        print(json.dumps({"mode": "materialize-policy" if args.apply else "dry-run-materialize-policy", "explicit_query_log_marker": staged, "query_log_ttl_activated": False}, ensure_ascii=False))
        return 0
    if args.stage_query_log_policy and args.table != "text_log":
        parser.error("--stage-query-log-policy is a separate operation; omit --table")
    if args.apply and args.stage_query_log_policy and not args.recovery_independent:
        raise SafetyError("query_log policy staging requires --recovery-independent after the new recovery code is deployed and verified")
    if args.apply and query_log_table and not args.recovery_independent:
        raise SafetyError("query_log remains protected until the new recovery code is deployed; pass --recovery-independent only after verifying the running release")

    running = run_command(["docker", "inspect", "--format", "{{.State.Running}}", args.container])
    if running != "true":
        raise SafetyError(f"{args.container} is not running")
    mounts = json.loads(run_command(["docker", "inspect", "--format", "{{json .Mounts}}", args.container]))
    policy_mounted = any(
        mount.get("Destination") == "/etc/clickhouse-server/config.d/production-system-logs.xml"
        and mount.get("Type") == "bind"
        and Path(mount.get("Source", "")).resolve() == args.policy_file.resolve()
        for mount in mounts
    )
    policy_days = policy_retention_days(args.policy_file, base_table)
    if args.apply and policy_days is None:
        raise SafetyError(f"staged policy is missing a valid TTL for {args.table}: {args.policy_file}")
    if policy_days is not None and args.retain_days < policy_days:
        raise SafetyError(f"requested retention {args.retain_days} days is shorter than staged policy {policy_days} days")
    ready, ready_status = server_ready(args.readyz)
    operations_degraded_exception = False
    # An unmounted host policy cannot affect the running container until a
    # separately controlled recreation. Only that reversible preparation may
    # proceed while the application is degraded. A mounted policy or actual
    # DROP PART operation retains the full readiness gate.
    if args.apply and not ready and (not args.stage_query_log_policy or policy_mounted):
        if args.allow_operations_degraded and operations_only_degraded(args.readyz):
            operations_degraded_exception = True
        else:
            raise SafetyError(f"application /readyz is {ready_status}; defer system-log cleanup until the application is ready")

    if args.stage_query_log_policy:
        policy_changed, marker_changed = stage_query_log_policy(args.policy_file, args.query_log_template, apply=args.apply)
        print(json.dumps({
            "mode": "stage-policy" if args.apply else "dry-run-stage-policy",
            "application_readyz": ready_status,
            "policy_mounted": policy_mounted,
            "host_policy_changed": policy_changed if args.apply else False,
            "would_change_host_policy": policy_changed if not args.apply else False,
            "staged_marker_present": query_log_marker(args.policy_file).is_file(),
            "would_change_marker": marker_changed if not args.apply else False,
            "query_log_ttl_activated": False,
            "next_step": "recreate ClickHouse only in a verified safe maintenance window, then confirm live system.query_log TTL before cleanup",
        }, ensure_ascii=False, indent=2))
        return 0

    query = query_factory(args.container)
    tables = query(
        "SELECT engine,partition_key,create_table_query,positionCaseInsensitive(create_table_query,' TTL ') AS ttl_position "
        f"FROM system.tables WHERE database='system' AND name='{args.table}' FORMAT JSONEachRow"
    )
    if len(tables) != 1 or tables[0]["engine"] != "MergeTree" or tables[0]["partition_key"] != "toYYYYMM(event_date)":
        raise SafetyError(f"unexpected system-log table schema: {tables!r}")
    query_log_live_ttl = int(tables[0]["ttl_position"]) > 0
    if query_log_table and args.table != "query_log":
        # A configuration change can leave the former table as query_log_0,
        # without a TTL of its own. The replacement query_log must already
        # have a live TTL before any former table is eligible for cleanup.
        current_table = query(
            "SELECT engine,partition_key,create_table_query,positionCaseInsensitive(create_table_query,' TTL ') AS ttl_position "
            "FROM system.tables WHERE database='system' AND name='query_log' FORMAT JSONEachRow"
        )
        if len(current_table) != 1 or current_table[0]["engine"] != "MergeTree" or current_table[0]["partition_key"] != "toYYYYMM(event_date)":
            raise SafetyError(f"unexpected active query_log schema: {current_table!r}")
        query_log_live_ttl = int(current_table[0]["ttl_position"]) > 0
    if args.apply and query_log_table:
        marker = query_log_marker(args.policy_file)
        if not marker.is_file() or marker.read_text().strip() != template_digest(args.query_log_template):
            raise SafetyError("query_log cleanup requires the explicit staged marker matching this release")
        if not query_log_live_ttl or (not policy_mounted and not args.allow_unmounted_live_ttl):
            raise SafetyError("query_log TTL is not active in the mounted policy and running ClickHouse table; defer cleanup until policy activation is verified")
        active_query_log_ddl = (tables if args.table == "query_log" else current_table)[0].get("create_table_query", "")
        if args.allow_unmounted_live_ttl and not policy_mounted and not has_exact_seven_day_ttl(active_query_log_ddl):
            raise SafetyError("unmounted query_log requires exact live seven-day TTL and ttl_only_drop_parts=1")
        if args.allow_unmounted_live_ttl and not policy_mounted:
            verify_inplace_activation(args.container, args.policy_file, active_query_log_ddl)
    cutoff = dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=args.retain_days)
    parts = inspect_parts(query, args.table)
    planned, eligible_bytes, mixed_parts = plan_parts(parts, cutoff, args.max_parts, args.max_bytes)
    report = {
        "mode": "apply" if args.apply else "dry-run",
        "table": args.table,
        "retention_days": args.retain_days,
        "cutoff_exclusive": cutoff.isoformat(),
        "application_readyz": ready_status,
        "operations_degraded_exception": operations_degraded_exception,
        "policy_file_present": args.policy_file.is_file(),
        "policy_retention_days": policy_days,
        "policy_mounted": policy_mounted,
        "live_table_has_ttl": int(tables[0]["ttl_position"]) > 0,
        "active_query_log_has_ttl": query_log_live_ttl if query_log_table else None,
        "unmounted_live_ttl_exception": bool(query_log_table and args.allow_unmounted_live_ttl and not policy_mounted),
        "active_parts": len(parts),
        "fully_expired_bytes": eligible_bytes,
        "mixed_age_parts_preserved": mixed_parts,
        "planned_bytes": sum(int(part["bytes_on_disk"]) for part in planned),
        "planned_parts": [{key: part[key] for key in ("name", "partition", "bytes_on_disk", "min_date", "max_date")} for part in planned],
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not args.apply:
        return 0
    for part in planned:
        if operations_degraded_exception:
            fresh_ready, _ = server_ready(args.readyz)
            if not fresh_ready and not operations_only_degraded(args.readyz):
                raise SafetyError("application readiness changed before bounded text_log DROP PART")
        current = query(
            "SELECT name,partition,bytes_on_disk,rows,min_date,max_date FROM system.parts "
            f"WHERE database='system' AND table='{args.table}' AND active=1 AND name='{part['name']}' FORMAT JSONEachRow"
        )
        if len(current) != 1 or current[0] != part or dt.date.fromisoformat(current[0]["max_date"]) >= cutoff:
            raise SafetyError(f"part changed after planning; stop before dropping {part['name']}")
        query(f"ALTER TABLE system.{args.table} DROP PART '{part['name']}'")
        still_active = query(
            "SELECT name FROM system.parts "
            f"WHERE database='system' AND table='{args.table}' AND active=1 AND name='{part['name']}' FORMAT JSONEachRow"
        )
        if still_active:
            raise SafetyError(f"part remains active after DROP PART: {part['name']}")
        print(f"dropped system.{args.table} part {part['name']} ({part['bytes_on_disk']} bytes)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (SafetyError, ET.ParseError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"system-log cleanup stopped: {exc}", file=sys.stderr)
        sys.exit(1)
