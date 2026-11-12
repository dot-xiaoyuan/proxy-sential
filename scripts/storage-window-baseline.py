#!/usr/bin/env python3
"""Measure one fixed passive-stream source/epoch window without business scans.

Run on the 184 storage host after the instrumented discovery release is live:
  python3 scripts/storage-window-baseline.py --source passive-discovery --epoch EPOCH --intervals 2

The command waits for a future periodic metric boundary, samples PostgreSQL and
ClickHouse system counters, then closes after the requested number of complete
30-second metric windows. It never updates a source cursor, database or service.
The PostgreSQL WAL/transaction and ClickHouse part/merge counters are system or
database wide; only journal metrics are attributed to the requested source.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import time
from typing import Any


SOURCE_NAME = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
EPOCH_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
METRIC_PREFIX = "passive stream metrics "
UTC = dt.timezone.utc


class ProbeError(RuntimeError):
    pass


def utc_now() -> dt.datetime:
    return dt.datetime.now(UTC)


def parse_stamp(raw: str) -> dt.datetime:
    try:
        # openEuler's Python 3.9 rejects Go's nine-digit RFC3339Nano fraction.
        # Six digits preserve sub-second ordering within our 10 ms gap budget.
        if not isinstance(raw, str):
            raise ValueError("timestamp is not text")
        nano = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\.(\d{1,9})(Z|[+-]\d\d:\d\d)", raw)
        if nano:
            raw = nano.group(1) + "." + nano.group(2)[:6].ljust(6, "0") + nano.group(3)
        value = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ProbeError("invalid timestamp in a system counter or stream metric") from exc
    if value.tzinfo is None:
        raise ProbeError("timestamp has no timezone")
    return value.astimezone(UTC)


def command(argv: list[str], *, timeout: int = 8) -> str:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProbeError(f"read-only probe {argv[0]} unavailable: {type(exc).__name__}") from exc
    if result.returncode:
        # Do not echo stderr: database connection errors can contain secrets.
        raise ProbeError(f"read-only probe {argv[0]} failed (exit {result.returncode})")
    return result.stdout.strip()


def pg_row(sql: str) -> dict[str, Any]:
    wrapped = (
        "BEGIN READ ONLY; SET LOCAL statement_timeout='3s'; "
        f"SELECT row_to_json(t) FROM ({sql}) AS t; COMMIT;"
    )
    raw = command([
        "docker", "exec", "proxy-sentinel-postgres", "sh", "-c",
        'exec psql -X -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "$1"',
        "sh", wrapped,
    ])
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        raise ProbeError("PostgreSQL system counter did not return one JSON row") from exc
    if not isinstance(parsed, dict):
        raise ProbeError("PostgreSQL system counter returned an invalid row")
    return parsed


def ch_rows(sql: str) -> list[dict[str, Any]]:
    raw = command([
        "docker", "exec", "proxy-sentinel-clickhouse", "sh", "-c",
        'exec clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" '
        '--database "$CLICKHOUSE_DB" --readonly 1 --max_execution_time 4 --max_threads 1 --query "$1"',
        "sh", sql,
    ])
    try:
        rows = [json.loads(line) for line in raw.splitlines() if line]
    except ValueError as exc:
        raise ProbeError("ClickHouse system counter returned invalid JSON") from exc
    if not all(isinstance(row, dict) for row in rows):
        raise ProbeError("ClickHouse system counter returned an invalid row")
    return rows


def system_snapshot() -> dict[str, Any]:
    started = utc_now()
    intervals: dict[str, dict[str, str]] = {}

    def measure(name: str, probe: Any) -> Any:
        before = utc_now()
        value = probe()
        intervals[name] = {"from": before.isoformat(), "to": utc_now().isoformat()}
        return value

    wal = measure("wal", lambda: pg_row("SELECT wal_bytes,wal_records,stats_reset FROM pg_stat_wal"))
    database = measure("database", lambda: pg_row(
        "SELECT xact_commit,xact_rollback,stats_reset FROM pg_stat_database "
        "WHERE datname=current_database()"
    ))
    parts = measure("parts", lambda: ch_rows(
        "SELECT table,count() AS parts,sum(bytes_on_disk) AS bytes_on_disk "
        "FROM system.parts WHERE active=1 AND database=currentDatabase() "
        "GROUP BY table ORDER BY table FORMAT JSONEachRow"
    ))
    merge_counters = measure("merges", lambda: ch_rows(
        "SELECT event,value FROM system.events WHERE event IN "
        "('Merge','MergeSourceParts','MergedRows','MergedUncompressedBytes',"
        "'MergeExecuteMilliseconds') ORDER BY event FORMAT JSONEachRow"
    ))
    return {"started_at": started.isoformat(), "finished_at": utc_now().isoformat(),
            "wal": wal, "database": database, "parts": parts,
            "merge_counters": merge_counters, "probe_intervals": intervals}


def recent_metrics(since: dt.datetime) -> list[dict[str, Any]]:
    # journalctl applies the grep before -n. Twenty lines cover ten minutes at
    # the current 30-second cadence without loading a whole service journal.
    raw = command([
        "journalctl", "-u", "proxy-sentinel-discovery.service",
        "--since", "@" + str(int(since.timestamp()) - 2),
        "--grep", METRIC_PREFIX, "-n", "20", "--no-pager", "-o", "cat",
    ])
    records: list[dict[str, Any]] = []
    for line in raw.splitlines():
        if METRIC_PREFIX not in line:
            continue
        if len(line) > 256 * 1024:
            raise ProbeError("stream metric record exceeds 256 KiB")
        try:
            item = json.loads(line.split(METRIC_PREFIX, 1)[1])
        except ValueError as exc:
            raise ProbeError("stream metric record is invalid JSON") from exc
        if not isinstance(item, dict) or item.get("kind") != "periodic":
            continue
        item["_at"] = parse_stamp(item.get("at"))
        item["_window_start"] = parse_stamp(item.get("window_start"))
        records.append(item)
    return sorted(records, key=lambda item: item["_at"])


def next_metric(after: dt.datetime, deadline: float, poll_seconds: float) -> dict[str, Any]:
    while time.monotonic() < deadline:
        for record in recent_metrics(after - dt.timedelta(minutes=1)):
            if record["_at"] > after:
                return record
        time.sleep(poll_seconds)
    raise ProbeError("periodic discovery metrics did not advance before the bounded deadline")


def check_metric_schema(record: dict[str, Any]) -> None:
    for field in ("capture_accepted", "sink_acks", "projection_writes", "durable_backlog", "queues"):
        if field not in record:
            raise ProbeError(f"running discovery release lacks {field}; deploy/verify instrumentation before measuring")
    if record["_at"] <= record["_window_start"]:
        raise ProbeError("stream metric window is empty or reversed")


def metric_sum(records: list[dict[str, Any]], field: str, key: str, counters: tuple[str, ...]) -> dict[str, int]:
    result = {counter: 0 for counter in counters}
    for record in records:
        values = record[field].get(key, {})
        if not isinstance(values, dict):
            raise ProbeError(f"invalid {field} source/epoch metric")
        for counter in counters:
            value = values.get(counter, 0)
            if not isinstance(value, int) or value < 0:
                raise ProbeError(f"invalid {field}.{counter} counter")
            result[counter] += value
    return result


def counter_delta(before: dict[str, Any], after: dict[str, Any], key: str, reset_field: str) -> int:
    if before.get(reset_field) != after.get(reset_field):
        raise ProbeError("system statistics reset during the measurement window")
    left, right = int(before[key]), int(after[key])
    if right < left:
        raise ProbeError("system counter decreased during the measurement window")
    return right - left


def build_report(source: str, epoch: str, records: list[dict[str, Any]],
                 before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    if not records:
        raise ProbeError("no complete stream metric windows")
    key = source + "/" + epoch
    prior = records[0]["_window_start"]
    for record in records:
        check_metric_schema(record)
        if abs((record["_window_start"] - prior).total_seconds()) > 0.01:
            raise ProbeError("discovery metrics have a gap or process restart; discard this window")
        prior = record["_at"]
    capture = metric_sum(records, "capture_accepted", key, ("segments", "events", "source_bytes"))
    acks = metric_sum(records, "sink_acks", key, ("body_segments", "body_events", "search_segments", "search_events", "eventbus_segments", "eventbus_events"))
    projection = metric_sum(records, "projection_writes", key, ("segments", "events", "fresh_events", "pg_fact_rows", "pg_state_rows"))
    if capture["segments"] == 0 and acks["body_segments"] == 0 and projection["segments"] == 0:
        raise ProbeError("requested source/epoch has no instrumented activity in this window")
    wal_bytes = counter_delta(before["wal"], after["wal"], "wal_bytes", "stats_reset")
    wal_records = counter_delta(before["wal"], after["wal"], "wal_records", "stats_reset")
    committed = counter_delta(before["database"], after["database"], "xact_commit", "stats_reset")
    rolled_back = counter_delta(before["database"], after["database"], "xact_rollback", "stats_reset")
    first_at, last_at = records[0]["_window_start"], records[-1]["_at"]
    skews: dict[str, dict[str, float]] = {}
    for name in ("wal", "database", "parts", "merges"):
        try:
            first_probe = before["probe_intervals"][name]
            last_probe = after["probe_intervals"][name]
            start_skew = (parse_stamp(first_probe["from"]) - first_at).total_seconds()
            end_skew = (parse_stamp(last_probe["to"]) - last_at).total_seconds()
        except (KeyError, TypeError) as exc:
            raise ProbeError("system counter probe timing is incomplete") from exc
        # A delayed system sample is a different time window. The actual read
        # occurred within each probe interval; its worst-case boundary drift
        # must fit the explicit budget before we divide by source events.
        if abs(start_skew) > 8 or abs(end_skew) > 8:
            raise ProbeError(f"{name} counters were sampled more than eight seconds from stream boundaries")
        skews[name] = {"start": round(start_skew, 3), "end": round(end_skew, 3)}
    old_parts = {row["table"]: row for row in before["parts"]}
    new_parts = {row["table"]: row for row in after["parts"]}
    old_merge = {row["event"]: int(row["value"]) for row in before["merge_counters"]}
    new_merge = {row["event"]: int(row["value"]) for row in after["merge_counters"]}
    merge_events = ("Merge", "MergeSourceParts", "MergedRows", "MergedUncompressedBytes", "MergeExecuteMilliseconds")
    if any(event not in old_merge or event not in new_merge for event in merge_events):
        raise ProbeError("ClickHouse cumulative merge counters are incomplete")
    merge_deltas = {}
    for event in merge_events:
        if new_merge[event] < old_merge[event]:
            raise ProbeError("ClickHouse merge counters reset during the measurement window")
        merge_deltas[event] = new_merge[event] - old_merge[event]
    part_deltas = [
        {"table": table, "parts_before": int(old_parts.get(table, {}).get("parts", 0)),
         "parts_after": int(new_parts.get(table, {}).get("parts", 0)),
         "bytes_before": int(old_parts.get(table, {}).get("bytes_on_disk", 0)),
         "bytes_after": int(new_parts.get(table, {}).get("bytes_on_disk", 0))}
        for table in sorted(set(old_parts) | set(new_parts))
    ]
    last = records[-1]
    per_thousand = None
    if projection["events"] > 0:
        per_thousand = {
            "pg_fact_rows_per_1000_projected_events": round(1000 * projection["pg_fact_rows"] / projection["events"], 2),
            "pg_state_rows_per_1000_projected_events": round(1000 * projection["pg_state_rows"] / projection["events"], 2),
        }
    return {
        "source": source, "epoch": epoch,
        "metric_window": {"from": first_at.isoformat(), "to": last_at.isoformat(), "periods": len(records)},
        "system_sample_skew_seconds": skews,
        "source_metrics": {"accepted_standard_events": capture["events"],
                           "accepted_segments": capture["segments"],
                           "serialized_source_bytes": capture["source_bytes"],
                           "clickhouse_confirmed_body_events": acks["body_events"],
                           "clickhouse_confirmed_search_events": acks["search_events"],
                           "broker_confirmed_events": acks["eventbus_events"],
                           "projected_events": projection["events"],
                           "fresh_projected_events": projection["fresh_events"],
                           "pg_fact_rows": projection["pg_fact_rows"],
                           "pg_device_state_rows": projection["pg_state_rows"],
                           "per_1000_projected_events": per_thousand},
        "backlog_at_end": last["durable_backlog"],
        "projection_queue_at_end": last["queues"].get("projection"),
        "system_wide": {"pg_wal_bytes": wal_bytes, "pg_wal_records": wal_records,
                        "pg_transactions_committed": committed, "pg_transactions_rolled_back": rolled_back,
                        "clickhouse_parts": part_deltas,
                        "clickhouse_merge_counters": merge_deltas},
        "unavailable": {
            "raw_dpi_input_events": "capture metrics count durably accepted standard events, not every DPI packet",
            "total_pg_row_writes": "only discovery fact/current-state rows are instrumented",
            "identity_state_changes": "identity pipeline is not instrumented in this source window",
            "risk_state_changes": "risk state is not instrumented in this source window",
            "oldest_pending_age": "durable backlog metric has counts and reserved bytes but no oldest acceptance time",
        },
        "interpretation": "ACKs and projections can complete older segments during this window; counts are throughput, not one cohort's conversion rate. WAL and transactions cover the PostgreSQL cluster/database; part counts cover this ClickHouse database; merge counters cover the entire ClickHouse server.",
    }


def run(source: str, epoch: str, intervals: int, poll_seconds: float, timeout_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    initial = utc_now()
    boundary = next_metric(initial, deadline, poll_seconds)
    check_metric_schema(boundary)
    before = system_snapshot()
    records = []
    previous = boundary
    for _ in range(intervals):
        record = next_metric(previous["_at"], deadline, poll_seconds)
        if abs((record["_window_start"] - previous["_at"]).total_seconds()) > 0.01:
            raise ProbeError("discovery metrics have a gap or process restart; discard this window")
        records.append(record)
        previous = record
    after = system_snapshot()
    return build_report(source, epoch, records, before, after)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="passive-discovery", help="fixed source kind")
    parser.add_argument("--epoch", help="fixed active source epoch; never inferred or moved")
    parser.add_argument("--preflight-system", action="store_true", help="read one PG/CH counter sample without waiting for a source window")
    parser.add_argument("--intervals", type=int, default=2, help="complete 30-second periods, 1..10")
    parser.add_argument("--poll-seconds", type=float, default=1.0, help="journal check cadence, 0.5..5 seconds")
    parser.add_argument("--timeout-seconds", type=int, default=180, help="total bounded wait, 30..600 seconds")
    args = parser.parse_args(argv)
    if not SOURCE_NAME.fullmatch(args.source) or (not args.preflight_system and (not args.epoch or not EPOCH_NAME.fullmatch(args.epoch))):
        parser.error("source or epoch contains unsupported characters")
    if not 1 <= args.intervals <= 10 or not 0.5 <= args.poll_seconds <= 5 or not 30 <= args.timeout_seconds <= 600:
        parser.error("intervals must be 1..10, poll 0.5..5 seconds, timeout 30..600 seconds")
    try:
        if args.preflight_system:
            result = system_snapshot()
        else:
            result = run(args.source, args.epoch, args.intervals, args.poll_seconds, args.timeout_seconds)
    except ProbeError as exc:
        print(json.dumps({"status": "unavailable", "reason": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
