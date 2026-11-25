#!/usr/bin/env python3
"""Collect one read-only daily 204 snapshot or compare the retained daily files."""
import argparse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import tempfile

CST = timezone(timedelta(hours=8))
PER_DAY = 86400
ARCHIVE = {"ch:passive_discovery_raw_archive", "pg:public.passive_archive_members", "pg:public.passive_archive_rows"}
HOT_HISTORY = {"pg:public.discovery_observations", "pg:public.passive_hardware_changes", "pg:public.passive_census_identifier_5m"}
CURRENT = {"pg:public.passive_hardware_facts", "pg:public.passive_hardware_current",
           "pg:public.discovery_observation_latest", "pg:public.discovery_passive_device_current"}


def timestamp(sample):
    result = datetime.fromisoformat(sample["sampled_at"].replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("snapshot timestamp has no offset")
    return result


def local_day(sample):
    return timestamp(sample).astimezone(CST).date()


def collect(folder):
    script = Path(__file__).with_name("passive_health.py")
    with script.open("rb") as source:
        proc = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "root@222.204.3.204",
                               "python3", "-", "--capacity"], stdin=source, stdout=subprocess.PIPE, timeout=90, check=True)
    sample = json.loads(proc.stdout)
    if sample["errors"] or not sample["pg_tables"] or not sample["ch_partitions"] or not sample["wal"]:
        raise ValueError("incomplete capacity sample")
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / f"capacity-{local_day(sample)}.json"
    with tempfile.NamedTemporaryFile(dir=folder) as staging:
        staging.write(proc.stdout)
        staging.flush()
        try:
            os.link(staging.name, target)
        except FileExistsError:
            if local_day(json.loads(target.read_text())) != local_day(sample):
                raise ValueError(f"existing file has the wrong sample date: {target}")
    return target


def retention(name):
    if name in ARCHIVE:
        return "archive"
    if name in HOT_HISTORY:
        return "hot_history"
    if name in CURRENT:
        return "current_state"
    return "other"


def table_sizes(sample):
    sizes = {}
    for row in sample["pg_tables"]:
        name = f'pg:{row["schemaname"]}.{row["relname"]}'
        sizes[name] = row["total_bytes"]
    for row in sample["ch_partitions"]:
        name = "ch:" + row["table"]
        sizes[name] = sizes.get(name, 0) + int(row["bytes"])
    return sizes


def wal_rate(before, after, seconds):
    delta = int(after["wal_bytes"]) - int(before["wal_bytes"])
    if before["stats_reset"] == after["stats_reset"] and delta >= 0:
        return delta / seconds
    return None


def interval(before, after):
    result = {"from": before["sampled_at"], "to": after["sampled_at"]}
    if local_day(after) != local_day(before) + timedelta(days=1):
        return dict(result, status="missing_day")
    seconds = (timestamp(after) - timestamp(before)).total_seconds()
    if seconds <= 0:
        raise ValueError("non-increasing sample time")
    old, new = table_sizes(before), table_sizes(after)
    growth = {key: new.get(key, 0) - old.get(key, 0) for key in sorted(old.keys() | new.keys())}
    reset = before["database"][0]["stats_reset"] != after["database"][0]["stats_reset"]
    old_pg = {(row["schemaname"], row["relname"]): row for row in before["pg_tables"]}
    updates = {}
    for row in after["pg_tables"]:
        key = row["schemaname"], row["relname"]
        previous = old_pg.get(key)
        name = ".".join(key)
        if previous is None or previous["relid"] != row["relid"] or reset:
            updates[name] = {"status": "new_relation_or_counter_reset"}
            continue
        total = row["n_tup_upd"] - previous["n_tup_upd"]
        hot = row["n_tup_hot_upd"] - previous["n_tup_hot_upd"]
        if not 0 <= hot <= total:
            updates[name] = {"status": "counter_reset"}
        else:
            updates[name] = {"updates": total, "hot_updates": hot, "hot_ratio": hot / total if total else None,
                             "heap_delta_bytes": row["heap_bytes"] - previous["heap_bytes"],
                             "index_delta_bytes": row["index_bytes"] - previous["index_bytes"]}
    return dict(result, status="measured", elapsed_seconds=seconds, table_delta_bytes=growth,
                new_tables=sorted(new.keys()-old.keys()), removed_tables=sorted(old.keys()-new.keys()),
                pg_updates=updates, wal_bytes_per_second=wal_rate(before["wal"][0], after["wal"][0], seconds))


def report(folder):
    samples = []
    for file in sorted(folder.glob("capacity-????-??-??.json")):
        sample = json.loads(file.read_text())
        if sample.get("errors") or file.name != f"capacity-{local_day(sample)}.json":
            raise ValueError(f"invalid snapshot {file}")
        samples.append(sample)
    if not samples:
        raise ValueError("no dated daily capacity snapshots")
    intervals = [interval(a, b) for a, b in zip(samples, samples[1:])]
    disk = samples[-1]["disk"]
    free_after_reserve = int(disk["available"]) - (int(disk["total"]) + 4) // 5
    result = {"samples": len(samples), "last_sampled_at": samples[-1]["sampled_at"], "intervals": intervals,
              "disk_bytes_above_20_percent_reserve": free_after_reserve,
              "projection_status": "waiting_for_seven_consecutive_daily_snapshots"}
    recent = intervals[-6:]
    if len(recent) != 6 or any(i["status"] != "measured" for i in recent):
        return result
    changes = defaultdict(int)
    for i in recent:
        for key, value in i["table_delta_bytes"].items():
            changes[key] += value
    span_days = sum(i["elapsed_seconds"] for i in recent) / PER_DAY
    daily = {key: value / span_days for key, value in changes.items()}
    growth = defaultdict(float)
    for name, rate in daily.items():
        # Keep shrinkage visible per table, but never use it to fund another table's growth.
        growth[retention(name)] += max(0, rate)
    increment = round(30 * growth["hot_history"] + 365 * growth["archive"])
    result.update(projection_status="measured_net_growth_scenario",
                  observed_span_days=span_days, table_bytes_per_day=daily, positive_bytes_per_day_by_role=dict(growth),
                  hot_history_extra_30d_bytes=round(30 * growth["hot_history"]),
                  archive_extra_365d_bytes=round(365 * growth["archive"]),
                  extra_bytes_above_reserve_after_hot_and_archive=free_after_reserve-increment)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["collect", "report"])
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.operation == "collect":
        print(collect(args.directory))
    else:
        print(json.dumps(report(args.directory), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
