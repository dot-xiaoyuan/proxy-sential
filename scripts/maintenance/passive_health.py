#!/usr/bin/env python3
"""Read-only checks for the passive discovery deployment. Emit one JSON object."""
import argparse
import datetime
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

CHARTS = ("activity_chart_facts_5m_v3", "activity_chart_facts_hour_v3", "activity_chart_facts_day_v3")
CHART_SQL = """
WITH
  (SELECT toUInt64(value) FROM system.merge_tree_settings WHERE name='parts_to_delay_insert') AS default_delay,
  part_counts AS (
    SELECT table, sum(n) AS active_parts, max(n) AS max_partition_parts FROM (
      SELECT table, partition_id, count() AS n FROM system.parts
      WHERE database=currentDatabase() AND table IN {charts} AND active GROUP BY table, partition_id
    ) GROUP BY table
  ),
  activity AS (
    SELECT table, countIf(event_type='NewPart' AND error=0) AS inserts,
           countIf(event_type='MergeParts' AND error=0) AS merges
    FROM system.part_log WHERE event_date>=yesterday() AND event_time>=now()-INTERVAL 1 HOUR
      AND database=currentDatabase() AND table IN {charts} GROUP BY table
  )
SELECT name AS table, coalesce(toUInt64OrNull(extract(engine_full, 'parts_to_delay_insert *= *([0-9]+)')),default_delay) AS delay_at,
 c.active_parts AS active_parts, c.max_partition_parts AS max_partition_parts, a.inserts AS inserts, a.merges AS merges
FROM system.tables LEFT JOIN part_counts c ON name=c.table LEFT JOIN activity a ON name=a.table
WHERE database=currentDatabase() AND name IN {charts} ORDER BY name
""".format(charts=repr(CHARTS))

QUEUE_SQL = """
SELECT (SELECT count(*) FROM passive_hardware_dirty) AS hardware_waiting,
 (SELECT count(*) FROM passive_hardware_dirty WHERE last_error<>'') AS hardware_errors,
 count(*) FILTER(WHERE attempts=0) AS waiting,
 count(*) FILTER(WHERE attempts BETWEEN 1 AND 7) AS retrying,
 count(*) FILTER(WHERE attempts>=8) AS failed
FROM passive_archive_rows WHERE verified_at IS NULL
"""


def run(args, data=None):
    proc = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=12, check=True)
    return proc.stdout


def pg(query):
    command = 'exec psql -X -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
    sql = "BEGIN READ ONLY; SET LOCAL statement_timeout='6s'; SELECT coalesce(json_agg(r),'[]') FROM (" + query + ") r; COMMIT;"
    return json.loads(run(["docker", "exec", "-i", "proxy-sentinel-postgres", "sh", "-c", command], sql))


def ch(query):
    command = ('exec clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" '
               '--database "$CLICKHOUSE_DB" --readonly 1 --max_threads 1 --max_execution_time 6 --format JSONEachRow')
    return [json.loads(line) for line in run(["docker", "exec", "-i", "proxy-sentinel-clickhouse",
                                              "sh", "-c", command], query).splitlines()]


def ready():
    try:
        response = urllib.request.urlopen("http://127.0.0.1:18080/readyz", timeout=6)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        payload = json.load(response)
        return {"http": response.status, "status": payload["status"],
                "components": {key: value["status"] for key, value in payload["components"].items()}}


def disk():
    stats = os.statvfs("/opt/proxy-sentinel/data")
    return {"available": stats.f_bavail * stats.f_frsize, "total": stats.f_blocks * stats.f_frsize}


def chart_alerts(row):
    alerts = []
    if int(row["inserts"]) >= 2 and not int(row["merges"]) and int(row["max_partition_parts"]) > 1:
        alerts.append("writes_without_merges")
    delay = int(row["delay_at"])
    if delay and int(row["max_partition_parts"]) >= 0.8 * delay:
        alerts.append("partition_part_pressure")
    return alerts


def status(health, failed_units, queues, filesystem):
    alerts = []
    if health and health.get("http") != 200:
        alerts.append("readyz")
    if failed_units:
        alerts.append("failed_units")
    if queues.get("failed", 0):
        alerts.append("archive_retry_exhausted")
    if queues.get("hardware_errors", 0):
        alerts.append("hardware_queue_error")
    if filesystem and filesystem["available"] < 0.2 * filesystem["total"]:
        alerts.append("disk_free_below_20_percent")
    return alerts


def capacity_checks():
    return {
        "disk": disk,
        "database": lambda: pg("SELECT pg_database_size(current_database()) AS bytes,stats_reset FROM pg_stat_database WHERE datname=current_database()"),
        "pg_tables": lambda: pg("""SELECT schemaname,relname,relid,pg_relation_size(relid) AS heap_bytes,
          pg_indexes_size(relid) AS index_bytes,pg_total_relation_size(relid) AS total_bytes,
          n_tup_upd,n_tup_hot_upd FROM pg_stat_user_tables ORDER BY schemaname,relname"""),
        "wal": lambda: pg("SELECT wal_bytes,stats_reset FROM pg_stat_wal"),
        "ch_partitions": lambda: ch("""SELECT table,partition_id,sum(bytes_on_disk) AS bytes,count() AS parts
          FROM system.parts WHERE database=currentDatabase() AND active GROUP BY table,partition_id ORDER BY table,partition_id"""),
    }


def check(extended=False):
    probes = capacity_checks() if extended else {
        "charts": lambda: ch(CHART_SQL),
        "archive_hardware": lambda: pg(QUEUE_SQL)[0],
        "watermarks": lambda: pg("SELECT sensor_id,source_event_type,cursor_timestamp,updated_at FROM passive_discovery_source_cursors ORDER BY sensor_id,source_event_type"),
        "delayed_inserts": lambda: ch("""SELECT (SELECT sum(value) FROM system.events WHERE event='DelayedInserts') AS total,
          sum(ProfileEvent_DelayedInserts) AS last_hour, count() AS metric_samples FROM system.metric_log
          WHERE event_date>=yesterday() AND event_time>=now()-INTERVAL 1 HOUR""")[0],
        "ch_errors": lambda: ch("""SELECT name,sum(value) AS total,max(last_error_time) AS latest,
          max(last_error_time)>=now()-INTERVAL 1 HOUR AS recent FROM system.errors WHERE value>0 GROUP BY name ORDER BY name"""),
        "readyz": ready,
        "failed_units": lambda: [line.split()[0] for line in run(
            ["systemctl", "list-units", "--failed", "--no-legend", "--no-pager", "--plain"]).splitlines() if line.strip()],
        "disk": disk,
    }
    report = {"sampled_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "release": os.path.basename(os.path.realpath("/opt/proxy-sentinel/current")), "alerts": [], "errors": {}}
    for key, probe in probes.items():
        try:
            report[key] = probe()
        except (IndexError, KeyError, ValueError, OSError, subprocess.SubprocessError) as error:
            report["errors"][key] = type(error).__name__
            report["alerts"].append(key + ":check_failed")
    if not extended:
        charts = report.get("charts", [])
        if {row["table"] for row in charts} != set(CHARTS):
            report["alerts"].append("missing_chart_metrics")
        for row in charts:
            report["alerts"].extend(row["table"] + ":" + alert for alert in chart_alerts(row))
        report["alerts"].extend(status(report.get("readyz"), report.get("failed_units"),
                                       report.get("archive_hardware", {}), report.get("disk")))
        delayed = report.get("delayed_inserts")
        if delayed and int(delayed["last_hour"]):
            report["alerts"].append("recent_delayed_inserts")
        if delayed and not int(delayed["metric_samples"]):
            report["alerts"].append("missing_metric_log_samples")
        if any(row["name"] == "CANNOT_PARSE_INPUT_ASSERTION_FAILED" and int(row["recent"]) for row in report.get("ch_errors", [])):
            report["alerts"].append("recent_clickhouse_parse_failure")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capacity", action="store_true", help="collect per-table daily capacity counters")
    parser.add_argument("--journal", action="store_true", help="send alert names to the local journal")
    args = parser.parse_args()
    result = check(args.capacity)
    print(json.dumps(result, separators=(",", ":"), ensure_ascii=False))
    if args.journal and result["alerts"]:
        subprocess.run(["logger", "-p", "daemon.warning", "-t", "proxy-sentinel-passive-health", "--",
                        ", ".join(result["alerts"])], check=True)
    return int(bool(result["errors"]))


if __name__ == "__main__":
    sys.exit(main())
