#!/usr/bin/env python3
"""Read-only snapshot on 184; emit bounded, credential-free JSON to stdout.

Run with: ssh root@222.204.3.184 python3 - < scripts/device-center-baseline.py
Does not change services, databases, configuration or collection scope.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.error
import urllib.request


def command(args, data=None, timeout=12):
    try:
        p = subprocess.run(args, input=data, text=True, capture_output=True, timeout=timeout)
        if p.returncode:
            # DB errors can contain data/credentials; record only their category.
            return {"error": "command_failed", "exit_code": p.returncode}
        return p.stdout.strip()
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}


def pg(query):
    raw = command(["docker", "exec", "-i", "proxy-sentinel-postgres", "sh", "-c",
                   'psql -X -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'],
                  "BEGIN READ ONLY; SET LOCAL statement_timeout='4s'; "
                  "SELECT coalesce(json_agg(t),'[]') FROM (" + query + ") t; COMMIT;")
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw)
    except ValueError:
        return {"error": "invalid_json"}


def ch(query):
    raw = command(["docker", "exec", "-i", "proxy-sentinel-clickhouse", "sh", "-c",
                   'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" '
                   '--database "$CLICKHOUSE_DB" --readonly 1 --max_execution_time 4 --max_threads 1 '
                   '--format JSONEachRow'], query)
    if isinstance(raw, dict):
        return raw
    try:
        return [json.loads(line) for line in raw.splitlines()]
    except ValueError:
        return {"error": "invalid_json"}


def health(port):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz", timeout=6) as r:
            return {"http_status": r.status, "body": json.load(r)}
    except urllib.error.HTTPError as e:
        return {"http_status": e.code, "body": json.loads(e.read())}
    except Exception as e:
        return {"error": type(e).__name__}


report = {"started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
          "hostname": command(["hostname"]), "releases": {}, "services": {}}
root = Path("/opt/proxy-sentinel")
for name in ["current", "previous"]:
    p = (root / name).resolve()
    report["releases"][name] = {"path": str(p)}
    for filename in ["release-manifest.json", "SHA256SUMS"]:
        if (p / filename).exists():
            content = (p / filename).read_bytes()
            report["releases"][name][filename] = json.loads(content) if filename.endswith("json") else hashlib.sha256(content).hexdigest()

for name in ["control-plane", "discovery", "passive-discovery", "ncu-identity-sync", "inventory", "inventory-backfill"]:
    raw = command(["systemctl", "show", "proxy-sentinel-" + name, "-p", "MainPID", "-p", "ActiveState",
                   "-p", "NRestarts", "-p", "ActiveEnterTimestamp"])
    if isinstance(raw, dict):
        report["services"][name] = raw
        continue
    item = dict(line.split("=", 1) for line in raw.splitlines())
    pid = int(item.get("MainPID", "0"))
    if pid and Path(f"/proc/{pid}/cmdline").exists():
        item["executable"] = os.path.realpath(f"/proc/{pid}/exe")
        args = Path(f"/proc/{pid}/cmdline").read_bytes().decode().split("\0")
        item["flag_names"] = [a.split("=")[0] for a in args if a.startswith("--")]
        item["read_only"] = [a for a in args if a.startswith("--read-only=")]
        env = Path(f"/proc/{pid}/environ").read_bytes().decode().split("\0")
        item["backfill_budget"] = [e for e in env if e.startswith("PROXY_SENTINEL_INVENTORY_BACKFILL_")]
    report["services"][name] = item

spool = Path("/var/lib/proxy-sentinel/discovery-spool")
files = list(spool.glob("*.json")) if spool.exists() else []
report["spool"] = {"path": str(spool), "exists": spool.exists(), "files": len(files),
                   "bytes": sum(p.stat().st_size for p in files if p.exists()),
                   "oldest_mtime": min((p.stat().st_mtime for p in files if p.exists()), default=None)}
report["pg"] = {}
queries = {
    "queues": "SELECT lane,count(*) pending,count(*) FILTER(WHERE error<>'') failed,min(created_at) oldest, sum(processed_offset) processed_offsets FROM discovery_batch_work WHERE NOT completed GROUP BY lane",
    "completed_5m": "SELECT lane,count(*) completed,max(completed_at) latest FROM discovery_batch_work WHERE completed_at>now()-interval '5 minutes' GROUP BY lane",
    "database": "SELECT now() measured_at,deadlocks,xact_commit,xact_rollback,blks_read,blks_hit,temp_bytes,blk_read_time,blk_write_time,stats_reset FROM pg_stat_database WHERE datname=current_database()",
    "wal": "SELECT * FROM pg_stat_wal",
    "active": "SELECT pid,wait_event_type,wait_event,round(extract(epoch from now()-query_start)) seconds,pg_blocking_pids(pid) blockers,query_id FROM pg_stat_activity WHERE state='active' AND pid<>pg_backend_pid() ORDER BY query_start LIMIT 30",
    "protocols": "SELECT protocol,enabled,received,parsed,rejected,admitted,last_seen,last_success FROM discovery_protocol_runtime ORDER BY protocol",
    "types": "SELECT device_type,last_device_type,classification_status,count(*) FROM discovery_device_state_v2 GROUP BY 1,2,3",
    "watermark": "SELECT * FROM discovery_pipeline_watermark",
}
for name, query in queries.items():
    report["pg"][name] = pg(query)
report["clickhouse"] = {
    "processes": ch("SELECT elapsed,read_rows,read_bytes,written_rows,written_bytes,memory_usage,query_kind FROM system.processes WHERE query_id<>currentQueryID() ORDER BY elapsed DESC LIMIT 20"),
    "archive_parts": ch("SELECT table,sum(rows) rows,sum(bytes_on_disk) bytes FROM system.parts WHERE active AND database=currentDatabase() AND table IN ('discovery_evidence_archive','normalized_events','normalized_event_ids_v2') GROUP BY table"),
}
report["containers"] = command(["docker", "stats", "--no-stream", "--format", "{{json .}}", "proxy-sentinel-postgres", "proxy-sentinel-clickhouse"])
report["disk"] = command(["df", "-k", "/"])
report["iostat"] = command(["iostat", "-dx", "1", "2"]) if Path("/usr/bin/iostat").exists() else {"error": "unavailable"}
report["health"] = {str(p): health(p) for p in [18080, 18082]}
report["current_at_end"] = str((root / "current").resolve())
report["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
print(json.dumps(report, ensure_ascii=False))
