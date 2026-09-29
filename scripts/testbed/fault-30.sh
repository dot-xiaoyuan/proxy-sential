#!/usr/bin/env bash
set -Eeuo pipefail

root="${PROXY_SENTINEL_ROOT:-/opt/proxy-sentinel}"
duration="${PROXY_SENTINEL_FAULT_RUN_SECONDS:-3}"
result="${1:-$root/data/acceptance/$(date -u +%Y%m%dT%H%M%SZ)-fault-ingest.json}"
sensor="acceptance-fault-$(date -u +%Y%m%dT%H%M%SZ)"
work_dir="$(mktemp -d /tmp/proxy-sentinel-fault.XXXXXX)"
source_file="$work_dir/eve.json"
worker_pid=""

cleanup() {
  if [[ -n "$worker_pid" ]] && kill -0 "$worker_pid" 2>/dev/null; then kill "$worker_pid" 2>/dev/null || true; fi
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

[[ -x "$root/current/bin/proxy-sentinel" ]] || { echo "找不到 proxy-sentinel 可执行文件" >&2; exit 1; }
[[ -r "$root/config/runtime.env" ]] || { echo "找不到 runtime.env" >&2; exit 1; }
for command in jq docker; do command -v "$command" >/dev/null || { echo "缺少命令: $command" >&2; exit 1; }; done
set -a
# shellcheck disable=SC1090
source "$root/config/runtime.env"
set +a
: "${PROXY_SENTINEL_POSTGRES_DSN:?runtime.env 缺少 PostgreSQL DSN}"
: "${PROXY_SENTINEL_CLICKHOUSE_DSN:?runtime.env 缺少 ClickHouse DSN}"

emit() {
  local sequence="$1" mode="${2:-append}" timestamp
  timestamp="$(date +%Y-%m-%dT%H:%M:%S.%6N%z)"
  if [[ "$mode" == replace ]]; then
    printf '{"timestamp":"%s","flow_id":%d,"event_type":"flow","src_ip":"10.254.30.8","dest_ip":"198.51.100.%d","src_port":41000,"dest_port":443,"proto":"TCP","flow":{"pkts_toserver":2,"pkts_toclient":2}}\n' "$timestamp" "$sequence" "$sequence" > "$source_file"
  else
    printf '{"timestamp":"%s","flow_id":%d,"event_type":"flow","src_ip":"10.254.30.8","dest_ip":"198.51.100.%d","src_port":41000,"dest_port":443,"proto":"TCP","flow":{"pkts_toserver":2,"pkts_toclient":2}}\n' "$timestamp" "$sequence" "$sequence" >> "$source_file"
  fi
}

run_worker() {
  local clickhouse_dsn="${1:-$PROXY_SENTINEL_CLICKHOUSE_DSN}" seconds="${2:-$duration}"
  "$root/current/bin/proxy-sentinel" ingest run --sensor-id "$sensor" --eve "$source_file" \
    --postgres-dsn "$PROXY_SENTINEL_POSTGRES_DSN" --clickhouse-dsn "$clickhouse_dsn" \
    --poll-interval 100ms --heartbeat-interval 1h --store-timeout 2s >"$work_dir/worker.log" 2>&1 &
  worker_pid=$!
  sleep "$seconds"
  kill -TERM "$worker_pid" 2>/dev/null || true
  wait "$worker_pid" 2>/dev/null || true
  worker_pid=""
}

pg() { docker exec proxy-sentinel-postgres psql -Atq -v ON_ERROR_STOP=1 -U proxy_sentinel -d proxy_sentinel -c "$1"; }
ch() { docker exec proxy-sentinel-clickhouse sh -c 'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --database "$CLICKHOUSE_DB" --query "$1"' sh "$1"; }
event_count() { ch "SELECT uniqExact(event_id) FROM normalized_events WHERE sensor_id='$sensor'"; }
visible_count() { ch "SELECT count() FROM normalized_events WHERE sensor_id='$sensor'"; }
checkpoint_offset() { pg "SELECT committed_offset FROM ingest_checkpoints WHERE sensor_id='$sensor' AND source_kind='suricata' AND source_path='$source_file'"; }

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
emit 1 replace
printf '{malformed-json\n' >> "$source_file"
run_worker
initial_unique="$(event_count)"
initial_offset="$(checkpoint_offset)"

run_worker
duplicate_unique="$(event_count)"

mv "$source_file" "$source_file.1"
emit 2 replace
run_worker
rotation_unique="$(event_count)"

emit 3
run_worker
before_truncate_offset="$(checkpoint_offset)"
emit 4 replace
run_worker
truncate_unique="$(event_count)"

emit 5
outage_offset_before="$(checkpoint_offset)"
run_worker "http://127.0.0.1:1" 2
outage_offset_after="$(checkpoint_offset)"
run_worker
recovery_unique="$(event_count)"

emit 6
"$root/current/bin/proxy-sentinel" ingest run --sensor-id "$sensor" --eve "$source_file" \
  --postgres-dsn "$PROXY_SENTINEL_POSTGRES_DSN" --clickhouse-dsn "$PROXY_SENTINEL_CLICKHOUSE_DSN" \
  --poll-interval 10ms --heartbeat-interval 1h --store-timeout 2m >"$work_dir/killed-worker.log" 2>&1 &
worker_pid=$!
sleep 0.05
kill -KILL "$worker_pid" 2>/dev/null || true
wait "$worker_pid" 2>/dev/null || true
worker_pid=""
run_worker

final_unique="$(event_count)"
final_visible="$(visible_count)"
malformed="$(ch "SELECT sum(JSONExtractInt(counters_json,'malformed')) FROM ingest_diagnostics WHERE sensor_id='$sensor'")"
failed_batches="$(pg "SELECT count(*) FROM ingest_batches WHERE sensor_id='$sensor' AND status='failed'")"
committed_batches="$(pg "SELECT count(*) FROM ingest_batches WHERE sensor_id='$sensor' AND status='committed'")"
finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

passed=false
if [[ "$initial_unique" == 1 && "$duplicate_unique" == 1 && "$rotation_unique" == 2 && "$truncate_unique" == 4 && \
      "$outage_offset_before" == "$outage_offset_after" && "$recovery_unique" == 5 && "$final_unique" == 6 && \
      "$final_visible" == "$final_unique" && "${malformed:-0}" -ge 1 && "$committed_batches" -ge 5 ]]; then
  passed=true
fi
mkdir -p "$(dirname "$result")"
jq -n --arg sensor "$sensor" --arg started_at "$started_at" --arg finished_at "$finished_at" \
  --argjson passed "$passed" --argjson initial_unique "$initial_unique" --argjson duplicate_unique "$duplicate_unique" \
  --argjson rotation_unique "$rotation_unique" --argjson truncate_unique "$truncate_unique" \
  --argjson outage_offset_before "$outage_offset_before" --argjson outage_offset_after "$outage_offset_after" \
  --argjson recovery_unique "$recovery_unique" --argjson final_unique "$final_unique" --argjson final_visible "$final_visible" \
  --argjson malformed "${malformed:-0}" --argjson failed_batches "$failed_batches" --argjson committed_batches "$committed_batches" \
  '{schema_version:"v1",test:"ingest_fault_recovery",sensor_id:$sensor,started_at:$started_at,finished_at:$finished_at,passed:$passed,
    checks:{initial_unique:$initial_unique,restart_unique:$duplicate_unique,rotation_unique:$rotation_unique,truncate_unique:$truncate_unique,
      outage_checkpoint_unchanged:($outage_offset_before==$outage_offset_after),recovery_unique:$recovery_unique,final_unique:$final_unique,
      final_visible:$final_visible,visible_duplicates:($final_visible-$final_unique),malformed_isolated:$malformed,
      failed_batches:$failed_batches,committed_batches:$committed_batches}}' > "$result"
echo "$result"
[[ "$passed" == true ]]
