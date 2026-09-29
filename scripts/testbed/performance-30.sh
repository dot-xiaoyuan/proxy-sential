#!/usr/bin/env bash
set -Eeuo pipefail

root="${PROXY_SENTINEL_ROOT:-/opt/proxy-sentinel}"
duration_seconds="${PROXY_SENTINEL_PERF_DURATION_SECONDS:-3600}"
result="${1:-$root/data/acceptance/$(date -u +%Y%m%dT%H%M%SZ)-performance.json}"
work_dir="$(mktemp -d /tmp/proxy-sentinel-performance.XXXXXX)"
source_file="$work_dir/eve.json"
latency_file="$work_dir/visibility-latency-seconds.txt"
stop_monitor="$work_dir/stop-monitor"
sensor="acceptance-perf-$(date -u +%Y%m%dT%H%M%SZ)"
worker_pid=""; monitor_pid=""

cleanup() {
  touch "$stop_monitor" 2>/dev/null || true
  for pid in "$worker_pid" "$monitor_pid"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then kill "$pid" 2>/dev/null || true; fi
  done
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

[[ "$duration_seconds" =~ ^[0-9]+$ ]] && (( duration_seconds >= 60 )) || { echo "持续时间至少为 60 秒" >&2; exit 2; }
[[ -x "$root/current/bin/proxy-sentinel" && -r "$root/config/runtime.env" ]] || { echo "部署目录不完整" >&2; exit 1; }
for command in awk curl docker jq sort; do command -v "$command" >/dev/null || { echo "缺少命令: $command" >&2; exit 1; }; done
set -a
# shellcheck disable=SC1090
source "$root/config/runtime.env"
set +a
: "${PROXY_SENTINEL_POSTGRES_DSN:?runtime.env 缺少 PostgreSQL DSN}"
: "${PROXY_SENTINEL_CLICKHOUSE_DSN:?runtime.env 缺少 ClickHouse DSN}"

ch() { docker exec proxy-sentinel-clickhouse sh -c 'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --database "$CLICKHOUSE_DB" --query "$1"' sh "$1"; }
p95_file() {
  local file="$1" count rank
  count="$(wc -l < "$file" | tr -d ' ')"
  if (( count == 0 )); then echo 0; return; fi
  rank=$(( (count * 95 + 99) / 100 ))
  sort -n "$file" | sed -n "${rank}p"
}

peak_per_minute="$(ch "SELECT max(events) FROM (SELECT toStartOfMinute(timestamp) minute,count() events FROM normalized_events WHERE sensor_id='office-30' AND timestamp >= now() - INTERVAL 24 HOUR GROUP BY minute)")"
[[ "$peak_per_minute" =~ ^[0-9]+$ ]] || { echo "无法读取最近 24 小时峰值" >&2; exit 1; }
target_per_minute=$(( peak_per_minute * 2 ))
rate_per_second=$(( (target_per_minute + 59) / 60 ))
expected_events=$(( rate_per_second * duration_seconds ))
: > "$source_file"
: > "$latency_file"
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
started_epoch="$(date +%s)"

"$root/current/bin/proxy-sentinel" ingest run --sensor-id "$sensor" --eve "$source_file" \
  --postgres-dsn "$PROXY_SENTINEL_POSTGRES_DSN" --clickhouse-dsn "$PROXY_SENTINEL_CLICKHOUSE_DSN" \
  --poll-interval 100ms --max-batch-bytes 2097152 --store-timeout 2m --heartbeat-interval 30s \
  >"$work_dir/ingest.log" 2>&1 &
worker_pid=$!

(
  while [[ ! -e "$stop_monitor" ]]; do
    sample="$(ch "SELECT if(count()=0,-1,greatest(0,dateDiff('millisecond',max(timestamp),now64(3)))/1000.0) FROM normalized_events WHERE sensor_id='$sensor'" 2>/dev/null || echo -1)"
    if [[ "$sample" =~ ^[0-9]+([.][0-9]+)?$ ]]; then printf '%s\n' "$sample" >> "$latency_file"; fi
    sleep 5
  done
) &
monitor_pid=$!

awk -v rate="$rate_per_second" -v duration="$duration_seconds" 'BEGIN {
  for (second=0; second<duration; second++) {
    timestamp=strftime("%Y-%m-%dT%H:%M:%S") ".000000+0800"
    for (i=1; i<=rate; i++) {
      sequence=second*rate+i
      destination=(sequence%200)+1
      port=10000+(sequence%50000)
      printf "{\"timestamp\":\"%s\",\"flow_id\":%d,\"event_type\":\"flow\",\"src_ip\":\"10.253.30.8\",\"dest_ip\":\"198.51.100.%d\",\"src_port\":%d,\"dest_port\":443,\"proto\":\"TCP\",\"flow\":{\"pkts_toserver\":2,\"pkts_toclient\":2}}\n", timestamp, sequence, destination, port
    }
    fflush()
    system("sleep 1")
  }
}' >> "$source_file"

generation_finished_epoch="$(date +%s)"
deadline=$(( generation_finished_epoch + 180 ))
unique_events=0
while (( $(date +%s) <= deadline )); do
  unique_events="$(ch "SELECT uniqExact(event_id) FROM normalized_events WHERE sensor_id='$sensor'")"
  (( unique_events >= expected_events )) && break
  sleep 2
done
catchup_finished_epoch="$(date +%s)"
touch "$stop_monitor"
wait "$monitor_pid" 2>/dev/null || true
monitor_pid=""
kill -TERM "$worker_pid" 2>/dev/null || true
wait "$worker_pid" 2>/dev/null || true
worker_pid=""

visible_events="$(ch "SELECT count() FROM normalized_events WHERE sensor_id='$sensor'")"
write_p95_ms="$(ch "SELECT quantileExact(0.95)(JSONExtractInt(details_json,'write_duration_ms')) FROM ingest_diagnostics WHERE sensor_id='$sensor' AND type='batch'")"
max_lag_bytes="$(ch "SELECT max(JSONExtractInt(details_json,'lag_bytes')) FROM ingest_diagnostics WHERE sensor_id='$sensor' AND type='batch'")"
batch_failures="$(docker exec proxy-sentinel-postgres psql -Atq -U proxy_sentinel -d proxy_sentinel -c "SELECT count(*) FROM ingest_batches WHERE sensor_id='$sensor' AND status='failed'")"
visibility_p95_seconds="$(p95_file "$latency_file")"
api_started_ms="$(date +%s%3N)"
api_probe_path="/readyz"
api_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:18080$api_probe_path")"
api_finished_ms="$(date +%s%3N)"
api_duration_ms=$(( api_finished_ms - api_started_ms ))
oom_count="$(journalctl --since "@$started_epoch" --no-pager -k 2>/dev/null | grep -Eci 'out of memory|oom-killer|killed process' || true)"
finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
passed=false
if (( unique_events == expected_events && visible_events == unique_events && batch_failures == 0 && oom_count == 0 && api_code == 200 )) && \
   awk -v latency="$visibility_p95_seconds" 'BEGIN {exit !(latency <= 60)}'; then
  passed=true
fi
mkdir -p "$(dirname "$result")"
jq -n --arg sensor "$sensor" --arg started_at "$started_at" --arg finished_at "$finished_at" \
  --argjson passed "$passed" --argjson duration_seconds "$duration_seconds" --argjson baseline_peak_per_minute "$peak_per_minute" \
  --argjson target_per_minute "$target_per_minute" --argjson rate_per_second "$rate_per_second" --argjson expected_events "$expected_events" \
  --argjson unique_events "$unique_events" --argjson visible_events "$visible_events" --argjson visibility_p95_seconds "$visibility_p95_seconds" \
  --argjson write_p95_ms "${write_p95_ms:-0}" --argjson max_lag_bytes "${max_lag_bytes:-0}" --argjson batch_failures "$batch_failures" \
  --argjson catchup_seconds "$(( catchup_finished_epoch - generation_finished_epoch ))" --arg api_probe_path "$api_probe_path" --argjson api_code "$api_code" \
  --argjson api_duration_ms "$api_duration_ms" --argjson oom_count "$oom_count" \
  '{schema_version:"v1",test:"double_peak_sustained_ingest",sensor_id:$sensor,started_at:$started_at,finished_at:$finished_at,passed:$passed,
    load:{duration_seconds:$duration_seconds,baseline_peak_per_minute:$baseline_peak_per_minute,target_per_minute:$target_per_minute,rate_per_second:$rate_per_second,expected_events:$expected_events},
    result:{unique_events:$unique_events,visible_events:$visible_events,visible_duplicates:($visible_events-$unique_events),visibility_p95_seconds:$visibility_p95_seconds,
      write_p95_ms:$write_p95_ms,max_lag_bytes:$max_lag_bytes,catchup_seconds:$catchup_seconds,batch_failures:$batch_failures,oom_count:$oom_count,
      api_probe_path:$api_probe_path,api_probe_http:$api_code,api_probe_duration_ms:$api_duration_ms}}' > "$result"
echo "$result"
[[ "$passed" == true ]]
