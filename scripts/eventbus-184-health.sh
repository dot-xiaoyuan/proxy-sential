#!/usr/bin/env bash
set -uo pipefail
RPK=/opt/redpanda/bin/rpk
BROKERS=127.0.0.1:19092
PSQL=(docker exec proxy-sentinel-postgres psql -U proxy_sentinel -d proxy_sentinel -Atc)
echo "=== services ==="
for unit in \
  proxy-sentinel-control-plane-eventbus.service \
  proxy-sentinel-control-plane.service \
  proxy-sentinel-eventbus-host.service \
  proxy-sentinel-eventbus-consumer.service \
  proxy-sentinel-eventbus-current-shadow.service \
  proxy-sentinel-eventbus-redis.service \
  proxy-sentinel-eventbus-shadow-api.service \
  proxy-sentinel-identity-event-relay.service \
  proxy-sentinel-identity-event-consumer.service \
  proxy-sentinel-recognition-materializer-eventbus.service \
  proxy-sentinel-recognition-materializer.service \
  proxy-sentinel-discovery.service \
  proxy-sentinel-handshake-signal.service \
  proxy-sentinel-ingest-stream-handshake-layered-r7.service \
  proxy-sentinel-flow-syn-signal.service \
  proxy-sentinel-ingest-stream-flow-syn.service ; do
  printf '%-62s %s\n' "$unit" "$(systemctl is-active "$unit" 2>/dev/null || true)"
done
echo "=== discovery capture continuity ==="
systemctl show proxy-sentinel-discovery.service -p ActiveEnterTimestamp -p NRestarts --no-pager 2>&1 || true
echo "=== discovery capture queue ==="
python3 - <<'PY'
import json,os,pathlib,time
path=pathlib.Path(os.environ.get('PROXY_SENTINEL_CAPTURE_STATS_FILE','/var/lib/proxy-sentinel/discovery-spool/stream-capture-stats/capture.stats'))
try:
    with path.open() as source:
        raw=source.read((1<<20)+1)
    if len(raw)>1<<20:
        raise ValueError('capture stats exceeds read limit')
    state=json.loads(raw)
    from datetime import datetime
    updated=datetime.fromisoformat(state['updated_at'].replace('Z','+00:00'))
    age=max(0,time.time()-updated.timestamp())
    print('capture_stats_age_seconds=%.1f updated_at=%s' % (age,state['updated_at']))
    queue=state.get('capture_queue')
    if queue is None:
        print('capture_queue_metrics=unavailable_in_this_version')
    else:
        print(' '.join('%s=%s' % (key,queue.get(key,'')) for key in ('batches','capacity','peak_observed_batches','full_count')))
        if queue.get('full_count',0)>0:
            print('ALERT: capture queue overflow occurred in this process; coverage gap remains unverified')
    if age>5:
        print('ALERT: capture stats heartbeat is stale; queue values are not current')
except (OSError,ValueError,KeyError,TypeError,AttributeError) as error:
    print('ALERT: discovery capture queue metrics unavailable:',error)
PY
echo "=== discovery stage timings (last 10 minutes, up to 5 summaries) ==="
journalctl -u proxy-sentinel-discovery.service --since '10 minutes ago' --grep='passive stream metrics ' -n 5 --no-pager 2>&1 || true
echo "=== flow SYN source progress ==="
python3 - <<'PY'
import hashlib,json,pathlib,time
source=pathlib.Path('/opt/proxy-sentinel/data/device-signals/flow-syn.jsonl')
journal=pathlib.Path('/opt/proxy-sentinel/data/stream-journal/flow-syn')
cursor=journal/(hashlib.sha256(b'device-signals\0'+str(source).encode()).hexdigest()+'.cursor')
try:
    state=json.loads(cursor.read_text())
    stat=source.stat()
except (OSError,ValueError) as error:
    print('ALERT: flow SYN source progress unavailable:',error)
else:
    current=f'{source}:{stat.st_dev}:{stat.st_ino}'
    age=int(time.time()-stat.st_mtime)
    if state.get('file_id')==current:
        lag=stat.st_size-state.get('offset',0)
        print(f"epoch={state.get('epoch','')} source_bytes={stat.st_size} cursor_offset={state.get('offset',0)} lag_bytes={lag} source_age_seconds={age}")
        if lag<0 or lag>64<<20 or age>120:
            print('ALERT: flow SYN source has a file gap, backlog or stale input')
    else:
        print(f"epoch={state.get('epoch','')} current_file_bytes={stat.st_size} cursor_file_id={state.get('file_id','')} source_age_seconds={age}")
        print('ALERT: flow SYN reader has not yet confirmed the rotated source file')
PY
if ! docker exec proxy-sentinel-clickhouse clickhouse-client --query "SELECT 'port_rows',count(),uniqExact(src_ip),max(window_start) FROM proxy_sentinel.discovery_observed_flow_ports_10m" 2>&1; then
  echo 'ALERT: flow SYN port projection query failed'
fi
echo "=== kafka ==="
"$RPK" -X brokers="$BROKERS" cluster health 2>&1 | sed -n '1,12p'
for group in ps-discovery-eventbus-facts-pg-v1 ps-identity-eventbus-shadow-v1 ; do
  echo "--- $group"
  "$RPK" -X brokers="$BROKERS" group describe "$group" 2>&1 | grep -E '^(STATE|TOTAL-LAG)' || true
done
echo "=== shadow api ==="
curl -sS -o /dev/null -w 'shadow_api=%{http_code}\n' --max-time 5 http://127.0.0.1:18084/healthz || true
echo "=== control plane ==="
curl -sS -o /dev/null -w 'readyz=%{http_code}\n' --max-time 8 http://127.0.0.1:18080/readyz || true
echo "=== discovery quarantine ==="
quarantine_dir=/var/lib/proxy-sentinel/discovery-spool/discovery-quarantine
if [[ -d "$quarantine_dir" ]]; then
  quarantine_count=$(find "$quarantine_dir" -maxdepth 1 -type f -name '*.json' | wc -l | tr -d ' ')
  printf 'quarantined_unprocessed=%s\n' "$quarantine_count"
  if [[ "$quarantine_count" != 0 ]]; then
    echo "ALERT: discovery segments are quarantined and await gap review"
  fi
else
  echo 'quarantined_unprocessed=0'
fi
echo "=== counts ==="
"${PSQL[@]}" "SELECT 'current_devices',count(*) FROM discovery_device_current_shadow UNION ALL SELECT 'current_facts',count(*) FROM discovery_service_facts_shadow UNION ALL SELECT 'identity_sessions',count(*) FROM identity_session_shadow UNION ALL SELECT 'identity_open',count(*) FROM identity_session_shadow WHERE ended_at IS NULL UNION ALL SELECT 'identity_endpoints',count(*) FROM identity_endpoint_current_shadow" 2>&1 || true
echo "=== discovery completeness ==="
"${PSQL[@]}" "SELECT 'current',count(*) FROM discovery_device_current_shadow UNION ALL SELECT 'current_false',count(*) FROM discovery_device_current_shadow WHERE document->>'current'='false' UNION ALL SELECT 'empty',count(*) FROM discovery_device_current_shadow WHERE fact_count=0 AND document='{}'::jsonb UNION ALL SELECT 'missing_stream',count(*) FROM stream_discovery_device_state s WHERE s.document->>'current'='true' AND NOT EXISTS(SELECT 1 FROM discovery_device_current_shadow c WHERE c.device_key=s.device_key) UNION ALL SELECT 'no_facts',count(*) FROM discovery_device_current_shadow WHERE fact_count=0 UNION ALL SELECT 'orphan_no_facts',count(*) FROM discovery_device_current_shadow c WHERE c.fact_count=0 AND NOT EXISTS(SELECT 1 FROM stream_discovery_device_state s JOIN stream_source_cutovers sc ON sc.epoch=s.epoch AND sc.state='active' WHERE s.device_key=c.device_key AND s.document->>'current'='true')" 2>&1 || true
echo "=== discovery current progress ==="
"${PSQL[@]}" "SELECT 'latest_current_observation',coalesce((SELECT last_seen::text FROM discovery_device_current_shadow ORDER BY last_seen DESC LIMIT 1),'') UNION ALL SELECT 'last_stream_reconcile',coalesce((SELECT max(updated_at)::text FROM discovery_current_stream_progress),'') UNION ALL SELECT 'fact_change_cursor',(SELECT last_fact_change_version::text FROM discovery_device_current_shadow_state WHERE id=TRUE)" 2>&1 || true
echo "=== discovery source freshness ==="
freshness=$("${PSQL[@]}" "SELECT c.epoch,coalesce(extract(epoch FROM now()-max(s.last_seen))::bigint,-1),coalesce(max(s.last_seen)::text,'') FROM stream_source_cutovers c LEFT JOIN stream_discovery_device_state s ON s.epoch=c.epoch WHERE c.state='active' AND c.source_kind='passive-discovery' GROUP BY c.epoch ORDER BY c.epoch" 2>&1) || freshness='query_failed'
if [[ -z "$freshness" ]]; then
  echo 'ALERT: no active passive discovery source'
elif [[ "$freshness" == 'query_failed' || "$freshness" == *'ERROR:'* ]]; then
  printf 'ALERT: discovery source freshness query failed: %s\n' "$freshness"
else
  while IFS='|' read -r epoch lag_seconds last_seen; do
    printf 'epoch=%s lag_seconds=%s last_seen=%s\n' "$epoch" "$lag_seconds" "$last_seen"
    if [[ ! "$lag_seconds" =~ ^[0-9]+$ ]] || (( lag_seconds > 120 )); then
      printf 'ALERT: passive discovery state is stale for epoch %s\n' "$epoch"
    fi
  done <<< "$freshness"
fi
echo "=== recognition coverage ==="
"${PSQL[@]}" "SELECT state->>'status',state->>'available_since',state->>'history_gap_seconds',jsonb_array_length(state->'items') FROM read_model_runtime_state WHERE name='recognition-fresh-coverage'" 2>&1 || true
echo "=== shared observation backlog ==="
"${PSQL[@]}" "SELECT 'wake_mode',mode FROM shared_observation_wake_mode UNION ALL SELECT 'realtime_pending',count(*)::text FROM shared_observation_jobs j WHERE j.revision>j.completed_revision AND NOT j.expired AND j.canceled_epoch='' AND EXISTS(SELECT 1 FROM stream_shared_source_cutovers c WHERE c.sensor_id=j.sensor_id AND c.cancel_id=j.generation_id AND c.state='active') UNION ALL SELECT 'realtime_oldest_seconds',coalesce(max(extract(epoch FROM now()-j.dirty_since))::bigint,0)::text FROM shared_observation_jobs j WHERE j.revision>j.completed_revision AND NOT j.expired AND j.canceled_epoch='' AND EXISTS(SELECT 1 FROM stream_shared_source_cutovers c WHERE c.sensor_id=j.sensor_id AND c.cancel_id=j.generation_id AND c.state='active') UNION ALL SELECT 'wakes_pending',count(*)::text FROM shared_observation_wakes WHERE processed_at IS NULL" 2>&1 || true
echo "=== NCU identity source ==="
curl -sS -o /dev/null -w 'ncu_identity_readyz=%{http_code}\n' --max-time 5 http://127.0.0.1:18082/readyz || true
identity_cutover=$("${PSQL[@]}" "SELECT 'identity_cutover',c.epoch,c.start_offset::text,coalesce(r.accepted_sequence,s.accepted_sequence,-1)::text,CASE WHEN coalesce(r.accepted_sequence,s.accepted_sequence,-1)+1>c.start_offset THEN 'next_batch_allowed' ELSE 'next_batch_below_fixed_start' END FROM stream_source_cutovers c LEFT JOIN identity_pipeline_scopes s ON s.scope_key=c.source_path LEFT JOIN identity_receive_progress r ON r.scope_key=c.source_path WHERE c.source_kind='identity-http' AND c.state='active'" 2>&1) || identity_cutover='query_failed'
printf '%s\n' "$identity_cutover"
if [[ "$identity_cutover" == *next_batch_below_fixed_start* ]]; then
  echo 'ALERT: NCU identity acceptance cannot advance past its fixed source start'
elif [[ "$identity_cutover" == query_failed ]]; then
  echo 'ALERT: NCU identity cutover query failed'
fi
