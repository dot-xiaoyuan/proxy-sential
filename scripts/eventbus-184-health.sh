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
  proxy-sentinel-recognition-materializer.service ; do
  printf '%-62s %s\n' "$unit" "$(systemctl is-active "$unit" 2>/dev/null || true)"
done
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
echo "=== recognition coverage ==="
"${PSQL[@]}" "SELECT state->>'status',state->>'available_since',state->>'history_gap_seconds',jsonb_array_length(state->'items') FROM read_model_runtime_state WHERE name='recognition-fresh-coverage'" 2>&1 || true
