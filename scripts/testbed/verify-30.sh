#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "用法: $0 --scenario-result FILE [--target root@192.168.0.30] [--subject-ip 192.168.0.194] [--output FILE]" >&2
}

scenario_result=""; target="root@192.168.0.30"; subject_ip="192.168.0.194"; output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --scenario-result) scenario_result="${2:-}"; shift 2 ;;
    --target) target="${2:-}"; shift 2 ;;
    --subject-ip) subject_ip="${2:-}"; shift 2 ;;
    --output) output="${2:-}"; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done
[[ -r "$scenario_result" ]] || { echo "场景结果不可读: $scenario_result" >&2; exit 2; }
[[ "$target" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9._:-]+$ ]] || { echo "检测机地址不合法" >&2; exit 2; }
[[ "$subject_ip" =~ ^[0-9a-fA-F:.]+$ ]] || { echo "测试主体 IP 不合法" >&2; exit 2; }
for command in jq base64 ssh; do command -v "$command" >/dev/null || { echo "缺少命令: $command" >&2; exit 1; }; done

scenario="$(jq -r '.scenario // empty' "$scenario_result")"
scenario_id="$(jq -r '.scenario_id // empty' "$scenario_result")"
started_at="$(jq -r '.started_at // empty' "$scenario_result")"
finished_at="$(jq -r '.finished_at // empty' "$scenario_result")"
expected="$(jq -r '.expected // empty' "$scenario_result")"
[[ "$scenario" =~ ^(normal-single|nat-two|nat-three|wireguard|openvpn|behavioral-only)$ ]] || { echo "未知场景: $scenario" >&2; exit 2; }
[[ "$scenario_id" =~ ^[A-Za-z0-9._:-]+$ ]] || { echo "场景 ID 不合法" >&2; exit 2; }
[[ "$started_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z$ && "$finished_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z$ ]] || { echo "场景时间不合法" >&2; exit 2; }
[[ -n "$output" ]] || output="$(dirname "$scenario_result")/${scenario_id}-verification.json"
mkdir -p "$(dirname "$output")"

encode_query() { printf '%s' "$1" | base64 | tr -d '\n'; }
postgres_query() {
  local encoded
  encoded="$(encode_query "$1")"
  ssh -o BatchMode=yes "$target" "printf '%s' '$encoded' | base64 -d | docker exec -i proxy-sentinel-postgres psql -Atq -v ON_ERROR_STOP=1 -U proxy_sentinel -d proxy_sentinel"
}
clickhouse_query() {
  local encoded
  encoded="$(encode_query "$1")"
  ssh -o BatchMode=yes "$target" "printf '%s' '$encoded' | base64 -d | docker exec -i proxy-sentinel-clickhouse sh -c 'clickhouse-client --user \"\$CLICKHOUSE_USER\" --password \"\$CLICKHOUSE_PASSWORD\" --database \"\$CLICKHOUSE_DB\"'"
}

event_json="$(clickhouse_query "SELECT count() AS event_count, toString(max(timestamp)) AS latest_event FROM normalized_events WHERE subject_ip = '$subject_ip' AND timestamp >= parseDateTime64BestEffort('$started_at', 6) - INTERVAL 30 SECOND AND timestamp <= parseDateTime64BestEffort('$finished_at', 6) + INTERVAL 3 MINUTE FORMAT JSONEachRow")"
evidence_json="$(postgres_query "SELECT COALESCE(json_agg(row_to_json(items)),'[]'::json)::text FROM (SELECT evidence_id,type,score,confidence,severity,created_at FROM evidence WHERE ip='$subject_ip'::inet AND created_at >= '$started_at'::timestamptz - interval '30 seconds' AND created_at <= '$finished_at'::timestamptz + interval '3 minutes' ORDER BY created_at,type) items;")"
risk_json="$(postgres_query "SELECT COALESCE((SELECT snapshot || jsonb_build_object('history_created_at',created_at) FROM risk_snapshot_history WHERE ip='$subject_ip'::inet AND created_at >= '$started_at'::timestamptz - interval '30 seconds' AND created_at <= '$finished_at'::timestamptz + interval '3 minutes' ORDER BY created_at DESC LIMIT 1),'{}'::jsonb)::text;")"
case_json="$(postgres_query "SELECT COALESCE((SELECT row_to_json(items) FROM (SELECT case_id,status,priority,risk_score,risk_confidence,assessment_level,first_seen,last_seen,updated_at FROM risk_cases WHERE ip='$subject_ip'::inet AND last_seen >= '$started_at'::timestamptz - interval '30 seconds' AND first_seen <= '$finished_at'::timestamptz + interval '3 minutes' ORDER BY updated_at DESC LIMIT 1) items),'{}'::json)::text;")"
[[ -n "$event_json" ]] || event_json='{}'
[[ -n "$evidence_json" ]] || evidence_json='[]'
[[ -n "$risk_json" ]] || risk_json='{}'
[[ -n "$case_json" ]] || case_json='{}'

event_count="$(jq -r '.event_count // 0' <<<"$event_json")"
risk_level="$(jq -r '.level // "none"' <<<"$risk_json")"
risk_basis="$(jq -r '.detection_basis // "none"' <<<"$risk_json")"
rule_match_count="$(jq '[.[] | select(.type == "vpn_proxy_rule_match")] | length' <<<"$evidence_json")"
passed=false
reason=""
if (( event_count == 0 )); then
  reason="场景时间窗内没有标准事件"
else
  case "$scenario" in
    normal-single)
      if [[ "$risk_level" == none || "$risk_level" == normal || "$risk_level" == suspicious ]]; then passed=true; else reason="普通单终端被提升到 $risk_level"; fi
      ;;
    nat-two)
      if [[ ( "$risk_level" == high || "$risk_level" == confirmed ) && "$risk_basis" == shared_device_divergence ]]; then passed=true; else reason="期望 shared_device_divergence/high，实际 $risk_basis/$risk_level"; fi
      ;;
    nat-three)
      if [[ "$risk_level" == confirmed && "$risk_basis" == shared_device_divergence ]]; then passed=true; else reason="期望 shared_device_divergence/confirmed，实际 $risk_basis/$risk_level"; fi
      ;;
    wireguard|openvpn)
      if [[ ( "$risk_level" == high || "$risk_level" == confirmed ) && "$risk_basis" == explicit_tunnel && "$rule_match_count" -gt 0 ]]; then passed=true; else reason="期望 explicit_tunnel/high 且有高置信规则，实际 $risk_basis/$risk_level/rules=$rule_match_count"; fi
      ;;
    behavioral-only)
      if [[ ( "$risk_level" == none || "$risk_level" == normal || "$risk_level" == suspicious ) && ( "$risk_basis" == none || "$risk_basis" == behavioral_only ) ]]; then passed=true; else reason="纯行为线索越过安全上限: $risk_basis/$risk_level"; fi
      ;;
  esac
fi

jq -n \
  --arg scenario_id "$scenario_id" --arg scenario "$scenario" --arg expected "$expected" \
  --arg subject_ip "$subject_ip" --arg started_at "$started_at" --arg finished_at "$finished_at" \
  --arg verified_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg reason "$reason" \
  --argjson passed "$passed" --argjson event "$event_json" --argjson evidence "$evidence_json" \
  --argjson risk "$risk_json" --argjson risk_case "$case_json" \
  'def epoch:
     if . == null or . == "" then null
     else (sub("\\.[0-9]+(?=Z|[+-][0-9]{2}:[0-9]{2}$)"; "") | sub("\\+00:00$"; "Z") | fromdateiso8601)
     end;
   ($risk.evidence_ids // []) as $risk_evidence_ids |
   ($evidence | map(select(.evidence_id as $id | $risk_evidence_ids | index($id))) | map(.created_at | epoch) | map(select(. != null)) | max // null) as $last_evidence_at |
   ($risk.history_created_at | epoch) as $risk_created_at |
   ($verified_at | epoch) as $verified_epoch |
   ($finished_at | epoch) as $finished_epoch |
   {schema_version:"v1",scenario_id:$scenario_id,scenario:$scenario,expected:$expected,subject_ip:$subject_ip,started_at:$started_at,finished_at:$finished_at,verified_at:$verified_at,passed:$passed,failure_reason:$reason,event:$event,evidence:$evidence,risk:$risk,case:$risk_case,
    latency:{verification_after_finish_seconds:($verified_epoch-$finished_epoch),risk_after_last_evidence_seconds:(if $risk_created_at != null and $last_evidence_at != null then ($risk_created_at-$last_evidence_at) else null end)}}' > "$output"

echo "$output"
[[ "$passed" == true ]]
