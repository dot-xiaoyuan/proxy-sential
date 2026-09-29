#!/usr/bin/env bash
set -Eeuo pipefail

runner="${PROXY_SENTINEL_SCENARIO_RUNNER:-/root/run-194.sh}"
result_dir="${PROXY_SENTINEL_TEST_RESULT_DIR:-/var/log/proxy-sentinel-testbed}"
cooldown="${PROXY_SENTINEL_SCENARIO_COOLDOWN_SECONDS:-720}"
initial_cooldown="${PROXY_SENTINEL_INITIAL_COOLDOWN_SECONDS:-720}"
[[ -x "$runner" ]] || { echo "场景脚本不可执行: $runner" >&2; exit 1; }
[[ "$cooldown" =~ ^[0-9]+$ && "$initial_cooldown" =~ ^[0-9]+$ ]] || { echo "冷却时间必须是整数秒" >&2; exit 2; }
mkdir -p "$result_dir"
suite_id="acceptance-$(date -u +%Y%m%dT%H%M%SZ)"
suite_log="$result_dir/$suite_id.log"
suite_result="$result_dir/$suite_id.json"
scenarios=(normal-single nat-two nat-three wireguard openvpn behavioral-only)

exec > >(tee -a "$suite_log") 2>&1
echo "suite=$suite_id status=waiting_initial_cooldown seconds=$initial_cooldown"
sleep "$initial_cooldown"
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
results=()
for index in "${!scenarios[@]}"; do
  scenario="${scenarios[$index]}"
  echo "suite=$suite_id scenario=$scenario status=generating"
  result="$($runner "$scenario")"
  results+=("$result")
  echo "suite=$suite_id scenario=$scenario status=generated result=$result"
  if (( index + 1 < ${#scenarios[@]} )); then
    echo "suite=$suite_id status=cooling_down seconds=$cooldown"
    sleep "$cooldown"
  fi
done
finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
{
  printf '{"schema_version":"v1","suite_id":"%s","started_at":"%s","finished_at":"%s","cooldown_seconds":%d,"status":"generated","results":[' "$suite_id" "$started_at" "$finished_at" "$cooldown"
  for index in "${!results[@]}"; do
    (( index == 0 )) || printf ','
    printf '"%s"' "${results[$index]}"
  done
  printf ']}\n'
} > "$suite_result"
echo "$suite_result"
