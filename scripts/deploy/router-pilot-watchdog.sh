#!/usr/bin/env bash

set -u

state_dir="${PROXY_SENTINEL_WATCHDOG_STATE_DIR:-/opt/proxy-sentinel/data/watchdog}"
log_file="${PROXY_SENTINEL_WATCHDOG_LOG_FILE:-/opt/proxy-sentinel/data/watchdog/overnight.log}"
baseline_file="${state_dir}/baseline"
lock_file="${state_dir}/watchdog.lock"
max_first_hour_growth_bytes="${PROXY_SENTINEL_MAX_FIRST_HOUR_GROWTH_BYTES:-10737418240}"
min_available_memory_kib="${PROXY_SENTINEL_MIN_AVAILABLE_MEMORY_KIB:-16777216}"
min_root_available_bytes="${PROXY_SENTINEL_MIN_ROOT_AVAILABLE_BYTES:-107374182400}"
max_load1="${PROXY_SENTINEL_MAX_LOAD1:-28}"
max_drop_ratio="${PROXY_SENTINEL_MAX_DROP_RATIO:-0.01}"
max_rolling_growth_per_hour_bytes="${PROXY_SENTINEL_MAX_ROLLING_GROWTH_PER_HOUR_BYTES:-5368709120}"
rolling_growth_window_seconds="${PROXY_SENTINEL_ROLLING_GROWTH_WINDOW_SECONDS:-300}"
rolling_growth_sample_file="${state_dir}/rolling-growth.sample"
supplement_rollback="${PROXY_SENTINEL_SUPPLEMENT_ROLLBACK:-/opt/proxy-sentinel/bin/router-pilot-snmp-rollback}"
shared_rollback="${PROXY_SENTINEL_SHARED_ROLLBACK:-/opt/proxy-sentinel/bin/router-pilot-shared-rollback}"

new_services=(
  proxy-sentinel-zeek-cluster.service
  proxy-sentinel-device-signal.service
  proxy-sentinel-ingest.service
)
if systemctl is-enabled --quiet proxy-sentinel-shared-signal.service 2>/dev/null; then
  new_services+=(proxy-sentinel-shared-signal.service)
fi

mkdir -p "${state_dir}"
chmod 0700 "${state_dir}"
touch "${log_file}"
chmod 0600 "${log_file}"

exec 9>"${lock_file}"
flock -n 9 || exit 0

now_epoch="$(date +%s)"
now_iso="$(date -Is)"
root_used_bytes="$(df -B1 --output=used / | awk 'NR == 2 { print $1 }')"
root_available_bytes="$(df -B1 --output=avail / | awk 'NR == 2 { print $1 }')"
available_memory_kib="$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)"
load1="$(awk '{ print $1 }' /proc/loadavg)"

if [[ ! -s "${baseline_file}" ]]; then
  printf '%s %s\n' "${now_epoch}" "${root_used_bytes}" >"${baseline_file}"
  chmod 0600 "${baseline_file}"
fi

read -r baseline_epoch baseline_used_bytes <"${baseline_file}"
elapsed_seconds=$((now_epoch - baseline_epoch))
growth_bytes=$((root_used_bytes - baseline_used_bytes))
rolling_growth_rate_bytes=0

counter_value() {
  local name="$1"
  local path="${state_dir}/${name}.count"
  [[ -r "${path}" ]] && cat "${path}" || printf '0'
}

set_counter() {
  local name="$1"
  local value="$2"
  printf '%s\n' "${value}" >"${state_dir}/${name}.count"
  chmod 0600 "${state_dir}/${name}.count"
}

increment_counter() {
  local name="$1"
  local value
  value="$(counter_value "${name}")"
  value=$((value + 1))
  set_counter "${name}" "${value}"
  printf '%s' "${value}"
}

reset_counter() {
  set_counter "$1" 0
}

rollback() {
  local reason="$1"
  local report="/opt/proxy-sentinel/backups/overnight-watchdog-triggered-$(date -u +%Y%m%dT%H%M%SZ).txt"

  systemctl stop proxy-sentinel-ingest.service proxy-sentinel-device-signal.service \
    proxy-sentinel-shared-signal.service \
    proxy-sentinel-zeek-cluster.service proxy-sentinel-suricata.service || true
  timeout 60 /usr/local/zeek/bin/zeekctl stop || true
  pkill -TERM -f '/usr/local/zeek/bin/zeek' || true
  systemctl disable proxy-sentinel-ingest.service proxy-sentinel-device-signal.service \
    proxy-sentinel-shared-signal.service \
    proxy-sentinel-zeek-cluster.service proxy-sentinel-suricata.service || true
  systemctl enable --now dpi-capture.service

  printf 'time=%s\nreason=%s\nroot_growth_bytes=%s\nload1=%s\nmem_available_kib=%s\n' \
    "${now_iso}" "${reason}" "${growth_bytes}" "${load1}" "${available_memory_kib}" >"${report}"
  chmod 0600 "${report}"
  printf '%s action=rollback reason=%q\n' "${now_iso}" "${reason}" >>"${log_file}"
  logger -t proxy-sentinel-watchdog "rollback completed: ${reason}"
  exit 1
}

for service in "${new_services[@]}"; do
  if ! systemctl is-active --quiet "${service}"; then
    rollback "required service inactive: ${service}"
  fi
done

if systemctl is-active --quiet dpi-capture.service; then
  rollback "legacy dpi-capture and Proxy Sentinel collectors are active together"
fi

if ((available_memory_kib < min_available_memory_kib)); then
  rollback "available memory below threshold"
fi

if ((root_available_bytes < min_root_available_bytes)); then
  rollback "root filesystem available space below threshold"
fi

if [[ ! -s "${rolling_growth_sample_file}" ]]; then
  printf '%s %s\n' "${now_epoch}" "${root_used_bytes}" >"${rolling_growth_sample_file}"
  chmod 0600 "${rolling_growth_sample_file}"
else
  read -r rolling_sample_epoch rolling_sample_used_bytes <"${rolling_growth_sample_file}"
  rolling_elapsed_seconds=$((now_epoch - rolling_sample_epoch))
  if ((rolling_elapsed_seconds >= rolling_growth_window_seconds)); then
    rolling_growth_bytes=$((root_used_bytes - rolling_sample_used_bytes))
    if ((rolling_growth_bytes > 0)); then
      rolling_growth_rate_bytes=$((rolling_growth_bytes * 3600 / rolling_elapsed_seconds))
    fi
    printf '%s %s\n' "${now_epoch}" "${root_used_bytes}" >"${rolling_growth_sample_file}"
    chmod 0600 "${rolling_growth_sample_file}"
    if ((rolling_growth_rate_bytes > max_rolling_growth_per_hour_bytes)); then
      rolling_growth_count="$(increment_counter rolling_growth)"
      if ((rolling_growth_count >= 2)); then
        if [[ -x "${shared_rollback}" && -L /opt/proxy-sentinel/backups/shared-canary-active ]]; then
          if "${shared_rollback}" "rolling root filesystem growth exceeded 5 GiB/hour"; then
            reset_counter rolling_growth
            printf '%s action=shared_rollback reason=%q rolling_growth_rate_bytes=%s\n' "${now_iso}" "rolling root filesystem growth exceeded 5 GiB/hour" "${rolling_growth_rate_bytes}" >>"${log_file}"
            exit 0
          fi
        fi
        if [[ -x "${supplement_rollback}" && -L /opt/proxy-sentinel/backups/snmp-canary-active ]]; then
          if "${supplement_rollback}" "rolling root filesystem growth exceeded 5 GiB/hour"; then
            reset_counter rolling_growth
            printf '%s action=supplement_rollback reason=%q rolling_growth_rate_bytes=%s\n' "${now_iso}" "rolling root filesystem growth exceeded 5 GiB/hour" "${rolling_growth_rate_bytes}" >>"${log_file}"
            exit 0
          fi
        fi
        rollback "rolling root filesystem growth exceeded threshold"
      fi
    else
      reset_counter rolling_growth
    fi
  fi
fi

if ((elapsed_seconds <= 3600 && growth_bytes > max_first_hour_growth_bytes)); then
  rollback "first-hour root filesystem growth exceeded threshold"
fi

if awk -v value="${load1}" -v limit="${max_load1}" 'BEGIN { exit !(value > limit) }'; then
  high_load_count="$(increment_counter high_load)"
  if ((high_load_count >= 5)); then
    rollback "one-minute load average exceeded threshold for five checks"
  fi
else
  reset_counter high_load
fi

ready_status="$(curl -fsS --max-time 5 http://127.0.0.1:18080/readyz 2>/dev/null | jq -r '.status // empty' 2>/dev/null || true)"
if [[ "${ready_status}" != "ready" ]]; then
  ready_failure_count="$(increment_counter ready_failure)"
  if ((ready_failure_count >= 3)); then
    rollback "control-plane readiness failed for three checks"
  fi
else
  reset_counter ready_failure
fi

for container in proxy-sentinel-postgres proxy-sentinel-clickhouse; do
  health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${container}" 2>/dev/null || true)"
  if [[ "${health}" != "healthy" ]]; then
    rollback "storage container unhealthy: ${container} (${health:-missing})"
  fi
done

netstats="$(timeout 25 /usr/local/zeek/bin/zeekctl netstats 2>/dev/null || true)"
drop_ratio="$(awk '
  {
    for (i = 1; i <= NF; i++) {
      split($i, item, "=")
      if (item[1] == "recvd") received += item[2]
      if (item[1] == "dropped") dropped += item[2]
    }
  }
  END {
    total = received + dropped
    if (total > 0) printf "%.8f", dropped / total
    else print "0"
  }
' <<<"${netstats}")"

if [[ -z "${netstats}" ]]; then
  netstats_failure_count="$(increment_counter netstats_failure)"
  if ((netstats_failure_count >= 3)); then
    rollback "Zeek packet statistics unavailable for three checks"
  fi
else
  reset_counter netstats_failure
fi

if awk -v value="${drop_ratio}" -v limit="${max_drop_ratio}" 'BEGIN { exit !(value >= limit) }'; then
  drop_failure_count="$(increment_counter packet_drop)"
  if ((drop_failure_count >= 2)); then
    rollback "Zeek packet drop ratio exceeded threshold for two checks"
  fi
else
  reset_counter packet_drop
fi

restart_count=0
for service in "${new_services[@]}"; do
  value="$(systemctl show "${service}" -p NRestarts --value 2>/dev/null || printf '0')"
  restart_count=$((restart_count + value))
done
if ((restart_count > 0)); then
  rollback "collector service restart detected"
fi

printf '%s status=healthy elapsed_seconds=%s root_growth_bytes=%s rolling_growth_rate_bytes=%s root_available_bytes=%s load1=%s mem_available_kib=%s ready=%s zeek_drop_ratio=%s restarts=%s\n' \
  "${now_iso}" "${elapsed_seconds}" "${growth_bytes}" "${rolling_growth_rate_bytes}" "${root_available_bytes}" "${load1}" \
  "${available_memory_kib}" "${ready_status:-missing}" "${drop_ratio}" "${restart_count}" >>"${log_file}"
