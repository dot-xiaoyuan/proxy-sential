#!/usr/bin/env bash
# Operate the single-node Redpanda deployment used for 184 event-bus validation.
#
# The 184 Docker daemon could not create new containers during the deployment
# attempt, so this script runs the official Redpanda distribution extracted from
# the pinned image under /opt/redpanda and managed by systemd. It is still a
# test deployment: one broker, PLAINTEXT on loopback, HDD data, developer mode.
# Production needs at least three brokers, TLS/SASL, SSD/NVMe and a capacity
# tested retention policy.
set -Eeuo pipefail

root="${PROXY_SENTINEL_ROOT:-/opt/proxy-sentinel}"
env_file="$root/config/eventbus.env"
service="proxy-sentinel-eventbus-host.service"
rpk_bin="/opt/redpanda/bin/rpk"
config="/etc/redpanda/redpanda.yaml"
topic="ps.discovery.events.v1"

usage() {
  cat <<'EOF'
用法: eventbus-184.sh <子命令>

  up          启动单节点 Redpanda（systemd），等待健康并创建发现主题
  down        停止并禁用服务，保留 data/eventbus
  restart     重启服务并等待健康
  status      服务、集群健康、主题、磁盘和内存
  logs        最近 100 行 journal
  topics      列出主题；topics describe <name> 查看详情
  smoke       创建临时主题，produce/consume 一条并校验
  version     打印 rpk/redpanda 版本
  config      检查关键配置路径（不打印凭据）
EOF
}

log() { printf '[eventbus-184] %s\n' "$*"; }
die() { printf '[eventbus-184] %s\n' "$*" >&2; exit 1; }

load_env() {
  [ -r "$env_file" ] || die "缺少 $env_file"
  # shellcheck disable=SC1090
  set -a; . "$env_file"; set +a
  : "${EVENTBUS_KAFKA_PORT:=19092}"
}

rpk() {
  "$rpk_bin" -X brokers=127.0.0.1:"${EVENTBUS_KAFKA_PORT}" "$@"
}

wait_health() {
  local status
  for _ in $(seq 1 90); do
    if rpk cluster health 2>/dev/null | grep -q 'Healthy:.*true'; then
      log "Redpanda healthy"
      return 0
    fi
    sleep 1
  done
  journalctl -u "$service" -n 60 --no-pager 2>&1 || true
  die "Redpanda 未在 90 秒内健康"
}

ensure_topic() {
  local name="${1:-$topic}" partitions="${2:-6}"
  if rpk topic describe "$name" >/dev/null 2>&1; then
    log "主题已存在: $name"
    return 0
  fi
  rpk topic create "$name" -p "$partitions" -r 1 >/dev/null
  log "已创建主题: $name (partitions=$partitions, replication=1)"
}

require_host() {
  [ -x "$rpk_bin" ] || die "缺少 $rpk_bin；先安装 /opt/redpanda"
  [ -r "$config" ] || die "缺少 $config"
}

cmd_up() {
  require_host
  load_env
  systemctl enable "$service" >/dev/null 2>&1 || true
  systemctl start "$service"
  wait_health
  ensure_topic "$topic" "${EVENTBUS_PARTITIONS:-6}"
  rpk topic alter-config "$topic" --no-confirm --set retention.ms=604800000 --set cleanup.policy=delete >/dev/null 2>&1 || true
  cmd_status
}

cmd_down() {
  load_env
  systemctl disable --now "$service"
  log "服务已停止并禁用；${PROXY_SENTINEL_EVENTBUS_DATA_DIR:-$root/data/eventbus} 保留"
}

cmd_restart() {
  require_host
  load_env
  systemctl restart "$service"
  wait_health
  cmd_status
}

cmd_status() {
  load_env
  printf 'service=%s active=%s\n' "$service" "$(systemctl is-active "$service" 2>/dev/null || true)"
  systemctl show -p MainPID -p TasksCurrent -p MemoryCurrent --value "$service" 2>/dev/null | paste -sd' ' - || true
  rpk cluster health 2>&1 || true
  rpk topic list 2>&1 || true
  local data="${PROXY_SENTINEL_EVENTBUS_DATA_DIR:-$root/data/eventbus}"
  df -h "$data" | tail -1 || true
  free -g | head -3 || true
}

cmd_logs() {
  journalctl -u "$service" -n 100 --no-pager 2>&1
}

cmd_topics() {
  require_host
  load_env
  if [ "${1:-}" = "describe" ] && [ -n "${2:-}" ]; then
    rpk topic describe "$2"
    return
  fi
  rpk topic list
}

cmd_smoke() {
  require_host
  load_env
  local smoke_topic="ps.smoke.$(date +%s)-$$"
  local text='{"schema_version":1,"source":"184-eventbus-smoke","owned_by":"proxy-sentinel"}'
  ensure_topic "$smoke_topic" 1
  trap "rpk topic delete '$smoke_topic' >/dev/null 2>&1 || true" EXIT
  printf '%s\n' "$text" | rpk topic produce "$smoke_topic" -k "smoke-$$" >/dev/null
  local consumed
  consumed="$(rpk topic consume "$smoke_topic" -n 1 -o start)"
  printf '%s\n' "$consumed"
  printf '%s\n' "$consumed" | grep -q '184-eventbus-smoke' || die "消费结果未包含 smoke 内容"
  log "smoke 通过: $smoke_topic"
}

cmd_version() {
  require_host
  "$rpk_bin" version 2>&1 || true
  "/opt/redpanda/bin/redpanda" --version 2>&1 || true
}

cmd_config() {
  printf 'service=%s\nconfig=%s\nrpk=%s\ndata=%s\nbrokers=127.0.0.1:%s\n' \
    "$service" "$config" "$rpk_bin" "${PROXY_SENTINEL_EVENTBUS_DATA_DIR:-$root/data/eventbus}" "${EVENTBUS_KAFKA_PORT:-19092}"
}

case "${1:-}" in
  up) cmd_up ;;
  down) cmd_down ;;
  restart) cmd_restart ;;
  status) cmd_status ;;
  logs) cmd_logs ;;
  topics) shift; cmd_topics "$@" ;;
  smoke) cmd_smoke ;;
  version) cmd_version ;;
  config) cmd_config ;;
  -h|--help|help|"") usage ;;
  *) usage; exit 2 ;;
esac
