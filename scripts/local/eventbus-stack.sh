#!/usr/bin/env bash
# Local-only Redpanda lifecycle for event bus Phase 1.
#
# This is not a production deployment script. It uses a single container, a
# single broker and PLAINTEXT, and is intentionally separate from the 184
# snapshot stack.
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
env_file="$root/data/run/eventbus.env"
compose_file="$root/deploy/compose/eventbus.yml"
container="proxy-sentinel-redpanda"

usage() {
  cat <<'EOF'
用法: scripts/local/eventbus-stack.sh <子命令>

  up       启动本地 Redpanda，等待健康并创建发现主题
  down     停止本地 Redpanda，保留 data/eventbus
  status   查看容器、集群健康、主题和 eventbus.stats
  smoke    启动后构建 probe，创建临时主题并完成 produce/consume

环境变量:
  REDPANDA_IMAGE                    默认 redpandadata/redpanda:v25.3.18
  EVENTBUS_KAFKA_PORT               默认 19092
  EVENTBUS_ADMIN_PORT               默认 19644
  PROXY_SENTINEL_EVENTBUS_DATA_DIR  默认 <repo>/data/eventbus
EOF
}

log() { printf '[eventbus] %s\n' "$*"; }
die() { printf '[eventbus] %s\n' "$*" >&2; exit 1; }

require_docker() {
  command -v docker >/dev/null || die "缺少 docker；event bus 本地验证需要 Docker/OrbStack"
  docker info >/dev/null 2>&1 || die "Docker 守护进程不可用；请先启动 OrbStack 后重试"
}

gen_env() {
  mkdir -p "$root/data/run" "$root/data/eventbus"
  if [ -f "$env_file" ]; then
    return 0
  fi
  cat >"$env_file" <<EOF
# 本地事件总线配置，由 eventbus-stack.sh 生成；data/ 已被 .gitignore 忽略。
REDPANDA_IMAGE=redpandadata/redpanda:v25.3.18
EVENTBUS_KAFKA_PORT=19092
EVENTBUS_ADMIN_PORT=19644
PROXY_SENTINEL_EVENTBUS_DATA_DIR=$root/data/eventbus
EOF
  chmod 0600 "$env_file"
  log "已生成 $env_file"
}

load_env() {
  [ -r "$env_file" ] || die "缺少 $env_file；先执行 eventbus-stack.sh up"
  set -a
  # shellcheck disable=SC1090
  . "$env_file"
  set +a
}

compose() {
  docker compose --env-file "$env_file" -f "$compose_file" "$@"
}

wait_health() {
  local status
  for _ in $(seq 1 60); do
    status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container" 2>/dev/null || true)"
    if [ "$status" = "healthy" ]; then
      log "Redpanda healthy"
      return 0
    fi
    sleep 1
  done
  docker logs "$container" 2>&1 | tail -40 || true
  die "Redpanda 未在 60 秒内健康"
}

ensure_topic() {
  local topic="${1:-ps.discovery.events.v1}"
  local partitions="${2:-6}"
  if docker exec "$container" rpk topic describe "$topic" >/dev/null 2>&1; then
    log "主题已存在: $topic"
    return 0
  fi
  docker exec "$container" rpk topic create "$topic" -p "$partitions" -r 1 >/dev/null
  log "已创建主题: $topic (partitions=$partitions, replication=1)"
}

cmd_up() {
  require_docker
  gen_env
  load_env
  compose up -d
  wait_health
  ensure_topic "ps.discovery.events.v1" 6
  compose ps
}

cmd_down() {
  require_docker
  load_env
  compose down
  log "Redpanda 已停止；data/eventbus 保留"
}

cmd_status() {
  require_docker
  load_env
  compose ps || true
  docker exec "$container" rpk cluster health || true
  docker exec "$container" rpk topic list || true
  local stats="${EVENTBUS_STATS_PATH:-$root/data/run/eventbus.stats}"
  if [ -f "$stats" ]; then
    log "eventbus.stats ($stats):"
    cat "$stats"
  else
    log "未找到 $stats；把 EVENTBUS_STATS_PATH 指向 discovery-worker 的 stream-capture-stats/eventbus.stats"
  fi
}

cmd_smoke() {
  require_docker
  load_env
  local port="${EVENTBUS_KAFKA_PORT:-19092}"
  local smoke_topic="ps.smoke.$(date +%s)-$$"
  local bin="$root/bin/event-bus-probe"
  mkdir -p "$root/bin"
  (cd "$root" && go build -o "$bin" ./cmd/event-bus-probe)
  ensure_topic "$smoke_topic" 1
  trap 'docker exec "$container" rpk topic delete "$smoke_topic" >/dev/null 2>&1 || true' EXIT
  local produced event_id consumed
  produced="$("$bin" -mode produce-sample -brokers "127.0.0.1:${port}" -topic "$smoke_topic" -timeout 20s)"
  printf '%s\n' "$produced"
  event_id="$(printf '%s\n' "$produced" | sed -n 's/.* event=\([^ ]*\).*/\1/p')"
  [ -n "$event_id" ] || die "probe 未输出 event id"
  consumed="$("$bin" -mode consume -brokers "127.0.0.1:${port}" -topic "$smoke_topic" -group "smoke-$$" -count 1 -timeout 20s)"
  printf '%s\n' "$consumed"
  printf '%s\n' "$consumed" | grep -q "event=${event_id}" || die "消费结果未包含刚生产的事件"
  log "smoke 通过: $event_id"
}

case "${1:-}" in
  up) cmd_up ;;
  down) cmd_down ;;
  status) cmd_status ;;
  smoke) cmd_smoke ;;
  -h|--help|help|"") usage ;;
  *) usage; exit 2 ;;
esac
