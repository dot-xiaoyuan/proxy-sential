#!/usr/bin/env bash
# Proxy Sentinel 本地栈管理：OrbStack 存储 + 迁移 + 回放 ingest + 读模型 + 控制面。
#
# 只服务本机开发，不涉及现场部署。所有运行时数据都在 <repo>/data 下，已被 .gitignore 忽略。
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
env_file="$root/deploy/compose/storage.env"
compose_file="$root/deploy/compose/storage.yml"
compose_local="$root/deploy/compose/local.yml"
bin="$root/bin/proxy-sentinel"
data_dir="$root/data"
run_dir="$data_dir/run"
log_dir="$data_dir/logs"
cookie_jar="$run_dir/health.cookie"

frontend_dir=""
force=false
confirmed=false
do_build=true

usage() {
  cat <<'EOF'
用法: scripts/local/local-stack.sh <子命令> [选项]

  doctor    环境自检：Docker/OrbStack、端口、工具、磁盘、0.30 可达性、前端产物
  up        起完整本地栈（生成配置 -> 存储 -> 迁移 -> 管理员 -> ingest -> 风险 -> 读模型 -> 控制面）
  down      逆序停止进程并关闭存储容器（保留 data/db）
  status    容器、进程、/readyz、事件与风险计数
  logs [名] 查看某个进程日志，默认列出全部日志文件
  reset     停栈并删除本地数据库后重新拉起
  purge     删除 data/db、data/zeek、data/run、data/logs 与本地运行时配置

选项:
  --force             up/reset 时无条件重建本地数据库
  --frontend-dir DIR  使用指定前端产物，跳过 pnpm 构建
  --no-build          up 时跳过 Go 二进制重建
  --yes               purge 确认
  -h, --help          显示帮助
EOF
}

log() { printf '[local-stack] %s\n' "$*"; }
die() { printf '[local-stack] %s\n' "$*" >&2; exit 1; }

rand_hex() {
  python3 -c 'import secrets,sys; print(secrets.token_hex(int(sys.argv[1])))' "$1"
}

require_docker() {
  command -v docker >/dev/null || die "缺少 docker；请先启动 OrbStack"
  docker info >/dev/null 2>&1 || die "Docker 守护进程不可用；请执行 open -a OrbStack 后重试"
}

compose() {
  docker compose --env-file "$env_file" -f "$compose_file" -f "$compose_local" "$@"
}

load_env() {
  [ -r "$env_file" ] || die "缺少本地运行时配置: ${env_file}（先执行 local-stack.sh up 生成）"
  set -a
  # shellcheck disable=SC1090
  . "$env_file"
  set +a
}

gen_env() {
  if [ -f "$env_file" ]; then
    return 0
  fi
  local pg_pw ch_pw ingest_key master_key admin_pw
  pg_pw="$(rand_hex 24)"
  ch_pw="$(rand_hex 24)"
  ingest_key="$(rand_hex 32)"
  master_key="$(rand_hex 24)"
  admin_pw="SrunLocal!$(rand_hex 8)"
  cat > "$env_file" <<EOF
# 本地开发配置，由 scripts/local/local-stack.sh 生成；.gitignore 已忽略本文件。
# 本地使用 Docker Hub 公共镜像；现场仍必须使用 Coding 仓库的不可变 digest。
POSTGRES_IMAGE=postgres:18
CLICKHOUSE_IMAGE=clickhouse/clickhouse-server:25.9.2.1
PROXY_SENTINEL_ROOT=$root
PROXY_SENTINEL_DATA_DIR=$data_dir/db
PROXY_SENTINEL_STORAGE_MODE=db
PROXY_SENTINEL_CONTROL_ADDR=127.0.0.1:18080
PROXY_SENTINEL_HEALTH_URL=http://127.0.0.1:18080/readyz
PROXY_SENTINEL_SENSOR_ID=office-30
PROXY_SENTINEL_READ_ONLY=false
POSTGRES_HOST_PORT=25432
POSTGRES_DB=proxy_sentinel
POSTGRES_USER=proxy_sentinel
POSTGRES_PASSWORD=$pg_pw
PROXY_SENTINEL_POSTGRES_DSN='postgres://proxy_sentinel:$pg_pw@127.0.0.1:25432/proxy_sentinel?sslmode=disable'
CLICKHOUSE_HTTP_HOST_PORT=28123
CLICKHOUSE_NATIVE_HOST_PORT=29000
CLICKHOUSE_DB=proxy_sentinel
CLICKHOUSE_USER=proxy_sentinel
CLICKHOUSE_PASSWORD=$ch_pw
PROXY_SENTINEL_CLICKHOUSE_DSN='http://127.0.0.1:28123/?user=proxy_sentinel&password=$ch_pw&database=proxy_sentinel'
PROXY_SENTINEL_IDENTITY_INGEST_KEY=$ingest_key
PROXY_SENTINEL_ACTION_MASTER_KEY=$master_key
PROXY_SENTINEL_ADMIN_USERNAME=admin
PROXY_SENTINEL_ADMIN_DISPLAY_NAME=系统管理员
PROXY_SENTINEL_ADMIN_PASSWORD=$admin_pw
EOF
  chmod 0600 "$env_file"
  log "已生成本地运行时配置: $env_file"
}

prepare_dirs() {
  mkdir -p "$data_dir/db/postgres" "$data_dir/db/clickhouse/data" "$data_dir/db/clickhouse/logs" \
    "$data_dir/shadow" "$data_dir/applications" "$data_dir/device-fingerprints" \
    "$data_dir/exports" "$run_dir" "$log_dir"
}

build_backend() {
  if [ "$do_build" = false ] && [ -x "$bin" ]; then
    return 0
  fi
  command -v go >/dev/null || die "缺少 go，无法构建后端二进制"
  log "构建本地后端二进制"
  # 构建缓存放在仓库内，避免在受限沙箱或共享开发机上写入 ~/Library/Caches。
  mkdir -p "$root/.gocache"
  (cd "$root" && GOCACHE="$root/.gocache" go build -o "$bin" ./cmd/proxy-sentinel) || die "后端构建失败"
}

build_frontend() {
  if [ -n "$frontend_dir" ]; then
    [ -f "$frontend_dir/index.html" ] || die "指定的前端目录没有 index.html: $frontend_dir"
    return 0
  fi
  frontend_dir="$root/frontend/dist"
  if [ -f "$frontend_dir/index.html" ]; then
    return 0
  fi
  command -v pnpm >/dev/null || die "缺少 pnpm 且 frontend/dist 不存在；可用 --frontend-dir 指定已有产物"
  log "构建前端产物（首次较慢）"
  (cd "$root/frontend" && pnpm install --frozen-lockfile && pnpm build) || die "前端构建失败"
  [ -f "$frontend_dir/index.html" ] || die "前端构建未产出 index.html"
}

pg_query() {
  docker exec -e PSQ="$1" proxy-sentinel-postgres sh -c 'psql -Atq -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "$PSQ"' 2>/dev/null || true
}

ch_query() {
  docker exec -e CHQ="$1" proxy-sentinel-clickhouse sh -c 'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --database "$CLICKHOUSE_DB" --query "$CHQ"' 2>/dev/null || true
}

container_health() {
  docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$1" 2>/dev/null || echo missing
}

wait_storage() {
  local attempt pg ch
  for attempt in $(seq 1 60); do
    pg="$(container_health proxy-sentinel-postgres)"
    ch="$(container_health proxy-sentinel-clickhouse)"
    if [ "$pg" = healthy ] && [ "$ch" = healthy ]; then
      log "存储就绪: postgres=$pg clickhouse=$ch"
      return 0
    fi
    sleep 3
  done
  die "存储未在时限内就绪: postgres=$pg clickhouse=$ch"
}

apply_migrations() {
  log "执行数据库迁移"
  "$bin" migrate --postgres-dir "$root/migrations/postgres" \
    --clickhouse-dir "$root/migrations/clickhouse" --timeout 30m >/dev/null
  local completed
  completed="$(pg_query "SELECT count(*) FROM application_read_model_backfills WHERE status='completed' AND name IN ('latest-observations-v1','normalized-event-features-v1','activity-chart-buckets-v2','application-observation-buckets-v2')")"
  if [ "${completed:-0}" = "4" ]; then
    log "统计读模型回填已完成，跳过"
    return 0
  fi
  log "准备统计读模型（空库约 1 分钟）"
  "$bin" migrate --postgres-dir "$root/migrations/postgres" \
    --clickhouse-dir "$root/migrations/clickhouse" \
    --backfill-application-read-model --timeout 2h >/dev/null
}

ensure_admin() {
  local users
  users="$(pg_query 'SELECT count(*) FROM local_users')"
  if [ "${users:-0}" != "0" ]; then
    return 0
  fi
  log "创建本地管理员 ${PROXY_SENTINEL_ADMIN_USERNAME:-admin}"
  PROXY_SENTINEL_ADMIN_PASSWORD="$PROXY_SENTINEL_ADMIN_PASSWORD" \
    "$bin" control-plane bootstrap-admin \
    --username "${PROXY_SENTINEL_ADMIN_USERNAME:-admin}" \
    --name "${PROXY_SENTINEL_ADMIN_DISPLAY_NAME:-系统管理员}" >/dev/null
}

replay_manifest() { printf '%s' "$data_dir/zeek/${PROXY_SENTINEL_SENSOR_ID:-office-30}/replay/manifest.json"; }

manifest_sha() { shasum -a 256 "$1" | awk '{print $1}'; }

guard_replay() {
  local manifest count sha recorded
  manifest="$(replay_manifest)"
  if [ ! -f "$manifest" ]; then
    log "未发现回放快照，跳过 ingest；先运行 scripts/local/pull-zeek-30.sh 再执行 up"
    return 1
  fi
  count="$(ch_query 'SELECT count() FROM normalized_events')"
  sha="$(manifest_sha "$manifest")"
  if [ "${count:-0}" != "0" ]; then
    recorded=""
    if [ -f "$run_dir/last-ingest.json" ]; then
      recorded="$(jq -r '.manifest_sha256 // empty' "$run_dir/last-ingest.json" 2>/dev/null || true)"
    fi
    if [ "$recorded" != "$sha" ]; then
      die "本地库已有 ${count} 条事件，但回放快照已变化；请执行 local-stack.sh reset，或用 up --force 重建"
    fi
    log "本地库已有 ${count} 条事件且快照一致，ingest 从检查点继续"
  fi
  return 0
}

ingest_source_args() {
  local dir="$1" args="" name
  for name in dhcp.log software.log mdns.log nbns.log llmnr.log conn.log dns.log http.log ssl.log x509.log snmp.log lldp.log ssdp.log proxy_transactions.log ttl.jsonl; do
    [ -s "$dir/$name" ] || continue
    case "$name" in
      dhcp.log) args="$args --zeek-dhcp $dir/$name" ;;
      software.log) args="$args --zeek-software $dir/$name" ;;
      mdns.log) args="$args --zeek-mdns $dir/$name" ;;
      nbns.log) args="$args --zeek-nbns $dir/$name" ;;
      llmnr.log) args="$args --zeek-llmnr $dir/$name" ;;
      conn.log) args="$args --zeek-conn $dir/$name" ;;
      dns.log) args="$args --zeek-dns $dir/$name" ;;
      http.log) args="$args --zeek-http $dir/$name" ;;
      ssl.log) args="$args --zeek-ssl $dir/$name" ;;
      x509.log) args="$args --zeek-x509 $dir/$name" ;;
      snmp.log) args="$args --zeek-snmp $dir/$name" ;;
      lldp.log) args="$args --zeek-lldp $dir/$name" ;;
      ssdp.log) args="$args --zeek-ssdp $dir/$name" ;;
      proxy_transactions.log) args="$args --zeek-proxy $dir/$name" ;;
      ttl.jsonl) args="$args --device-signals $dir/$name" ;;
    esac
  done
  printf '%s' "$args"
}

risk_window() {
  local manifest span
  manifest="$(replay_manifest)"
  span=0
  if [ -f "$manifest" ]; then
    span="$(jq -r '.span_seconds // 0 | floor' "$manifest")"
  fi
  # risk materialize 只接受 10m/1h/24h/7d 四档窗口（internal/materialize.queryWindow），
  # 而 --window 是 Go duration，7 天必须写成 168h。这里按回放跨度选取能覆盖整段数据的最大档位。
  if [ "${span:-0}" -le 600 ]; then
    printf '10m'
  elif [ "$span" -le 3600 ]; then
    printf '1h'
  elif [ "$span" -le 86400 ]; then
    printf '24h'
  else
    printf '168h'
  fi
}

cutover_from_manifest() {
  python3 - "$(replay_manifest)" <<'PY'
import datetime as dt
import json
import sys

try:
    manifest = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    print("")
    raise SystemExit
oldest = manifest.get("oldest_ts") or ""
if not oldest:
    print("")
    raise SystemExit
text = oldest[:-1] + "+00:00" if oldest.endswith("Z") else oldest
value = dt.datetime.fromisoformat(text) - dt.timedelta(hours=1)
print(value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z")
PY
}

is_alive() {
  local pidfile="$run_dir/$1.pid" pid
  [ -f "$pidfile" ] || return 1
  pid="$(cat "$pidfile" 2>/dev/null || true)"
  [ -n "$pid" ] || return 1
  kill -0 "$pid" 2>/dev/null
}

spawn() {
  local name="$1"
  shift
  local pidfile="$run_dir/$name.pid" logfile="$log_dir/$name.log"
  if is_alive "$name"; then
    log "$name 已在运行 (pid $(cat "$pidfile"))"
    return 0
  fi
  nohup "$@" >"$logfile" 2>&1 &
  local pid=$!
  printf '%s\n' "$pid" > "$pidfile"
  disown 2>/dev/null || true
  log "$name 已启动 pid=$pid log=$logfile"
}

stop_proc() {
  local name="$1" pidfile="$run_dir/$name.pid" pid attempt
  if ! is_alive "$name"; then
    rm -f "$pidfile"
    return 0
  fi
  pid="$(cat "$pidfile")"
  kill "$pid" 2>/dev/null || true
  for attempt in $(seq 1 20); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.5
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$pidfile"
  log "$name 已停止"
}

process_names() {
  printf '%s' "control-plane risk lane-realtime lane-coarse lane-recognition lane-identity ingest"
}

stop_all_procs() {
  local name
  for name in $(process_names); do
    stop_proc "$name"
  done
}

start_ingest() {
  local dir args
  dir="$data_dir/zeek/${PROXY_SENTINEL_SENSOR_ID:-office-30}/replay"
  args="$(ingest_source_args "$dir")"
  if [ -z "${args// /}" ]; then
    log "回放目录没有可消费的日志，跳过 ingest"
    return 0
  fi
  # shellcheck disable=SC2086
  spawn ingest "$bin" ingest run --sensor-id "${PROXY_SENTINEL_SENSOR_ID:-office-30}" $args \
    --poll-interval 2s --max-batch-bytes 8388608 --store-timeout 2m --heartbeat-interval 30s
}

wait_ingest_drain() {
  local attempt last current stable
  last=""
  stable=0
  for attempt in $(seq 1 100); do
    current="$(ch_query 'SELECT count() FROM normalized_events')"
    if [ -n "$current" ] && [ "$current" = "$last" ]; then
      stable=$((stable + 1))
      if [ "$stable" -ge 3 ]; then
        log "ingest 已追平，normalized_events=${current:-0}"
        return 0
      fi
    else
      stable=0
    fi
    last="$current"
    sleep 3
  done
  log "ingest 未在时限内完全追平，继续启动后续组件（当前 normalized_events=${last:-0}）"
}

write_ingest_marker() {
  local manifest
  manifest="$(replay_manifest)"
  [ -f "$manifest" ] || return 0
  printf '{"manifest_sha256":"%s","recorded_at":"%s"}\n' "$(manifest_sha "$manifest")" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$run_dir/last-ingest.json"
}

start_risk() {
  local window
  window="$(risk_window)"
  log "风险物化窗口 ${window}（按回放跨度选取，本地有意偏离生产的 10m）"
  "$bin" risk materialize --once --sensor-id "${PROXY_SENTINEL_SENSOR_ID:-office-30}" --window "$window" --event-limit 200000
  spawn risk "$bin" risk materialize --sensor-id "${PROXY_SENTINEL_SENSOR_ID:-office-30}" --window "$window" --interval 5m --event-limit 200000
}

start_lanes() {
  local cutover sensor
  sensor="${PROXY_SENTINEL_SENSOR_ID:-office-30}"
  # 与现场 systemd 单元保持一致：realtime/coarse 使用 V3 活动读模型，
  # 否则本地会退回已停更的 V2 图表游标，导致总览读数一直不可用。
  export PROXY_SENTINEL_ACTIVITY_READ_MODEL_V3=true
  cutover="$(cutover_from_manifest)"
  if [ -n "$cutover" ]; then
    log "V3 读模型起点 PROXY_SENTINEL_ACTIVITY_V3_CUTOVER=$cutover"
    export PROXY_SENTINEL_ACTIVITY_V3_CUTOVER="$cutover"
  fi
  spawn lane-realtime "$bin" read-model run --lane realtime --sensor-id "$sensor"
  unset PROXY_SENTINEL_ACTIVITY_V3_CUTOVER || true
  spawn lane-coarse "$bin" read-model run --lane coarse --sensor-id "$sensor"
  unset PROXY_SENTINEL_ACTIVITY_READ_MODEL_V3 || true
  spawn lane-recognition "$bin" read-model run --lane recognition --sensor-id "$sensor"
  spawn lane-identity "$bin" read-model run --lane identity --sensor-id "$sensor"
}

wait_read_models() {
  local attempt pending
  for attempt in $(seq 1 120); do
    pending="$(pg_query 'SELECT count(*) FROM read_model_jobs WHERE processed_generation<dirty_generation')"
    if [ "${pending:-1}" = "0" ]; then
      log "读模型任务已排空"
      return 0
    fi
    sleep 5
  done
  log "读模型仍有 ${pending:-未知} 个未完成任务，继续启动控制面"
}

start_control_plane() {
  # 现场通过 control-plane 的 systemd drop-in 打开这两个开关，本地必须一致。
  export PROXY_SENTINEL_ACTIVITY_READ_MODEL_V3=true
  export PROXY_SENTINEL_RECOGNITION_SUMMARY_V1=true
  spawn control-plane "$bin" control-plane serve \
    --addr "${PROXY_SENTINEL_CONTROL_ADDR:-127.0.0.1:18080}" \
    --shadow-dir "$data_dir/shadow" \
    --sensor-id "${PROXY_SENTINEL_SENSOR_ID:-office-30}" \
    --frontend-dir "$frontend_dir" \
    --storage-mode db \
    --read-only=false \
    --applications-dir "$data_dir/applications" \
    --device-fingerprint-dir "$data_dir/device-fingerprints" \
    --device-fingerprint-auto-update=false \
    --export-dir "$data_dir/exports" \
    --postgres-migrations-dir "$root/migrations/postgres"
}

wait_ready() {
  local url="${PROXY_SENTINEL_HEALTH_URL:-http://127.0.0.1:18080/readyz}" attempt code
  for attempt in $(seq 1 40); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$url" 2>/dev/null || true)"
    if [ "$code" = "200" ]; then
      log "控制面就绪: $url"
      break
    fi
    sleep 2
  done
  if [ "$code" != "200" ]; then
    die "控制面未在时限内就绪，请查看 $log_dir/control-plane.log"
  fi
  local base attempt2
  base="${PROXY_SENTINEL_CONTROL_ADDR:-127.0.0.1:18080}"
  rm -f "$cookie_jar"
  if ! curl -s -o /dev/null --max-time 5 -X POST -H 'Content-Type: application/json' \
    -d "{\"username\":\"${PROXY_SENTINEL_ADMIN_USERNAME:-admin}\",\"password\":\"$PROXY_SENTINEL_ADMIN_PASSWORD\"}" \
    -c "$cookie_jar" "http://$base/api/v1/auth/login"; then
    log "登录探测失败，跳过总览校验"
    return 0
  fi
  for attempt2 in $(seq 1 90); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -b "$cookie_jar" "http://$base/api/v1/overview" 2>/dev/null || true)"
    if [ "$code" = "200" ]; then
      log "总览接口可用"
      return 0
    fi
    sleep 2
  done
  log "总览接口仍返回 ${code}，读模型可能还在构建；可稍后用 status 复查"
}

wipe_db() {
  stop_all_procs
  if docker inspect proxy-sentinel-postgres >/dev/null 2>&1; then
    compose down -v >/dev/null 2>&1 || true
  fi
  rm -rf "$data_dir/db"
  prepare_dirs
  rm -f "$run_dir/last-ingest.json"
}

cmd_up() {
  require_docker
  gen_env
  load_env
  prepare_dirs
  if [ "$force" = true ]; then
    log "重建本地数据库"
    wipe_db
  fi
  build_backend
  build_frontend
  log "启动 PostgreSQL 与 ClickHouse"
  compose up -d
  wait_storage
  apply_migrations
  ensure_admin
  local have_replay=false
  if guard_replay; then
    have_replay=true
  fi
  if [ "$have_replay" = true ]; then
    start_ingest
    wait_ingest_drain
    write_ingest_marker
    start_risk
  fi
  start_lanes
  wait_read_models
  start_control_plane
  wait_ready
  cmd_status
}

cmd_down() {
  stop_all_procs
  if [ -r "$env_file" ]; then
    compose down >/dev/null 2>&1 || true
  fi
  log "本地栈已停止（数据保留在 $data_dir/db）"
}

cmd_status() {
  if [ -r "$env_file" ]; then
    load_env
  fi
  echo "--- 容器 ---"
  docker ps --filter name=proxy-sentinel-postgres --filter name=proxy-sentinel-clickhouse \
    --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || true
  echo "--- 进程 ---"
  local name pid
  for name in $(process_names); do
    if is_alive "$name"; then
      pid="$(cat "$run_dir/$name.pid")"
      printf '%-18s 运行中 pid=%s\n' "$name" "$pid"
    else
      printf '%-18s 未运行\n' "$name"
    fi
  done
  echo "--- 健康与数据 ---"
  local url="${PROXY_SENTINEL_HEALTH_URL:-http://127.0.0.1:18080/readyz}"
  printf 'readyz              %s\n' "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$url" 2>/dev/null || echo unreachable)"
  printf 'normalized_events   %s\n' "$(ch_query 'SELECT count() FROM normalized_events')"
  printf 'risk_snapshots      %s\n' "$(pg_query 'SELECT count(*) FROM risk_snapshots')"
  printf 'collector_runs      %s\n' "$(pg_query 'SELECT count(*) FROM collector_runs')"
  printf 'local_users         %s\n' "$(pg_query 'SELECT count(*) FROM local_users')"
}

cmd_logs() {
  if [ $# -eq 0 ]; then
    ls -la "$log_dir" 2>/dev/null || log "暂无日志目录"
    return 0
  fi
  local name="$1" lines="${2:-80}"
  [ -f "$log_dir/$name.log" ] || die "没有日志: ${name}（可选: $(process_names)）"
  tail -n "$lines" "$log_dir/$name.log"
}

cmd_reset() {
  require_docker
  load_env
  log "重置本地数据库"
  wipe_db
  cmd_up
}

cmd_purge() {
  [ "$confirmed" = true ] || die "purge 会删除本地数据与配置，请加 --yes 确认"
  stop_all_procs
  if [ -r "$env_file" ]; then
    compose down -v >/dev/null 2>&1 || true
  fi
  rm -rf "$data_dir/db" "$data_dir/zeek" "$run_dir" "$log_dir"
  rm -f "$env_file"
  log "已删除本地数据库、回放快照、日志与运行时配置"
}

port_busy() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

cmd_doctor() {
  require_docker
  local failures=0
  printf 'docker context      %s\n' "$(docker context show 2>/dev/null || echo unknown)"
  local mem_bytes
  mem_bytes="$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)"
  printf 'docker 内存上限     %s GB\n' "$((mem_bytes / 1024 / 1024 / 1024))"
  if [ "$mem_bytes" -lt $((10 * 1024 * 1024 * 1024)) ]; then
    log "提示: Docker VM 内存低于 10GB，local.yml 已把 ClickHouse 限制到 6GB；回放大量数据前建议在 OrbStack 提高内存"
  fi
  local tool
  for tool in python3 jq rsync ssh curl go docker; do
    if command -v "$tool" >/dev/null; then
      printf '%-19s %s\n' "$tool" "$(command -v "$tool")"
    else
      printf '%-19s 缺失\n' "$tool"
      failures=$((failures + 1))
    fi
  done
  if command -v pnpm >/dev/null; then
    printf '%-19s %s\n' pnpm "$(command -v pnpm)"
  else
    printf '%-19s 缺失（需要 --frontend-dir 或预置 frontend/dist）\n' pnpm
  fi
  printf '磁盘可用            %s\n' "$(df -h "$root" | awk 'NR==2 {print $4}')"
  if [ -f "$root/frontend/dist/index.html" ]; then
    printf '前端产物            已存在\n'
  else
    printf '前端产物            缺失，up 时会执行 pnpm build\n'
  fi
  if [ -f "$env_file" ]; then
    printf '运行时配置          已存在\n'
  else
    printf '运行时配置          缺失，up 时会生成\n'
  fi
  local port
  for port in 25432 28123 18080; do
    if port_busy "$port"; then
      printf '端口 %-6s        占用\n' "$port"
    else
      printf '端口 %-6s        空闲\n' "$port"
    fi
  done
  if ssh -o BatchMode=yes -o ConnectTimeout=8 -q root@192.168.0.30 'echo ok' >/dev/null 2>&1; then
    printf '%-19s 可达\n' '0.30 SSH'
  else
    printf '%-19s 不可达（离线回放仍可用 --source-dir）\n' '0.30 SSH'
  fi
  if [ "$failures" -gt 0 ]; then
    die "doctor 发现 $failures 项缺失"
  fi
  log "doctor 通过"
}

command_name="${1:-}"
if [ $# -gt 0 ]; then
  shift
fi
while [ $# -gt 0 ]; do
  case "$1" in
    --force) force=true; shift ;;
    --frontend-dir) frontend_dir="${2:-}"; shift 2 ;;
    --no-build) do_build=false; shift ;;
    --yes) confirmed=true; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; die "未知参数: $1" ;;
    *) break ;;
  esac
done

case "$command_name" in
  doctor) cmd_doctor ;;
  up) cmd_up ;;
  down) cmd_down ;;
  status) cmd_status ;;
  logs) cmd_logs "$@" ;;
  reset) cmd_reset ;;
  purge) cmd_purge ;;
  "") usage; exit 2 ;;
  *) usage >&2; die "未知子命令: $command_name" ;;
esac
