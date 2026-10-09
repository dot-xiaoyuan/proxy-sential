#!/usr/bin/env bash
set -euo pipefail

target="${1:-root@192.168.0.30}"
[[ "$target" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9._:-]+$ ]] || { echo "无效部署目标：$target" >&2; exit 2; }
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/proxy-sentinel-backend.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT
mkdir -p "$work_dir/bin"
cp -R "$repo_root/migrations" "$work_dir/migrations"
mkdir -p "$work_dir/systemd"
for unit in proxy-sentinel-read-model-realtime.service proxy-sentinel-read-model-coarse.service proxy-sentinel-recognition-materializer.service; do
  cp "$repo_root/deploy/systemd/$unit" "$work_dir/systemd/$unit"
done

echo "构建 Linux amd64 后端"
(
  cd "$repo_root"
  version="dev-$(git rev-parse --short HEAD)-$(date +%Y%m%d%H%M%S)"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$work_dir/bin/proxy-sentinel" ./cmd/proxy-sentinel
)

echo "更新后端到 $target"
COPYFILE_DISABLE=1 tar --no-xattrs -czf - -C "$work_dir" bin migrations systemd | ssh "$target" '
  set -eu
  live=/opt/proxy-sentinel/current/bin/proxy-sentinel
  test -f "$live"
  stage=$(mktemp -d /tmp/proxy-sentinel-backend.XXXXXX)
  trap '\''rm -rf "$stage"'\'' EXIT
  tar -xzf - -C "$stage"
  # 迁移和有界回填成功后才切换程序；开发部署不创建备份。
  test -r /opt/proxy-sentinel/config/runtime.env
  set -a
  . /opt/proxy-sentinel/config/runtime.env
  set +a
  echo "执行版本化迁移"
  "$stage/bin/proxy-sentinel" migrate \
    --postgres-dir "$stage/migrations/postgres" \
    --clickhouse-dir "$stage/migrations/clickhouse" \
    --timeout "${PROXY_SENTINEL_MIGRATION_TIMEOUT:-5m}"
  # V3 读模型独立持续更新；旧 V2 drain 在持续流量下可能永不追平。
  # 仅在明确启用旧读模型回填时执行，与完整安装器保持一致。
  if [ "${PROXY_SENTINEL_RUN_LEGACY_BACKFILL:-false}" = true ]; then
    "$stage/bin/proxy-sentinel" migrate \
      --postgres-dir "$stage/migrations/postgres" \
      --clickhouse-dir "$stage/migrations/clickhouse" \
      --backfill-application-read-model --timeout "${PROXY_SENTINEL_MIGRATION_TIMEOUT:-2h}"
  fi
  mkdir -p /opt/proxy-sentinel/current/migrations
  cp -R "$stage/migrations/postgres" "$stage/migrations/clickhouse" /opt/proxy-sentinel/current/migrations/
  # 替换文件而非覆盖运行中进程正在使用的二进制。
  install -m 0755 "$stage/bin/proxy-sentinel" "$live.new"
  mv -f "$live.new" "$live"
  # 快捷发布也必须同步独立读模型服务，避免旧 V2 游标停止刷新后总览整体不可用。
  for unit in proxy-sentinel-read-model-realtime.service proxy-sentinel-read-model-coarse.service proxy-sentinel-recognition-materializer.service; do
    install -m 0644 "$stage/systemd/$unit" "/etc/systemd/system/$unit"
  done
  mkdir -p /etc/systemd/system/proxy-sentinel-control-plane.service.d
  printf "%s\n" \
    "[Service]" \
    "Environment=PROXY_SENTINEL_ACTIVITY_READ_MODEL_V3=true" \
    "Environment=PROXY_SENTINEL_RECOGNITION_SUMMARY_V1=true" \
    > /etc/systemd/system/proxy-sentinel-control-plane.service.d/read-model-v3.conf
  systemctl daemon-reload
  systemctl enable --now proxy-sentinel-read-model-realtime.service proxy-sentinel-read-model-coarse.service proxy-sentinel-recognition-materializer.service
  # 重启常驻后端服务；定时任务下次运行自动使用新程序。
  for unit in proxy-sentinel-read-model-realtime proxy-sentinel-read-model-coarse proxy-sentinel-recognition-materializer proxy-sentinel-control-plane proxy-sentinel-ingest proxy-sentinel-risk-materializer proxy-sentinel-device-signal; do
    if systemctl is-active --quiet "$unit.service"; then
      systemctl restart "$unit.service"
      systemctl is-active --quiet "$unit.service"
    fi
  done
  body=""
  for _ in $(seq 1 20); do
    body=$(curl -fsS --max-time 5 http://127.0.0.1:18080/readyz 2>/dev/null || true)
    if printf "%s" "$body" | grep -q '\''"statistics_read_model":{"status":"ready"}'\''; then
      printf "%s\n" "$body"
      exit 0
    fi
    sleep 2
  done
  printf "读模型未在发布窗口内恢复：%s\n" "$body" >&2
  exit 1
'
echo "后端更新完成。"
