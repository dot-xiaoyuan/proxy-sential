#!/usr/bin/env bash
set -euo pipefail

target="${1:-root@192.168.0.30}"
[[ "$target" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9._:-]+$ ]] || { echo "无效部署目标：$target" >&2; exit 2; }
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/proxy-sentinel-backend.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT
mkdir -p "$work_dir/bin"
cp -R "$repo_root/migrations" "$work_dir/migrations"
mkdir -p "$work_dir/assets"
cp -R "$repo_root/assets/zeek" "$work_dir/assets/zeek"

echo "构建 Linux amd64 后端"
(
  cd "$repo_root"
  version="dev-$(git rev-parse --short HEAD)-$(date +%Y%m%d%H%M%S)"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$work_dir/bin/proxy-sentinel" ./cmd/proxy-sentinel
)

echo "更新后端到 $target"
COPYFILE_DISABLE=1 tar --no-xattrs -czf - -C "$work_dir" bin migrations assets | ssh "$target" '
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
  echo "执行版本化迁移并追平应用读模型"
  "$stage/bin/proxy-sentinel" migrate \
    --postgres-dir "$stage/migrations/postgres" \
    --clickhouse-dir "$stage/migrations/clickhouse" \
    --backfill-application-read-model --timeout 2h
  mkdir -p /opt/proxy-sentinel/current/migrations
  cp -R "$stage/migrations/postgres" "$stage/migrations/clickhouse" /opt/proxy-sentinel/current/migrations/
  mkdir -p /opt/proxy-sentinel/current/assets
  cp -R "$stage/assets/zeek" /opt/proxy-sentinel/current/assets/
  # 替换文件而非覆盖运行中进程正在使用的二进制。
  install -m 0755 "$stage/bin/proxy-sentinel" "$live.new"
  mv -f "$live.new" "$live"
  # 重启常驻后端服务；定时任务下次运行自动使用新程序。
  for unit in proxy-sentinel-control-plane proxy-sentinel-ingest proxy-sentinel-risk-materializer proxy-sentinel-recognition-materializer proxy-sentinel-device-signal proxy-sentinel-zeek; do
    if systemctl is-active --quiet "$unit.service"; then
      systemctl restart "$unit.service"
      systemctl is-active --quiet "$unit.service"
    fi
  done
  curl -fsS --retry 5 --retry-connrefused --retry-delay 1 --max-time 5 http://127.0.0.1:18080/readyz
'
echo "后端更新完成。"
