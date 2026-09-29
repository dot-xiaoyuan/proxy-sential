#!/usr/bin/env bash
set -euo pipefail

target="${1:-root@192.168.0.30}"
[[ "$target" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9._:-]+$ ]] || { echo "无效部署目标：$target" >&2; exit 2; }
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "构建前端"
(cd "$repo_root/frontend" && VITE_ENABLE_MOCKS=false VITE_API_BASE=/api/v1 pnpm build)

echo "更新前端到 $target"
# 不携带 macOS 扩展属性，保持与 Linux tar 的兼容性。
COPYFILE_DISABLE=1 tar --no-xattrs -czf - -C "$repo_root/frontend/dist" . | ssh "$target" '
  set -eu
  frontend_dir=/opt/proxy-sentinel/current/frontend/dist
  test -f "$frontend_dir/index.html"
  tar -xzf - -C "$frontend_dir"
'

echo "前端更新完成，强制刷新浏览器即可。"
