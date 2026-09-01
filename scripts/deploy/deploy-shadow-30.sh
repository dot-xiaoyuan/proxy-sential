#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'EOF'
deploy-shadow-30.sh 已停用：旧流程依赖目标机源码，且无法保证数据库迁移和应用切换回滚。
请改用：
  make deploy TARGET=root@192.168.0.30 VERSION=<version> ENV_FILE=<file>
EOF
exit 2
