#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
output=${1:-"$repo_root/dist/device-fingerprint-bundle.tar.gz"}

mkdir -p "$(dirname "$output")"
cd "$repo_root"
uap_sha=$(git ls-remote https://github.com/ua-parser/uap-core.git refs/heads/master | awk 'NR == 1 {print $1}')
if [[ ! "$uap_sha" =~ ^[0-9a-fA-F]{40}$ ]]; then
  echo "无法解析 uap-core master 提交 SHA" >&2
  exit 1
fi
GOTOOLCHAIN=local go run ./cmd/proxy-sentinel device-fingerprint build --uap-sha "$uap_sha" --output "$output"
GOTOOLCHAIN=local go run ./cmd/proxy-sentinel device-fingerprint verify --bundle "$output"
echo "离线设备特征包已生成：$output"
