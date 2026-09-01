#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <user@host> <bundle.tar.gz>" >&2
  exit 2
fi

target=$1
bundle=$2
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
stamp=$(date +%Y%m%d%H%M%S)
remote_bundle="/tmp/proxy-sentinel-device-fingerprint-$stamp.tar.gz"

cd "$repo_root"
GOTOOLCHAIN=local go run ./cmd/proxy-sentinel device-fingerprint verify --bundle "$bundle" >/dev/null
scp "$bundle" "$target:$remote_bundle"
ssh "$target" "trap 'rm -f $remote_bundle' EXIT; curl --fail --silent --show-error -F bundle=@$remote_bundle http://127.0.0.1:18080/api/v1/device-fingerprint-library/import"
ssh "$target" "curl --fail --silent --show-error http://127.0.0.1:18080/api/v1/device-fingerprint-library"
