#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <user@host> <bundle.tar.gz>" >&2
  exit 2
fi

target=$1
bundle=$2
admin_user=${PROXY_SENTINEL_ADMIN_USER:-admin}
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
stamp=$(date +%Y%m%d%H%M%S)
remote_bundle="/tmp/proxy-sentinel-device-fingerprint-$stamp.tar.gz"

if [[ -z ${PROXY_SENTINEL_ADMIN_PASSWORD:-} ]]; then
  read -r -s -p "Proxy Sentinel 管理员密码: " PROXY_SENTINEL_ADMIN_PASSWORD
  echo >&2
fi
login_payload=$(printf '%s\0%s' "$admin_user" "$PROXY_SENTINEL_ADMIN_PASSWORD" | python3 -c 'import json,sys; user,password=sys.stdin.buffer.read().split(b"\0",1); print(json.dumps({"username":user.decode(),"password":password.decode()}))')
unset PROXY_SENTINEL_ADMIN_PASSWORD

cd "$repo_root"
GOTOOLCHAIN=local go run ./cmd/proxy-sentinel device-fingerprint verify --bundle "$bundle" >/dev/null
scp "$bundle" "$target:$remote_bundle"
printf '%s\n' "$login_payload" | ssh "$target" "
  set -euo pipefail
  cookie_file=\$(mktemp)
  response_file=\$(mktemp)
  trap 'rm -f \"\$cookie_file\" \"\$response_file\" \"$remote_bundle\"' EXIT
  IFS= read -r login_payload
  printf '%s' \"\$login_payload\" | curl --fail --silent --show-error -c \"\$cookie_file\" -H 'Content-Type: application/json' --data-binary @- http://127.0.0.1:18080/api/v1/auth/login >\"\$response_file\"
  csrf=\$(sed -n 's/.*\"csrf_token\":\"\([^\"]*\)\".*/\1/p' \"\$response_file\")
  test -n \"\$csrf\"
  curl --fail --silent --show-error -b \"\$cookie_file\" -H \"X-CSRF-Token: \$csrf\" -F bundle=@$remote_bundle http://127.0.0.1:18080/api/v1/device-fingerprint-library/import
  curl --fail --silent --show-error -b \"\$cookie_file\" http://127.0.0.1:18080/api/v1/device-fingerprint-library
"
