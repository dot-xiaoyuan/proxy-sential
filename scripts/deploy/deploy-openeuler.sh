#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: deploy-openeuler.sh --target user@host --version VERSION --env-file FILE" >&2
}

target=""
version=""
env_file=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) target="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --env-file) env_file="${2:-}"; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done
[[ "$target" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9._:-]+$ ]] || { echo "invalid deployment target" >&2; exit 2; }
[[ "$version" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || { echo "invalid release version" >&2; exit 2; }
remote_env=""
if [[ "$env_file" == remote:* ]]; then
  remote_env="${env_file#remote:}"
  [[ "$remote_env" == /opt/* ]] || { echo "remote environment must be an absolute /opt path" >&2; exit 2; }
else
  [[ -f "$env_file" ]] || { echo "environment file not found: $env_file" >&2; exit 2; }
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/proxy-sentinel-deploy.XXXXXX")"
remote_tmp=""
cleanup() {
  rm -rf "$work_dir"
  if [[ "$remote_tmp" == /tmp/proxy-sentinel-deploy.* ]]; then
    ssh -o BatchMode=yes "$target" "rm -rf '$remote_tmp'" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

archive="$work_dir/proxy-sentinel-$version.tar.gz"
"$repo_root/scripts/deploy/build-release.sh" --version "$version" --output "$archive"

ssh -o BatchMode=yes "$target" 'set -eu; test "$(uname -s)" = Linux; test "$(uname -m)" = x86_64; . /etc/os-release; test "$ID" = openEuler'
remote_tmp="$(ssh -o BatchMode=yes "$target" 'mktemp -d /tmp/proxy-sentinel-deploy.XXXXXX')"
[[ "$remote_tmp" == /tmp/proxy-sentinel-deploy.* ]] || { echo "unsafe remote temporary path" >&2; exit 1; }

admin_secret=""
if ! ssh -o BatchMode=yes "$target" 'docker inspect proxy-sentinel-postgres >/dev/null 2>&1 && docker exec proxy-sentinel-postgres sh -c '\''psql -Atq -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT 1 FROM local_users LIMIT 1"'\'' 2>/dev/null | grep -q 1'; then
  admin_password="${PROXY_SENTINEL_INITIAL_ADMIN_PASSWORD:-}"
  if [[ -z "$admin_password" ]]; then
    [[ -t 0 ]] || { echo "initial administrator password is required; run interactively" >&2; exit 1; }
    read -r -s -p "初始管理员密码（至少 12 位，不会写入日志）: " admin_password
    echo
  fi
  [[ ${#admin_password} -ge 12 ]] || { echo "initial administrator password must contain at least 12 characters" >&2; exit 1; }
  admin_secret="$work_dir/admin-password"
  printf '%s\n' "$admin_password" > "$admin_secret"
  chmod 0600 "$admin_secret"
  unset admin_password PROXY_SENTINEL_INITIAL_ADMIN_PASSWORD
fi

if [[ -n "$remote_env" ]]; then
  ssh -o BatchMode=yes "$target" "test -r '$remote_env'" || { echo "remote environment is not readable: $remote_env" >&2; exit 1; }
  installer_env="$remote_env"
  scp -q "$archive" "$archive.sha256" "$repo_root/scripts/deploy/install-openeuler.sh" "$target:$remote_tmp/"
else
  installer_env="$remote_tmp/$(basename "$env_file")"
  scp -q "$archive" "$archive.sha256" "$env_file" "$repo_root/scripts/deploy/install-openeuler.sh" "$target:$remote_tmp/"
fi
if [[ -n "$admin_secret" ]]; then
  scp -q "$admin_secret" "$target:$remote_tmp/admin-password"
fi
ssh -tt -o BatchMode=yes "$target" "chmod 0700 '$remote_tmp/install-openeuler.sh'; '$remote_tmp/install-openeuler.sh' --version '$version' --archive '$remote_tmp/$(basename "$archive")' --checksum '$remote_tmp/$(basename "$archive").sha256' --env-file '$installer_env' --admin-secret '$remote_tmp/admin-password'"
echo "deployment completed: target=$target version=$version"
