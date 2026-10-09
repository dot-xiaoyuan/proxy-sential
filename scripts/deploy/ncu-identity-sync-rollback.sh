#!/usr/bin/env bash
set -euo pipefail

root=/opt/proxy-sentinel
env_file="$root/config/ncu-identity-sync.env"
password_file="$root/secrets/ncu-event-redis.password"
source_list=list:antiproxy:127.0.0.1

[[ -r "$env_file" ]] || { echo "missing $env_file" >&2; exit 1; }
[[ -r "$password_file" ]] || { echo "missing $password_file" >&2; exit 1; }
# shellcheck disable=SC1090
source "$env_file"
[[ -n "${NCU_EVENT_REDIS_ADDR:-}" ]] || { echo "NCU_EVENT_REDIS_ADDR is required" >&2; exit 1; }

systemctl stop proxy-sentinel-ncu-identity-sync.service
"$root/current/bin/legacy-4k-identity-bridge" \
  --event-redis-addr="$NCU_EVENT_REDIS_ADDR" \
  --event-redis-password-file="$password_file" \
  --event-list="$source_list" \
  --restore-processing

if [[ -L "$root/previous" ]]; then
  ln -sfn "$(readlink "$root/previous")" "$root/current"
fi
systemctl start dpi-capture.service
systemctl is-active --quiet dpi-capture.service
echo "NCU identity synchronization rolled back; processing messages restored before source queue"
