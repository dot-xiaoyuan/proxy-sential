#!/usr/bin/env bash
set -euo pipefail

script="${1:-$(dirname "$0")/upgrade-application.sh}"
defer_discovery_restart=false
units=(proxy-sentinel-control-plane-eventbus.service proxy-sentinel-ingest-stream-packet-layered-r7.service)
systemctl() {
  case "$1:${*: -1}" in
    is-active:proxy-sentinel-control-plane-eventbus.service) return 0 ;;
    is-active:proxy-sentinel-ingest-stream-packet-layered-r7.service) return 3 ;;
    is-failed:proxy-sentinel-ingest-stream-packet-layered-r7.service) return 0 ;;
    is-enabled:proxy-sentinel-ingest-stream-packet-layered-r7.service) return 0 ;;
    *) return 1 ;;
  esac
}

# The failed but enabled reader must be restarted after switching. Only a
# running process can participate in the old-release executable preflight.
eval "$(sed -n '/^preflight_units=()/,/^done/p' "$script")"
if [[ "${preflight_units[*]}" != proxy-sentinel-control-plane-eventbus.service ]]; then
  echo "old-process preflight includes a failed source reader: ${preflight_units[*]}" >&2
  exit 1
fi
if [[ "${units[*]}" != *proxy-sentinel-ingest-stream-packet-layered-r7.service* ]]; then
  echo 'failed source reader was dropped from the restart set' >&2
  exit 1
fi
echo 'failed source reader retained for restart and omitted from old-process preflight'
