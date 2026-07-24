#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: prepare-testbed.sh

Prepare a Debian/Ubuntu Suricata mirror-traffic testbed for Proxy Sentinel.

Installs:
  suricata jq tcpdump iproute2 coreutils python3

This script does not rewrite /etc/suricata/suricata.yaml. Capture is performed
by capture-mirror-sample.sh with an isolated log directory.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ ! -r /etc/os-release ]]; then
  echo "/etc/os-release not found; cannot determine Linux distribution" >&2
  exit 1
fi

# shellcheck disable=SC1091
. /etc/os-release

case "${ID_LIKE:-$ID}" in
  *debian*|*ubuntu*)
    ;;
  *)
    echo "unsupported distribution: ${PRETTY_NAME:-unknown}" >&2
    echo "install suricata, jq, tcpdump, iproute2, coreutils and python3 manually, then run capture-mirror-sample.sh" >&2
    exit 1
    ;;
esac

if [[ "$(id -u)" -ne 0 ]]; then
  if ! command -v sudo >/dev/null 2>&1; then
    echo "please run as root, or install sudo" >&2
    exit 1
  fi
  sudo apt-get update
  sudo apt-get install -y suricata jq tcpdump iproute2 coreutils python3
  sudo mkdir -p /tmp/proxy-sentinel
  sudo chmod 1777 /tmp/proxy-sentinel
else
  apt-get update
  apt-get install -y suricata jq tcpdump iproute2 coreutils python3
  mkdir -p /tmp/proxy-sentinel
  chmod 1777 /tmp/proxy-sentinel
fi

echo "installed versions:"
suricata --build-info | sed -n '1,8p'
jq --version
tcpdump --version | sed -n '1p'

echo
echo "next steps:"
echo "  1. scripts/suricata/select-mirror-if.sh"
echo "  2. sudo scripts/suricata/capture-mirror-sample.sh --interface auto --duration 1800"
echo "  3. scripts/suricata/validate-eve-sample.sh /tmp/proxy-sentinel/<run>/eve.json"
