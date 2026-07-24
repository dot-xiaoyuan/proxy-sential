#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: prepare-testbed.sh

Prepare a Debian/Ubuntu or openEuler Suricata mirror-traffic testbed for
Proxy Sentinel.

Installs:
  suricata jq tcpdump iproute2 coreutils python3

On openEuler, the iproute2 package is named iproute. Suricata must be
available from a configured DNF repository or already installed.

This script does not rewrite /etc/suricata/suricata.yaml. Capture is performed
by capture-mirror-sample.sh with an isolated log directory.
EOF
}

detect_distribution() {
  local os_release_file="${PROXY_SENTINEL_OS_RELEASE_FILE:-/etc/os-release}"
  local distribution

  if [[ ! -r "$os_release_file" ]]; then
    echo "$os_release_file not found; cannot determine Linux distribution" >&2
    return 1
  fi

  ID=
  ID_LIKE=
  PRETTY_NAME=
  # shellcheck disable=SC1090
  . "$os_release_file"
  distribution="$(printf ' %s %s ' "${ID:-}" "${ID_LIKE:-}" | tr '[:upper:]' '[:lower:]')"

  case "$distribution" in
    *" debian "*|*" ubuntu "*)
      package_manager="apt"
      ;;
    *" openeuler "*)
      package_manager="dnf"
      ;;
    *)
      echo "unsupported distribution: ${PRETTY_NAME:-unknown}" >&2
      echo "install suricata, jq, tcpdump, iproute2, coreutils and python3 manually, then run capture-mirror-sample.sh" >&2
      return 1
      ;;
  esac
}

install_packages() {
  local -a privilege=(command)

  if [[ "$(id -u)" -ne 0 ]]; then
    if ! command -v sudo >/dev/null 2>&1; then
      echo "please run as root, or install sudo" >&2
      return 1
    fi
    privilege=(sudo)
  fi

  case "$package_manager" in
    apt)
      "${privilege[@]}" apt-get update
      "${privilege[@]}" apt-get install -y suricata jq tcpdump iproute2 coreutils python3
      ;;
    dnf)
      if ! command -v dnf >/dev/null 2>&1; then
        echo "dnf is required on openEuler" >&2
        return 1
      fi
      "${privilege[@]}" dnf makecache
      "${privilege[@]}" dnf install -y jq tcpdump iproute coreutils python3
      if ! command -v suricata >/dev/null 2>&1 \
        && ! "${privilege[@]}" dnf install -y suricata; then
        cat >&2 <<'EOF'
Suricata is not available from the configured openEuler DNF repositories.
Install Suricata from a trusted repository or from source, then rerun this
script. For openEuler 22.03, this repository provides a source install helper:
  sudo scripts/suricata/install-suricata-source-openeuler.sh

Official source installation instructions:
  https://docs.suricata.io/en/latest/install.html
EOF
        return 1
      fi
      ;;
    *)
      echo "internal error: unknown package manager $package_manager" >&2
      return 1
      ;;
  esac

  "${privilege[@]}" mkdir -p /tmp/proxy-sentinel
  "${privilege[@]}" chmod 1777 /tmp/proxy-sentinel
}

main() {
  case "${1:-}" in
    -h|--help)
      usage
      return 0
      ;;
    "")
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      return 2
      ;;
  esac

  detect_distribution
  install_packages

  echo "installed versions:"
  suricata --build-info | sed -n '1,8p'
  jq --version
  tcpdump --version | sed -n '1p'

  echo
  echo "next steps:"
  echo "  1. scripts/suricata/select-mirror-if.sh"
  echo "  2. sudo scripts/suricata/capture-mirror-sample.sh --interface auto --duration 1800"
  echo "  3. scripts/suricata/validate-eve-sample.sh /tmp/proxy-sentinel/<run>/eve.json"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
