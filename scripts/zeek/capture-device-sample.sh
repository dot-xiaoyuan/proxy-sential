#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
suricata_script_dir="$(cd "$script_dir/../suricata" && pwd)"

usage() {
  cat <<'EOF'
Usage: capture-device-sample.sh [options]

Options:
  --interface IFACE      Mirror interface. Use "auto" to detect. Default: auto
  --duration SECONDS     Zeek capture duration. Default: 1800
  --out-dir DIR          Sample output parent directory. Default: /tmp/proxy-sentinel

Runs Zeek on the mirror interface and writes dhcp.log under an isolated run
directory. It does not stop or alter systemd Zeek or Suricata services.
EOF
}

iface="auto"
duration="1800"
out_dir="/tmp/proxy-sentinel"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --interface)
      iface="${2:-}"
      shift 2
      ;;
    --duration)
      duration="${2:-}"
      shift 2
      ;;
    --out-dir)
      out_dir="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

need_cmd ip
need_cmd zeek
need_cmd timeout

if [[ "$(id -u)" -ne 0 ]]; then
  echo "capture requires root privileges for Zeek live capture" >&2
  exit 1
fi

if [[ "$iface" == "auto" ]]; then
  iface="$("$suricata_script_dir/select-mirror-if.sh")"
fi

if [[ ! -d "/sys/class/net/$iface" ]]; then
  echo "interface not found: $iface" >&2
  exit 1
fi

timestamp="$(date +%Y%m%d-%H%M%S)"
run_dir="$out_dir/zeek-device-$timestamp"
mkdir -p "$run_dir"

echo "zeek device capture"
echo "  interface: $iface"
echo "  duration: ${duration}s"
echo "  run_dir: $run_dir"

set +e
(
  cd "$run_dir"
  timeout --foreground "$duration" zeek -i "$iface" policy/protocols/dhcp/software.zeek > zeek-run.log 2>&1
)
status=$?
set -e

if [[ "$status" -ne 0 && "$status" -ne 124 ]]; then
  echo "zeek capture failed with status $status" >&2
  tail -80 "$run_dir/zeek-run.log" >&2 || true
  exit "$status"
fi

dhcp="$run_dir/dhcp.log"
if [[ ! -s "$dhcp" ]]; then
  echo "dhcp.log output not found or empty: $dhcp" >&2
  echo "check whether the mirror interface sees DHCP broadcast traffic" >&2
  exit 1
fi

cp "$dhcp" "$out_dir/zeek-dhcp-$timestamp.log"

echo "capture complete"
echo "  dhcp: $dhcp"
echo "  exported: $out_dir/zeek-dhcp-$timestamp.log"
echo "  validate: scripts/zeek/validate-dhcp-sample.sh $dhcp"
