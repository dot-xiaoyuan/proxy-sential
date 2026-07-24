#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: select-mirror-if.sh [--prefer IFACE] [--sample-seconds N]

Select a likely mirror interface for the Proxy Sentinel Suricata testbed.

Rules:
  1. Prefer the configured interface when it exists and is not loopback.
  2. Otherwise skip the default-route interface.
  3. Pick the non-default interface whose RX bytes increase the most.

The selected interface is printed to stdout. Diagnostics are printed to stderr.
EOF
}

prefer_if="eth1"
sample_seconds="3"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefer)
      prefer_if="${2:-}"
      shift 2
      ;;
    --sample-seconds)
      sample_seconds="${2:-}"
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

if [[ -z "$prefer_if" || -z "$sample_seconds" ]]; then
  echo "missing argument value" >&2
  exit 2
fi

if [[ -d "/sys/class/net/$prefer_if" && "$prefer_if" != "lo" ]]; then
  echo "selected preferred interface: $prefer_if" >&2
  printf '%s\n' "$prefer_if"
  exit 0
fi

default_if="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"

rx_bytes() {
  local iface="$1"
  cat "/sys/class/net/$iface/statistics/rx_bytes"
}

best_if=""
best_delta="-1"

for path in /sys/class/net/*; do
  iface="$(basename "$path")"
  case "$iface" in
    lo|docker*|br-*|veth*|virbr*|tun*|tap*)
      continue
      ;;
  esac
  if [[ "$iface" == "$default_if" ]]; then
    continue
  fi

  before="$(rx_bytes "$iface")"
  sleep "$sample_seconds"
  after="$(rx_bytes "$iface")"
  delta=$((after - before))

  echo "candidate interface $iface rx_delta_bytes=$delta" >&2
  if (( delta > best_delta )); then
    best_if="$iface"
    best_delta="$delta"
  fi
done

if [[ -z "$best_if" ]]; then
  echo "no non-default mirror interface candidate found" >&2
  exit 1
fi

if (( best_delta <= 0 )); then
  echo "selected $best_if, but RX bytes did not increase during sampling" >&2
else
  echo "selected interface: $best_if rx_delta_bytes=$best_delta" >&2
fi

printf '%s\n' "$best_if"
