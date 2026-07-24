#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage: capture-mirror-sample.sh [options]

Options:
  --interface IFACE      Mirror interface. Use "auto" to detect. Default: auto
  --duration SECONDS     Suricata capture duration. Default: 1800
  --out-dir DIR          Sample output parent directory. Default: /tmp/proxy-sentinel
  --config FILE          Suricata config. Default: /etc/suricata/suricata.yaml
  --tcpdump-count N      Packets for mirror-port smoke test. Default: 100
  --tcpdump-timeout N    Seconds before tcpdump smoke test fails. Default: 60

The script runs Suricata in the foreground through timeout and writes an
isolated log directory under --out-dir. It does not stop or alter systemd
Suricata services.
EOF
}

iface="auto"
duration="1800"
out_dir="/tmp/proxy-sentinel"
config="/etc/suricata/suricata.yaml"
tcpdump_count="100"
tcpdump_timeout="60"

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
    --config)
      config="${2:-}"
      shift 2
      ;;
    --tcpdump-count)
      tcpdump_count="${2:-}"
      shift 2
      ;;
    --tcpdump-timeout)
      tcpdump_timeout="${2:-}"
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
need_cmd jq
need_cmd suricata
need_cmd tcpdump
need_cmd timeout

if [[ "$(id -u)" -ne 0 ]]; then
  echo "capture requires root privileges for tcpdump and Suricata" >&2
  exit 1
fi

if [[ ! -r "$config" ]]; then
  echo "suricata config not readable: $config" >&2
  exit 1
fi

if [[ "$iface" == "auto" ]]; then
  iface="$("$script_dir/select-mirror-if.sh")"
fi

if [[ ! -d "/sys/class/net/$iface" ]]; then
  echo "interface not found: $iface" >&2
  exit 1
fi

timestamp="$(date +%Y%m%d-%H%M%S)"
run_dir="$out_dir/mirror-$timestamp"
mkdir -p "$run_dir"

echo "testbed capture"
echo "  interface: $iface"
echo "  duration: ${duration}s"
echo "  run_dir: $run_dir"
echo "  config: $config"

echo "checking disk space for $out_dir"
df -h "$out_dir" | tee "$run_dir/disk-before.txt"

echo "running tcpdump smoke test"
if ! timeout "$tcpdump_timeout" tcpdump -i "$iface" -nn -c "$tcpdump_count" -w "$run_dir/tcpdump-smoke.pcap" 'ip or ip6'; then
  echo "tcpdump did not capture $tcpdump_count packets within ${tcpdump_timeout}s" >&2
  echo "check mirror-port wiring or choose the correct interface" >&2
  exit 1
fi

tcpdump -nn -r "$run_dir/tcpdump-smoke.pcap" -c 20 > "$run_dir/tcpdump-smoke.txt" 2>&1 || true

echo "validating Suricata config"
suricata -T -c "$config" -l "$run_dir" > "$run_dir/suricata-config-test.log" 2>&1

echo "starting Suricata capture"
set +e
timeout --foreground "$duration" suricata -c "$config" -i "$iface" -l "$run_dir" > "$run_dir/suricata-run.log" 2>&1
status=$?
set -e

if [[ "$status" -ne 0 && "$status" -ne 124 ]]; then
  echo "suricata capture failed with status $status" >&2
  tail -80 "$run_dir/suricata-run.log" >&2 || true
  exit "$status"
fi

eve="$run_dir/eve.json"
if [[ ! -s "$eve" ]]; then
  echo "EVE output not found or empty: $eve" >&2
  echo "Suricata may be configured without eve-log output; inspect $run_dir/suricata-run.log" >&2
  exit 1
fi

cp "$eve" "$out_dir/eve-mirror-$timestamp.jsonl"

echo "event type counts"
jq -r 'select(type == "object") | .event_type // "missing_event_type"' "$eve" \
  | sort | uniq -c | tee "$run_dir/event-type-counts.txt"

echo "capture complete"
echo "  eve: $eve"
echo "  exported: $out_dir/eve-mirror-$timestamp.jsonl"
echo "  validate: scripts/suricata/validate-eve-sample.sh $eve"
