#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: validate-dhcp-sample.sh [options] DHCP_LOG

Options:
  --min-lines N          Required DHCP data rows. Default: 1

Validates that a Zeek dhcp.log sample is useful enough for device fingerprint
adapter fixture work.
EOF
}

min_lines="1"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --min-lines)
      min_lines="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      if [[ -n "${sample:-}" ]]; then
        echo "unexpected argument: $1" >&2
        exit 2
      fi
      sample="$1"
      shift
      ;;
  esac
done

if [[ -z "${sample:-}" ]]; then
  usage >&2
  exit 2
fi

if [[ ! -s "$sample" ]]; then
  echo "sample not found or empty: $sample" >&2
  exit 1
fi

first_payload="$(awk 'NF && $1 !~ /^#/ { print substr($0, 1, 1); exit }' "$sample")"

if [[ "$first_payload" == "{" ]]; then
  if ! jq -r 'type' "$sample" >/dev/null 2>&1; then
    echo "sample contains malformed JSON lines: $sample" >&2
    exit 1
  fi
  line_count="$(jq -r 'select(type == "object") | 1' "$sample" | wc -l | tr -d ' ')"
  client_count="$(jq -r 'select((.assigned_addr? // .requested_addr? // .client_addr? // "") != "") | 1' "$sample" | wc -l | tr -d ' ')"
  mac_count="$(jq -r 'select((.mac? // .client_mac? // .client_chaddr? // "") != "") | 1' "$sample" | wc -l | tr -d ' ')"
  hostname_count="$(jq -r 'select((.host_name? // .hostname? // .client_fqdn? // "") != "") | 1' "$sample" | wc -l | tr -d ' ')"
  vendor_count="$(jq -r 'select((.client_software? // .vendor_class? // "") != "") | 1' "$sample" | wc -l | tr -d ' ')"
else
  line_count="$(awk 'NF && $1 !~ /^#/ { count++ } END { print count + 0 }' "$sample")"
  fields_line="$(awk '/^#fields[ \t]/ { sub(/^#fields[ \t]+/, ""); print; exit }' "$sample")"
  if [[ -z "$fields_line" ]]; then
    echo "missing Zeek #fields directive; cannot validate TSV log" >&2
    exit 1
  fi
  client_count="$(awk -v fields="$fields_line" '
    BEGIN {
      split(fields, names, "\t")
      for (i in names) {
        if (names[i] == "assigned_addr") assigned=i
        if (names[i] == "requested_addr") requested=i
        if (names[i] == "client_addr") client=i
      }
    }
    NF && $1 !~ /^#/ {
      if ((assigned && $assigned != "-") || (requested && $requested != "-") || (client && $client != "-")) count++
    }
    END { print count + 0 }
  ' "$sample")"
  mac_count="$(awk -v fields="$fields_line" '
    BEGIN {
      split(fields, names, "\t")
      for (i in names) {
        if (names[i] == "mac") mac=i
        if (names[i] == "client_mac") client_mac=i
        if (names[i] == "client_chaddr") chaddr=i
      }
    }
    NF && $1 !~ /^#/ {
      if ((mac && $mac != "-") || (client_mac && $client_mac != "-") || (chaddr && $chaddr != "-")) count++
    }
    END { print count + 0 }
  ' "$sample")"
  hostname_count="$(awk -v fields="$fields_line" '
    BEGIN {
      split(fields, names, "\t")
      for (i in names) {
        if (names[i] == "host_name") host=i
        if (names[i] == "hostname") hostname=i
        if (names[i] == "client_fqdn") fqdn=i
      }
    }
    NF && $1 !~ /^#/ {
      if ((host && $host != "-") || (hostname && $hostname != "-") || (fqdn && $fqdn != "-")) count++
    }
    END { print count + 0 }
  ' "$sample")"
  vendor_count="$(awk -v fields="$fields_line" '
    BEGIN {
      split(fields, names, "\t")
      for (i in names) {
        if (names[i] == "client_software") software=i
        if (names[i] == "vendor_class") vendor=i
      }
    }
    NF && $1 !~ /^#/ {
      if ((software && $software != "-") || (vendor && $vendor != "-")) count++
    }
    END { print count + 0 }
  ' "$sample")"
fi

echo "dhcp data rows: $line_count"
echo "rows with client address: $client_count"
echo "rows with client mac: $mac_count"
echo "rows with hostname/fqdn: $hostname_count"
echo "rows with vendor class/software: $vendor_count"

failed=0
if (( line_count < min_lines )); then
  echo "FAIL: dhcp.log has $line_count data rows, expected at least $min_lines" >&2
  failed=1
fi
if (( client_count == 0 )); then
  echo "FAIL: no DHCP client address fields found" >&2
  failed=1
fi
if (( mac_count == 0 )); then
  echo "WARN: no DHCP client MAC fields found" >&2
fi
if (( hostname_count == 0 && vendor_count == 0 )); then
  echo "FAIL: no hostname/fqdn or vendor class fields found" >&2
  failed=1
fi

if (( failed != 0 )); then
  exit 1
fi

echo "dhcp sample accepted for Zeek device adapter fixture preparation"
