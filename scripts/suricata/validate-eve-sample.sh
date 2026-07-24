#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: validate-eve-sample.sh [options] EVE_JSONL

Options:
  --min-covered-core-types N   Required count among flow,dns,tls,http. Default: 3
  --min-per-type N             Required lines for each covered core type. Default: 10

Validates that a Suricata EVE JSONL sample is useful enough for Sprint 1
adapter fixture work.
EOF
}

min_covered_core_types="3"
min_per_type="10"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --min-covered-core-types)
      min_covered_core_types="${2:-}"
      shift 2
      ;;
    --min-per-type)
      min_per_type="${2:-}"
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

if ! jq -r 'type' "$sample" >/dev/null 2>&1; then
  echo "sample contains malformed JSON lines: $sample" >&2
  exit 1
fi

bad_type_count="$(jq -r 'select(type != "object") | 1' "$sample" | wc -l | tr -d ' ')"
if (( bad_type_count > 0 )); then
  echo "sample contains $bad_type_count non-object JSON lines: $sample" >&2
  exit 1
fi

echo "event type counts:"
jq -r '.event_type // "missing_event_type"' "$sample" | sort | uniq -c

core_types=(flow dns tls http)
covered=0
failed=0

count_type() {
  local event_type="$1"
  jq --arg t "$event_type" -r 'select(.event_type == $t) | 1' "$sample" | wc -l | tr -d ' '
}

for event_type in "${core_types[@]}"; do
  count="$(count_type "$event_type")"
  if (( count > 0 )); then
    covered=$((covered + 1))
    if (( count < min_per_type )); then
      echo "FAIL: $event_type has $count lines, expected at least $min_per_type" >&2
      failed=1
    fi
  fi
done

if (( covered < min_covered_core_types )); then
  echo "FAIL: covered $covered core event types, expected at least $min_covered_core_types among flow,dns,tls,http" >&2
  failed=1
fi

dns_query_count="$(jq -r 'select(.event_type == "dns" and (.dns.rrname? // .dns.query? // "") != "") | 1' "$sample" | wc -l | tr -d ' ')"
tls_fingerprint_count="$(jq -r 'select(.event_type == "tls" and (((.tls.sni? // "") != "") or ((.tls.ja3.hash? // .tls.ja3? // "") != "") or ((.tls.ja4? // "") != ""))) | 1' "$sample" | wc -l | tr -d ' ')"
http_host_ua_count="$(jq -r 'select(.event_type == "http" and (((.http.hostname? // .http.host? // "") != "") or ((.http.http_user_agent? // .http.user_agent? // "") != ""))) | 1' "$sample" | wc -l | tr -d ' ')"

if (( dns_query_count == 0 )); then
  echo "WARN: no DNS query field found" >&2
fi
if (( tls_fingerprint_count == 0 )); then
  echo "WARN: no TLS SNI, JA3 or JA4 field found" >&2
fi
if (( http_host_ua_count == 0 )); then
  echo "WARN: no HTTP Host or User-Agent field found" >&2
fi

if (( failed != 0 )); then
  exit 1
fi

echo "sample accepted for adapter fixture preparation"
