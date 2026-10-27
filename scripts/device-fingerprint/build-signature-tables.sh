#!/usr/bin/env bash
# Regenerate the embedded signature tables that are derived from public registries.
#
# Only the SNMP enterprise-number table is downloaded here; the model catalogue
# and the device-type prior are curated by hand and must be edited directly.
# The generated file is committed so that runtime and tests never reach the
# network.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${ROOT}/internal/fingerprint/data/snmp-enterprise-oid.json"
URL="https://www.iana.org/assignments/enterprise-numbers.txt"
SOURCE_URL="${URL}"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

echo ">> downloading IANA private enterprise numbers"
curl -fsSL --max-time 180 -o "${tmp}/pen.txt" "${URL}"

updated="(last updated 2026-10-26)"
if ! grep -q "last updated" "${tmp}/pen.txt"; then
  echo "ERROR: unexpected IANA payload, refusing to rewrite the table" >&2
  exit 1
fi
updated="$(grep -m1 "last updated" "${tmp}/pen.txt" | sed 's/.*last updated //; s/)//')"

python3 - "${tmp}/pen.txt" "${OUT}" "${updated}" "${SOURCE_URL}" <<'PY'
import json
import re
import sys

source, output, updated, url = sys.argv[1:5]
lines = open(source, encoding="utf-8", errors="replace").read().splitlines()
entries, current = {}, None
for line in lines:
    if not line.strip():
        continue
    if re.fullmatch(r"\d+", line.strip()) and not line.startswith(" "):
        current = line.strip()
        continue
    if current and line.startswith("  ") and not line.startswith("    "):
        org = re.sub(r"\s+", " ", line.strip())
        org = re.sub(r"\s*\((?:https?://|www\.)[^)]*\)\s*", "", org).strip()
        if org:
            entries.setdefault(current, org)
        current = None

if len(entries) < 40000:
    raise SystemExit(f"refusing to write a truncated table: {len(entries)} entries")

doc = {
    "version": f"iana-pen-{updated}",
    "source": "IANA Private Enterprise Numbers",
    "source_url": url,
    "prefix": "1.3.6.1.4.1",
    "license": "public-registry",
    "entries": dict(sorted(entries.items(), key=lambda kv: int(kv[0]))),
}
with open(output, "w", encoding="utf-8") as handle:
    json.dump(doc, handle, ensure_ascii=False, separators=(",", ":"))
print(f"wrote {output}: {len(entries)} entries, version iana-pen-{updated}")
PY

echo ">> done; run: go test ./internal/fingerprint/ -run TestSNMP"
