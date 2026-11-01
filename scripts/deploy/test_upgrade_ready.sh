#!/usr/bin/env bash
set -euo pipefail

script="${1:-$(dirname "$0")/upgrade-application.sh}"
units=(proxy-sentinel-ingest-stream-handshake-layered-r7.service)
root=/opt/fixture
failed=false
late_fail=false
systemctl() { [[ "$1" != is-active || "$failed" == false ]]; }
curl() { return 0; }
python3() { return 0; }
readlink() { echo /opt/fixture/releases/r43; }
seq() { echo 1; }
sleep() { if [[ "$1" == 5 && "$late_fail" == true ]]; then failed=true; fi; }
eval "$(sed -n '/^ready() {/,/^}/p' "$script")"

ready || { echo 'stable service was rejected' >&2; exit 1; }
late_fail=true
if ready; then
  echo 'service that exited after initial Type=simple activation was accepted' >&2
  exit 1
fi
