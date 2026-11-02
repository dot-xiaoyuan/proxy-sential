#!/usr/bin/env bash
# Existing-installation application update. Refuses all schema changes.
set -euo pipefail
root="${PROXY_SENTINEL_ROOT:-/opt/proxy-sentinel}"
version=""; archive=""; checksum=""; preserve_inventory=false; defer_discovery_restart=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="${2:-}"; shift 2 ;;
    --archive) archive="${2:-}"; shift 2 ;;
    --checksum) checksum="${2:-}"; shift 2 ;;
    --preserve-inventory) preserve_inventory=true; shift ;;
    --defer-discovery-restart) defer_discovery_restart=true; shift ;;
    *) echo "usage: upgrade-application.sh --version VERSION --archive FILE --checksum FILE [--preserve-inventory] [--defer-discovery-restart]" >&2; exit 2 ;;
  esac
done
[[ "$root" =~ ^/opt/[A-Za-z0-9._/-]+$ && "$root" != *..* ]] || exit 2
[[ "$version" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || exit 2
[[ -r "$archive" && -r "$checksum" && -L "$root/current" ]] || exit 2
for command in python3 flock tar sha256sum systemctl docker curl; do command -v "$command" >/dev/null; done
exec 9>"$root/config/application-upgrade.lock"
flock -n 9 || { echo "another application upgrade is running" >&2; exit 1; }
(cd "$(dirname "$archive")" && sha256sum -c "$(basename "$checksum")")
old_target="$(readlink -f "$root/current")"
[[ "$old_target" == "$root/releases/"* && -d "$old_target" ]] || exit 2
release="$root/releases/$version"
[[ ! -e "$release" ]] || { echo "release already exists: $version" >&2; exit 1; }
stage="$(mktemp -d "$root/releases/.application-stage.XXXXXX")"
frontend_state=""
trap 'rm -rf "$stage"; [[ -z "$frontend_state" ]] || rm -f "$frontend_state"' EXIT
# Validate members and capacity before any archive content reaches the release
# filesystem. Keep headroom for live database writes and rollback metadata.
python3 "$(dirname "$0")/validate-release-archive.py" "$archive" "$root/releases"
tar --no-same-owner -xzf "$archive" -C "$stage"
(cd "$stage" && sha256sum -c SHA256SUMS >/dev/null)
python3 - "$stage/release-manifest.json" "$version" <<'PY'
import json,sys
m=json.load(open(sys.argv[1]))
assert m['version']==sys.argv[2] and m['os']=='linux' and m['arch']=='amd64'
PY
[[ -x "$stage/bin/proxy-sentinel" ]]
python3 "$stage/scripts/verify-service-expectations.py" --root "$root"
python3 "$(dirname "$0")/verify-applied-migrations.py" "$stage"
# Durable release directory is the rollback copy. Business DBs are untouched.
units=()
# An auto-restarting discovery service can briefly fail is-active between
# intent validation and this list. Keep declared running sources in the
# restart set so they cannot resume on the old executable after the switch.
expected_discovery_units="$(python3 - "$root/config/service-expectations.json" <<'PY'
import json,sys
from pathlib import Path
path=Path(sys.argv[1])
expected=json.loads(path.read_text()) if path.exists() else {}
for unit in ('proxy-sentinel-discovery.service','proxy-sentinel-passive-discovery.service'):
    if expected.get(unit)=='running':
        print(unit,end=' ')
PY
)"
for unit in proxy-sentinel-control-plane proxy-sentinel-control-plane-eventbus proxy-sentinel-ingest proxy-sentinel-ingest-stream-dhcp-binding-b56 proxy-sentinel-ingest-stream-dhcp-message-r1 proxy-sentinel-ingest-stream-packet-b54 proxy-sentinel-ingest-stream-handshake-b54 proxy-sentinel-ingest-stream-packet-b76 proxy-sentinel-ingest-stream-handshake-b76 proxy-sentinel-ingest-stream-dhcp-layered-r8 proxy-sentinel-ingest-stream-packet-layered-r7 proxy-sentinel-ingest-stream-handshake-layered-r7 proxy-sentinel-ingest-stream-flow-syn proxy-sentinel-risk-materializer proxy-sentinel-device-signal proxy-sentinel-handshake-signal proxy-sentinel-flow-syn-signal proxy-sentinel-router-prober proxy-sentinel-read-model-realtime proxy-sentinel-read-model-coarse proxy-sentinel-recognition-materializer proxy-sentinel-inventory proxy-sentinel-inventory-backfill proxy-sentinel-identity-materializer proxy-sentinel-ncu-identity-materializer proxy-sentinel-application-materializer proxy-sentinel-discovery proxy-sentinel-passive-discovery proxy-sentinel-ncu-identity-sync; do
  if [[ "$preserve_inventory" == true && "$unit" == proxy-sentinel-inventory ]]; then continue; fi
  if systemctl is-active --quiet "$unit.service" || [[ " $expected_discovery_units " == *" $unit.service "* ]] ||
    { systemctl is-failed --quiet "$unit.service" && systemctl is-enabled --quiet "$unit.service"; }; then
    units+=("$unit.service")
  fi
done
if [[ "$preserve_inventory" == true ]] && ! systemctl is-active --quiet proxy-sentinel-inventory.service; then
  echo "preserved inventory service is not active" >&2
  exit 1
fi
(( ${#units[@]} > 0 )) || { echo "no active application services" >&2; exit 1; }
python3 "$(dirname "$0")/verify-application-cli.py" --stage "$stage" --units "${units[@]}"
deferred_unit=proxy-sentinel-discovery.service
old_discovery_pid=""
deferred_started_new=false
pointer_switched=false
if [[ "$defer_discovery_restart" == true ]]; then
  [[ " ${units[*]} " == *" $deferred_unit "* ]] || { echo "deferred discovery service is not in the active release" >&2; exit 1; }
  systemctl is-active --quiet "$deferred_unit" || { echo "deferred discovery service is not active" >&2; exit 1; }
  [[ "$(systemctl show "$deferred_unit" -p Restart --value)" == on-failure ]] || { echo "deferred discovery service does not auto-restart on failure" >&2; exit 1; }
  old_discovery_pid="$(systemctl show "$deferred_unit" -p MainPID --value)"
  [[ "$old_discovery_pid" =~ ^[1-9][0-9]*$ && "$(readlink -f "/proc/$old_discovery_pid/exe")" == "$old_target/bin/discovery-worker" ]] || {
    echo "deferred discovery process does not run the old release" >&2; exit 1;
  }
fi
mv "$stage" "$release"
restart_workers() {
  local failed=0
  for unit in "${units[@]}"; do
    if [[ "$defer_discovery_restart" == true && "$unit" == "$deferred_unit" ]]; then continue; fi
    if ! systemctl restart "$unit"; then failed=1; fi
  done
  return "$failed"
}
wait_deferred_discovery() {
  [[ "$defer_discovery_restart" == true ]] || return 0
  local pid exe unexpected_pid="" unexpected_count=0
  for _ in $(seq 1 540); do
    pid="$(systemctl show "$deferred_unit" -p MainPID --value)"
    if [[ "$pid" =~ ^[1-9][0-9]*$ && "$pid" != "$old_discovery_pid" ]]; then
      exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
      if [[ "$exe" == "$release/bin/discovery-worker" ]]; then
        deferred_started_new=true
        return 0
      fi
      if [[ "$exe" == "$old_target/bin/discovery-worker" ]]; then
        # A restart can race with the atomic current switch. Let this old
        # process drain naturally too, then verify the next start.
        old_discovery_pid="$pid"
        unexpected_pid=""
        unexpected_count=0
      else
        # systemd reports MainPID before exec; /proc briefly still points at
        # systemd. Recheck the same PID before treating it as an invalid start.
        if [[ "$pid" == "$unexpected_pid" ]]; then
          unexpected_count=$((unexpected_count + 1))
        else
          unexpected_pid="$pid"
          unexpected_count=1
        fi
        if (( unexpected_count >= 3 )); then
          deferred_started_new=true
          echo "deferred discovery restarted with unexpected executable: $exe" >&2
          return 1
        fi
      fi
    fi
    sleep 5
  done
  echo "deferred discovery did not naturally restart into $release within 45 minutes" >&2
  return 1
}
ready() {
  for _ in $(seq 1 30); do
    if curl -fsS --max-time 5 "${PROXY_SENTINEL_HEALTH_URL:-http://127.0.0.1:18080/readyz}" >/dev/null; then
      for unit in "${units[@]}"; do systemctl is-active --quiet "$unit" || return 1; done
      if python3 "$(dirname "$0")/verify-application-runtime.py" --root "$root" --release "$(readlink -f "$root/current")" --units "${units[@]}"; then
        # Type=simple may report active before a reader exits on startup.
        sleep 5
        for unit in "${units[@]}"; do systemctl is-active --quiet "$unit" || return 1; done
        if curl -fsS --max-time 5 "${PROXY_SENTINEL_HEALTH_URL:-http://127.0.0.1:18080/readyz}" >/dev/null &&
          python3 "$(dirname "$0")/verify-application-runtime.py" --root "$root" --release "$(readlink -f "$root/current")" --units "${units[@]}"; then
          return 0
        fi
      fi
    fi
    sleep 2
  done
  return 1
}
rollback() {
  local result=$?
  trap - ERR
  if [[ "$pointer_switched" != true ]]; then
    if [[ -n "$frontend_state" && -s "$frontend_state" ]]; then
      python3 "$(dirname "$0")/manage-frontend-previous.py" restore --root "$root" --state "$frontend_state" || {
        echo "frontend rollback failed; state retained: $frontend_state" >&2
        frontend_state=""
      }
    fi
    echo "application upgrade aborted before changing current" >&2
    exit "$result"
  fi
  if [[ "$defer_discovery_restart" == true && "$deferred_started_new" != true ]]; then
    local pid exe
    pid="$(systemctl show "$deferred_unit" -p MainPID --value 2>/dev/null || true)"
    if [[ "$pid" =~ ^[1-9][0-9]*$ && "$pid" != "$old_discovery_pid" ]]; then
      exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
      [[ "$exe" == "$old_target/bin/discovery-worker" ]] || deferred_started_new=true
    fi
  fi
  if [[ "$deferred_started_new" == true ]]; then
    ln -sfn "$old_target" "$root/previous.next"
    mv -Tf "$root/previous.next" "$root/previous"
    echo "application upgrade incomplete: candidate remains current and old release is previous; discovery left its old process, so automatic rollback could interrupt its in-memory capture queue" >&2
    exit "$result"
  fi
  ln -sfn "$old_target" "$root/current.next"
  mv -Tf "$root/current.next" "$root/current"
  if [[ -n "$frontend_state" && -s "$frontend_state" ]]; then
    python3 "$(dirname "$0")/manage-frontend-previous.py" restore --root "$root" --state "$frontend_state" || { echo "frontend rollback failed; state retained: $frontend_state" >&2; frontend_state=""; }
  fi
  local rollback_failed=false
  restart_workers || rollback_failed=true
  ready || rollback_failed=true
  if [[ "$rollback_failed" == true ]]; then
    echo "application upgrade failed; pointer restored to $old_target but rollback runtime verification failed" >&2
  else
    echo "application upgrade failed; restored $old_target and verified application processes" >&2
  fi
  exit "$result"
}
trap rollback ERR
frontend_state="$(mktemp "$root/config/frontend-upgrade-state.XXXXXX")"
python3 "$(dirname "$0")/manage-frontend-previous.py" prepare --root "$root" --candidate "$release" --state "$frontend_state"
if [[ "$defer_discovery_restart" == true ]]; then
  current_pid="$(systemctl show "$deferred_unit" -p MainPID --value)"
  [[ "$current_pid" == "$old_discovery_pid" && "$(readlink -f "/proc/$current_pid/exe")" == "$old_target/bin/discovery-worker" ]] || {
    echo "deferred discovery restarted before pointer switch; retry this upgrade after checking its queue" >&2
    false
  }
fi
ln -sfn "$release" "$root/current.next"
mv -Tf "$root/current.next" "$root/current"
pointer_switched=true
restart_workers
wait_deferred_discovery
ready
if [[ "$preserve_inventory" == true ]]; then systemctl is-active --quiet proxy-sentinel-inventory.service; fi
python3 "$release/scripts/verify-service-expectations.py" --root "$root"
ln -sfn "$old_target" "$root/previous.next"
mv -Tf "$root/previous.next" "$root/previous"
trap - ERR
cat > "$release/deployment-manifest.json" <<JSON
{"version":"$version","mode":"application_only","previous":"$old_target","preserve_inventory":$preserve_inventory,"installed_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
JSON
echo "application upgrade completed: $version; previous=$old_target"
