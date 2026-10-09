#!/usr/bin/env bash
# Existing-installation application update. Refuses all schema changes.
set -euo pipefail
root="${PROXY_SENTINEL_ROOT:-/opt/proxy-sentinel}"
version=""; archive=""; checksum=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="${2:-}"; shift 2 ;;
    --archive) archive="${2:-}"; shift 2 ;;
    --checksum) checksum="${2:-}"; shift 2 ;;
    *) echo "usage: upgrade-application.sh --version VERSION --archive FILE --checksum FILE" >&2; exit 2 ;;
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
python3 "$(dirname "$0")/verify-applied-migrations.py" "$stage"
# Durable release directory is the rollback copy. Business DBs are untouched.
units=()
for unit in proxy-sentinel-control-plane proxy-sentinel-ingest proxy-sentinel-risk-materializer proxy-sentinel-device-signal proxy-sentinel-read-model-realtime proxy-sentinel-read-model-coarse proxy-sentinel-recognition-materializer proxy-sentinel-identity-materializer proxy-sentinel-ncu-identity-materializer proxy-sentinel-application-materializer proxy-sentinel-discovery proxy-sentinel-ncu-identity-sync; do
  if systemctl is-active --quiet "$unit.service"; then units+=("$unit.service"); fi
done
(( ${#units[@]} > 0 )) || { echo "no active application services" >&2; exit 1; }
mv "$stage" "$release"
restart_workers() {
  local failed=0
  for unit in "${units[@]}"; do
    if ! systemctl restart "$unit"; then failed=1; fi
  done
  return "$failed"
}
ready() {
  for _ in $(seq 1 30); do
    if curl -fsS --max-time 5 "${PROXY_SENTINEL_HEALTH_URL:-http://127.0.0.1:18080/readyz}" >/dev/null; then
      for unit in "${units[@]}"; do systemctl is-active --quiet "$unit" || return 1; done
      if python3 "$(dirname "$0")/verify-application-runtime.py" --root "$root" --release "$(readlink -f "$root/current")" --units "${units[@]}"; then
        return 0
      fi
    fi
    sleep 2
  done
  return 1
}
rollback() {
  local result=$?
  trap - ERR
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
ln -sfn "$release" "$root/current.next"
mv -Tf "$root/current.next" "$root/current"
restart_workers
ready
ln -sfn "$old_target" "$root/previous.next"
mv -Tf "$root/previous.next" "$root/previous"
trap - ERR
cat > "$release/deployment-manifest.json" <<JSON
{"version":"$version","mode":"application_only","previous":"$old_target","installed_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
JSON
echo "application upgrade completed: $version; previous=$old_target"
