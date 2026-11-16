#!/usr/bin/env bash
# Move the separately pinned minute observer to an immutable application release.
set -euo pipefail
root="${PROXY_SENTINEL_ROOT:-/opt/proxy-sentinel}"
version=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="${2:-}"; shift 2 ;;
    *) echo "usage: upgrade-recognition-minute-shadow.sh --version VERSION" >&2; exit 2 ;;
  esac
done
[[ "$root" =~ ^/opt/[A-Za-z0-9._/-]+$ && "$root" != *..* ]] || exit 2
[[ "$version" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || exit 2
release="$(readlink -f "$root/current")"
[[ "$release" == "$root/releases/$version" && -x "$release/bin/recognition-minute-shadow" ]] || exit 2
unit=proxy-sentinel-recognition-minute-shadow.service
systemctl is-active --quiet "$unit"
systemctl is-enabled --quiet "$unit"
python3 "$release/scripts/verify-application-cli.py" --stage "$release" --units "$unit"

override_dir="/etc/systemd/system/$unit.d"
override="$override_dir/90-proxy-sentinel-immutable-release.conf"
obsolete_override="$override_dir/zzzzzzzzzz-current.conf"
install -d -m 0755 "$override_dir"
backup="$(mktemp -d "$root/config/recognition-minute-shadow-unit.XXXXXX")"
systemctl cat "$unit" > "$backup/unit-before.txt"
had_override=false
if [[ -e "$override" ]]; then
  cp -p "$override" "$backup/override-before.conf"
  had_override=true
fi
had_obsolete_override=false
if [[ -e "$obsolete_override" ]]; then
  # Only retire the known current-symlink override. An unknown later drop-in
  # may carry site policy and must be reviewed before changing the unit.
  expected_obsolete="$(printf '[Service]\nExecStart=\nExecStart=%s/current/bin/recognition-minute-shadow --interval=60s --lookback-minutes=10' "$root")"
  [[ "$(cat "$obsolete_override")" == "$expected_obsolete" ]] || {
    echo "unexpected later recognition minute override: $obsolete_override" >&2
    exit 1
  }
  cp -p "$obsolete_override" "$backup/obsolete-override-before.conf"
  had_obsolete_override=true
fi
restore() {
  trap - ERR
  if [[ "$had_override" == true ]]; then cp -p "$backup/override-before.conf" "$override"; else rm -f "$override"; fi
  if [[ "$had_obsolete_override" == true ]]; then cp -p "$backup/obsolete-override-before.conf" "$obsolete_override"; fi
  systemctl daemon-reload
  systemctl restart "$unit"
  echo "minute observer update failed; restored unit from $backup" >&2
}
trap restore ERR
tmp="$(mktemp "$override_dir/.release.XXXXXX")"
cat > "$tmp" <<EOF
[Service]
ExecStart=
ExecStart=$release/bin/recognition-minute-shadow --interval=60s --lookback-minutes=10
EOF
chmod 0644 "$tmp"
mv -f "$tmp" "$override"
if [[ "$had_obsolete_override" == true ]]; then rm -f "$obsolete_override"; fi
systemctl daemon-reload
systemctl restart "$unit"
systemctl is-active --quiet "$unit"
python3 "$release/scripts/verify-application-runtime.py" --root "$root" --release "$release" --units "$unit"
sleep 5
systemctl is-active --quiet "$unit"
python3 "$release/scripts/verify-application-runtime.py" --root "$root" --release "$release" --units "$unit"
trap - ERR
echo "minute observer updated: $version; unit backup=$backup"
