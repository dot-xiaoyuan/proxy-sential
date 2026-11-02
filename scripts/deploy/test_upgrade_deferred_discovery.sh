#!/usr/bin/env bash
set -euo pipefail

script="${1:-$(dirname "$0")/upgrade-application.sh}"
eval "$(sed -n '/^restart_workers() {/,/^}/p; /^wait_deferred_discovery() {/,/^}/p' "$script")"

root=/opt/fixture
old_target=$root/releases/r49
release=$root/releases/r52
deferred_unit=proxy-sentinel-discovery.service
defer_discovery_restart=true
deferred_started_new=false
old_discovery_pid=100
units=(control.service "$deferred_unit" ingest.service)
restarted=()
poll_file="$(mktemp)"
exec_file="$(mktemp)"
trap 'rm -f "$poll_file" "$exec_file"' EXIT
echo 0 > "$poll_file"
echo 0 > "$exec_file"
systemctl() {
  if [[ "$1" == restart ]]; then restarted+=("$2"); return 0; fi
  poll=$(($(cat "$poll_file") + 1))
  echo "$poll" > "$poll_file"
  case "$poll" in
    1) echo 100 ;;
    2) echo 200 ;;
    *) echo 300 ;;
  esac
}
readlink() {
  case "$2" in
    /proc/200/exe) echo "$old_target/bin/discovery-worker" ;;
    /proc/300/exe)
      seen=$(($(cat "$exec_file") + 1))
      echo "$seen" > "$exec_file"
      if [[ "$seen" == 1 ]]; then echo /usr/lib/systemd/systemd; else echo "$release/bin/discovery-worker"; fi ;;
    *) return 1 ;;
  esac
}
sleep() { :; }
seq() { echo 1; echo 2; echo 3; echo 4; }

restart_workers
[[ "${restarted[*]}" == 'control.service ingest.service' ]]
wait_deferred_discovery
[[ "$deferred_started_new" == true && "$old_discovery_pid" == 200 && "$(cat "$poll_file")" == 4 ]]

echo 'deferred discovery natural restart and service exclusion verified'
