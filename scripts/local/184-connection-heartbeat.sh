#!/usr/bin/env bash
set -euo pipefail

# Run in the foreground under `caffeinate -i -s` to keep the Mac awake.
# SSH sends encrypted keepalives and reconnects after a broken VPN path.
host=root@222.204.3.184
state_dir="/tmp/proxy-sentinel-184-heartbeat-$(id -u)"
pid_file="$state_dir/pid"
log_file="$state_dir/transitions.log"
mkdir -p -m 700 "$state_dir"
if [[ -L "$state_dir" || "$(stat -f %u "$state_dir")" != "$(id -u)" ]]; then
  echo "unsafe heartbeat state directory" >&2
  exit 1
fi
chmod 700 "$state_dir"

running() {
  [[ -f "$pid_file" ]] || return 1
  local pid
  pid="$(cat "$pid_file")"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  ps -p "$pid" -o command= 2>/dev/null | grep -Fq '184-connection-heartbeat.sh run'
}

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$1" >>"$log_file"; }

case "${1:-}" in
  status)
    if running; then echo "running (pid $(cat "$pid_file"))"; else echo stopped; fi
    [[ ! -f "$log_file" ]] || tail -n 3 "$log_file"
    ;;
  stop)
    if running; then kill "$(cat "$pid_file")"; echo "heartbeat stopping"; else echo "heartbeat not running"; fi
    ;;
  run)
    if running; then echo "heartbeat already running" >&2; exit 1; fi
    echo "$$" >"$pid_file"
    child_pid=
    cleanup() {
      [[ -z "$child_pid" ]] || kill "$child_pid" 2>/dev/null || true
      if [[ -f "$pid_file" && "$(cat "$pid_file")" == "$$" ]]; then rm -f "$pid_file"; fi
      log stopped
    }
    trap 'exit 0' INT TERM
    trap cleanup EXIT
    delay=5
    while :; do
      log connecting
      ssh -N -T -o BatchMode=yes -o StrictHostKeyChecking=yes \
        -o ConnectTimeout=8 -o ConnectionAttempts=1 \
        -o ServerAliveInterval=20 -o ServerAliveCountMax=3 \
        "$host" &
      child_pid=$!
      for _ in 1 2 3 4 5 6 7 8; do
        if ! kill -0 "$child_pid" 2>/dev/null; then break; fi
        sleep 1
      done
      if kill -0 "$child_pid" 2>/dev/null; then log connected; delay=5; fi
      wait "$child_pid" || true
      child_pid=
      log disconnected
      sleep "$delay" & child_pid=$!
      wait "$child_pid" || true
      child_pid=
      if (( delay < 60 )); then delay=$(( delay * 2 )); fi
      if (( delay > 60 )); then delay=60; fi
    done
    ;;
  *) echo "usage: caffeinate -i -s $0 run | $0 status | $0 stop" >&2; exit 2 ;;
esac
