#!/bin/sh
set -eu
cd /results
tcpdump -i lo -s 0 -U -w traffic.pcap >capture.log 2>&1 &
capture_pid=$!
trap 'kill -INT "$capture_pid" 2>/dev/null || true' EXIT INT TERM
tries=0
until grep -q 'listening on' capture.log; do
  kill -0 "$capture_pid"
  tries=$((tries+1))
  [ "$tries" -lt 50 ] || exit 1
  sleep 0.1
done
campus-load --requests 10000 --concurrency 16 --rate 1000 > transport.json
sleep 1
kill -INT "$capture_pid"
wait "$capture_pid" || true
trap - EXIT INT TERM
mkdir -p parsed
suricata --runmode single -k none -r traffic.pcap -l parsed >parser.log 2>&1
suricata -V > parser-version.txt
