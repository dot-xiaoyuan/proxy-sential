#!/bin/sh
set -eu
scenario=${1:-heterogeneous}
case "$scenario" in heterogeneous|homogeneous|single|multi_browser) ;; *) exit 2 ;; esac
root=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
result="$root/artifacts/shared-access-campus/nat-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$result"
printf '{"scenario":"%s"}\n' "$scenario" > "$result/scenario.json"
base="sentinel-campus-$$"
capture_binary=${SENTINEL_CAPTURE_BINARY:-}
set --
if [ -n "$capture_binary" ]; then
  [ -f "$capture_binary" ] || exit 2
  set -- -v "$capture_binary:/sentinel:ro"
  python3 - "$result/capture-scope.json" "$base" <<'PYCFG'
import datetime,json,sys
now=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
json.dump({'schema_version':'capture-scope/v1','sensor_id':'campus-lab','collector_instance_id':sys.argv[2],'campus_id':'campus-lab','access_domain':'lab-nas','valid_from':now.isoformat(),'valid_until':(now+datetime.timedelta(hours=1)).isoformat()},open(sys.argv[1],'w'),indent=2)
PYCFG
fi
cleanup() {
  docker rm -f "$base-a" "$base-b" "$base-router" "$base-server" >/dev/null 2>&1 || true
  docker network rm "$base-lan" "$base-wan" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
docker network create --internal --subnet 172.29.250.0/24 "$base-wan" > "$result/network-wan.txt"
docker network create --internal --subnet 172.29.251.0/24 "$base-lan" > "$result/network-lan.txt"
docker run -d --name "$base-server" --network "$base-wan" --ip 172.29.250.10 --cap-drop ALL --cap-add NET_BIND_SERVICE --security-opt no-new-privileges -v "$root/scripts/testbed/campus/nat-traffic.py:/traffic.py:ro" sentinel-campus-lab:local -c 'openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/key.pem -out /tmp/cert.pem -days 1 -subj /CN=campus.test -addext subjectAltName=IP:172.29.250.10 >/dev/null 2>&1 && exec python3 /traffic.py server' > "$result/server-id.txt"
i=0
until docker cp "$base-server:/tmp/cert.pem" "$result/cert.pem" 2>/dev/null; do i=$((i+1)); [ "$i" -lt 50 ]; sleep 0.2; done
docker run -d "$@" --name "$base-router" --network "$base-wan" --ip 172.29.250.2 --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW --sysctl net.ipv4.ip_forward=1 --security-opt no-new-privileges -v "$result:/results" sentinel-campus-lab:local -c 'sleep 86400' > "$result/router-id.txt"
docker network connect --ip 172.29.251.2 "$base-lan" "$base-router"
docker exec "$base-router" sh -c 'iptables -t nat -A POSTROUTING -s 172.29.251.0/24 -d 172.29.250.10 -j SNAT --to-source 172.29.250.2; iptables -A FORWARD -s 172.29.251.0/24 -d 172.29.250.10 -j ACCEPT; iptables -A FORWARD -s 172.29.250.10 -d 172.29.251.0/24 -j ACCEPT; tcpdump -i eth0 -s 0 -U -w /results/nat.pcap host 172.29.250.10 >/results/capture.log 2>&1 & echo $! >/tmp/capture.pid'
i=0
until grep -q 'listening on' "$result/capture.log"; do i=$((i+1)); [ "$i" -lt 50 ]; sleep 0.2; done
if [ -n "$capture_binary" ]; then
  docker exec "$base-router" sh -c '/sentinel device-signal run --interface eth0 --output /results/device-signals.jsonl --sensor-id campus-lab --collector-instance-id "$1" --capture-scope-config /results/capture-scope.json --bucket 1s >/results/device-signal.log 2>&1 & echo $! >/tmp/device.pid' sh "$base"
fi
for name in a b; do
  ttl=64; ip=172.29.251.11
  if [ "$name" = b ]; then ip=172.29.251.12; if [ "$scenario" = heterogeneous ]; then ttl=128; fi; fi
  docker run -d --name "$base-$name" --network "$base-lan" --ip "$ip" --cap-drop ALL --cap-add NET_ADMIN --sysctl "net.ipv4.ip_default_ttl=$ttl" --security-opt no-new-privileges -v "$root/scripts/testbed/campus/nat-traffic.py:/traffic.py:ro" -v "$result/cert.pem:/tmp/cert.pem:ro" sentinel-campus-lab:local -c 'ip route add 172.29.250.0/24 via 172.29.251.2; sleep 86400' > "$result/client-$name-id.txt"
done
# The scenario controls physical container count and programmed profile diversity.
docker exec "$base-a" python3 /traffic.py client android > "$result/android.json" &
a_pid=$!
second_container="$base-b"
second_profile=windows
case "$scenario" in homogeneous) second_profile=android ;; single) second_container="$base-a"; second_profile=android ;; multi_browser) second_container="$base-a" ;; esac
docker exec "$second_container" python3 /traffic.py client "$second_profile" > "$result/windows.json" &
b_pid=$!
status=0
wait "$a_pid" || status=1
wait "$b_pid" || status=1
sleep 1
if [ -n "$capture_binary" ]; then
  docker exec "$base-router" sh -c 'kill -INT "$(cat /tmp/device.pid)"'
fi
docker exec "$base-router" sh -c 'kill -INT "$(cat /tmp/capture.pid)"'
sleep 1
docker exec "$base-router" sh -c 'mkdir -p /results/parsed; suricata --runmode single -k none --set app-layer.protocols.tls.ja3-fingerprints=yes -r /results/nat.pcap -l /results/parsed >/results/parser.log 2>&1; suricata -V >/results/parser-version.txt'
if [ -n "$capture_binary" ]; then
  docker exec "$base-router" /sentinel adapter suricata --input /results/parsed/eve.json --output /results/scoped-normalized.jsonl --sensor-id campus-lab --collector-instance-id "$base" --capture-scope-config /results/capture-scope.json 2> "$result/scoped-adapter.log"
fi
printf '%s\n' "$result"
exit "$status"
