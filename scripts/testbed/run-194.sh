#!/usr/bin/env bash
set -Eeuo pipefail

scenario="${1:-}"
result_dir="${PROXY_SENTINEL_TEST_RESULT_DIR:-/var/log/proxy-sentinel-testbed}"
mkdir -p "$result_dir"
scenario_id="${scenario}-$(date -u +%Y%m%dT%H%M%SZ)"
result="$result_dir/$scenario_id.json"
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
status="generated"
detail=""

run_http() {
  local namespace="$1" ua="$2"
  ip netns exec "$namespace" curl -sS --max-time 15 -A "$ua" --resolve 'www.baidu.com:80:183.2.172.177' "http://www.baidu.com/?scenario=$scenario_id" >/dev/null
}
run_tls() {
  local namespace="$1" tls_max="$2"
  ip netns exec "$namespace" curl -ksS --max-time 15 --tls-max "$tls_max" --resolve 'www.baidu.com:443:183.2.172.177' "https://www.baidu.com/?scenario=$scenario_id" >/dev/null
}
send_udp_signature() {
  local namespace="$1" first_hex="$2" size="$3" port="$4"
  ip netns exec "$namespace" python3 - "$first_hex" "$size" "$port" <<'PY'
import socket,sys
head=bytes.fromhex(sys.argv[1]); size=int(sys.argv[2]); port=int(sys.argv[3])
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for _ in range(20):
    sock.sendto(head+b'\0'*(size-len(head)),('1.1.1.1',port))
    import time; time.sleep(.05)
PY
}
send_mdns_names() {
  python3 - <<'PY'
import socket,struct,time
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_TTL,1)
sock.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_IF,socket.inet_aton('192.168.0.194'))
for name in ('android-phone.local','windows-pc.local','iphone-tablet.local'):
    labels=b''.join(bytes([len(part)])+part.encode() for part in name.split('.'))+b'\0'
    packet=struct.pack('!HHHHHH',0,0,1,0,0,0)+labels+struct.pack('!HH',1,1)
    sock.sendto(packet,('224.0.0.251',5353)); time.sleep(.2)
PY
}

case "$scenario" in
  normal-single)
    expected="normal_or_suspicious_never_high"
    run_http ps-a "Mozilla/5.0 ProxySentinel-Normal"
    ;;
  nat-two)
    expected="high_shared_device_divergence"
    run_http ps-a "Mozilla/5.0 Android"
    run_http ps-b "Mozilla/5.0 Windows NT 10.0"
    ;;
  nat-three)
    expected="confirmed_shared_device_divergence"
    run_http ps-a "Mozilla/5.0 Android"
    run_http ps-b "Mozilla/5.0 Windows NT 10.0"
    run_http ps-c "Mozilla/5.0 iPhone"
    run_tls ps-a 1.2
    run_tls ps-b 1.3
    run_tls ps-c 1.2
    send_mdns_names
    ;;
  wireguard)
    expected="high_explicit_tunnel"
    send_udp_signature ps-a "01000000" 148 51820
    ;;
  openvpn)
    expected="high_explicit_tunnel"
    send_udp_signature ps-a "38" 64 1194
    ;;
  behavioral-only)
    expected="at_most_suspicious"
    for port in 80 81 82 83 84 85; do ip netns exec ps-a timeout 1 bash -c "</dev/tcp/1.1.1.1/$port" >/dev/null 2>&1 || true; done
    ;;
  *)
    echo "用法: $0 {normal-single|nat-two|nat-three|wireguard|openvpn|behavioral-only}" >&2
    exit 2
    ;;
esac

finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '{"scenario_id":"%s","scenario":"%s","started_at":"%s","finished_at":"%s","expected":"%s","generator_status":"%s","detail":"%s"}\n' "$scenario_id" "$scenario" "$started" "$finished" "$expected" "$status" "$detail" > "$result"
echo "$result"
