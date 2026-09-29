#!/usr/bin/env bash
set -Eeuo pipefail

uplink="${PROXY_SENTINEL_TEST_UPLINK:-ens33}"
state_dir="${PROXY_SENTINEL_TEST_STATE_DIR:-/var/lib/proxy-sentinel-testbed}"
for namespace in ps-a ps-b ps-c; do ip netns del "$namespace" >/dev/null 2>&1 || true; done
ip link del psbr194 >/dev/null 2>&1 || true
iptables -t nat -D POSTROUTING -s 10.194.0.0/24 -o "$uplink" -m comment --comment proxy-sentinel-testbed -j MASQUERADE >/dev/null 2>&1 || true
iptables -D FORWARD -i psbr194 -o "$uplink" -m comment --comment proxy-sentinel-testbed -j ACCEPT >/dev/null 2>&1 || true
iptables -D FORWARD -i "$uplink" -o psbr194 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment proxy-sentinel-testbed -j ACCEPT >/dev/null 2>&1 || true
if [[ -f "$state_dir/ip_forward.before" ]]; then
  value="$(<"$state_dir/ip_forward.before")"
  [[ "$value" == 0 || "$value" == 1 ]] && sysctl -q -w "net.ipv4.ip_forward=$value"
fi
echo "测试命名空间和专用 NAT 规则已清理"
