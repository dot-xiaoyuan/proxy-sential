#!/usr/bin/env bash
set -Eeuo pipefail

uplink="${PROXY_SENTINEL_TEST_UPLINK:-ens33}"
state_dir="${PROXY_SENTINEL_TEST_STATE_DIR:-/var/lib/proxy-sentinel-testbed}"
[[ $(id -u) -eq 0 ]] || { echo "必须使用 root 运行" >&2; exit 1; }
ip link show "$uplink" >/dev/null || { echo "上联网卡不存在: $uplink" >&2; exit 1; }
for command in ip iptables sysctl; do command -v "$command" >/dev/null || { echo "缺少命令: $command" >&2; exit 1; }; done
mkdir -p "$state_dir"
[[ -f "$state_dir/ip_forward.before" ]] || cat /proc/sys/net/ipv4/ip_forward > "$state_dir/ip_forward.before"
sysctl -q -w net.ipv4.ip_forward=1

ip link show psbr194 >/dev/null 2>&1 || ip link add psbr194 type bridge
ip addr replace 10.194.0.1/24 dev psbr194
ip link set psbr194 up

for spec in "ps-a 10.194.0.11 64" "ps-b 10.194.0.12 128" "ps-c 10.194.0.13 255"; do
  read -r namespace address ttl <<<"$spec"
  suffix="${namespace#ps-}"
  host_veth="psv-${suffix}h"
  ns_veth="psv-${suffix}n"
  ip netns list | awk '{print $1}' | grep -qx "$namespace" || ip netns add "$namespace"
  if ! ip link show "$host_veth" >/dev/null 2>&1; then
    ip link add "$host_veth" type veth peer name "$ns_veth"
    ip link set "$ns_veth" netns "$namespace"
  fi
  ip link set "$host_veth" master psbr194
  ip link set "$host_veth" up
  ip -n "$namespace" link set lo up
  ip -n "$namespace" link set "$ns_veth" up
  ip -n "$namespace" addr replace "$address/24" dev "$ns_veth"
  ip -n "$namespace" route replace default via 10.194.0.1
  ip netns exec "$namespace" sysctl -q -w "net.ipv4.ip_default_ttl=$ttl"
done

rule=(-s 10.194.0.0/24 -o "$uplink" -m comment --comment proxy-sentinel-testbed -j MASQUERADE)
iptables -t nat -C POSTROUTING "${rule[@]}" >/dev/null 2>&1 || iptables -t nat -A POSTROUTING "${rule[@]}"
forward_out=(-i psbr194 -o "$uplink" -m comment --comment proxy-sentinel-testbed -j ACCEPT)
forward_in=(-i "$uplink" -o psbr194 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment proxy-sentinel-testbed -j ACCEPT)
iptables -C FORWARD "${forward_out[@]}" >/dev/null 2>&1 || iptables -A FORWARD "${forward_out[@]}"
iptables -C FORWARD "${forward_in[@]}" >/dev/null 2>&1 || iptables -A FORWARD "${forward_in[@]}"

echo "测试拓扑已就绪: ps-a/ps-b/ps-c -> 10.194.0.1 -> $uplink"
