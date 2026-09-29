#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "$0")/../.." && pwd)"
replay_dir="$(mktemp -d "${TMPDIR:-/tmp}/sentinel-proxy.XXXXXX")"
trap 'rm -rf "$replay_dir"' EXIT
python3 "$repo_dir/scripts/proxy-protocol/make-replay.py" "$replay_dir/replay.pcap"
cd "$replay_dir"
zeek -C -r replay.pcap "$repo_dir/assets/zeek/proxy-transactions.zeek" LogAscii::use_json=T
cd "$repo_dir"
PROXY_SENTINEL_TEST_ZEEK_PROXY_LOG="$replay_dir/proxy_transactions.log" go test ./internal/adapter/zeek -run TestProxyPacketReplay -count=1 -v
go test ./internal/proxyprotocol ./internal/controlplane -run 'TestProtocol|TestForged|TestAttribution|TestRepository|TestProxyManual' -count=1
