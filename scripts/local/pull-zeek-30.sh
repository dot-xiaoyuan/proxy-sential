#!/usr/bin/env bash
# 从 192.168.0.30 只读拉取 Zeek 日志快照，生成本地回放目录与 manifest。
#
# 该脚本只对远端执行 stat / tail / rsync 读操作，不写远端任何文件。
# 数据流向：远端 logs/current -> data/zeek/<sensor>/raw -> replay（可选时间平移）
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
helper="$root/scripts/local/zeek_replay.py"

target="root@192.168.0.30"
remote_dir="/opt/proxy-sentinel/data/zeek/logs/current"
remote_ttl="/opt/proxy-sentinel/data/device-signals/ttl.jsonl"
local_source=""
sensor_id="office-30"
dest=""
files="dhcp.log software.log mdns.log nbns.log llmnr.log conn.log dns.log http.log ssl.log x509.log snmp.log lldp.log ssdp.log proxy_transactions.log"
with_ttl=false
ttl_bytes=""
shift_to_now=false
append=false
dry_run=false

ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10 -q)
rsh="ssh -o BatchMode=yes -o ConnectTimeout=10 -q"
# 超过该跨度就应该启用 --shift-to-now：ClickHouse normalized_events 只有 7 天 TTL。
ttl_warn_seconds=518400

usage() {
  cat <<'EOF'
用法: scripts/local/pull-zeek-30.sh [选项]

  --target USER@HOST     远端地址，默认 root@192.168.0.30
  --remote-dir DIR       远端 Zeek 日志目录，默认 /opt/proxy-sentinel/data/zeek/logs/current
  --source-dir DIR       离线模式：从本地目录取文件，不走 SSH（用于测试与离线回放）
  --dest DIR             本地目标目录，默认 <repo>/data/zeek/<sensor-id>
  --sensor-id ID         传感器标识，默认 office-30
  --files "a.log b.log"  覆盖默认文件清单
  --with-ttl             额外拉取 device-signals/ttl.jsonl（默认关闭，该文件约 234MB）
  --ttl-bytes N          拉 TTL 流时只取尾部 N 字节，例如 50M
  --shift-to-now         生成时间平移到“当前”的 replay 目录
  --append               对 raw/ 使用 rsync --append 做增量续拉
  --dry-run              只打印将要拉取的文件与字节数
  -h, --help             显示帮助
EOF
}

log() { printf '[local-zeek] %s\n' "$*"; }
die() { printf '[local-zeek] %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --target) target="${2:-}"; shift 2 ;;
    --remote-dir) remote_dir="${2:-}"; shift 2 ;;
    --source-dir) local_source="${2:-}"; shift 2 ;;
    --dest) dest="${2:-}"; shift 2 ;;
    --sensor-id) sensor_id="${2:-}"; shift 2 ;;
    --files) files="${2:-}"; shift 2 ;;
    --with-ttl) with_ttl=true; shift ;;
    --ttl-bytes) ttl_bytes="${2:-}"; shift 2 ;;
    --shift-to-now) shift_to_now=true; shift ;;
    --append) append=true; shift ;;
    --dry-run) dry_run=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "未知参数: $1" ;;
  esac
done

[[ "$sensor_id" =~ ^[A-Za-z0-9._-]+$ ]] || die "非法 sensor-id: $sensor_id"
if [ -n "$ttl_bytes" ]; then
  [[ "$ttl_bytes" =~ ^[0-9]+[KMG]?$ ]] || die "非法 --ttl-bytes: $ttl_bytes"
fi
command -v python3 >/dev/null || die "缺少 python3"
command -v jq >/dev/null || die "缺少 jq"
if [ -n "$local_source" ]; then
  [ -d "$local_source" ] || die "离线目录不存在: $local_source"
else
  command -v rsync >/dev/null || die "缺少 rsync"
  command -v ssh >/dev/null || die "缺少 ssh"
fi
[ -r "$helper" ] || die "缺少辅助模块: $helper"

if [ -z "$dest" ]; then
  dest="$root/data/zeek/$sensor_id"
fi
mkdir -p "$dest/raw" || die "无法创建目标目录: $dest/raw"
raw_dir="$dest/raw"
replay_dir="$dest/replay"

remote_size() {
  ssh "${ssh_opts[@]}" "$target" "stat -c %s '$1' 2>/dev/null" 2>/dev/null || true
}

fetch_remote() {
  local name="$1" out="$2" remote="$target:$remote_dir/$1"
  if [ "$append" = true ] && [ -f "$out" ]; then
    local rsize lsize
    rsize="$(remote_size "$remote_dir/$name")"
    lsize="$(wc -c < "$out" | tr -d ' ')"
    if [ -n "$rsize" ] && [ "$rsize" -ge "$lsize" ]; then
      rsync -e "$rsh" --append "$remote" "$out"
      return 0
    fi
    log "远端 $name 小于本地副本，放弃增量续拉并改为完整拉取"
  fi
  rsync -e "$rsh" "$remote" "$out"
}

portable_copy() {
  if cp -c "$1" "$2" 2>/dev/null; then
    return 0
  fi
  cp "$1" "$2"
}

fetched=""
skipped=""
for name in $files; do
  [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || die "非法文件名: $name"
  out="$raw_dir/$name"
  if [ -n "$local_source" ]; then
    if [ ! -f "$local_source/$name" ]; then
      skipped="$skipped $name"
      continue
    fi
    if [ "$dry_run" = true ]; then
      printf '[local-zeek] 将复制 %-24s %s bytes\n' "$name" "$(wc -c < "$local_source/$name" | tr -d ' ')"
      continue
    fi
    cp "$local_source/$name" "$out"
  else
    rsize="$(remote_size "$remote_dir/$name")"
    if [ -z "$rsize" ]; then
      skipped="$skipped $name"
      continue
    fi
    if [ "$dry_run" = true ]; then
      printf '[local-zeek] 将拉取 %-24s %s bytes\n' "$name" "$rsize"
      continue
    fi
    fetch_remote "$name" "$out"
  fi
  if [ -s "$out" ]; then
    fetched="$fetched $name"
  else
    skipped="$skipped $name"
  fi
done

if [ "$with_ttl" = true ]; then
  out="$raw_dir/ttl.jsonl"
  if [ "$dry_run" = true ]; then
    log "将拉取 device-signals/ttl.jsonl ${ttl_bytes:+尾部 $ttl_bytes}"
  elif [ -n "$local_source" ]; then
    src="${local_source%/}/../device-signals/ttl.jsonl"
    [ -f "$src" ] || src="$local_source/ttl.jsonl"
    [ -f "$src" ] || die "离线模式找不到 ttl.jsonl"
    cp "$src" "$out"
  elif [ -n "$ttl_bytes" ]; then
    ssh "${ssh_opts[@]}" "$target" "tail -c $ttl_bytes '$remote_ttl'" > "$out"
  else
    rsync -e "$rsh" "$target:$remote_ttl" "$out"
  fi
  if [ "$dry_run" = false ]; then
    if [ -s "$out" ]; then
      fetched="$fetched ttl.jsonl"
    else
      skipped="$skipped ttl.jsonl"
    fi
  fi
fi

if [ "$dry_run" = true ]; then
  log "dry-run 结束，未传输任何数据"
  exit 0
fi

if [ -z "${fetched// /}" ]; then
  die "没有拉取到任何非空文件；请检查远端 $remote_dir 与 proxy-sentinel-zeek.service 状态"
fi

anchor_now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
newest=""
raw_paths=""
for name in $fetched; do
  raw_paths="$raw_paths $raw_dir/$name"
done

if [ "$shift_to_now" = true ]; then
  scan_json="$(python3 "$helper" scan $raw_paths)"
  newest="$(printf '%s' "$scan_json" | jq -r '.newest_ts')"
  if [ -z "$newest" ] || [ "$newest" = "null" ]; then
    die "无法从 raw 目录解析出事件时间，不能做时间平移"
  fi
  log "最新事件时间 ${newest}，将平移到 $anchor_now"
fi

rm -rf "$replay_dir"
mkdir -p "$replay_dir"
offset=""
for name in $fetched; do
  if [ "$shift_to_now" = true ]; then
    if [ -z "$offset" ]; then
      shift_json="$(python3 "$helper" shift --input "$raw_dir/$name" --output "$replay_dir/$name" --anchor-now "$anchor_now" --newest "$newest")"
      offset="$(printf '%s' "$shift_json" | jq -r '.offset_seconds')"
    else
      python3 "$helper" shift --input "$raw_dir/$name" --output "$replay_dir/$name" --offset "$offset" >/dev/null
    fi
  else
    portable_copy "$raw_dir/$name" "$replay_dir/$name"
  fi
done

source_label="$remote_dir"
source_host="$target"
if [ -n "$local_source" ]; then
  source_host="local"
  source_label="$local_source"
fi

manifest_summary="$(python3 "$helper" manifest \
  --input-dir "$replay_dir" \
  --output "$replay_dir/manifest.json" \
  --source-host "$source_host" \
  --source-dir "$source_label" \
  --sensor-id "$sensor_id" \
  --time-shift "${offset:-0}" \
  --anchor-now "$anchor_now" \
  --skipped $skipped)"

printf '%s\n' "$manifest_summary" | jq -r '"文件=\(.files) 行数=\(.lines) 异常行=\(.malformed) 跳过=\(.skipped) 跨度=\(.span_seconds|floor)秒 平移=\(.time_shift_seconds)秒"'

span="$(printf '%s' "$manifest_summary" | jq -r '.span_seconds | floor')"
if [ "$span" -gt "$ttl_warn_seconds" ] && [ "$shift_to_now" = false ]; then
  log "警告: 快照跨度 ${span} 秒超过 6 天，ClickHouse normalized_events 只有 7 天 TTL，建议加 --shift-to-now"
fi
log "回放目录: $replay_dir"
