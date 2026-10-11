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
live=false
daemon=false
interval=60
with_eve=false
remote_eve="/var/log/suricata/eve.json"
eve_name="eve.json"
eve_bytes=""

# 直连 ssh 一律 -n：这些调用只需要 stdout，否则会吞掉调用方的 stdin
# （增量镜像的 while read 循环就是这样被截断的）。rsync 的 -e 不能带 -n。
ssh_opts=(-n -o BatchMode=yes -o ConnectTimeout=10 -q)
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

增量镜像（--live，供 local-stack.sh sync 使用）:
  --live                 增量镜像到 <dest>/live，按远端 inode 与偏移量续读
  --daemon               常驻循环执行增量镜像
  --interval N           常驻循环间隔秒数，默认 60
  --with-eve             额外镜像 /var/log/suricata/eve.json
  --remote-eve PATH      远端 EVE 路径，默认 /var/log/suricata/eve.json
  --eve-name NAME        本地 EVE 文件名，默认 eve.json
  --eve-bytes N          EVE 首次只取尾部 N 字节，例如 50M
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
    --live) live=true; shift ;;
    --daemon) daemon=true; shift ;;
    --interval) interval="${2:-}"; shift 2 ;;
    --with-eve) with_eve=true; shift ;;
    --remote-eve) remote_eve="${2:-}"; shift 2 ;;
    --eve-name) eve_name="${2:-}"; shift 2 ;;
    --eve-bytes) eve_bytes="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "未知参数: $1" ;;
  esac
done

[[ "$sensor_id" =~ ^[A-Za-z0-9._-]+$ ]] || die "非法 sensor-id: $sensor_id"
if [ -n "$ttl_bytes" ]; then
  [[ "$ttl_bytes" =~ ^[0-9]+[KMG]?$ ]] || die "非法 --ttl-bytes: $ttl_bytes"
fi
if [ -n "$eve_bytes" ]; then
  [[ "$eve_bytes" =~ ^[0-9]+[KMG]?$ ]] || die "非法 --eve-bytes: $eve_bytes"
fi
[[ "$interval" =~ ^[0-9]+$ ]] && [ "$interval" -gt 0 ] || die "非法 --interval: $interval"
[[ "$eve_name" =~ ^[A-Za-z0-9._-]+$ ]] || die "非法 --eve-name: $eve_name"
if [ "$live" = true ]; then
  [ -z "$local_source" ] || die "--live 不支持 --source-dir 离线模式"
fi
if [ "$daemon" = true ] && [ "$live" = false ]; then
  die "--daemon 只能配合 --live 使用"
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

# ---------------------------------------------------------------------------
# 增量镜像（--live）
#
# ingest 的检查点按 (路径, dev, inode) 识别文件：同 inode 追加只会读新增字节，
# 换 inode 或 offset 超过文件大小则从 0 重读。因此增量镜像的做法是：
#   - 远端 inode 未变且变大：按远端偏移量追加增量字节，本地 inode 保持不变；
#   - 远端 inode 变了（logrotate 改名轮转）：先从远端 <路径>.1 补齐旧文件尾部，
#     把它保留为 <名>.1（正好对上 realtime worker 的轮转续读约定），再重新拉新文件；
#   - 远端变小（copytruncate）：直接重建本地文件。
# 远端偏移量记在 live/.sync-state.tsv，与本地文件大小无关（首次可用尾字节播种）。
# ---------------------------------------------------------------------------
live_dir="$dest/live"
live_state="$live_dir/.sync-state.tsv"
live_sources_file="$live_dir/.sources.tsv"

remote_stat() {
  ssh "${ssh_opts[@]}" "$target" "stat -c '%i %s' '$1' 2>/dev/null" 2>/dev/null || true
}

# --ttl-bytes/--eve-bytes 用 tail 风格后缀（如 50M），比较前先换算成字节数。
to_bytes() {
  case "${1:-}" in
    "") printf '0' ;;
    *[Kk]) printf '%s' "$(( ${1%[Kk]} * 1024 ))" ;;
    *[Mm]) printf '%s' "$(( ${1%[Mm]} * 1024 * 1024 ))" ;;
    *[Gg]) printf '%s' "$(( ${1%[Gg]} * 1024 * 1024 * 1024 ))" ;;
    *) printf '%s' "$1" ;;
  esac
}

state_get() {
  [ -f "$live_state" ] || return 0
  awk -F'\t' -v n="$1" -v f="$2" '$1==n {print $f; exit}' "$live_state" 2>/dev/null || true
}

state_set() {
  local name="$1" inode="$2" offset="$3" tmp="$live_state.tmp"
  [ -f "$live_state" ] || : > "$live_state"
  awk -F'\t' -v n="$name" '$1!=n' "$live_state" > "$tmp" 2>/dev/null || : > "$tmp"
  printf '%s\t%s\t%s\n' "$name" "$inode" "$offset" >> "$tmp"
  mv -f "$tmp" "$live_state"
}

append_from_remote() {
  local remote_path="$1" offset="$2" out="$3"
  ssh "${ssh_opts[@]}" "$target" "tail -c +$((offset + 1)) '$remote_path'" >> "$out"
}

write_from_remote() {
  local remote_path="$1" out="$2" tmp="$out.new"
  if ! ssh "${ssh_opts[@]}" "$target" "cat '$remote_path'" > "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  mv -f "$tmp" "$out"
}

live_sources() {
  local name
  for name in $files; do
    [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || die "非法文件名: $name"
    printf '%s\t%s\t\n' "$name" "$remote_dir/$name"
  done
  if [ "$with_eve" = true ]; then
    printf '%s\t%s\t%s\n' "$eve_name" "$remote_eve" "$eve_bytes"
  fi
  if [ "$with_ttl" = true ]; then
    printf '%s\t%s\t%s\n' "ttl.jsonl" "$remote_ttl" "$ttl_bytes"
  fi
}

sync_live_one() {
  local name="$1" remote_path="$2" seed_bytes="$3"
  local out="$live_dir/$name" stat inode rsize prev_inode prev_offset
  stat="$(remote_stat "$remote_path")"
  if [ -z "$stat" ]; then
    # 只提示一次，否则常驻镜像每轮都会刷同样的缺失日志。
    if [ ! -f "$out" ] && ! grep -qxF "$name" "$live_dir/.missing" 2>/dev/null; then
      log "远端缺失，跳过: $remote_path"
      mkdir -p "$live_dir"
      printf '%s\n' "$name" >> "$live_dir/.missing"
    fi
    return 0
  fi
  inode="${stat%% *}"
  rsize="${stat##* }"
  prev_inode="$(state_get "$name" 2)"
  prev_offset="$(state_get "$name" 3)"

  if [ "$dry_run" = true ]; then
    printf '[local-zeek] %-22s 远端 %s bytes 已读 %s\n' "$name" "$rsize" "${prev_offset:-0}"
    return 0
  fi

  mkdir -p "$live_dir"
  if [ ! -f "$out" ]; then
    fetch_live_base "$name" "$remote_path" "$rsize" "$seed_bytes" "$out"
    state_set "$name" "$inode" "$rsize"
    return 0
  fi

  if [ "$inode" != "$prev_inode" ] || [ "$rsize" -lt "$prev_offset" ]; then
    local completed=false arch_stat arch_size
    if [ "$inode" != "$prev_inode" ]; then
      arch_stat="$(remote_stat "$remote_path.1")"
      if [ -n "$arch_stat" ]; then
        arch_size="${arch_stat##* }"
        if [ "$arch_size" -gt "$prev_offset" ]; then
          append_from_remote "$remote_path.1" "$prev_offset" "$out" || die "轮转补尾失败: $name"
          completed=true
        fi
      fi
    fi
    if [ "$completed" = true ]; then
      mv -f "$out" "$out.1"
      log "$name 检测到轮转，上一份完整文件保留为 $name.1"
    else
      log "$name 检测到截断，重建本地文件"
    fi
    fetch_live_base "$name" "$remote_path" "$rsize" "$seed_bytes" "$out"
    state_set "$name" "$inode" "$rsize"
    return 0
  fi

  if [ "$rsize" -gt "$prev_offset" ]; then
    local before after expected consumed
    before="$(wc -c < "$out" | tr -d ' ')"
    append_from_remote "$remote_path" "$prev_offset" "$out" || die "增量拉取失败: $name"
    after="$(wc -c < "$out" | tr -d ' ')"
    expected=$((before + rsize - prev_offset))
    consumed=$((after - before))
    # 远端是被持续写入的文件，stat 之后到 tail 之间还会增长，所以实际消费的字节数
    # 通常略大于 rsize-prev_offset；只有"读少了"才说明传输被截断。
    if [ "$after" -lt "$expected" ]; then
      log "$name 增量传输不完整（$after < ${expected}），按上限播种重建"
      fetch_live_base "$name" "$remote_path" "$rsize" "$seed_bytes" "$out"
      state_set "$name" "$inode" "$rsize"
      return 0
    fi
    if [ "$consumed" -le 0 ]; then
      return 0
    fi
    state_set "$name" "$inode" "$((prev_offset + consumed))"
    log "$name 增量 +${consumed}B"
  fi
  return 0
}

# 建立本地基线：远端比播种上限大就只取尾部（丢掉落在中途的残行），否则整文件拉取。
fetch_live_base() {
  local name="$1" remote_path="$2" rsize="$3" seed_bytes="$4" out="$5" seed_num
  seed_num="$(to_bytes "$seed_bytes")"
  if [ "$seed_num" -gt 0 ] && [ "$rsize" -gt "$seed_num" ]; then
    if ! ssh "${ssh_opts[@]}" "$target" "tail -c $seed_bytes '$remote_path'" | tail -n +2 > "$out"; then
      rm -f "$out"
      die "种子拉取失败: $name"
    fi
    log "$name 播种 ${seed_bytes}B（远端 ${rsize}B）"
  else
    if ! write_from_remote "$remote_path" "$out"; then
      die "拉取失败: $name"
    fi
    log "$name 全量 ${rsize}B"
  fi
}

# 手动 sync 与常驻镜像会同时跑，并发追加同一个文件必然写坏，
# 所以用目录锁串行化；持有者已退出的陈旧锁会被自动清理。
acquire_live_lock() {
  local lock="$live_dir/.sync-lock" attempt holder
  for attempt in $(seq 1 120); do
    if mkdir "$lock" 2>/dev/null; then
      printf '%s\n' "$$" > "$lock/pid"
      return 0
    fi
    holder="$(cat "$lock/pid" 2>/dev/null || true)"
    if [ -n "$holder" ] && ! kill -0 "$holder" 2>/dev/null; then
      log "清理陈旧的增量镜像锁（pid ${holder} 已退出）"
      rm -rf "$lock"
      continue
    fi
    sleep 1
  done
  return 1
}

release_live_lock() { rm -rf "$live_dir/.sync-lock" 2>/dev/null || true; }

sync_live_once() {
  mkdir -p "$live_dir"
  if ! acquire_live_lock; then
    log "已有增量镜像在运行，本轮跳过"
    return 0
  fi
  trap 'release_live_lock' EXIT INT TERM
  live_sources > "$live_sources_file"
  local name remote_path seed
  while IFS="$(printf '\t')" read -r name remote_path seed; do
    [ -n "$name" ] || continue
    sync_live_one "$name" "$remote_path" "$seed"
  done < "$live_sources_file"
  release_live_lock
  trap - EXIT INT TERM
}

if [ "$live" = true ]; then
  if [ "$daemon" = true ]; then
    log "增量镜像常驻启动：间隔 ${interval}s，目标 $live_dir"
    while true; do
      ( sync_live_once ) || log "本轮同步失败，等待下一轮"
      sleep "$interval"
    done
  fi
  sync_live_once
  log "增量镜像目录: $live_dir"
  exit 0
fi

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
