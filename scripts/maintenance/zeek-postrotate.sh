#!/usr/bin/env bash
# Zeek 原生轮转后处理脚本：将 <base>.YYYY-MM-DD-HH-MM-SS.log 原子重命名为
# <base>.log-YYYYMMDD-HHMMSS（同文件系统 mv 保持 inode 不变），
# 使其与 realtime ingest 尾读器及 passive_archive_rotations 原文归档校验 100% 兼容。
set -euo pipefail

rotated_file="${1:-}"
base_name="${2:-}"
if [[ -z "$rotated_file" || -z "$base_name" || ! -f "$rotated_file" ]]; then
  exit 0
fi

dir_name="$(dirname "$rotated_file")"
file_name="$(basename "$rotated_file")"
# 从 Zeek 默认命名 <base>.YYYY-MM-DD-HH-MM-SS.log 提取紧凑时间戳 YYYYMMDD-HHMMSS
if [[ "$file_name" =~ ^.+\.([0-9]{4})-([0-9]{2})-([0-9]{2})-([0-9]{2})-([0-9]{2})-([0-9]{2})\.log$ ]]; then
  stamp="${BASH_REMATCH[1]}${BASH_REMATCH[2]}${BASH_REMATCH[3]}-${BASH_REMATCH[4]}${BASH_REMATCH[5]}${BASH_REMATCH[6]}"
else
  stamp="$(date -u +%Y%m%d-%H%M%S)"
fi

target="${dir_name}/${base_name}.log-${stamp}"
if [[ -e "$target" || -e "${target}.gz" ]]; then
  target="${dir_name}/${base_name}.log-${stamp}-$$"
fi
mv -f -- "$rotated_file" "$target"
