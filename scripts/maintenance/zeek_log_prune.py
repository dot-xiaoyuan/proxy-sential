#!/usr/bin/env python3
"""Zeek 轮转日志延迟压缩与分级过期清理（仅处理已轮转文件，绝不触碰活跃 *.log）。"""
import argparse
import gzip
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

# 匹配 zeek-postrotate.sh 产出的 <base>.log-YYYYMMDD-HHMMSS(.gz)
ROTATED_RE = re.compile(r"^([A-Za-z0-9_.-]+)\.log-(\d{8}-\d{6}(?:-\d+)?)(\.gz)?$")

# 高流量流量明细日志（保留较短周期即可控制 15 GiB 稳态）
HIGH_VOLUME_LOGS = {"conn", "dns", "files", "http", "ssl", "x509", "analyzer", "weird"}


def compress_file(src: Path, dry_run: bool) -> tuple[int, int]:
    """将未压缩的轮转文件原子 gzip 压缩为 .gz，返回 (原字节数, 压缩后字节数)。"""
    orig_size = src.stat().st_size
    dst = Path(str(src) + ".gz")
    if dry_run:
        return orig_size, 0
    tmp = Path(str(src) + f".gz.tmp.{os.getpid()}")
    try:
        with src.open("rb") as fin, gzip.open(tmp, "wb", compresslevel=6) as fout:
            shutil.copyfileobj(fin, fout, length=1024 * 1024)
        st = src.stat()
        os.utime(tmp, (st.st_atime, st.st_mtime))
        os.replace(tmp, dst)
        new_size = dst.stat().st_size
        src.unlink()
        return orig_size, new_size
    except Exception:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
        raise


def maintain(
    log_dir: Path,
    now_ts: float,
    compress_delay_sec: int,
    high_vol_retention_sec: int,
    discovery_retention_sec: int,
    max_compress_per_run: int,
    dry_run: bool,
) -> dict:
    summary = {
        "log_dir": str(log_dir),
        "dry_run": dry_run,
        "scanned": 0,
        "compressed_files": 0,
        "compressed_saved_bytes": 0,
        "deleted_files": 0,
        "deleted_bytes": 0,
        "skipped_recent": 0,
        "errors": [],
    }
    if not log_dir.is_dir():
        summary["errors"].append(f"directory not found: {log_dir}")
        return summary

    entries = sorted(log_dir.iterdir(), key=lambda p: p.name)
    for path in entries:
        if not path.is_file() or path.is_symlink():
            continue
        m = ROTATED_RE.match(path.name)
        if not m:
            continue
        summary["scanned"] += 1
        base, _stamp, gz_ext = m.group(1), m.group(2), m.group(3)
        try:
            st = path.stat()
        except OSError as exc:
            summary["errors"].append(f"stat {path.name}: {exc}")
            continue
        age_sec = max(0.0, now_ts - st.st_mtime)
        retention_sec = high_vol_retention_sec if base in HIGH_VOLUME_LOGS else discovery_retention_sec

        if gz_ext:
            if age_sec >= retention_sec:
                size = st.st_size
                if not dry_run:
                    try:
                        path.unlink()
                    except OSError as exc:
                        summary["errors"].append(f"unlink {path.name}: {exc}")
                        continue
                summary["deleted_files"] += 1
                summary["deleted_bytes"] += size
            continue

        # 未压缩的轮转文件：延迟 compress_delay_sec 让 ingest 和原文归档充分消费完原 inode
        if age_sec < compress_delay_sec:
            summary["skipped_recent"] += 1
            continue
        if age_sec >= retention_sec:
            size = st.st_size
            if not dry_run:
                try:
                    path.unlink()
                except OSError as exc:
                    summary["errors"].append(f"unlink {path.name}: {exc}")
                    continue
            summary["deleted_files"] += 1
            summary["deleted_bytes"] += size
            continue
        if summary["compressed_files"] >= max_compress_per_run:
            continue
        try:
            orig_size, new_size = compress_file(path, dry_run)
            summary["compressed_files"] += 1
            if not dry_run:
                summary["compressed_saved_bytes"] += max(0, orig_size - new_size)
        except Exception as exc:
            summary["errors"].append(f"compress {path.name}: {exc}")

    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Zeek 轮转日志延迟压缩与分级过期清理")
    parser.add_argument("--dir", default=os.environ.get("PROXY_SENTINEL_ZEEK_LOG_DIR", "/opt/proxy-sentinel/data/zeek/logs/current"))
    parser.add_argument("--compress-delay-minutes", type=int, default=int(os.environ.get("ZEEK_COMPRESS_DELAY_MINUTES", "35")))
    parser.add_argument("--high-volume-hours", type=int, default=int(os.environ.get("ZEEK_HIGH_VOLUME_RETENTION_HOURS", "24")))
    parser.add_argument("--discovery-hours", type=int, default=int(os.environ.get("ZEEK_DISCOVERY_RETENTION_HOURS", "72")))
    parser.add_argument("--max-compress", type=int, default=int(os.environ.get("ZEEK_MAX_COMPRESS_PER_RUN", "64")))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    result = maintain(
        log_dir=Path(args.dir),
        now_ts=time.time(),
        compress_delay_sec=max(60, args.compress_delay_minutes * 60),
        high_vol_retention_sec=max(3600, args.high_volume_hours * 3600),
        discovery_retention_sec=max(3600, args.discovery_hours * 3600),
        max_compress_per_run=max(1, args.max_compress),
        dry_run=args.dry_run,
    )
    print(json.dumps(result, ensure_ascii=False))
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
