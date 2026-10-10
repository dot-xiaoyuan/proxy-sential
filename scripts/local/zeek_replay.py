#!/usr/bin/env python3
"""本地 Zeek 回放辅助工具。

只做纯数据变换：扫描事件时间范围、按单一偏移量平移时间戳、生成回放清单。
不访问网络、不写远端主机。CLI 以 JSON 输出，供 scripts/local/pull-zeek-30.sh 消费。

时间字段兼容两种形态：
- Zeek 自身日志（LogAscii::use_json=T）的 ``ts``，epoch 秒（可含小数）。
- 设备侧边信号（packet-sidecar ttl.jsonl）的 ``timestamp``，RFC3339 UTC。
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

SCHEMA_VERSION = "v1"
MANIFEST_NAME = "manifest.json"


def parse_rfc3339(value: str) -> float:
    """把 RFC3339 时间串转成 epoch 秒；带 Z 或 +08:00 偏移都可以。"""
    text = value.strip()
    if not text:
        raise ValueError("empty timestamp")
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    return dt.datetime.fromisoformat(text).timestamp()


def event_time(obj: object) -> float | None:
    """返回事件时间（epoch 秒）；无法识别时返回 None。"""
    if not isinstance(obj, dict):
        return None
    raw = obj.get("ts")
    if isinstance(raw, bool):
        raw = None
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str):
        try:
            return float(raw)
        except ValueError:
            pass
    stamp = obj.get("timestamp")
    if isinstance(stamp, str):
        try:
            return parse_rfc3339(stamp)
        except ValueError:
            return None
    return None


def format_stamp(when: float) -> str:
    """把 epoch 秒格式化成 RFC3339 UTC，保留原始微秒精度风格。"""
    value = dt.datetime.fromtimestamp(when, dt.timezone.utc)
    text = value.strftime("%Y-%m-%dT%H:%M:%S.%f").rstrip("0").rstrip(".")
    return text + "Z"


def has_numeric_ts(obj: dict) -> bool:
    raw = obj.get("ts")
    return isinstance(raw, (int, float)) and not isinstance(raw, bool)


def has_stamp(obj: dict) -> bool:
    return isinstance(obj.get("timestamp"), str)


def scan_file(path: Path) -> dict:
    """扫描单个 JSONL 文件的事件条数与时间范围。"""
    count = 0
    malformed = 0
    unshiftable = 0
    oldest: float | None = None
    newest: float | None = None
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            count += 1
            when = event_time(obj)
            if when is None:
                unshiftable += 1
                continue
            if oldest is None or when < oldest:
                oldest = when
            if newest is None or when > newest:
                newest = when
    return {
        "name": path.name,
        "bytes": path.stat().st_size,
        "lines": count,
        "malformed": malformed,
        "without_time": unshiftable,
        "oldest_ts": iso_or_empty(oldest),
        "newest_ts": iso_or_empty(newest),
    }


def scan_files(paths: list[Path]) -> dict:
    files = []
    oldest: float | None = None
    newest: float | None = None
    for path in paths:
        item = scan_file(path)
        files.append(item)
        for key, keep in (("oldest_ts", "min"), ("newest_ts", "max")):
            if not item[key]:
                continue
            when = parse_rfc3339(item[key])
            if keep == "min":
                oldest = when if oldest is None or when < oldest else oldest
            else:
                newest = when if newest is None or when > newest else newest
    span = 0.0 if oldest is None or newest is None else max(0.0, newest - oldest)
    return {
        "schema_version": SCHEMA_VERSION,
        "files": files,
        "oldest_ts": iso_or_empty(oldest),
        "newest_ts": iso_or_empty(newest),
        "span_seconds": round(span, 6),
        "lines": sum(item["lines"] for item in files),
        "malformed": sum(item["malformed"] for item in files),
    }


def compute_offset(newest: float, anchor_now: float) -> float:
    """让最新事件落在 anchor_now 的单一全局偏移量。"""
    return anchor_now - newest


def shift_file(path: Path, output: Path, offset: float) -> dict:
    """按 offset 平移单个文件的时间字段，保持行序与 JSON 键序。"""
    shifted = 0
    untouched = 0
    malformed = 0
    passthrough = 0
    output.parent.mkdir(parents=True, exist_ok=True)
    with path.open("r", encoding="utf-8", errors="replace") as source, output.open(
        "w", encoding="utf-8"
    ) as sink:
        for line in source:
            stripped = line.rstrip("\n")
            if not stripped.strip() or stripped.lstrip().startswith("#"):
                sink.write(stripped + "\n")
                passthrough += 1
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                malformed += 1
                sink.write(stripped + "\n")
                continue
            when = event_time(obj)
            if when is None or not isinstance(obj, dict):
                untouched += 1
            else:
                target = when + offset
                if has_numeric_ts(obj):
                    obj["ts"] = target
                if has_stamp(obj):
                    obj["timestamp"] = format_stamp(target)
                shifted += 1
            sink.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")
    return {
        "name": path.name,
        "shifted": shifted,
        "without_time": untouched,
        "malformed": malformed,
        "passthrough": passthrough,
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(
    input_dir: Path,
    output: Path,
    source_host: str,
    source_dir: str,
    sensor_id: str,
    time_shift_seconds: float,
    anchor_now: float | None,
    skipped: list[str],
) -> dict:
    paths = sorted(
        item
        for item in input_dir.iterdir()
        if item.is_file() and item.name != MANIFEST_NAME and item.stat().st_size > 0
    )
    scanned = scan_files(paths)
    files = []
    for item, scan in zip(paths, scanned["files"]):
        files.append(
            {
                "name": item.name,
                "bytes": item.stat().st_size,
                "modified_at": dt.datetime.fromtimestamp(
                    item.stat().st_mtime, dt.timezone.utc
                )
                .isoformat()
                .replace("+00:00", "Z"),
                "sha256": sha256_file(item),
                "lines": scan["lines"],
                "malformed": scan["malformed"],
                "oldest_ts": scan["oldest_ts"],
                "newest_ts": scan["newest_ts"],
            }
        )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "sensor_id": sensor_id,
        "source_host": source_host,
        "source_dir": source_dir,
        "pulled_at": dt.datetime.fromtimestamp(
            anchor_now if anchor_now is not None else dt.datetime.now(dt.timezone.utc).timestamp(),
            dt.timezone.utc,
        )
        .isoformat()
        .replace("+00:00", "Z"),
        "time_shift_seconds": round(time_shift_seconds, 6),
        "files": files,
        "skipped": sorted(skipped),
        "lines": scanned["lines"],
        "malformed": scanned["malformed"],
        "oldest_ts": scanned["oldest_ts"],
        "newest_ts": scanned["newest_ts"],
        "span_seconds": scanned["span_seconds"],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def iso_or_empty(when: float | None) -> str:
    if when is None:
        return ""
    return format_stamp(when)


def _path_list(values: list[str]) -> list[Path]:
    return [Path(value) for value in values]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="本地 Zeek 回放辅助工具")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="扫描 JSONL 文件的事件条数与时间范围")
    scan.add_argument("files", nargs="+")

    shift = sub.add_parser("shift", help="按固定偏移量平移时间字段")
    shift.add_argument("--input", required=True)
    shift.add_argument("--output", required=True)
    anchor = shift.add_mutually_exclusive_group(required=True)
    anchor.add_argument("--offset", type=float)
    anchor.add_argument("--anchor-now", default="")
    shift.add_argument("--newest", default="", help="配合 --anchor-now 使用的当前最新事件时间")

    manifest = sub.add_parser("manifest", help="为回放目录生成清单")
    manifest.add_argument("--input-dir", required=True)
    manifest.add_argument("--output", required=True)
    manifest.add_argument("--source-host", default="")
    manifest.add_argument("--source-dir", default="")
    manifest.add_argument("--sensor-id", default="office-30")
    manifest.add_argument("--time-shift", type=float, default=0.0)
    manifest.add_argument("--anchor-now", default="")
    manifest.add_argument("--skipped", nargs="*", default=[])

    args = parser.parse_args(argv)

    if args.command == "scan":
        print(json.dumps(scan_files(_path_list(args.files)), ensure_ascii=False))
        return 0
    if args.command == "shift":
        if args.offset is not None:
            offset = args.offset
        else:
            if not args.newest:
                parser.error("--anchor-now requires --newest")
            offset = compute_offset(
                parse_rfc3339(args.newest), parse_rfc3339(args.anchor_now)
            )
        result = shift_file(Path(args.input), Path(args.output), offset)
        result["offset_seconds"] = round(offset, 6)
        print(json.dumps(result, ensure_ascii=False))
        return 0

    anchor = parse_rfc3339(args.anchor_now) if args.anchor_now else None
    result = build_manifest(
        input_dir=Path(args.input_dir),
        output=Path(args.output),
        source_host=args.source_host,
        source_dir=args.source_dir,
        sensor_id=args.sensor_id,
        time_shift_seconds=args.time_shift,
        anchor_now=anchor,
        skipped=list(args.skipped),
    )
    print(
        json.dumps(
            {
                "files": len(result["files"]),
                "lines": result["lines"],
                "malformed": result["malformed"],
                "skipped": len(result["skipped"]),
                "oldest_ts": result["oldest_ts"],
                "newest_ts": result["newest_ts"],
                "span_seconds": result["span_seconds"],
                "time_shift_seconds": result["time_shift_seconds"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
