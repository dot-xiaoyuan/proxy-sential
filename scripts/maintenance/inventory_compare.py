#!/usr/bin/env python3
"""Offline inventory reconciliation. Read system CSV from 204-inventory-snapshot.sql."""

import argparse
import csv
import hashlib
import ipaddress
import json
import re
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

LEDGER_COLUMNS = "台账来源 导出时间 传感器 校区 网络域 VLAN VRF".split() + [
    "设备 IP",
    "设备 MAC",
    "设备类型",
    "厂商",
    "型号",
    "资产编号",
    "证据引用",
]
SNAPSHOT_COLUMNS = "record sensor site domain vlan vrf ip mac state device_type model evidence snapshot_at total source_through".split()
OUTPUT_COLUMNS = LEDGER_COLUMNS + [
    "结论",
    "作用域和绑定匹配",
    "原因",
    "系统确认类型",
    "系统确认型号",
    "系统证据引用",
]
SOURCES = {"AC 的 AP 清单": "AC", "交换机台账": "交换机", "一卡通平台": "一卡通"}
AP_RANGE = ipaddress.ip_network("10.161.64.0/18")
TYPES = {
    "ap": "access_point",
    "无线接入点": "access_point",
    "无线ap": "access_point",
    "交换机": "switch",
    "门禁设备": "access_control",
    "摄像机": "camera",
    "打印机": "printer",
    "路由器": "router",
}
MAX_ROWS = 200_000


@dataclass
class Snapshot:
    manifest: dict
    pairs: dict = field(default_factory=lambda: defaultdict(set))
    by_ip: dict = field(default_factory=lambda: defaultdict(set))
    by_mac: dict = field(default_factory=lambda: defaultdict(set))
    scopes: dict = field(default_factory=lambda: defaultdict(set))
    observed_scopes: set = field(default_factory=set)
    references: dict = field(default_factory=lambda: defaultdict(set))


def read_csv(path, columns):
    if path.stat().st_size > 100 * 1024 * 1024:
        raise ValueError(f"{path.name} 超过 100 MiB")
    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = csv.DictReader(stream, strict=True)
        if set(rows.fieldnames or ()) != set(columns) or len(
            rows.fieldnames or ()
        ) != len(columns):
            raise ValueError(f"{path.name} 的表头与模板不符")
        for index, row in enumerate(rows, 1):
            if None in row or index > MAX_ROWS + 1:
                raise ValueError(f"{path.name} 第 {index + 1} 行列数或行数超限")
            # The handover template has source names prefilled on otherwise empty rows.
            yield {name: (row[name] or "").strip() for name in columns}


def timestamp(value):
    if not value:
        raise ValueError("缺时间")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("时间需要时区")
    return stamp


def mac_address(text):
    plain = text.lower().replace("-", ":")
    if (
        not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", plain)
        or int(plain[:2], 16) & 1
        or plain == "00:00:00:00:00:00"
    ):
        raise ValueError("MAC 无效")
    return plain


def vlan_scope(raw):
    if not raw:
        return ""
    tags = raw.split("/")
    if len(tags) > 2 or any(
        not t.isascii() or not t.isdigit() or int(t) > 4094 for t in tags
    ):
        raise ValueError("VLAN 无效")
    return "/".join(str(int(t)) for t in tags)


def read_snapshot(path):
    rows = read_csv(path, SNAPSHOT_COLUMNS)
    meta = next(rows, None)
    if not meta or meta["record"] != "manifest":
        raise ValueError("系统快照缺清单")
    timestamp(meta["snapshot_at"])
    timestamp(meta["source_through"])
    total = int(meta["total"])
    if not 0 <= total <= MAX_ROWS:
        raise ValueError("系统快照超过行数上限")
    snapshot = Snapshot(meta)
    count = 0
    for r in rows:
        count += 1
        scope = (r["sensor"], r["site"], r["domain"], vlan_scope(r["vlan"]), r["vrf"])
        k = r["record"]
        if k not in ("ip", "mac", "binding") or not r["sensor"]:
            raise ValueError("系统快照行类型或传感器无效")
        ip = str(ipaddress.ip_address(r["ip"])) if k in ("ip", "binding") else ""
        mac = mac_address(r["mac"]) if k in ("mac", "binding") else ""
        snapshot.observed_scopes.add(scope)
        for identifier in (ip, mac):
            if identifier:
                snapshot.scopes[identifier].add(scope)
                if r["evidence"]:
                    snapshot.references[scope, identifier].add(r["evidence"])
        if k == "binding":
            snapshot.pairs[(scope, ip, mac)].add(
                (r["state"], r["device_type"], r["model"], r["evidence"])
            )
            snapshot.by_ip[scope, ip].add(mac)
            snapshot.by_mac[scope, mac].add(ip)
    if count != total:
        raise ValueError(f"系统清单记载 {total} 行，实际读取 {count} 行")
    return snapshot


def ledger_key(row):
    timestamp(row["导出时间"])
    if not all(row[k] for k in ("传感器", "校区", "网络域", "VLAN", "证据引用")):
        raise ValueError("缺传感器、校区、网络域、VLAN 或证据引用")
    scope = (
        row["传感器"],
        row["校区"],
        row["网络域"],
        vlan_scope(row["VLAN"]),
        row["VRF"],
    )
    return (
        scope,
        str(ipaddress.ip_address(row["设备 IP"])),
        mac_address(row["设备 MAC"]),
    )


def compare(row, key, duplicate, snapshot):
    scope, ip, mac = key
    matches = snapshot.pairs.get(key, set())
    current = snapshot.by_ip.get((scope, ip), set())
    status, reason = "", ""
    kind, model, refs = "", "", ""
    exact = False
    if duplicate:
        status, reason = (
            "台账重复或冲突",
            "该台账来源中同作用域 IP 多次出现，需核对资产行",
        )
    elif len(current) > 1 or any(s[0] == "binding_conflict" for s in matches):
        status, reason = "系统绑定冲突", "该地址的活动绑定存在冲突"
    elif matches:
        exact = True
        conclusions = {(state, kind, model) for state, kind, model, _ in matches}
        refs = ";".join(sorted({item[3] for item in matches if item[3]}))
        if len(conclusions) > 1 or any(
            state == "product_conflict" for state, _, _ in conclusions
        ):
            status, reason = "系统产品结论冲突", "同身份的产品结论需复核"
        else:
            state, kind, model = conclusions.pop()
            reported = row["设备类型"].casefold()
            if state != "identified" or not kind:
                status, reason = "已观测未定型", "有效绑定一致，系统无已确认类型"
            elif reported and TYPES.get(reported, reported) != kind.casefold():
                status, reason = "类型差异", "精确绑定一致，登记类型和系统确认类型不同"
            elif row["型号"] and model and row["型号"].casefold() != model.casefold():
                status, reason = "型号差异", "精确绑定一致，两份型号不同"
            elif row["型号"] and not model:
                status, reason = "系统缺型号", "精确绑定一致，台账提供型号"
            else:
                status, reason = "匹配", "有效 IP、MAC 和作用域一致"
    elif current or snapshot.by_mac.get((scope, mac)):
        status, reason = "换绑或归属差异", "同作用域存在不同的有效 IP–MAC 配对"
    elif scope in snapshot.scopes.get(ip, ()) or scope in snapshot.scopes.get(mac, ()):
        status, reason = (
            "仅见标识，缺有效绑定",
            "窗口内可见 IP 或 MAC，无法确定为该台设备",
        )
    elif snapshot.scopes.get(ip) or snapshot.scopes.get(mac):
        status, reason = "作用域差异", "标识仅出现于其他作用域或缺 VLAN 的观测"
    elif scope not in snapshot.observed_scopes:
        status, reason = (
            "作用域缺观测",
            "系统快照缺少该作用域的观测，无法判定设备是否可见",
        )
    else:
        status, reason = "窗口内未见标识", "系统指定窗口的普查索引中没有这两个标识"
    if not exact and not duplicate:
        related = snapshot.references.get((scope, ip), set()) | snapshot.references.get(
            (scope, mac), set()
        )
        refs = ";".join(sorted(related))
    reported = row["设备类型"].casefold()
    supplement = (
        row["台账来源"] == "AC 的 AP 清单"
        and ipaddress.ip_address(ip) in AP_RANGE
        and status in ("已观测未定型", "系统缺型号")
        and not model
        and row["型号"]
        and TYPES.get(reported, reported) == "access_point"
    )
    return status, exact, reason, kind, model, refs, bool(supplement)


def write_csv(path, rows):
    with path.open("x", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        for row in rows:
            # Asset names and models are supplied by external spreadsheets.
            writer.writerow(
                {
                    k: (
                        "'" + v
                        if v.lstrip().startswith(("=", "+", "-", "@"))
                        or v.startswith(("\t", "\r", "\n"))
                        else v
                    )
                    for k, v in row.items()
                }
            )


def file_sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(system, files, out):
    if out.exists():
        raise ValueError("输出目录已存在，请指定新的目录")
    index = read_snapshot(system)
    entries = []
    duplicates = Counter()
    for path in files:
        for row in read_csv(path, LEDGER_COLUMNS):
            if not any(row[k] for k in LEDGER_COLUMNS[1:]):
                continue
            if row["台账来源"] not in SOURCES:
                raise ValueError(f"{path.name} 的台账来源不受支持")
            try:
                key, issue = ledger_key(row), ""
                duplicates[(row["台账来源"], *key[:2])] += 1
            except ValueError as error:
                key, issue = None, str(error)
            entries.append((row, key, issue))
            if len(entries) > MAX_ROWS:
                raise ValueError("外部台账总行数超过上限")
    results = defaultdict(list)
    supplements = []
    summary = {
        "system_snapshot": index.manifest["snapshot_at"],
        "source_through": index.manifest["source_through"],
        "system_rows": int(index.manifest["total"]),
        "system_sha256": file_sha(system),
        "ledger_files": [{"file": p.name, "sha256": file_sha(p)} for p in files],
        "sources": {},
    }
    for row, key, issue in entries:
        source = row["台账来源"]
        if key:
            status, exact, reason, kind, model, refs, supplement = compare(
                row, key, duplicates[(source, *key[:2])] > 1, index
            )
        else:
            status, exact, reason, kind, model, refs, supplement = (
                "台账字段待核实",
                False,
                issue,
                "",
                "",
                "",
                False,
            )
        result = dict(
            row,
            结论=status,
            作用域和绑定匹配="是" if exact else "",
            原因=reason,
            系统确认类型=kind,
            系统确认型号=model,
            系统证据引用=refs,
        )
        results[source].append(result)
        if supplement:
            supplements.append(result)
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=out.parent) as tmp:
        stage = Path(tmp) / "result"
        stage.mkdir(mode=0o700)
        for source, file in SOURCES.items():
            rows = results[source]
            counts = dict(Counter(r["结论"] for r in rows))
            summary["sources"][source] = {
                "provided": bool(rows),
                "rows": len(rows),
                "statuses": counts,
                "scoped_matches": sum(r["作用域和绑定匹配"] == "是" for r in rows),
                "differences_or_review": len(rows) - counts.get("匹配", 0),
            }
            if rows:
                write_csv(stage / f"{file}对账.csv", rows)
        if results["AC 的 AP 清单"]:
            write_csv(stage / "AC型号补全清单.csv", supplements)
        summary["ap_model_supplements"] = (
            len(supplements) if results["AC 的 AP 清单"] else None
        )
        (stage / "汇总.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        stage.rename(out)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system", required=True, type=Path)
    parser.add_argument("--ledger", required=True, type=Path, nargs="+")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        run(args.system, args.ledger, args.out)
    except (ValueError, OSError, csv.Error) as err:
        parser.exit(2, f"{err}\n")
