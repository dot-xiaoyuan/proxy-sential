#!/usr/bin/env python3
"""Create a deterministic, redacted Suricata EVE JSONL fixture sample."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any


DOMAIN_KEYS = {
    "rrname",
    "query",
    "hostname",
    "host",
    "sni",
    "url",
}
USER_KEYS = {
    "user",
    "username",
    "user_id",
    "userid",
    "email",
    "src_user",
    "dest_user",
}
MAC_KEYS = {"mac", "src_mac", "dest_mac", "dhcp_client_mac"}
IP_KEY_HINTS = ("ip", "addr")
CORE_TYPES = {"flow", "dns", "tls", "http", "quic", "alert"}
DOMAIN_RE = re.compile(r"(?i)\b([a-z0-9-]+\.)+[a-z]{2,}\b")


class Redactor:
    def __init__(self) -> None:
        self.ip_map: dict[str, str] = {}
        self.domain_map: dict[str, str] = {}
        self.user_map: dict[str, str] = {}
        self.mac_map: dict[str, str] = {}

    def ip(self, value: str) -> str:
        if value not in self.ip_map:
            idx = len(self.ip_map) + 1
            host = ((idx - 1) % 250) + 1
            block = (idx - 1) // 250
            try:
                parsed = ipaddress.ip_address(value)
            except ValueError:
                return value

            if parsed.version == 4:
                if parsed.is_private:
                    mapped = f"10.255.{block}.{host}"
                else:
                    mapped = f"198.51.100.{host}"
            else:
                mapped = f"2001:db8::{idx}"
            self.ip_map[value] = mapped
        return self.ip_map[value]

    def domain(self, value: str) -> str:
        normalized = value.rstrip(".")
        if normalized not in self.domain_map:
            self.domain_map[normalized] = f"domain-{len(self.domain_map) + 1:04d}.example.test"
        redacted = self.domain_map[normalized]
        return redacted + ("." if value.endswith(".") else "")

    def user(self, value: Any) -> str:
        text = str(value)
        if text not in self.user_map:
            self.user_map[text] = f"user-{len(self.user_map) + 1:04d}"
        return self.user_map[text]

    def mac(self, value: str) -> str:
        if value not in self.mac_map:
            idx = len(self.mac_map) + 1
            self.mac_map[value] = f"02:00:00:00:{idx // 256:02x}:{idx % 256:02x}"
        return self.mac_map[value]

    def string_value(self, key: str, value: str) -> str:
        lower_key = key.lower()

        if lower_key in MAC_KEYS:
            return self.mac(value)

        if lower_key in USER_KEYS:
            return self.user(value)

        if lower_key in DOMAIN_KEYS:
            return DOMAIN_RE.sub(lambda m: self.domain(m.group(0)), value)

        if any(hint in lower_key for hint in IP_KEY_HINTS):
            return self.ip(value)

        if "agent" in lower_key:
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
            return f"redacted-user-agent/{digest}"

        return DOMAIN_RE.sub(lambda m: self.domain(m.group(0)), value)

    def redact(self, value: Any, key: str = "") -> Any:
        if isinstance(value, dict):
            return {k: self.redact(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [self.redact(item, key) for item in value]
        if isinstance(value, str):
            return self.string_value(key, value)
        return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Source Suricata EVE JSONL file")
    parser.add_argument("--output", required=True, help="Redacted JSONL output path")
    parser.add_argument("--limit", type=int, default=1000, help="Maximum output lines")
    parser.add_argument("--min-lines", type=int, default=200, help="Warn if fewer lines are produced")
    parser.add_argument(
        "--event-types",
        default=",".join(sorted(CORE_TYPES)),
        help="Comma-separated Suricata event types to include",
    )
    parser.add_argument(
        "--per-type-limit",
        type=int,
        default=0,
        help="Maximum output lines per event type. Default: disabled",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    src = Path(args.input)
    dst = Path(args.output)
    redactor = Redactor()
    emitted = 0
    malformed = 0
    selected_types = {item.strip() for item in args.event_types.split(",") if item.strip()}
    emitted_by_type: dict[str, int] = {}

    if not selected_types:
        print("at least one --event-types value is required", file=sys.stderr)
        return 2

    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open("r", encoding="utf-8") as infile, dst.open("w", encoding="utf-8") as outfile:
        for line in infile:
            if emitted >= args.limit:
                break
            stripped = line.strip()
            if not stripped:
                continue
            try:
                event = json.loads(stripped)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if not isinstance(event, dict):
                continue
            event_type = event.get("event_type")
            if event_type not in selected_types:
                continue
            if args.per_type_limit > 0 and emitted_by_type.get(event_type, 0) >= args.per_type_limit:
                continue
            outfile.write(json.dumps(redactor.redact(event), ensure_ascii=False, separators=(",", ":")) + "\n")
            emitted += 1
            emitted_by_type[event_type] = emitted_by_type.get(event_type, 0) + 1

    print(f"wrote {emitted} redacted lines to {dst}", file=sys.stderr)
    if malformed:
        print(f"skipped {malformed} malformed lines", file=sys.stderr)
    if emitted < args.min_lines:
        print(f"warning: emitted fewer than {args.min_lines} lines", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
