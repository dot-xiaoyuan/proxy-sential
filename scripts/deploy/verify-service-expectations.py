#!/usr/bin/env python3
"""Read-only comparison of declared discovery service intent and systemd state."""
import argparse
import json
from pathlib import Path
import subprocess

UNITS = ("proxy-sentinel-discovery.service", "proxy-sentinel-passive-discovery.service")


def verify(root, inspect=None):
    path = Path(root) / "config" / "service-expectations.json"
    expected = json.loads(path.read_text()) if path.exists() else {}
    if not isinstance(expected, dict) or set(expected) - set(UNITS):
        raise ValueError("unsupported discovery service expectation")
    if any(value not in ("running", "stopped") for value in expected.values()):
        raise ValueError("service intent must be running or stopped")
    if inspect is None:
        def inspect(unit):
            return subprocess.check_output(
                ["systemctl", "show", unit, "-p", "ActiveState", "--value"],
                text=True, timeout=5).strip()
    result = []
    for unit in UNITS:
        state = inspect(unit)
        intent = expected.get(unit, "unspecified")
        matches = None if intent == "unspecified" else (
            state == "active" if intent == "running" else state in ("inactive", "failed"))
        result.append({"unit": unit, "expected": intent, "actual": state, "matches": matches})
    return {"services": result, "expectations_complete": len(expected) == len(UNITS),
            "passed": all(item["matches"] is not False for item in result)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    args = parser.parse_args()
    try:
        result = verify(args.root)
        print(json.dumps(result))
        if not result["passed"]:
            raise SystemExit("discovery service state differs from declared intent; no service was started")
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error))


if __name__ == "__main__":
    main()
