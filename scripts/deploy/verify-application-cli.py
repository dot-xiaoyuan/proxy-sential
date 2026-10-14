#!/usr/bin/env python3
"""Check active unit flags against candidate help before switching current.

Only flag names are reported. Environment files and credential values are not read.
"""
import argparse
import json
from pathlib import Path
import re
import runpy
import shlex
import subprocess


def invocation(value):
    match = re.search(r"argv\[\]=(.*?) ; ignore_errors=", value)
    if not match:
        raise ValueError("cannot inspect unit invocation")
    args = shlex.split(match[1])
    prefix = []
    for arg in args[1:]:
        if arg.startswith("-"):
            break
        prefix.append(arg)
    flags = {arg.split("=", 1)[0].lstrip("-") for arg in args[1:] if arg.startswith("-")}
    return args[0], prefix, flags


def verify(stage, units):
    binaries = runpy.run_path(str(Path(__file__).with_name("verify-application-runtime.py")))["UNIT_BINARIES"]
    result = []
    for unit in units:
        if unit not in binaries:
            raise ValueError("unsupported application unit")
        value = subprocess.check_output(["systemctl", "show", unit, "-p", "ExecStart", "--value"], text=True, timeout=5)
        executable, prefix, flags = invocation(value)
        if Path(executable).name != binaries[unit]:
            raise ValueError("unexpected executable: " + unit)
        help_result = subprocess.run([str(Path(stage) / "bin" / binaries[unit]), *prefix, "--help"], capture_output=True, text=True, timeout=15)
        supported = set(re.findall(r"^\s+--?([\w-]+)(?:\s|=|$)", help_result.stdout + help_result.stderr, re.M))
        missing = sorted(flags - supported)
        if missing:
            raise ValueError("candidate lacks unit flags: " + unit + ": " + ", ".join(missing))
        result.append({"unit": unit, "checked_flags": len(flags)})
    return {"verified_application_cli": result}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--units", nargs="+", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.stage, args.units)))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error))
