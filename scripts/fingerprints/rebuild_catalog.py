#!/usr/bin/env python3
"""Rebuild byte-for-byte from the bundled pinned raw inputs, without networking.
Run with the same interpreter as build_catalog.py (PyYAML==6.0.3).
Writes a candidate directory, never silently replaces the active embedded data.
"""
import argparse, json, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=True)
    catalog = json.loads(
        (ROOT / "internal/fingerprint/data/multisource-catalog.json").read_text()
    )
    raw = json.loads(
        (ROOT / "internal/fingerprint/data/multisource-provenance.json").read_text()
    )
    with tempfile.TemporaryDirectory(prefix="sentinel-fingerprints-") as d:
        root = Path(d).resolve()
        for name, value in raw.items():
            path = root / name
            if not path.resolve().is_relative_to(root) or ".." in Path(name).parts:
                raise ValueError("unsafe provenance path")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value)
        (root / "versions.json").write_text(
            json.dumps({s["id"]: s["version"] for s in catalog["sources"]})
        )
        for src, dst in {
            "openwrt/toh.json": "toh.complete.json",
            "openwrt/LICENSE": "openwrt-LICENSE",
            "p0f/COPYING": "p0f-COPYING",
            "p0f/README": "p0f-README",
        }.items():
            (root / dst).write_text(raw[src])
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/fingerprints/build_catalog.py"),
                "--snapshots",
                str(root),
                "--output",
                str(a.output.resolve()),
            ],
            check=True,
        )
        with (a.output / "catalog-input.json").open("rb") as source, (
            a.output / "multisource-catalog.json"
        ).open("wb") as target:
            subprocess.run(
                ["go", "run", "./cmd/fingerprint-catalog-compile"],
                cwd=ROOT,
                stdin=source,
                stdout=target,
                check=True,
            )
        for name in ["multisource-catalog.json", "multisource-provenance.json"]:
            # JSON object ordering does not affect the per-source digest.
            if json.loads((a.output / name).read_text()) != json.loads(
                (ROOT / "internal/fingerprint/data" / name).read_text()
            ):
                raise SystemExit("rebuild differs: " + name)
        print("Rebuild verified: complete catalog and preserved input match.")


if __name__ == "__main__":
    main()
