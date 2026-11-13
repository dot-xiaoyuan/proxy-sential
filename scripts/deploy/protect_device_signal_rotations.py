#!/usr/bin/env python3
"""Keep a continuous hard-link chain of completed router-signal gzip rotations.

Run after logrotate exits. The initial ttl-live-* hard link is the recovery
anchor. A new compressed archive is accepted only when the previously protected
archive is still visible at an older numbered active rotation. No source cursor,
epoch, archive contents, or logrotate state is changed by this script.
"""

import argparse
import fcntl
import gzip
import hashlib
import os
from pathlib import Path
import shutil
import stat
import sys


MAX_CHAIN_LINKS = 4096
MAX_ACTIVE_ROTATIONS = 50


def same_file(left: Path, right: Path) -> bool:
    try:
        a, b = left.stat(), right.stat()
    except FileNotFoundError:
        return False
    return a.st_dev == b.st_dev and a.st_ino == b.st_ino


def digest(path: Path, compressed: bool) -> tuple[int, bytes]:
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"not a regular archive: {path}")
    sha = hashlib.sha256()
    length = 0
    opener = gzip.open if compressed else open
    with opener(path, "rb") as stream:
        while block := stream.read(1024 * 1024):
            length += len(block)
            sha.update(block)
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise RuntimeError(f"archive changed during verification: {path}")
    return length, sha.digest()


def chain_path(directory: Path, sequence: int) -> Path:
    return directory / f"ttl-chain-{sequence:012d}.jsonl.gz"


def active_gzip(source: Path, ordinal: int) -> Path:
    return Path(f"{source}.{ordinal}.gz")


def durable_link(source: Path, target: Path) -> None:
    if target.exists():
        if not same_file(source, target):
            raise RuntimeError(f"protected name already belongs to another archive: {target}")
        return
    with source.open("rb") as stream:
        os.fsync(stream.fileno())
        os.link(source, target)
    directory_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def protect(source: Path, recovery: Path) -> str:
    live = list(recovery.glob("ttl-live-*.jsonl"))
    if len(live) != 1:
        raise RuntimeError(f"expected exactly one initial live anchor in {recovery}, found {len(live)}")
    live_anchor = live[0]
    if not live_anchor.is_file():
        raise RuntimeError(f"initial live anchor is missing: {live_anchor}")

    existing = sorted(recovery.glob("ttl-chain-*.jsonl.gz"))
    if len(existing) >= MAX_CHAIN_LINKS:
        raise RuntimeError(f"protected rotation count reached {MAX_CHAIN_LINKS}; verify consumed evidence before cleanup")
    for sequence, path in enumerate(existing):
        if path != chain_path(recovery, sequence):
            raise RuntimeError(f"protected rotation sequence has a gap at {sequence}")

    if not existing:
        # The first gzip is the same source generation as the live hard link.
        # It appears only after delaycompress has finished the second rotation.
        if same_file(live_anchor, source) or same_file(live_anchor, Path(f"{source}.1")):
            return "initial live anchor is still active; waiting for its complete gzip"
        expected = digest(live_anchor, False)
        match = None
        for ordinal in range(2, MAX_ACTIVE_ROTATIONS + 1):
            candidate = active_gzip(source, ordinal)
            if candidate.is_file() and digest(candidate, True) == expected:
                if match is not None:
                    raise RuntimeError("initial live anchor matches multiple active gzip rotations")
                match = (ordinal, candidate)
        if match is None:
            raise RuntimeError("initial live anchor has no verified active gzip successor")
        durable_link(match[1], chain_path(recovery, 0))
        existing = [chain_path(recovery, 0)]

    last = existing[-1]
    active_ordinal = next(
        (ordinal for ordinal in range(2, MAX_ACTIVE_ROTATIONS + 1)
         if same_file(last, active_gzip(source, ordinal))),
        None,
    )
    if active_ordinal is None:
        raise RuntimeError("last protected gzip is outside the active rotation range; continuity cannot be proved")
    appended = 0
    for ordinal in range(active_ordinal - 1, 1, -1):
        candidate = active_gzip(source, ordinal)
        if not candidate.is_file():
            raise RuntimeError(f"missing intermediate gzip rotation: {candidate}")
        sequence = len(existing) + appended
        if sequence >= MAX_CHAIN_LINKS:
            raise RuntimeError(f"protected rotation count reached {MAX_CHAIN_LINKS}")
        # Reading to EOF checks the gzip trailer and that the file is stable.
        digest(candidate, True)
        durable_link(candidate, chain_path(recovery, sequence))
        appended += 1
    free = shutil.disk_usage(recovery).free
    suffix = f"; WARNING free space {free // (1024 ** 3)} GiB" if free < 50 * 1024 ** 3 else ""
    return f"verified chain through {len(existing) + appended - 1}, appended {appended}{suffix}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("recovery_root", type=Path)
    args = parser.parse_args()
    if not args.recovery_root.exists():
        raise RuntimeError(f"packet recovery directory is missing: {args.recovery_root}")
    candidates = [entry for entry in args.recovery_root.iterdir()
                  if entry.is_dir() and list(entry.glob("ttl-live-*.jsonl"))]
    if len(candidates) != 1:
        raise RuntimeError(f"expected one packet recovery epoch, found {len(candidates)}")
    recovery = candidates[0]
    with (recovery / ".ttl-chain.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        print(protect(args.source, recovery))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError) as error:
        print(f"packet rotation protection failed: {error}", file=sys.stderr)
        sys.exit(1)
