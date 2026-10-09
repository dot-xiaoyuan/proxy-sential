#!/usr/bin/env python3
"""Validate a release and reserve filesystem capacity before extracting it."""
import json
import os
import pathlib
import sys
import tarfile

DEFAULT_RESERVE = 1024**3
MIN_RESERVE = 256 * 1024**2
INODE_RESERVE = 1024


def validate(archive_path, release_root, reserve=DEFAULT_RESERVE):
    if not isinstance(reserve, int) or reserve < MIN_RESERVE:
        raise ValueError('release headroom reserve must be at least 256 MiB')
    stat = os.statvfs(release_root)
    available = stat.f_bavail * stat.f_frsize
    paths = set()
    payload_bytes = allocation_bytes = entries = 0
    with tarfile.open(archive_path) as archive:
        for member in archive:
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):
                raise ValueError('unsafe release member: ' + repr(member.name))
            canonical = str(path)
            if canonical in paths:
                raise ValueError('duplicate release member: ' + repr(member.name))
            paths.add(canonical)
            entries += 1
            if member.size < 0:
                raise ValueError('negative release member size')
            if member.isfile():
                payload_bytes += member.size
                allocation_bytes += ((member.size + stat.f_frsize - 1) // stat.f_frsize) * stat.f_frsize
            else:
                allocation_bytes += stat.f_frsize
            if allocation_bytes + reserve > available:
                raise ValueError('insufficient filesystem headroom for release extraction and rollback')
            if entries + INODE_RESERVE > stat.f_favail:
                raise ValueError('insufficient filesystem inode headroom for release extraction')
    if entries == 0:
        raise ValueError('empty release archive')
    return payload_bytes, entries


def main():
    if len(sys.argv) != 3:
        raise ValueError('usage: validate-release-archive.py ARCHIVE RELEASE_ROOT')
    try:
        reserve = int(os.environ.get('PROXY_SENTINEL_UPGRADE_MIN_FREE_BYTES', str(DEFAULT_RESERVE)))
    except ValueError:
        raise ValueError('invalid release headroom reserve') from None
    size, entries = validate(sys.argv[1], sys.argv[2], reserve)
    print(json.dumps({'archive_payload_bytes': size, 'archive_entries': entries, 'reserved_free_bytes': reserve}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, tarfile.TarError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
