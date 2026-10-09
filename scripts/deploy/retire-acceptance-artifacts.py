#!/usr/bin/env python3
"""Retire individually backed-up temporary acceptance binaries and old packages."""
import argparse
from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import time
import uuid

MIN_BYTES = 8 * 1024 * 1024
PACKAGE = re.compile(r'proxy-sentinel-(\d{4}\.\d{2}\.\d{2}-release-r\d+)\.tar\.gz')


def signature(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def open_directory(path, stack):
    if not Path(path).is_absolute():
        raise ValueError('absolute directory required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    stack.callback(os.close, fd)
    for part in Path(path).parts[1:]:
        if part in ('.', '..'):
            raise ValueError('unsafe directory path')
        fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        stack.callback(os.close, fd)
    return fd


def child_directory(parent, name, stack, create=False):
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
        except FileExistsError:
            pass
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    stack.callback(os.close, fd)
    return fd


def digest(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256()
    for block in iter(lambda: os.read(fd, 1024 * 1024), b''):
        h.update(block)
    return h.hexdigest()


def active_inodes():
    result = set()
    for entry in Path('/proc').iterdir():
        if entry.name.isdigit():
            try:
                info = (entry / 'exe').stat()
                result.add((info.st_dev, info.st_ino))
            except FileNotFoundError:
                pass
            # Other failures must not be treated as proof of disuse.
    return result


def referenced_by_units(root):
    for base in (Path('/etc/systemd/system'), Path('/usr/lib/systemd/system')):
        for pattern in ('*.service', '*.timer', '*.service.d/*.conf', '*.timer.d/*.conf'):
            for path in base.glob(pattern):
                if path.is_file() and str(root).encode() in path.read_bytes():
                    return True
    return False


def protected_versions(application):
    result = set()
    for name in ('current', 'previous'):
        pointer = application / name
        if not pointer.is_symlink():
            raise ValueError('protected application pointer missing')
        target = pointer.resolve(strict=True)
        if target.parent != application / 'releases':
            raise ValueError('protected pointer outside release directory')
        result.add(target.name)
    return result


def safe_relative(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or '..' in path.parts or str(path) != name or not re.fullmatch(r'[A-Za-z0-9_./-]+', name):
        raise ValueError('unsafe temporary artifact path')
    if name.startswith('.') or path.parts[0] == 'bin':
        raise ValueError('reserved temporary artifact path')
    return path


def verify_type(fd, path, versions):
    os.lseek(fd, 0, os.SEEK_SET)
    header = os.read(fd, 64)
    if header.startswith(b'\x7fELF'):
        if len(header) != 64 or header[4:7] != b'\x02\x01\x01' or int.from_bytes(header[18:20], 'little') != 62 or int.from_bytes(header[16:18], 'little') not in (2, 3):
            raise ValueError('unexpected acceptance executable format')
        return None
    package = PACKAGE.fullmatch(path.name)
    if not package or header[:2] != b'\x1f\x8b' or package[1] in versions:
        raise ValueError('unsupported or protected temporary package')
    os.lseek(fd, 0, os.SEEK_SET)
    with os.fdopen(os.dup(fd), 'rb') as source, tarfile.open(fileobj=source, mode='r:gz') as archive:
        matches = [m for m in archive if str(PurePosixPath(m.name)) == 'release-manifest.json']
        if len(matches) != 1 or not matches[0].isfile() or matches[0].size > 65536:
            raise ValueError('invalid package identity')
        manifest = json.load(archive.extractfile(matches[0]))
        if manifest.get('version') != package[1] or manifest.get('os') != 'linux' or manifest.get('arch') != 'amd64':
            raise ValueError('package identity mismatch')
    return package[1]


def validate(root, application, plan, stack, active=None, unit_reference=None):
    if plan.get('schema_version') != 1 or plan.get('root') != str(root) or plan.get('application_root') != str(application):
        raise ValueError('plan identity mismatch')
    root_fd = open_directory(root, stack)
    active = active_inodes() if active is None else active
    if referenced_by_units(root) if unit_reference is None else unit_reference:
        raise ValueError('temporary root referenced by service definition')
    versions = protected_versions(application)
    candidates, seen = [], set()
    parents = {'.': root_fd}
    for item in plan.get('items', []):
        relative = safe_relative(item['path'])
        if item['path'] in seen:
            raise ValueError('duplicate retirement path')
        seen.add(item['path'])
        backup = item['backup']
        if not isinstance(backup.get('path'), str) or not backup['path'].startswith('/') or backup.get('sha256') != item['sha256'] or backup.get('bytes') != item['bytes'] or not re.fullmatch(r'[0-9a-f]{64}', item['sha256']):
            raise ValueError('matching local backup attestation required')
        parent_fd = root_fd
        prefix = PurePosixPath('.')
        for part in relative.parts[:-1]:
            prefix /= part
            key = str(prefix)
            if key not in parents:
                parents[key] = child_directory(parent_fd, part, stack)
            parent_fd = parents[key]
        fd = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        stack.callback(os.close, fd)
        info = os.fstat(fd)
        expected = (item['device'], item['inode'], item['bytes'], item['mtime_ns'])
        if not stat.S_ISREG(info.st_mode) or info.st_size < MIN_BYTES or info.st_nlink != 1 or signature(info) != expected:
            raise ValueError('temporary artifact identity changed')
        if (info.st_dev, info.st_ino) in active:
            raise ValueError('temporary executable is running')
        version = verify_type(fd, relative, versions)
        if digest(fd) != item['sha256'] or signature(os.fstat(fd)) != expected:
            raise ValueError('temporary artifact checksum changed')
        candidates.append({'item': item, 'fd': fd, 'parent_fd': parent_fd, 'name': relative.name, 'signature': expected, 'version': version})
    return root_fd, candidates


def apply(root, application, root_fd, candidates, stack, active=None, unit_reference=None, after_stage=None):
    if referenced_by_units(root) if unit_reference is None else unit_reference:
        raise ValueError('temporary root referenced before retirement')
    data_fd = open_directory(application / 'data', stack)
    audit_fd = child_directory(data_fd, 'acceptance-artifact-retirement-audit', stack, create=True)
    os.fsync(data_fd)
    token = str(time.time_ns()) + '-' + uuid.uuid4().hex
    audit_file_fd = os.open(token + '.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=audit_fd)
    audit = stack.enter_context(os.fdopen(audit_file_fd, 'w'))
    os.fsync(audit_fd)
    def record(value):
        audit.write(json.dumps(value) + '\n')
        audit.flush()
        os.fsync(audit.fileno())
    staging_name = '.retirement-staging-' + token
    os.mkdir(staging_name, 0o700, dir_fd=root_fd)
    os.fsync(root_fd)
    stage_fd = child_directory(root_fd, staging_name, stack)
    staged = []
    retired = 0
    try:
        for i, candidate in enumerate(candidates):
            name = str(i)
            record({'phase': 'stage_requested', 'source': candidate['item']['path'], 'staging': staging_name + '/' + name, 'sha256': candidate['item']['sha256'], 'backup': candidate['item']['backup']})
            os.rename(candidate['name'], name, src_dir_fd=candidate['parent_fd'], dst_dir_fd=stage_fd)
            staged.append((candidate, name))
            os.fsync(candidate['parent_fd'])
            os.fsync(stage_fd)
            info = os.stat(name, dir_fd=stage_fd, follow_symlinks=False)
            if signature(info) != candidate['signature'] or not stat.S_ISREG(info.st_mode):
                raise ValueError('candidate replaced during staging')
        if after_stage is not None:
            after_stage(staging_name)
        if referenced_by_units(root) if unit_reference is None else unit_reference:
            raise ValueError('temporary root became referenced while staging')
        running = active_inodes() if active is None else active
        versions = protected_versions(application)
        # Validate the entire staged set before unlinking any file. The private
        # rename prevents deleting a concurrent replacement at its original name.
        for candidate, name in staged:
            info = os.stat(name, dir_fd=stage_fd, follow_symlinks=False)
            if signature(info) != candidate['signature'] or (info.st_dev, info.st_ino) in running or candidate['version'] in versions:
                raise ValueError('staged artifact changed or became protected')
            if digest(candidate['fd']) != candidate['item']['sha256'] or signature(os.fstat(candidate['fd'])) != candidate['signature']:
                raise ValueError('staged artifact checksum changed')
        for candidate, name in staged:
            if referenced_by_units(root) if unit_reference is None else unit_reference:
                raise ValueError('temporary root became referenced before unlink')
            running = active_inodes() if active is None else active
            info = os.stat(name, dir_fd=stage_fd, follow_symlinks=False)
            if signature(info) != candidate['signature'] or (info.st_dev, info.st_ino) in running or candidate['version'] in protected_versions(application):
                raise ValueError('staged artifact became protected before unlink')
            record({'phase': 'verified_before_unlink', 'source': candidate['item']['path']})
            os.unlink(name, dir_fd=stage_fd)
            os.fsync(stage_fd)
            retired += 1
            record({'phase': 'retired', 'source': candidate['item']['path'], 'bytes': candidate['item']['bytes']})
    except BaseException:
        # Restore surviving files without overwriting new files at their original
        # names. Collisions remain recoverable in the private staging directory.
        for candidate, name in staged:
            try:
                os.stat(name, dir_fd=stage_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            try:
                os.link(name, candidate['name'], src_dir_fd=stage_fd, dst_dir_fd=candidate['parent_fd'], follow_symlinks=False)
                os.fsync(candidate['parent_fd'])
                os.unlink(name, dir_fd=stage_fd)
                os.fsync(stage_fd)
                record({'phase': 'restored', 'source': candidate['item']['path']})
            except FileExistsError:
                record({'phase': 'restore_collision', 'source': candidate['item']['path'], 'staging': staging_name + '/' + name})
        raise
    finally:
        try:
            os.rmdir(staging_name, dir_fd=root_fd)
            os.fsync(root_fd)
        except OSError:
            record({'phase': 'staging_retained', 'path': staging_name})
    return {'retired_files': retired, 'removed_owned_file_bytes': sum(c['item']['bytes'] for c in candidates), 'audit': str(application / 'data/acceptance-artifact-retirement-audit' / (token + '.jsonl')), 'space_reclaimed': 'not_measured'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    plan = json.loads(Path(args.plan).read_text())
    root, application = Path(plan['root']), Path(plan['application_root'])
    if not re.fullmatch(r'/tmp/sentinel-release-acceptance-30-\d{8}', str(root)) or application != Path('/opt/proxy-sentinel'):
        raise ValueError('retirement restricted to the owned 30 acceptance root')
    with ExitStack() as stack:
        config_fd = open_directory(application / 'config', stack)
        lock = os.open('application-upgrade.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=config_fd)
        stack.callback(os.close, lock)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        root_fd, candidates = validate(root, application, plan, stack)
        print(json.dumps({'phase': 'validated', 'files': len(candidates), 'owned_file_bytes': sum(c['item']['bytes'] for c in candidates)}), flush=True)
        if args.apply:
            print(json.dumps(apply(root, application, root_fd, candidates, stack)), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        raise SystemExit(str(error))
