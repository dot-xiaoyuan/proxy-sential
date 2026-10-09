#!/usr/bin/env python3
"""Retire verified old application copies, preserving local restore archives."""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import time
import uuid

# Early installer releases use descriptive suffixes. Their manifest, exact
# content snapshot and restore archive receive the same checks as numbered ones.
VERSION = re.compile(r'\d{4}\.\d{2}\.\d{2}-[A-Za-z0-9][A-Za-z0-9._-]{0,63}')


def valid_version(version):
    if not isinstance(version, str) or '..' in version or not VERSION.fullmatch(version):
        return False
    try:
        datetime.date.fromisoformat(version[:10].replace('.', '-'))
    except ValueError:
        return False
    return True


def digest_file(path):
    with path.open('rb') as source:
        return digest_stream(source)


def digest_stream(source):
    digest = hashlib.sha256()
    for block in iter(lambda: source.read(256*1024), b''):
        digest.update(block)
    return digest.hexdigest()


def safe_member(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or str(path) != name:
        raise ValueError('unsafe release contents')
    return name


def active_executables():
    result = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        for name in ['exe', 'cwd', 'root']:
            try:
                result.append(os.readlink(entry/name).removesuffix(' (deleted)'))
            except FileNotFoundError:
                pass
        try:
            for descriptor in (entry/'fd').iterdir():
                try:
                    result.append(os.readlink(descriptor).removesuffix(' (deleted)'))
                except FileNotFoundError:
                    pass
            for line in (entry/'maps').read_text().splitlines():
                fields = line.split(None, 5)
                if len(fields) == 6 and fields[5].startswith('/'):
                    result.append(fields[5].removesuffix(' (deleted)'))
        except FileNotFoundError:
            pass
        # Other failures are not proof that an executable is unused.
    return result


def unit_definitions(root=None):
    result = []
    for base in [Path('/etc/systemd/system'), Path('/usr/lib/systemd/system')]:
        for pattern in ['*.service', '*.timer', '*.service.d/*.conf', '*.timer.d/*.conf']:
            for path in base.glob(pattern):
                if path.is_file():
                    result.append(path.read_bytes())
    if root is not None:
        config = root/'config'
        if config.is_symlink():
            raise ValueError('application config directory is symlink')
        if config.exists():
            for path in config.rglob('*'):
                if path.is_symlink():
                    result.append(str(path.resolve(strict=True)).encode())
                elif path.is_file():
                    result.append(path.read_bytes())
    return result


def release_referenced(directory, active_paths, unit_contents):
    target = str(directory)
    # A process or configuration can reference the directory itself, without
    # a trailing slash. Keep a component boundary so r8 does not match r80.
    if any(path == target or path.startswith(target+'/') for path in active_paths):
        return True
    reference = re.compile(re.escape(target.encode())+rb'(?![A-Za-z0-9._-])')
    return any(reference.search(content) for content in unit_contents)


def tree_signature(directory):
    files, dirs = {}, {'.'}
    for path in directory.rglob('*'):
        if path.is_symlink():
            raise ValueError('release contains symlink')
        relative = str(path.relative_to(directory))
        stat = path.stat()
        if path.is_file():
            files[relative] = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_mode, stat.st_uid, stat.st_gid)
        elif path.is_dir():
            dirs.add(relative)
        else:
            raise ValueError('release contains nonregular entry')
    return files, dirs


def protected_releases(root):
    protected = set()
    for name in ['current', 'previous', 'frontend-previous']:
        pointer = root/name
        if name == 'frontend-previous' and not pointer.exists() and not pointer.is_symlink():
            continue
        if not pointer.is_symlink():
            raise ValueError('protected release pointer missing')
        target = pointer.resolve(strict=True)
        if target.parent != root/'releases':
            raise ValueError('protected pointer outside releases')
        protected.add(target)
    return protected


def validate(root, plan, active_paths=None, unit_contents=None):
    if plan.get('schema_version') != 1 or plan.get('root') != str(root):
        raise ValueError('plan root or schema mismatch')
    for path in [root, root/'releases', root/'data', root/'data/release-backups']:
        if path.is_symlink() or not path.is_dir():
            raise ValueError('invalid retirement root')
    protected = protected_releases(root)
    active_paths = active_executables() if active_paths is None else active_paths
    unit_contents = unit_definitions(root) if unit_contents is None else unit_contents
    result, seen = [], set()
    for item in plan.get('releases', []):
        version = item['version']
        if not valid_version(version) or version in seen:
            raise ValueError('invalid or duplicate release version')
        seen.add(version)
        directory = root/'releases'/version
        if directory in protected or release_referenced(directory, active_paths, unit_contents):
            raise ValueError('protected release: '+version)
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError('release directory missing or symlink')
        expected = {safe_member(name): digest for name, digest in item['files'].items()}
        expected_dirs = {safe_member(name) for name in item['directories']}
        backup = root/'data/release-backups'/('proxy-sentinel-'+version+'.tar.gz')
        if backup.is_symlink() or not backup.is_file() or digest_file(backup) != item['archive_sha256']:
            raise ValueError('restore backup checksum mismatch: '+version)
        restored, restore_dirs, restore_metadata = {}, {'.'}, {}
        try:
            with tarfile.open(backup) as archive:
                for member in archive:
                    name = str(PurePosixPath(member.name))
                    safe_member(name)
                    if member.isdir():
                        restore_dirs.add(name)
                    elif member.isfile() and name not in restored:
                        restored[name] = digest_stream(archive.extractfile(member))
                        restore_metadata[name] = {'mode':member.mode,'uid':member.uid,'gid':member.gid}
                    else:
                        raise ValueError('unsafe restore backup')
        except tarfile.TarError as error:
            raise ValueError('invalid restore backup') from error
        if restored != expected or restore_dirs != expected_dirs:
            raise ValueError('restore backup contents mismatch')
        metadata = item.get('file_metadata')
        if metadata is not None and restore_metadata != metadata:
            raise ValueError('restore backup file metadata mismatch')
        files, dirs = tree_signature(directory)
        allowed = set(expected)
        deployment = None
        if 'deployment-manifest.json' in files and 'deployment-manifest.json' not in expected:
            deployment = json.loads((directory/'deployment-manifest.json').read_text())
            if deployment.get('version') != version:
                raise ValueError('deployment version mismatch')
            allowed.add('deployment-manifest.json')
        if set(files) != allowed or dirs != expected_dirs:
            raise ValueError('unexpected release contents: '+version)
        for name, digest in expected.items():
            if digest_file(directory/name) != digest:
                raise ValueError('release payload mismatch: '+version)
            if metadata is not None:
                current = (directory/name).stat()
                if metadata[name] != {'mode':stat.S_IMODE(current.st_mode),'uid':current.st_uid,'gid':current.st_gid}:
                    raise ValueError('release file metadata mismatch: '+version)
        manifest = json.loads((directory/'release-manifest.json').read_text())
        if manifest.get('version') != version or manifest.get('os') != 'linux' or manifest.get('arch') != 'amd64':
            raise ValueError('release identity mismatch')
        result.append({'directory':directory, 'signature':(files,dirs), 'backup':backup, 'backup_signature':(backup.stat().st_dev,backup.stat().st_ino,backup.stat().st_size,backup.stat().st_mtime_ns), 'archive_sha256':item['archive_sha256'], 'manifest':manifest, 'deployment':deployment})
    return result


def apply(root, candidates, active_paths=None, unit_contents=None):
    protected = protected_releases(root)
    active_paths = active_executables() if active_paths is None else active_paths
    unit_contents = unit_definitions(root) if unit_contents is None else unit_contents
    # Recheck every candidate before removing any directory.
    for candidate in candidates:
        if candidate['directory'] in protected or release_referenced(candidate['directory'], active_paths, unit_contents):
            raise ValueError('protected release changed after validation')
        backup = candidate['backup']
        if backup.is_symlink() or not backup.is_file():
            raise ValueError('restore backup removed after validation')
        stat = backup.stat()
        if (stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns) != candidate['backup_signature']:
            raise ValueError('restore backup changed after validation')
        if tree_signature(candidate['directory']) != candidate['signature']:
            raise ValueError('release contents changed after validation')
    audit_dir = root/'data/release-retirement-audit'
    if audit_dir.is_symlink():
        raise ValueError('audit directory is symlink')
    audit_dir.mkdir(exist_ok=True)
    audit_path = audit_dir/(str(time.time_ns())+'-'+uuid.uuid4().hex+'.jsonl')
    retired = payload_bytes = 0
    with audit_path.open('x') as audit:
        for candidate in candidates:
            if candidate['directory'] in protected_releases(root):
                raise ValueError('protected release changed before retirement')
            version = candidate['directory'].name
            record = {'version':version,'restore_archive':str(candidate['backup']),'archive_sha256':candidate['archive_sha256'],'release_manifest':candidate['manifest'],'deployment_manifest':candidate['deployment'],'phase':'validated'}
            audit.write(json.dumps(record)+'\n');audit.flush();os.fsync(audit.fileno())
            shutil.rmtree(candidate['directory'])
            payload_bytes += sum(stat[2] for stat in candidate['signature'][0].values())
            retired += 1
            audit.write(json.dumps({'version':version,'phase':'retired'})+'\n');audit.flush();os.fsync(audit.fileno())
    return {'retired_releases':retired,'removed_owned_file_bytes':payload_bytes,'audit':str(audit_path),'os_space_reclaimed':'not_measured'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan',required=True)
    parser.add_argument('--apply',action='store_true')
    args = parser.parse_args()
    plan = json.loads(Path(args.plan).read_text())
    root = Path(plan['root'])
    if not re.fullmatch(r'/opt/[A-Za-z0-9_./-]+',str(root)) or '..' in root.parts:
        raise ValueError('invalid application root')
    if root.is_symlink() or (root/'config').is_symlink() or not (root/'config').is_dir():
        raise ValueError('invalid application lock directory')
    if (root/'config/application-upgrade.lock').is_symlink():
        raise ValueError('application lock is symlink')
    with (root/'config/application-upgrade.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        candidates = validate(root,plan)
        print(json.dumps({'phase':'validated','releases':len(candidates),'versions':[c['directory'].name for c in candidates]}),flush=True)
        if args.apply:
            print(json.dumps(apply(root,candidates)),flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError,ValueError,KeyError,tarfile.TarError) as error:
        raise SystemExit(str(error))
