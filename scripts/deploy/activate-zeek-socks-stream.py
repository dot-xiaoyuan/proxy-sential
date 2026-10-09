#!/usr/bin/env python3
"""Activate a checked native collector with rollback and producer epoch refresh."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.request

PREFIX = 'Sentinel_SOCKSStream/'
PAYLOAD = {PREFIX + path for path in ('__zeek_plugin__', 'scripts/__load__.zeek', 'scripts/main.zeek', 'scripts/dpd.sig', 'lib/Sentinel-SOCKSStream.linux-x86_64.so')}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def parse_version(output):
    pieces = output.strip().rsplit(' version ',1)
    if len(pieces) != 2 or Path(pieces[0]).name != 'zeek' or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',pieces[1]):
        raise ValueError('unexpected Zeek version output')
    return pieces[1]


def validate_payload(archive, manifest):
    if sha(archive.read_bytes()) != manifest['archive_sha256']:
        raise ValueError('collector archive checksum mismatch')
    if set(manifest['payload_files']) != PAYLOAD:
        raise ValueError('unexpected collector payload manifest')
    content = {}
    with tarfile.open(archive) as package:
        seen = set()
        for member in package.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or member.name in seen:
                raise ValueError('invalid or duplicate collector archive member')
            seen.add(member.name)
            if member.isdir() and str(path) in {PREFIX.rstrip('/'), PREFIX+'scripts', PREFIX+'lib'}:
                continue
            if not member.isfile() or member.name not in PAYLOAD or member.size > 2*1024*1024:
                raise ValueError('unexpected collector archive member')
            data = package.extractfile(member).read()
            if sha(data) != manifest['payload_files'][member.name]:
                raise ValueError('collector payload checksum mismatch')
            content[member.name] = data
    if set(content) != PAYLOAD:
        raise ValueError('collector archive incomplete')
    return content



def installed_payload(target, manifest):
    if target.is_symlink() or not target.is_dir() or set(manifest['payload_files']) != PAYLOAD:
        raise ValueError('invalid installed collector directory')
    if target.name != 'Sentinel_SOCKSStream-'+manifest['archive_sha256'][:16]:
        raise ValueError('installed collector path does not match its manifest')
    for name, digest in manifest['payload_files'].items():
        path = target/name.removeprefix(PREFIX)
        if path.is_symlink() or not path.is_file() or sha(path.read_bytes()) != digest:
            raise ValueError('installed collector payload changed')


def managed_target(text, parent):
    expression = r'\[Service\]\nEnvironment="ZEEK_PLUGIN_PATH=('+re.escape(str(parent))+r'/Sentinel_SOCKSStream-[a-f0-9]{16})"\n'
    match = re.fullmatch(expression,text)
    if not match:
        raise ValueError('existing collector configuration is not managed by this installer')
    target = Path(match.group(1))
    if target.parent.resolve() != parent or target.resolve() != target:
        raise ValueError('managed collector path is indirect')
    return target


def replace_dropin(path, expected, replacement):
    # Stage a complete durable file before publication; a partial write must
    # never replace the systemd configuration used at the next restart.
    if path.is_symlink():
        raise ValueError('collector configuration cannot be a symlink')
    current = path.read_bytes() if path.exists() else None
    if current != expected:
        raise ValueError('collector configuration changed externally')
    if replacement is None:
        path.unlink()
    else:
        fd, temporary = tempfile.mkstemp(prefix='.socks-stream-',dir=path.parent)
        temporary = Path(temporary)
        try:
            with os.fdopen(fd,'wb') as stream:
                stream.write(replacement); stream.flush(); os.fsync(stream.fileno())
                os.fchmod(stream.fileno(),0o644)
            if (path.read_bytes() if path.exists() else None) != expected:
                raise ValueError('collector configuration changed before publication')
            if expected is None:
                os.link(temporary,path)
            else:
                os.replace(temporary,path)
        finally:
            temporary.unlink(missing_ok=True)
    directory = os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)


def switch_collector(dropin, previous, replacement, refresh):
    replace_dropin(dropin,previous,replacement)
    try:
        refresh()
    except BaseException:
        replace_dropin(dropin,replacement,previous)
        refresh()
        raise


def verify_mapped(target, manifest):
    pid = int(subprocess.check_output(['systemctl','show','proxy-sentinel-zeek.service','--property=MainPID','--value'],text=True))
    paths = {line.split()[-1] for line in Path('/proc/'+str(pid)+'/maps').read_text().splitlines() if 'Sentinel-SOCKSStream.linux-x86_64.so' in line}
    wanted = target/'lib/Sentinel-SOCKSStream.linux-x86_64.so'
    if paths != {str(wanted)} or sha(wanted.read_bytes()) != manifest['payload_files'][PREFIX+'lib/Sentinel-SOCKSStream.linux-x86_64.so']:
        raise RuntimeError('running Zeek did not load the checked collector')


def run(argv, timeout=30, **kwargs):
    return subprocess.run(argv, check=True, timeout=timeout, **kwargs)


def active():
    for unit in ('zeek', 'ingest', 'control-plane', 'suricata'):
        run(['systemctl', 'is-active', '--quiet', 'proxy-sentinel-'+unit+'.service'])
    with urllib.request.urlopen('http://127.0.0.1:18080/readyz', timeout=5) as response:
        if response.status != 200:
            raise RuntimeError('application not ready after collector activation')


def restart():
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'restart', 'proxy-sentinel-zeek.service'], timeout=60)
    run(['systemctl', 'start', 'proxy-sentinel-proxy-source-refresh.service'], timeout=180)
    run(['systemctl', 'is-active', '--quiet', 'proxy-sentinel-proxy-source-refresh.timer'])
    for attempt in range(15):
        try:
            active()
            return
        except (subprocess.CalledProcessError, OSError, RuntimeError):
            if attempt == 14:
                raise
            time.sleep(2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', type=Path, required=True)
    parser.add_argument('--activate', action='store_true')
    args = parser.parse_args()
    root = Path('/opt/proxy-sentinel')
    release = args.release.resolve(strict=True)
    if release.parent != root/'releases' or release != (root/'current').resolve(strict=True):
        raise ValueError('collector must come from the current managed release')
    with (root/'config/application-upgrade.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Recheck after the lock; application upgrades use this same lock.
        if release != (root/'current').resolve(strict=True):
            raise ValueError('managed release changed during preflight')
        manifest = json.loads((release/'assets/zeek/plugins/Sentinel_SOCKSStream.json').read_text())
        if manifest['kind'] != 'sentinel-zeek-native-collector' or manifest['plugin'] != 'Sentinel::SOCKSStream' or manifest['plugin_version'] not in ('1.0.0','1.1.0','1.2.0','1.3.0'):
            raise ValueError('unsupported collector manifest')
        binary = Path(shutil.which('zeek') or '/usr/local/bin/zeek').resolve(strict=True)
        version = parse_version(subprocess.check_output([str(binary),'--version'],text=True))
        if version != manifest['zeek_version'] or platform.machine() != manifest['arch'] or sha(binary.read_bytes()) != manifest['zeek_binary_sha256']:
            raise ValueError('collector was built for a different Zeek binary or architecture')
        expected_source = {'CMakeLists.txt', 'src/Plugin.cc', 'src/Stream.cc', 'src/Stream.h', 'src/stream_test.cc', 'scripts/__load__.zeek', 'scripts/main.zeek', 'scripts/dpd.sig'}
        expected_source = {'collectors/zeek/socks-stream/'+name for name in expected_source}
        if set(manifest['source_files']) != expected_source:
            raise ValueError('collector source manifest incomplete')
        for name, digest in manifest['source_files'].items():
            if sha((release/name).read_bytes()) != digest:
                raise ValueError('collector source checksum mismatch')
        content = validate_payload(release/'assets/zeek/plugins/Sentinel_SOCKSStream.tgz', manifest)
        for name in ('__load__.zeek', 'main.zeek', 'dpd.sig'):
            if content[PREFIX+'scripts/'+name] != (release/'collectors/zeek/socks-stream/scripts'/name).read_bytes():
                raise ValueError('packaged collector scripts differ from reviewed source')
        dropin = Path('/etc/systemd/system/proxy-sentinel-zeek.service.d/socks-stream.conf')
        if dropin.is_symlink():
            raise ValueError('collector configuration cannot be a symlink')
        previous = dropin.read_bytes() if dropin.exists() else None
        plugin_parent = root/'collectors/zeek-plugins'
        target = plugin_parent/('Sentinel_SOCKSStream-'+manifest['archive_sha256'][:16])
        old_target = None
        if previous is not None:
            old_target = managed_target(previous.decode(),plugin_parent)
            old_manifest_path = old_target/'.sentinel-manifest.json'
            if old_manifest_path.is_symlink():
                raise ValueError('installed collector metadata cannot be indirect')
            if old_manifest_path.exists():
                old_manifest = json.loads(old_manifest_path.read_text())
            else:
                # The first checked deployment predates per-install metadata.
                candidates = [root/'current/assets/zeek/plugins/Sentinel_SOCKSStream.json', root/'previous/assets/zeek/plugins/Sentinel_SOCKSStream.json']
                matched = [json.loads(path.read_text()) for path in candidates if path.exists() and old_target.name == 'Sentinel_SOCKSStream-'+json.loads(path.read_text())['archive_sha256'][:16]]
                if not matched:
                    raise ValueError('existing collector has no checked release provenance')
                old_manifest = matched[0]
            installed_payload(old_target,old_manifest)
        if target.exists():
            installed_payload(target,manifest)
        old_env = subprocess.check_output(['systemctl','show','proxy-sentinel-zeek.service','--property=Environment','--value'],text=True)
        old_paths = [entry.partition('=')[2] for entry in shlex.split(old_env) if entry.startswith('ZEEK_PLUGIN_PATH=')]
        if old_paths != ([str(old_target)] if old_target else []):
            raise ValueError('existing custom Zeek plugin path requires explicit integration')
        # A private directory outside Zeek's search path holds compiler preflight logs.
        with tempfile.TemporaryDirectory(prefix='sentinel-socks-stream-',dir='/tmp') as private:
            private = Path(private)
            for name, data in content.items():
                path = private/name
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(data)
                path.chmod(0o644)
            env = os.environ.copy()
            env['ZEEK_PLUGIN_PATH'] = str(private/PREFIX.rstrip('/'))
            with (private/'preflight.log').open('wb') as log:
                run([str(binary),str(release/'assets/zeek/local-device-signals.zeek'),'policy/protocols/dhcp/software.zeek',str(release/'assets/zeek/proxy-transactions.zeek'),'LogAscii::use_json=T'],cwd=private,env=env,stdout=log,stderr=log)
            active()
            if not args.activate:
                print(json.dumps({'preflight':'passed','activated':False,'zeek_version':version,'archive_sha256':manifest['archive_sha256']}))
                return
            if old_target is not None and not (old_target/'.sentinel-manifest.json').exists():
                replace_dropin(old_target/'.sentinel-manifest.json',None,(json.dumps(old_manifest,sort_keys=True)+'\n').encode())
            plugin_parent.mkdir(parents=True,exist_ok=True)
            if not target.exists():
                with tempfile.TemporaryDirectory(prefix='.socks-stream-',dir=plugin_parent) as stage:
                    prepared = Path(stage)/'payload'
                    shutil.copytree(private/PREFIX.rstrip('/'),prepared)
                    (prepared/'.sentinel-manifest.json').write_text(json.dumps(manifest,sort_keys=True)+'\n')
                    # Validate every byte again before the immutable directory is used.
                    for name,digest in manifest['payload_files'].items():
                        if sha((prepared/name.removeprefix(PREFIX)).read_bytes()) != digest:
                            raise ValueError('prepared collector checksum mismatch')
                    for item in prepared.rglob('*'):
                        if item.is_file():
                            fd = os.open(item,os.O_RDONLY)
                            try: os.fsync(fd)
                            finally: os.close(fd)
                    for item in [path for path in prepared.rglob('*') if path.is_dir()]+[prepared]:
                        fd = os.open(item,os.O_RDONLY|os.O_DIRECTORY)
                        try: os.fsync(fd)
                        finally: os.close(fd)
                    os.rename(prepared,target)
                    fd = os.open(plugin_parent,os.O_RDONLY|os.O_DIRECTORY)
                    try: os.fsync(fd)
                    finally: os.close(fd)
            installed_payload(target,manifest)
            text = ('[Service]\nEnvironment="ZEEK_PLUGIN_PATH='+str(target)+'"\n').encode()
            if previous == text:
                active(); verify_mapped(target,manifest)
                print(json.dumps({'activated':True,'already_active':True,'restarted':False,'archive_sha256':manifest['archive_sha256']}))
                return
            invocation_before = subprocess.check_output(['systemctl','show','proxy-sentinel-zeek.service','--property=InvocationID','--value'],text=True).strip()
            dropin.parent.mkdir(parents=True,exist_ok=True)
            def refresh():
                restart()
                if dropin.read_bytes() == text:
                    verify_mapped(target,manifest)
                    invocation_after = subprocess.check_output(['systemctl','show','proxy-sentinel-zeek.service','--property=InvocationID','--value'],text=True).strip()
                    if not invocation_after or invocation_before == invocation_after:
                        raise RuntimeError('collector invocation did not rotate')
                elif old_target is not None:
                    verify_mapped(old_target,old_manifest)
            switch_collector(dropin,previous,text,refresh)
            print(json.dumps({'activated':True,'plugin_directory':str(target),'previous_plugin_directory':str(old_target) if old_target else None,'archive_sha256':manifest['archive_sha256'],'plugin_version':manifest['plugin_version'],'zeek_version':version,'invocation_changed':True,'application_ready':True}))


if __name__ == '__main__':
    main()
