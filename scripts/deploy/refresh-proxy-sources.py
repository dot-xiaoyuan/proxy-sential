#!/usr/bin/env python3
"""Bind trusted proxy adapters to actual systemd collector invocations."""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess

SOURCES = {'suricata': ('proxy-sentinel-suricata.service', 'sentinel-suricata-http'),
           'zeek': ('proxy-sentinel-zeek.service', 'sentinel-zeek-proxy')}
UTC = dt.timezone.utc


def timestamp(value):
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00'))


def refresh(previous, profile, invocations, now):
    for field in ('sensor_id', 'campus_id', 'access_domain'):
        if not re.fullmatch(r'[A-Za-z0-9._:-]+', profile.get(field, '')):
            raise ValueError('invalid controlled scope: ' + field)
    enabled = profile.get('sources', ['suricata', 'zeek'])
    if not enabled or len(set(enabled)) != len(enabled) or any(s not in SOURCES for s in enabled):
        raise ValueError('invalid proxy sources')
    scope_hash = hashlib.sha256(json.dumps({k: profile[k] for k in ('sensor_id', 'campus_id', 'access_domain')}, sort_keys=True).encode()).hexdigest()[:12]
    active = {source: invocations.get(source, '') + '-' + scope_hash for source in enabled if invocations.get(source)}
    producers = []
    for old in previous.get('producers', []):
        item = dict(old)
        if not item.get('valid_from'):
            raise ValueError('managed registration requires bounded producer epochs')
        current = (item['sensor_id'] == profile['sensor_id'] and active.get(item['source']) == item['instance_id'])
        if not current and not item.get('valid_until'):
            item['valid_until'] = now.isoformat().replace('+00:00', 'Z')
        if not item.get('valid_until') or timestamp(item['valid_until']) > now - dt.timedelta(days=8):
            producers.append(item)
    for source, instance in active.items():
        if not any(p['sensor_id'] == profile['sensor_id'] and p['source'] == source and p['instance_id'] == instance and not p.get('valid_until') for p in producers):
            # InvocationIDs are never reused by systemd. Do not reopen a retired epoch.
            if any(p['source'] == source and p['instance_id'] == instance for p in producers):
                raise ValueError('retired collector invocation cannot be reopened')
            producers.append(dict(sensor_id=profile['sensor_id'], source=source, instance_id=instance,
                                  parser_id=SOURCES[source][1], parser_version='1', campus_id=profile['campus_id'],
                                  access_domain=profile['access_domain'], key=secrets.token_hex(32),
                                  valid_from=now.isoformat().replace('+00:00', 'Z')))
    if len(producers) > 512:
        raise ValueError('proxy epoch history exceeds safe registration bound')
    return {'version': 'systemd-proxy-sources/v1', 'producers': producers}, active


def atomic(path, data):
    temporary = path.with_name(path.name + '.new')
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', default='/opt/proxy-sentinel')
    args = parser.parse_args()
    root = Path(args.root)
    if not re.fullmatch(r'/opt/[A-Za-z0-9_./-]+', str(root)) or '..' in root.parts:
        raise ValueError('unsafe installation root')
    config = root / 'config'
    profile = json.loads((config / 'proxy-source-scope.json').read_text())
    with (config / 'proxy-source.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = config / 'proxy-producers.json'
        previous = json.loads(path.read_text()) if path.exists() else {}
        invocations = {}
        for source, (unit, _) in SOURCES.items():
            values = subprocess.check_output(['systemctl', 'show', unit, '-p', 'ActiveState', '-p', 'InvocationID'], text=True)
            fields = dict(line.split('=', 1) for line in values.splitlines() if '=' in line)
            invocation = fields.get('InvocationID', '')
            if fields.get('ActiveState') == 'active' and re.fullmatch(r'[a-f0-9]{32}', invocation):
                invocations[source] = invocation
        value, active = refresh(previous, profile, invocations, dt.datetime.now(UTC))
        # Zeek opens a stream lazily on its first transaction. Make an empty
        # controlled JSONL source available without fabricating an event.
        if 'zeek' in active:
            log_path = root / 'data/zeek/logs/current/proxy_transactions.log'
            log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                fd = os.open(str(log_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
            except FileExistsError:
                pass
            else:
                os.close(fd)

        raw = json.dumps(value, sort_keys=True, indent=2) + '\n'
        env = 'PROXY_SENTINEL_PROXY_PROTOCOL_CONFIG=' + str(path) + '\n'
        env += 'PROXY_SENTINEL_SURICATA_INSTANCE_ID=' + active.get('suricata', '') + '\n'
        env += 'PROXY_SENTINEL_ZEEK_INSTANCE_ID=' + active.get('zeek', '') + '\n'
        env += 'PROXY_SENTINEL_ZEEK_PROXY_PATH=' + str(root / 'data/zeek/logs/current/proxy_transactions.log') + '\n'
        env_path = config / 'proxy-source.env'
        digest = hashlib.sha256((raw + env).encode()).hexdigest()
        accepted = config / 'proxy-source.accepted'
        if not path.exists() or path.read_text() != raw:
            atomic(path, raw)
        if not env_path.exists() or env_path.read_text() != env:
            atomic(env_path, env)
        if accepted.exists() and accepted.read_text().strip() == digest:
            return
        # Both consumers snapshot registrations at startup. Restart after both files are durable.
        subprocess.run(['systemctl', 'try-restart', 'proxy-sentinel-ingest.service', 'proxy-sentinel-control-plane.service'], check=True, timeout=120)
        atomic(accepted, digest + '\n')
        print('proxy source registration refreshed; active collectors=' + ','.join(sorted(active)))


if __name__ == '__main__':
    main()
