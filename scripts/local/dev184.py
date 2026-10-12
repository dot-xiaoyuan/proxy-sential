#!/usr/bin/env python3
"""Read-only 184 snapshots and an isolated local development stack (stdlib only)."""
import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import signal
import subprocess
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / 'data/dev184'
TARGET = 'root@222.204.3.184'
PG = 'proxy-sentinel-dev184-postgres'
CH = 'proxy-sentinel-dev184-clickhouse'
SSH = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=3', TARGET]
EXCLUDED = ['identity_ip_mac_history', 'device_signal_events', 'identity_ingest_batches']


def log(message):
    print(f'[dev184] {message}', flush=True)


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def remote_db(kind, sql=None, command=None, output=None):
    container = 'proxy-sentinel-postgres' if kind == 'pg' else 'proxy-sentinel-clickhouse'
    if command is None:
        command = ('PGOPTIONS="-c default_transaction_read_only=on -c statement_timeout=120000" '
                   'psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At') if kind == 'pg' else (
                   'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" '
                   '--database "$CLICKHOUSE_DB" --readonly 1 --max_threads 2 --max_memory_usage 1073741824 --multiquery')
    args = SSH + [shlex.join(['docker', 'exec', '-i', container, 'sh', '-c', command])]
    for attempt in range(3):
        if output is not None:
            output.seek(0)
            output.truncate()
        try:
            return run(args, input=(sql.encode() if sql is not None else None), stdout=output or subprocess.PIPE).stdout
        except subprocess.CalledProcessError as error:
            if error.returncode != 255 or attempt == 2:
                raise
            log('SSH 连接中断，稍后重试当前只读导出')
            time.sleep(3 * (attempt + 1))


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def capture(resume=None):
    STATE.mkdir(parents=True, exist_ok=True)
    (STATE / 'go.mod').write_text('module proxy-sentinel.local/runtime-data\n')
    if shutil.disk_usage(STATE).free < 10 * 1024**3:
        raise RuntimeError('本地可用空间不足 10GB')
    info = run(SSH + ['hostname; id -u; readlink -f /opt/proxy-sentinel/current; systemctl is-active proxy-sentinel-control-plane proxy-sentinel-ncu-identity-sync'], capture_output=True, text=True).stdout.splitlines()
    if len(info) != 5 or info[1] != '0' or info[-2:] != ['active', 'active']:
        raise RuntimeError('184 身份或服务只读核对未通过')
    sensor_ids = remote_db('pg', 'SELECT sensor_id FROM sensors ORDER BY sensor_id;').decode().splitlines()
    if len(sensor_ids) != 1:
        raise RuntimeError('需要为多传感器现场显式选择快照范围')
    sensor = sensor_ids[0]
    if not sensor.replace('-', '').replace('_', '').isalnum():
        raise RuntimeError('传感器 ID 无效')
    stamp = dt.datetime.now(dt.timezone.utc)
    folder = STATE / 'snapshots' / stamp.strftime('%Y%m%dT%H%M%SZ')
    if resume:
        folder = Path(resume).resolve(strict=True)
        if folder.parent != (STATE / 'snapshots').resolve():
            raise RuntimeError('续传目录必须属于本地 dev184/snapshots')
        if (folder / 'manifest.json').exists():
            raise RuntimeError('快照已经完成，不允许重写；请重新 capture 创建新快照')
        stamp = dt.datetime.strptime(folder.name, '%Y%m%dT%H%M%SZ').replace(tzinfo=dt.timezone.utc)
    else:
        folder.mkdir(parents=True)
    manifest = {'source': TARGET, 'host': info[0], 'release': info[2], 'sensor_id': sensor,
                'started_at': stamp.isoformat(), 'postgres_excluded_history_tables': EXCLUDED,
                'postgres_history_scope': '最近 2000 个终端各两条 IP/MAC 历史；另外两张原始批次表不导出',
                'cross_database_atomic': False, 'clickhouse': [], 'files': {}}
    progress = folder / 'capture-progress.json'
    if progress.exists():
        previous = json.loads(progress.read_text())
        if previous['release'] != info[2] or previous['sensor_id'] != sensor:
            raise RuntimeError('续传时现场版本或传感器已变化，请另取快照')
    else:
        progress.write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
    for kind in ['pg', 'ch']:
        sql = 'SELECT version,checksum FROM schema_migrations ORDER BY version;' if kind == 'pg' else 'SELECT version,checksum FROM schema_migrations FINAL ORDER BY version FORMAT TSV;'
        ledger = remote_db(kind, sql).decode()
        (folder / f'{kind}-migrations.tsv').write_text(ledger)
        for line in ledger.splitlines():
            name, checksum = line.split('|' if kind == 'pg' else '\t')
            path = ROOT / 'migrations' / ('postgres' if kind == 'pg' else 'clickhouse') / name
            if not path.exists() or digest(path) != checksum:
                raise RuntimeError(f'{kind} 迁移账本与本地源码不一致：{name}')
    log('只读导出 PostgreSQL 业务快照（排除三张大型原始历史表）')
    command = 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --compress=6 --no-owner --no-acl --lock-wait-timeout=5s '
    command += ' '.join('--exclude-table-data=public.' + table for table in EXCLUDED)
    archive = folder / 'postgres.dump'
    if resume and archive.exists():
        run(['docker', 'run', '--rm', '--network', 'none', '-v', f'{folder}:/snapshot:ro', 'postgres:18', 'pg_restore', '--list', '/snapshot/postgres.dump'], stdout=subprocess.DEVNULL)
        log('已验证完成的 PostgreSQL 导出，继续剩余快照')
    else:
        partial = folder / 'postgres.dump.partial'
        with partial.open('wb') as output:
            remote_db('pg', command=command, output=output)
        partial.replace(archive)
    log('只读导出最近 2000 个终端各两条 IP/MAC 历史')
    history_sql = '''COPY (SELECT h.* FROM (SELECT endpoint_id FROM endpoint_entities ORDER BY last_seen DESC NULLS LAST,endpoint_id LIMIT 2000) e CROSS JOIN LATERAL
      (SELECT * FROM identity_ip_mac_history WHERE endpoint_id=e.endpoint_id
       ORDER BY last_seen DESC,first_seen DESC LIMIT 2) h) TO STDOUT WITH (FORMAT binary);'''
    history = folder / 'identity_ip_mac_history.copy'
    partial = folder / 'identity_ip_mac_history.copy.partial'
    with partial.open('wb') as output:
        remote_db('pg', history_sql, output=output)
    partial.replace(history)
    cutoff = stamp.strftime('%Y-%m-%d %H:%M:%S')
    bound = f"toDateTime64('{cutoff}',6,'UTC')"
    specs = [
        ('normalized_events', f"sensor_id='{sensor}' AND timestamp BETWEEN {bound}-INTERVAL 6 HOUR AND {bound}", 'LIMIT 10000 BY type LIMIT 120000'),
        ('ingest_diagnostics', f'timestamp <= {bound}', 'LIMIT 10000'),
        ('application_observations', f'timestamp <= {bound}', 'LIMIT 100000'),
        ('activity_chart_facts_5m_v3', f'bucket_start BETWEEN {bound}-INTERVAL 6 HOUR AND {bound}', 'LIMIT 200000'),
        ('activity_chart_facts_hour_v3', f'bucket_start BETWEEN {bound}-INTERVAL 7 DAY AND {bound}', 'LIMIT 100000'),
        ('activity_chart_facts_day_v3', f'bucket_start BETWEEN {bound}-INTERVAL 7 DAY AND {bound}', 'LIMIT 100000'),
        ('activity_chart_bucket_versions_v3', '1', 'LIMIT 100000'),
    ]
    for table, where, limit in specs:
        log(f'只读导出 ClickHouse {table}')
        description = remote_db('ch', f'DESCRIBE TABLE {table} FORMAT JSON;')
        columns = [row['name'] for row in json.loads(description)['data'] if row['default_type'] not in ('MATERIALIZED', 'ALIAS')]
        query = f"SELECT {','.join(columns)} FROM {table} WHERE {where} {limit} FORMAT Native;"
        path = folder / f'{table}.native.gz'
        # Compress locally: no backup files or configuration changes on 184.
        with (folder / f'{table}.native').open('wb') as output:
            remote_db('ch', query, output=output)
        with (folder / f'{table}.native').open('rb') as source, gzip.open(path, 'wb') as output:
            shutil.copyfileobj(source, output)
        (folder / f'{table}.native').unlink()
        manifest['clickhouse'].append({'table': table, 'columns': columns, 'where': where, 'limit': limit, 'file': path.name})
    manifest['completed_at'] = dt.datetime.now(dt.timezone.utc).isoformat()
    manifest['files'] = {p.name: {'sha256': digest(p), 'bytes': p.stat().st_size} for p in folder.iterdir() if p.is_file()}
    (folder / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    latest = STATE / 'latest'
    temporary = STATE / 'latest.tmp'
    temporary.symlink_to(folder.relative_to(STATE))
    temporary.replace(latest)
    log(f'快照完成：{folder}；总大小 {sum(f["bytes"] for f in manifest["files"].values()) / 1024**2:.1f} MiB')


def config(snapshot):
    path = STATE / 'runtime.env'
    if path.exists():
        env = dict(line.split('=', 1) for line in path.read_text().splitlines() if line and not line.startswith('#'))
    else:
        env = {'DEV184_POSTGRES_PASSWORD': secrets.token_hex(24), 'DEV184_CLICKHOUSE_PASSWORD': secrets.token_hex(24),
               'DEV184_ACTION_MASTER_KEY': secrets.token_hex(32), 'DEV184_ADMIN_USERNAME': 'dev-admin',
               'DEV184_ADMIN_PASSWORD': 'Local184!' + secrets.token_hex(12)}
    env.update({'DEV184_ROOT': str(ROOT), 'DEV184_SNAPSHOT_DIR': str(snapshot),
                'DEV184_DB_DIR': str(STATE / 'db' / snapshot.name),
                'DEV184_SENSOR_ID': json.loads((snapshot / 'manifest.json').read_text())['sensor_id']})
    path.write_text(''.join(f'{key}={value}\n' for key, value in env.items()))
    path.chmod(0o600)
    return env


def compose(*args):
    return ['docker', 'compose', '--env-file', str(STATE / 'runtime.env'), '-f', str(ROOT / 'deploy/compose/snapshot.yml'), *args]


def pg(sql):
    return run(['docker', 'exec', '-i', PG, 'sh', '-c', 'psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At'], input=sql.encode(), capture_output=True).stdout.decode()


def local_env(env):
    return dict(os.environ, PROXY_SENTINEL_POSTGRES_DSN=f'postgres://proxy_sentinel:{env["DEV184_POSTGRES_PASSWORD"]}@127.0.0.1:25433/proxy_sentinel?sslmode=disable',
                PROXY_SENTINEL_CLICKHOUSE_DSN=f'http://127.0.0.1:28124/?user=proxy_sentinel&password={env["DEV184_CLICKHOUSE_PASSWORD"]}&database=proxy_sentinel',
                PROXY_SENTINEL_ADMIN_PASSWORD=env['DEV184_ADMIN_PASSWORD'])


def build():
    (STATE / 'bin').mkdir(parents=True, exist_ok=True)
    architecture = run(['docker', 'image', 'inspect', 'golang:1.24-bookworm', '--format', '{{.Architecture}}'], capture_output=True, text=True).stdout.strip()
    log(f'构建本地后端（linux/{architecture}）')
    run(['go', 'build', '-o', str(STATE / 'bin/proxy-sentinel.next'), './cmd/proxy-sentinel'], cwd=ROOT,
        env=dict(os.environ, GOOS='linux', GOARCH=architecture, CGO_ENABLED='0'))
    (STATE / 'bin/proxy-sentinel.next').replace(STATE / 'bin/proxy-sentinel')
    run(['go', 'build', '-o', str(STATE / 'bin/proxy-sentinel-host'), './cmd/proxy-sentinel'], cwd=ROOT)


def stop_frontend():
    pidfile = STATE / 'frontend.pid'
    if pidfile.exists():
        pid = int(pidfile.read_text())
        # Only stop our own recorded process, never an unrelated reused PID.
        result = subprocess.run(['ps', '-p', str(pid), '-o', 'command='], capture_output=True, text=True)
        if 'pnpm' in result.stdout and '--port 5173' in result.stdout:
            os.killpg(pid, signal.SIGTERM)
        pidfile.unlink()


def start_frontend():
    stop_frontend()
    envpath = ROOT / 'frontend/.env.development.local'
    desired = 'VITE_API_BASE=/api/v1\nVITE_ENABLE_MOCKS=false\nVITE_DEV_PROXY_TARGET=http://127.0.0.1:18084\n'
    if envpath.exists() and envpath.read_text() != desired:
        backup = STATE / f'frontend-env-backup-{time.time_ns()}'
        shutil.copy2(envpath, backup)
        log(f'已保留已有前端环境文件：{backup}')
    envpath.write_text(desired)
    frontend_env = dict(os.environ)
    for key in ['VITE_API_BASE', 'VITE_ENABLE_MOCKS', 'VITE_DEV_PROXY_TARGET']:
        frontend_env.pop(key, None)
    with (STATE / 'frontend.log').open('ab') as output:
        proc = subprocess.Popen(['pnpm', 'dev', '--host', '127.0.0.1', '--port', '5173', '--strictPort'],
                                cwd=ROOT / 'frontend', env=frontend_env, stdout=output, stderr=output, start_new_session=True)
    (STATE / 'frontend.pid').write_text(str(proc.pid))


def wait_url(url):
    for _ in range(60):
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(1)
    raise RuntimeError(f'本地服务未就绪：{url}')


def up():
    # Go's ./... discovery must not walk mutable database part directories.
    (STATE / 'go.mod').write_text('module proxy-sentinel.local/runtime-data\n')
    snapshot = (STATE / 'latest').resolve(strict=True)
    manifest = json.loads((snapshot / 'manifest.json').read_text())
    if manifest['source'] != TARGET:
        raise RuntimeError('快照来源必须是 184')
    for name, metadata in manifest['files'].items():
        if digest(snapshot / name) != metadata['sha256']:
            raise RuntimeError(f'快照校验失败：{name}')
    env = config(snapshot)
    run(['docker', 'info'], stdout=subprocess.DEVNULL)
    build()
    if not (ROOT / 'frontend/dist/index.html').exists():
        run(['pnpm', 'build'], cwd=ROOT / 'frontend')
    run(compose('stop', 'backend', 'realtime'), stdout=subprocess.DEVNULL)
    run(compose('up', '-d', '--wait', 'postgres', 'clickhouse'))
    marker = Path(env['DEV184_DB_DIR']) / 'restored.json'
    if not marker.exists():
        progress_path = Path(env['DEV184_DB_DIR']) / 'restore-progress.json'
        progress = json.loads(progress_path.read_text()) if progress_path.exists() else {}
        archive_hash = manifest['files']['postgres.dump']['sha256']
        if progress.get('archive_sha256', archive_hash) != archive_hash:
            raise RuntimeError('恢复进度与候选快照不一致')
        progress['archive_sha256'] = archive_hash
        def checkpoint():
            progress_path.write_text(json.dumps(progress))
        if not progress.get('postgres'):
            if pg("SELECT count(*) FROM information_schema.tables WHERE table_schema='public';").strip() != '0':
                raise RuntimeError('本地数据库已有内容但没有 PostgreSQL 恢复完成标记；保留数据库，需排查中断恢复')
            log('恢复 PostgreSQL 快照到本地专用数据库')
            run(['docker', 'exec', PG, 'sh', '-c', 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --no-acl --exit-on-error --jobs=2 /snapshot/postgres.dump'], stdout=subprocess.DEVNULL)
            progress['postgres'] = True
            checkpoint()
        if not progress.get('ip_history'):
            with (snapshot / 'identity_ip_mac_history.copy').open('rb') as source:
                run(['docker', 'exec', '-i', PG, 'sh', '-c', 'psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "BEGIN" -c "CREATE TEMP TABLE snapshot_ip_history (LIKE identity_ip_mac_history INCLUDING DEFAULTS)" -c "COPY snapshot_ip_history FROM STDIN WITH (FORMAT binary)" -c "INSERT INTO identity_ip_mac_history SELECT h.* FROM snapshot_ip_history h WHERE EXISTS (SELECT 1 FROM endpoint_entities e WHERE e.endpoint_id=h.endpoint_id) ON CONFLICT DO NOTHING" -c "COMMIT"'], stdin=source, stdout=subprocess.DEVNULL)
            progress['ip_history'] = True
            checkpoint()
        log('在本地执行迁移并建立 ClickHouse 表结构')
        run([str(STATE / 'bin/proxy-sentinel-host'), 'migrate', '--postgres-dir', str(ROOT / 'migrations/postgres'), '--clickhouse-dir', str(ROOT / 'migrations/clickhouse'), '--timeout', '30m'], env=local_env(env))
        if progress.get('clickhouse_importing'):
            raise RuntimeError('ClickHouse 导入曾中断，保留数据；检查该表后清除导入标记，禁止直接叠加恢复')
        for item in manifest['clickhouse']:
            if item['table'] in progress.get('clickhouse_completed', []):
                continue
            progress['clickhouse_importing'] = item['table']
            checkpoint()
            log(f'恢复 ClickHouse {item["table"]}')
            query = f'INSERT INTO {item["table"]} ({",".join(item["columns"])}) FORMAT Native'
            command = 'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --database "$CLICKHOUSE_DB" --query ' + shlex.quote(query)
            with gzip.open(snapshot / item['file'], 'rb') as source:
                process = subprocess.Popen(['docker', 'exec', '-i', CH, 'sh', '-c', command], stdin=subprocess.PIPE)
                try:
                    shutil.copyfileobj(source, process.stdin)
                finally:
                    process.stdin.close()
                if process.wait() != 0:
                    raise RuntimeError(f'ClickHouse 恢复失败：{item["table"]}')
            progress.setdefault('clickhouse_completed', []).append(item['table'])
            del progress['clickhouse_importing']
            checkpoint()
        # Copied configuration remains available for inspection, with external
        # dispatch disabled. The backend's Docker network also has no WAN route.
        pg('''UPDATE enforcement_connectors SET enabled=false,mode='shadow';
            UPDATE discovery_sources SET enabled=false;
            UPDATE discovery_scan_profiles SET enabled=false;
            UPDATE notification_channels SET enabled=false;
            UPDATE behavior_report_channels SET enabled=false;''')
        if pg("SELECT count(*) FROM local_users WHERE username='dev-admin';").strip() == '0':
            run([str(STATE / 'bin/proxy-sentinel-host'), 'control-plane', 'bootstrap-admin', '--username', env['DEV184_ADMIN_USERNAME'], '--name', '本地联调管理员'], env=local_env(env), stdout=subprocess.DEVNULL)
        marker.write_text(json.dumps({'snapshot': str(snapshot), 'restored_at': dt.datetime.now(dt.timezone.utc).isoformat()}))
    else:
        run([str(STATE / 'bin/proxy-sentinel-host'), 'migrate', '--postgres-dir', str(ROOT / 'migrations/postgres'), '--clickhouse-dir', str(ROOT / 'migrations/clickhouse'), '--timeout', '30m'], env=local_env(env))
    run(compose('up', '-d', '--force-recreate', 'backend', 'realtime', 'edge'))
    wait_url('http://127.0.0.1:18084/readyz')
    start_frontend()
    wait_url('http://127.0.0.1:5173')
    log('前端 http://127.0.0.1:5173；后端 http://127.0.0.1:18084；账号 dev-admin，口令位于 data/dev184/runtime.env')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['capture', 'up', 'restart', 'down', 'status'])
    parser.add_argument('--resume', help='继续已完成 PostgreSQL 导出的快照目录，仅用于 capture')
    args = parser.parse_args()
    if args.resume and args.command != 'capture':
        parser.error('--resume 仅用于 capture')
    if args.command == 'capture':
        capture(args.resume)
    elif args.command in ['up', 'restart']:
        up()
    elif args.command == 'down':
        stop_frontend()
        run(compose('down'))
    else:
        run(compose('ps'))
        log(pg("SELECT 'endpoints',count(*) FROM endpoint_entities UNION ALL SELECT 'sessions',count(*) FROM account_sessions UNION ALL SELECT 'ip_history',count(*) FROM identity_ip_mac_history;"))


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        # Commands may carry credentials through environment; never dump env.
        raise SystemExit(f'[dev184] 失败：{error}')
