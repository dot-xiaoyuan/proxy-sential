#!/usr/bin/env python3
"""Read-only schema admission for application-only upgrades."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

stage = Path(sys.argv[1])
commands = {
    'postgres': ['docker', 'exec', 'proxy-sentinel-postgres', 'sh', '-c', 'psql -X -At -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT row_to_json(m) FROM (SELECT version,checksum FROM schema_migrations) m"'],
    'clickhouse': ['docker', 'exec', 'proxy-sentinel-clickhouse', 'sh', '-c', 'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --database "$CLICKHOUSE_DB" --query "SELECT version,checksum FROM schema_migrations FINAL FORMAT JSONEachRow"'],
}
for kind, command in commands.items():
    raw = subprocess.check_output(command, text=True, timeout=30)
    ledger = {row['version']: row['checksum'] for row in map(json.loads, raw.splitlines())}
    files = sorted((stage / 'migrations' / kind).glob('*.sql'))
    if not files:
        raise SystemExit('empty candidate migration directory: ' + kind)
    for path in files:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if ledger.get(path.name) != digest:
            raise SystemExit('application-only upgrade denied: unapplied or changed migration ' + kind + '/' + path.name)
    print(kind + ': all ' + str(len(files)) + ' candidate migrations already applied with matching checksums')
