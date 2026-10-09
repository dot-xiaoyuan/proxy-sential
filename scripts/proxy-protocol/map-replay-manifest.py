#!/usr/bin/env python3
"""Map a fresh parser run to controlled fixture ports, never inferred identities."""
import json
from pathlib import Path
import sys
p = Path(sys.argv[1])
m = json.loads((p/'manifest.json').read_text())
if m['kind'] not in ('generated-tcp-segmentation-replay','real-loopback-socket-acceptance') or m.get('production_database_used') is not False:
    raise SystemExit('controlled fixture manifest required')
pairs = {(case['client_port'],case['server_port']):case['name'] for case in m['cases']}
if len(pairs) != len(m['cases']):
    raise SystemExit('duplicate fixture connection')
rows = [json.loads(line) for line in (p/'proxy_transactions.log').read_text().splitlines()]
uid_cases = {}
for row in rows:
    pair = row['id.orig_p'],row['id.resp_p']
    if pair not in pairs:
        raise SystemExit('parser output escaped controlled fixture connections')
    name = pairs[pair]
    if row['uid'] in uid_cases and uid_cases[row['uid']] != name:
        raise SystemExit('parser UID collided across fixture cases')
    uid_cases[row['uid']] = name
m['uid_cases'] = uid_cases
m['parser_rows'] = len(rows)
(p/'manifest.json').write_text(json.dumps(m,indent=2)+'\n')
print(json.dumps({'cases':len(m['cases']),'parser_rows':len(rows)}))
