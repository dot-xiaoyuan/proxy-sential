#!/usr/bin/env python3
"""Check queue and expiry observations from a controlled offline Zeek replay."""
import json
from pathlib import Path
import sys

folder = Path(sys.argv[1])
m = json.loads((folder/'manifest.json').read_text())
if m['kind'] != 'generated-tcp-segmentation-replay' or m.get('production_database_used') is not False:
    raise SystemExit('controlled replay required')
cases = {case['client_port']:case for case in m['cases']}
if len(cases) != len(m['cases']):
    raise SystemExit('duplicate controlled client port')
states = {}
for line in (folder/'state.jsonl').read_text().splitlines():
    row = json.loads(line)
    port,kind = row['client_port'],row.pop('kind')
    if port not in cases or kind not in ('reply','final') or (port,kind) in states:
        raise SystemExit('foreign or repeated state snapshot')
    states[port,kind] = row
for port,case in cases.items():
    want = case['state_expected']
    for kind,fields in (('reply',('first_reply_pending',)),('final',('peak_pending','remaining_pending','ambiguous'))):
        row = states[port,kind]
        for key in fields:
            if row[key] != want[key]:
                raise SystemExit(case['name']+': '+key+' got '+str(row[key])+' want '+str(want[key]))
    if states[port,'final']['peak_pending'] > m['maximum_pending_http_transactions']:
        raise SystemExit('queue bound exceeded')
print(json.dumps({'cases':len(cases),'queue_limit':m['maximum_pending_http_transactions'],'delayed_expiry':m['delayed_expiry'],'state_checks':'passed'}))
