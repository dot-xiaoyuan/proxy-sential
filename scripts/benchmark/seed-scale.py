#!/usr/bin/env python3
"""Synthetic scale data for the owned disposable local benchmark only."""
import argparse
import base64
import json
import urllib.error
import time
import urllib.parse
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument('--dsn', required=True)
parser.add_argument('--replenish',action='store_true',help='Append unique fixture events lost to seven-day TTL; never modify existing data')
parser.add_argument('--count', type=int, default=10_000_000)
args = parser.parse_args()
url = urllib.parse.urlsplit(args.dsn)
if url.hostname != '127.0.0.1' or url.port != 28129 or args.count != 10_000_000:
    parser.error('requires the owned disposable ClickHouse on 127.0.0.1:28129 and exactly ten million rows')
credentials = urllib.parse.parse_qs(url.query)
token = base64.b64encode((credentials['user'][0]+':'+credentials['password'][0]).encode()).decode()
base = urllib.parse.urlunsplit((url.scheme,url.netloc,'/','',''))
def query(sql):
    request = urllib.request.Request(base, data=sql.encode(), headers={'Authorization':'Basic '+token})
    try:
        with urllib.request.urlopen(request,timeout=120) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        raise RuntimeError(error.read().decode()) from None

sensor = 'bench-scale-20260917'
existing = int(query(
    f"SELECT count() FROM normalized_events WHERE sensor_id='{sensor}' AND source='test' FORMAT TabSeparated"
))
if args.replenish and not 0 < existing < args.count:
    raise SystemExit('replenish requires an existing fixture below ten million rows')
if existing and not args.replenish:
    raise SystemExit('scale data already exists; refusing to reseed or clean databases')

start = time.monotonic()
prefix = f'bench-replenish-{time.time_ns()}' if args.replenish else 'bench'
seed_count = args.count - existing
for offset in range(0, seed_count, 100_000):
    batch_size = min(100_000, seed_count - offset)
    query(f"""INSERT INTO normalized_events
    (timestamp,event_id,schema_version,source,source_event_type,type,sensor_id,campus_id,subject_ip,observer_json,payload_json,flow_json,raw_ref_json)
    WITH number+{offset} AS n,intDiv(n,10) AS connection,
        now64(9)-toIntervalSecond(n%560000+60) AS observed,
        if(n%5=0,'dns','tls') AS event_type,
        concat('service-',toString(connection%40),'.example.test') AS domain,
        concat('10.0.',toString(intDiv(connection%24000,250)),'.',toString(connection%250+1)) AS ip,
        concat('{prefix}-event-',toString(n)) AS event_id,
        concat('{prefix}-connection-',toString(connection)) AS connection_id,
        n%10*100+100 AS upload,n%10*1000+1000 AS download
    SELECT observed,event_id,'v1','test',event_type,event_type,'{sensor}','bench-campus',ip,
        '{{"campus_id":"bench-campus"}}',
        concat('{{"',if(event_type='dns','query','sni'),'":"',domain,'"}}'),
        concat('{{"connection_id":"',connection_id,'","bytes_toserver":',toString(upload),',"bytes_toclient":',toString(download),'}}'),'{{}}'
    FROM numbers({batch_size})
    SETTINGS max_threads=2,max_block_size=8192,max_memory_usage=536870912,async_insert=0""")
    print(json.dumps({'seeded': offset + batch_size, 'seconds': round(time.monotonic() - start, 2)}), flush=True)
print(json.dumps({
    'sensor': sensor, 'appended_events': seed_count, 'target_events': args.count,
    'replenish': args.replenish, 'elapsed_seconds': round(time.monotonic() - start, 2),
}), flush=True)
