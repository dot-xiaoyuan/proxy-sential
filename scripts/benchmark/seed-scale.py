#!/usr/bin/env python3
"""Synthetic scale data for the owned disposable local benchmark only."""
import argparse
import base64
import json
import datetime
import urllib.error
import time
import urllib.parse
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument('--dsn', required=True)
parser.add_argument('--normalize-only',action='store_true')
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
existing = int(query(f"SELECT count() FROM application_observations WHERE sensor_id='{sensor}' FORMAT TabSeparated"))
if args.replenish and args.normalize_only:parser.error('replenish and normalize-only are mutually exclusive')
if args.replenish and not (0<existing<args.count):raise SystemExit('replenish requires an existing fixture below ten million rows')
if existing and not args.normalize_only and not args.replenish:
    raise SystemExit('scale data already exists; refusing to reseed or clean databases')
start = time.monotonic()
if args.normalize_only and existing != args.count:raise SystemExit("requires completed observation seed")
prefix='bench-replenish-'+str(time.time_ns()) if args.replenish else 'bench'
seed_count=((args.count-existing+99999)//100000)*100000 if args.replenish else args.count
for offset in ([] if args.normalize_only else range(0,seed_count,100_000)):
    query(f"""INSERT INTO application_observations
    (timestamp,sensor_id,event_id,campus_id,ip,connection_id,event_type,domain,source_field,bundle_version,target_id,target_type,name,category,upload_bytes,download_bytes,observation_json,classification_revision,batch_id)
    WITH number+{offset} AS n,intDiv(n,10) AS connection,
    now64(9)-toIntervalSecond(n%560000+60) AS observed,
    if(n%5=0,'dns','tls') AS event_type,
    if(connection%10=0,'',concat('app-',toString(connection%40))) AS target_id,
    concat('service-',toString(connection%40),'.example.test') AS domain,
    concat('10.',toString(intDiv(connection%24000,65000)),'.',toString(intDiv(connection%24000,250)),'.',toString(connection%250+1)) AS ip,
    concat('{prefix}-event-',toString(n)) AS event_id,
    concat('{prefix}-connection-',toString(connection)) AS connection_id,
    toUInt64(n%10*100+100) AS upload,toUInt64(n%10*1000+1000) AS download
    SELECT observed,'{sensor}',event_id,'bench-campus',ip,connection_id,event_type,domain,
    if(event_type='dns','dns.query','tls.sni'),'bench-v1',target_id,
    if(target_id='','','application'),if(target_id='','',concat('Benchmark service ',toString(connection%40))),'service',upload,download,
    concat('{{"event_id":"',event_id,'","timestamp":"',formatDateTime(observed,'%Y-%m-%dT%H:%i:%S.%fZ','UTC'),'","sensor_id":"{sensor}","campus_id":"bench-campus","ip":"',ip,'","connection_id":"',connection_id,'","event_type":"',event_type,'","domain":"',domain,'","source_field":"',if(event_type='dns','dns.query','tls.sni'),'","bundle_version":"bench-v1","upload_bytes":',toString(upload),',"download_bytes":',toString(download),',"match":{{"target_id":"',target_id,'","target_type":"',if(target_id='','','application'),'","name":"',if(target_id='','',concat('Benchmark service ',toString(connection%40))),'","category":"service","confidence":0.9}}}}'),1,1
    FROM numbers(100000)
    SETTINGS max_threads=2,max_block_size=8192,max_memory_usage=536870912,async_insert=0""")
    print(json.dumps({'seeded':offset+100000,'seconds':round(time.monotonic()-start,2)}),flush=True)
existing_events=int(query(f"SELECT count() FROM normalized_events WHERE sensor_id='{sensor}' FORMAT TabSeparated"))
if existing_events and not args.replenish:raise SystemExit("normalized data already exists; refusing duplicate seed")
until=datetime.datetime.now(datetime.timezone.utc)
for hour in range(168):
    begin=until-datetime.timedelta(hours=168-hour)
    end=begin+datetime.timedelta(hours=1)
    query(f"""INSERT INTO normalized_events
        (timestamp,event_id,schema_version,source,source_event_type,type,sensor_id,subject_ip,observer_json,payload_json,flow_json,raw_ref_json)
        SELECT timestamp,event_id,'v1','test',event_type,event_type,sensor_id,ip,
        '{{"campus_id":"bench-campus"}}',
        concat('{{"',if(event_type='dns','query','sni'),'":"',domain,'"}}'),
        concat('{{"connection_id":"',connection_id,'","bytes_toserver":',toString(upload_bytes),',"bytes_toclient":',toString(download_bytes),'}}'),'{{}}'
        FROM application_observations WHERE sensor_id='{sensor}' AND startsWith(event_id,'{prefix}-event-') AND timestamp>=parseDateTime64BestEffort('{begin.isoformat()}',9) AND timestamp<parseDateTime64BestEffort('{end.isoformat()}',9)
        SETTINGS max_threads=2,max_block_size=8192,max_memory_usage=536870912""")
    if hour%24==0:print(json.dumps({'normalized_hours':hour+1}),flush=True)
print(json.dumps({'sensor':sensor,'appended_observations':seed_count if not args.normalize_only else 0,'target_observations':args.count,'replenish':args.replenish,'elapsed_seconds':round(time.monotonic()-start,2)}),flush=True)
