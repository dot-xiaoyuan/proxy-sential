#!/usr/bin/env python3
"""OpenAPI HTTP latency census. Writes are allowed only on an explicitly isolated localhost fixture.
Successful, error and unavailable-resource samples are kept separate; errors are not business benchmarks.
"""
import subprocess, threading, uuid
import concurrent.futures
import argparse, datetime, hashlib, http.cookiejar, json, math, pathlib, re, statistics, time, urllib.error, urllib.parse, urllib.request

parser=argparse.ArgumentParser()
parser.add_argument('--spec',required=True,help='OpenAPI converted to JSON')
parser.add_argument('--base',required=True,help='API base including /api/v1')
parser.add_argument('--cookies')
parser.add_argument('--output',required=True)
parser.add_argument('--samples',type=int,default=3)
parser.add_argument('--p95-limit-ms',type=float,default=500)
parser.add_argument('--p99-limit-ms',type=float,default=1000)
parser.add_argument('--concurrency',type=int,default=1)
parser.add_argument('--only',default='',help='Regex selecting method + OpenAPI path')
parser.add_argument('--timeout',type=float,default=25)
parser.add_argument('--isolated-writes',action='store_true')
parser.add_argument('--owned-metrics',action='store_true',help='Collect SQL scans and sampled lock waits from the named disposable local containers only')
parser.add_argument('--business-manifest',help='JSON map of operation keys to normal-result assertions')
parser.add_argument('--window',default='24h',help='Business time window; report each window separately')
parser.add_argument('--request-fixtures',help='Operation-specific paths, bodies and unique fields for the attested disposable database')
args=parser.parse_args()
if args.samples<1 or args.timeout<=0 or args.concurrency<1 or args.p95_limit_ms<=0 or args.p99_limit_ms<=0:parser.error("samples, timeout, concurrency and latency limits must be positive")
if args.isolated_writes and urllib.parse.urlsplit(args.base).hostname not in ('127.0.0.1','localhost','::1'):
    parser.error('write benchmarks require an isolated localhost fixture; never use a production forward')
if args.concurrency>1 and args.isolated_writes and not args.request_fixtures:parser.error('concurrent writes require operation-specific business fixtures')
started_date=datetime.datetime.now(datetime.timezone.utc).isoformat()
spec=json.load(open(args.spec));out=pathlib.Path(args.output);out.mkdir(parents=True,exist_ok=True)
ids={'ip':'203.0.113.10','account_id':'bench-account','endpoint_id':'mac:00:10:20:30:40:50','case_id':'bench-case','campus_id':'bench-campus','building_id':'bench-building','network_zone_id':'bench-zone','access_point_id':'bench-ap','connector_id':'bench-connector','policy_id':'bench-policy','user_id':'bench-user','operation':'status','kind':'campuses'}
csrf='';cache={}
manifest=json.load(open(args.business_manifest)) if args.business_manifest else {}
fixtures=json.load(open(args.request_fixtures)) if args.request_fixtures else {}
route_trace=''
metrics_stop=threading.Event()
def docker_sql(engine,sql):
    container='proxy-sentinel-perf-'+engine+'-20260917'
    command=['docker','exec','-i',container]
    if engine=='ch':command+=['clickhouse-client','--user','benchmark','--password','benchmark-isolated-only','--multiquery']
    else:command+=['psql','-U','postgres','-d','sentinel_benchmark','-At']
    return subprocess.check_output(command,input=sql.encode(),timeout=10).decode().strip()
def pg_counters():
    return json.loads(docker_sql('pg',"SELECT json_build_object('seq_rows',coalesce(sum(seq_tup_read),0),'indexed_rows_fetched',coalesce(sum(idx_tup_fetch),0),'seq_scans',coalesce(sum(seq_scan),0),'index_scans',coalesce(sum(idx_scan),0)) FROM pg_stat_user_tables;"))
def normal_result(template,method,payload):
    key=method.upper()+' '+template
    checks=manifest.get(key)
    if checks is None:
        if method=='get' and template=='/overview':checks=[{'field':'throughput.events','op':'gt','value':0}]
        elif method=='get' and template in ('/activity/overview','/dpi/overview'):checks=[{'field':'event_count','op':'gt','value':0}]
        elif method=='get' and template=='/application-activity':checks=[{'field':'observation_count','op':'gt','value':0},{'field':'items','op':'nonempty'}]
        elif method=='get' and template=='/events':checks=[{'field':'events','op':'nonempty'}]
        elif method=='get' and template in ('/devices','/application-activity/observations'):checks=[{'field':'items','op':'nonempty'}]
        elif method=='get' and template=='/device-recognition/summary':checks=[{'field':'total_endpoints','op':'gt','value':0},{'field':'event_count','op':'gt','value':0}]
        else:return 'unverified'
    checks=list(checks)
    if method=='get' and template in ('/overview','/activity/overview','/dpi/overview','/application-activity'):
        checks.append({'field':'statistics_as_of','op':'fresh','value':5})
    if method=='get' and template=='/application-activity/observations':
        checks.append({'field':'total_as_of','op':'fresh','value':5})
    if method=='get' and template=='/device-recognition/summary':
        checks.append({'field':'as_of','op':'fresh','value':5})
    for check in checks:
        value=payload
        for part in check['field'].split('.'):
            value=value.get(part) if isinstance(value,dict) else None
        if check['op']=='gt' and not (isinstance(value,(int,float)) and value>check['value']):return 'failed:'+check['field']
        if check['op']=='eq' and value!=check['value']:return 'failed:'+check['field']
        if check['op']=='nonempty' and not (isinstance(value,(list,dict,str)) and len(value)>0):return 'failed:'+check['field']
        if check['op']=='fresh':
            try:
                stamp=datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
                age=(datetime.datetime.now(datetime.timezone.utc)-stamp).total_seconds()
                if not -1<=age<=check['value']:return 'failed:stale_'+check['field']
            except (TypeError,ValueError,AttributeError):return 'failed:timestamp_'+check['field']
        if check['op'] not in ('gt','eq','nonempty','fresh'):raise ValueError('unknown business assertion '+check['op'])
    return 'verified'

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*a,**k): return None

def request(method,path,body=None,trace=None,extra_headers=None):
    jar=http.cookiejar.MozillaCookieJar(args.cookies) if args.cookies else http.cookiejar.CookieJar()
    if args.cookies:jar.load(ignore_discard=True)
    opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPCookieProcessor(jar))
    data=None if body is None else json.dumps(body).encode()
    headers={'Content-Type':'application/json'}
    if extra_headers:headers.update(extra_headers)
    if trace:headers['X-Benchmark-ID']=trace
    if csrf:headers['X-CSRF-Token']=csrf
    started=time.perf_counter();status=0;raw=b'';error=''
    try:
        with opener.open(urllib.request.Request(args.base.rstrip('/')+path,data=data,headers=headers,method=method),timeout=args.timeout) as response:status=response.status;raw=response.read()
    except urllib.error.HTTPError as e:status=e.code;raw=e.read()
    except Exception as e:error=type(e).__name__
    elapsed=(time.perf_counter()-started)*1000
    try:payload=json.loads(raw)
    except Exception:payload={}
    return {'status':status,'ms':round(elapsed,3),'bytes':len(raw),'error':error,'error_code':payload.get('code',payload.get('error','')) if status>=400 and isinstance(payload,dict) else ''},payload

def rows(payload):
    if isinstance(payload,list):return payload
    if not isinstance(payload,dict):return []
    for key in ['items','events','runs','signals','diagnostics','users','exceptions','actions','batches','policies','executions','flows','exports','audit_logs']:
        if isinstance(payload.get(key),list):return payload[key]
    return []

# A loopback address alone is insufficient: it could forward to production.
# Only the opt-in fixture server exposes this attestation; ordinary deployments
# must never accept the write-pressure flag.
if args.isolated_writes or args.owned_metrics:
    meta, identity=request('GET','/__benchmark__/identity')
    if meta['status']!=200 or not isinstance(identity,dict) or identity.get('fixture')!='proxy-sentinel-disposable-benchmark' or identity.get('isolated') is not True or identity.get('writes_allowed') is not True or identity.get('database')!='sentinel_benchmark':
        parser.error('write benchmarks refused: disposable fixture identity was not verified')

# Reuse real IDs where resources exist, without retaining their response documents.
for path,keys in [('/session',[]),('/devices?limit=20',['endpoint_id','current_ip','primary_mac','current_account']),('/risks?limit=20',['ip','account_id']),('/cases?limit=20',['case_id']),('/events?limit=20',['event_id']),('/dpi/flows?limit=20',['flow_id']),('/shadow/runs?limit=20',['run_id']),('/ingest/diagnostics?limit=20',['diagnostic_id']),('/audit-logs?limit=20',['audit_id']),('/actions?limit=20',['action_id']),('/actions/connectors',['connector_id']),('/integrations/identity/batches?limit=20',['batch_id']),('/policies?limit=20',['policy_id']),('/policy-executions?limit=20',['execution_id']),('/users',['user_id']),('/campus-exceptions',['exception_id'])]:
    meta,payload=request('GET',path)
    if path=='/session' and meta['status']==200:csrf=payload.get('csrf_token','')
    for row in rows(payload):
        for key in keys:
            if row.get(key):ids[{'current_ip':'ip','current_account':'account_id'}.get(key,key)]=str(row[key]);keys=[x for x in keys if x!=key]
        if not keys:break
    print('discovery',path,meta['status'],meta['ms'],flush=True)

def resolve(schema):
    if '$ref' in schema:
        value=spec
        for key in schema['$ref'].split('/')[1:]:value=value[key]
        return value
    return schema

def sample(schema,name='',depth=0):
    schema=resolve(schema)
    if depth>6:return None
    if 'default'in schema:return schema['default']
    if 'enum'in schema:return schema['enum'][0]
    for key in ('oneOf','anyOf'):
        if key in schema:return sample(schema[key][0],name,depth+1)
    if 'allOf'in schema:
        result={}
        for s in schema['allOf']:
            part=sample(s,name,depth+1)
            if isinstance(part,dict):result.update(part)
        return result
    typ=schema.get('type','object' if 'properties'in schema else 'string')
    if isinstance(typ,list):typ=next((x for x in typ if x!='null'),'string')
    if typ=='object':return {key:sample(value,key,depth+1) for key,value in schema.get('properties',{}).items() if key in schema.get('required',[]) or key in ('name','reason','enabled','code','campus_id','cidrs','endpoint_id','account_id','username','password','display_name')}
    if typ=='array':return [sample(schema.get('items',{}),name,depth+1) for _ in range(schema.get('minItems',0))]
    if typ in ('integer','number'):return max(schema.get('minimum',0),1)
    if typ=='boolean':return True
    if name in ids:return ids[name]
    if name=='password':return 'benchmark-local-123456'
    if name in ('ip','source_ip'):return ids['ip']
    if name in ('cidr',):return '203.0.113.0/24'
    if schema.get('format')=='date-time':return datetime.datetime.now(datetime.timezone.utc).isoformat()
    return 'benchmark-'+name if name else 'benchmark'

inventory=[];results=[]
for path,item in spec['paths'].items():
    for method,op in item.items():
        if method not in ('get','post','put','patch','delete','head'):continue
        entry={'method':method.upper(),'template':path,'operation_id':op.get('operationId','')}
        inventory.append(entry)
        if args.only and not re.search(args.only,method.upper()+' '+path):continue
        if method!='get' and not args.isolated_writes:
            results.append({**entry,'category':'not_run_live_write','samples':[]});continue
        if method=='get' and (path=='/application-activity/unknown-domains' or path.endswith('/account-preview')) and not args.isolated_writes:
            results.append({**entry,'category':'not_run_async_task_submission','samples':[]});continue
        if path in ('/auth/login','/auth/logout') and method=='post':
            results.append({**entry,'category':'session_setup_separate','samples':[]});continue
        values=dict(ids)
        if '/policies/{id}'in path:values['id']=ids['policy_id']
        elif '/policy-executions/{id}'in path:values['id']=ids.get('execution_id','bench-execution')
        elif '/accounts/{id}'in path:values['id']=ids['account_id']
        if '/users/'in path:values['operation']='enable'
        if '/cases/'in path:values['operation']='comments'
        if '/history/'in path:values['kind']='evidence'
        if '/policy-executions/'in path:values['operation']='approve'
        if '/jobs/'in path:values['operation']='pause'
        actual=re.sub(r'\{([^}]+)\}',lambda m:urllib.parse.quote(values.get(m.group(1),'benchmark-missing-'+m.group(1)),safe=''),path)
        query={}
        for param in item.get('parameters',[])+op.get('parameters',[]):
            param=resolve(param)
            if param.get('in')!='query':continue
            name=param['name'];s=resolve(param.get('schema',{}))
            if name=='limit':query[name]=20
            elif name=='window':query[name]=args.window
            elif name=='dimension':query[name]='domain'
            elif name=='account' and param.get('required'):query[name]=ids['account_id']
            elif param.get('required'):query[name]=sample(s,name)
        if query:actual+='?'+urllib.parse.urlencode(query)
        body=None
        if method!='get':
            req=resolve(op.get('requestBody',{}));content=req.get('content',{})
            body=sample(content.get('application/json',{}).get('schema',{})) if 'application/json'in content else {}
            if path=='/organization/{kind}':body={'campus_id':ids['campus_id'],'name':'Benchmark campus','code':'BENCH'}
            if path=='/cases/{case_id}/{operation}':body={'comment':'benchmark isolated fixture'}
            if path=='/actions/emergency-stop':body={'enabled':True,'reason':'benchmark fixture'}
            if path=='/users':body={'username':'benchmark-user','display_name':'Benchmark user','password':'benchmark-local-123456','role':'viewer'}
            if path=='/rules/reload':body={}
            if path=='/campus-exceptions':body={'scope_type':'ip','scope_value':ids['ip'],'reason':'benchmark isolated fixture','enabled':True}
            if path=='/labels':body={'target_type':'ip','target_id':ids['ip'],'label':'needs_more_data','reason':'benchmark isolated fixture','evidence_ids':['benchmark-evidence']}
            if path=='/actions/connectors':body={'connector_id':'bench-connector','name':'Benchmark shadow webhook','type':'http_webhook','enabled':False,'mode':'shadow','endpoint_url':'http://127.0.0.1:1','cooldown_seconds':60}
        fixture=fixtures.get(method.upper()+' '+path,{})
        if method!='get' and args.concurrency>1 and not fixture:
            parser.error('concurrent write has no operation-specific fixture: '+method.upper()+' '+path)
        if fixture:
            actual=fixture.get('path',actual)
            body=fixture.get('body',body)
        samples=[]
        route_trace=uuid.uuid4().hex[:16]
        scan_before=pg_counters() if args.owned_metrics else None
        lock_samples=[]
        metrics_stop.clear()
        def sample_locks():
            while not metrics_stop.wait(.1):
                try:
                    lock_samples.append(int(docker_sql('pg',"SELECT count(*) FROM pg_stat_activity WHERE datname='sentinel_benchmark' AND state='active' AND wait_event_type='Lock';")))
                except Exception:lock_samples.append(None)
        metrics_thread=threading.Thread(target=sample_locks,daemon=True) if args.owned_metrics else None
        if metrics_thread:metrics_thread.start()
        def perform(n):
            request_body=dict(body) if isinstance(body,dict) else body
            token=route_trace+'-'+str(n)
            for field in fixture.get('unique_fields',[]):
                request_body[field]=str(request_body.get(field,''))+'-'+token
            headers={key:value.replace('{sample}',token) for key,value in fixture.get('headers',{}).items()}
            if method=='post' and path=='/users':request_body['username']='benchmark-user-'+str(time.time_ns())
            meta,payload=request(method.upper(),actual,request_body,token,headers)
            visibility=fixture.get('visibility')
            if visibility and 200<=meta['status']<300:
                observed,document=request('GET',visibility['path'])
                expected=request_body[visibility['id_field']]
                records=document.get(visibility['collection'],[]) if isinstance(document,dict) else []
                meta['visibility_ms']=observed['ms']
                meta['immediate_visible']=observed['status']==200 and any(row.get(visibility['id_field'])==expected and all(row.get(k)==request_body.get(k) for k in visibility.get('match_fields',[])) for row in records if isinstance(row,dict))
            return meta,payload
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            for n,(meta,payload) in enumerate(executor.map(perform,range(args.samples))):
                meta['normal_result']=normal_result(path,method,payload) if 200<=meta['status']<300 else 'http_error'
                if meta.get('immediate_visible') is False:meta['normal_result']='failed:not_immediately_visible'
                samples.append(meta)
                if args.samples<=10:print(method.upper(),actual,n+1,meta['status'],meta['ms'],flush=True)
                if isinstance(payload,dict):
                    for key in ('export_id','exception_id','policy_id','action_id','connector_id','user_id'):
                        if payload.get(key):ids[key]=str(payload[key])
        ok=[s['ms']for s in samples if 200<=s['status']<300]
        verified=sum(s['normal_result']=='verified' for s in samples)
        category=('business_success' if verified==len(samples) else 'http_success_unverified_or_invalid_business') if len(ok)==len(samples) else 'mixed_or_error'
        metrics_stop.set()
        if metrics_thread:metrics_thread.join(timeout=12)
        sql_metrics={}
        if args.owned_metrics:
            scan_after=pg_counters()
            sql_metrics['postgres_global_counter_delta']={k:scan_after[k]-scan_before[k] for k in scan_before}
            sql_metrics['postgres_lock_sampling']={'interval_ms':100,'samples':lock_samples,'estimated_waiter_ms':sum(x for x in lock_samples if x is not None)*100,'method':'sampled active Lock waiters; global disposable database, includes background load'}
            docker_sql('ch','SYSTEM FLUSH LOGS;')
            raw_metrics=docker_sql('ch',"SELECT count() AS queries,sum(read_rows) AS scanned_rows,sum(read_bytes) AS scanned_bytes,max(memory_usage) AS peak_query_memory_bytes,quantileExact(.95)(query_duration_ms) AS sql_p95_ms FROM system.query_log WHERE type='QueryFinish' AND startsWith(query_id,'sentinel-bench-"+route_trace+"-') FORMAT JSONEachRow;")
            sql_metrics['clickhouse']=json.loads(raw_metrics)

        timings=sorted(s['ms'] for s in samples)
        result={**entry,'path':actual,'category':category,'samples':samples,'successes':len(ok),'normal_business_successes':verified,'business_failure_rate':1-verified/len(samples),'sql_metrics':sql_metrics,'p50_ms':statistics.median(timings),'p95_ms':timings[max(0,math.ceil(len(timings)*.95)-1)],'p99_ms':timings[max(0,math.ceil(len(timings)*.99)-1)],'error_rate':1-len(ok)/len(samples),'response_bytes_p50':statistics.median(s['bytes'] for s in samples),'max_ms':max(timings),'success_mean_ms':statistics.mean(ok) if ok else None}
        result['latency_gate_pass']=category=='business_success' and result['p95_ms']<=args.p95_limit_ms and result['p99_ms']<args.p99_limit_ms
        result['concurrent_sample_requirement_met']=args.samples>=200 and args.concurrency==20 and verified==args.samples
        result['concurrent_scenario_pass']=result['latency_gate_pass'] and result['concurrent_sample_requirement_met']
        results.append(result)
        print(method.upper(),actual,category,'p95_ms',round(result['p95_ms'],3),'p99_ms',round(result['p99_ms'],3),flush=True)
        with (out/'samples.jsonl').open('a') as f:f.write(json.dumps(result,ensure_ascii=False)+'\n')
summary={'base':args.base,'started_date':started_date,'finished_date':datetime.datetime.now(datetime.timezone.utc).isoformat(),'latency_limits_ms':{'p95_max':args.p95_limit_ms,'p99_exclusive_max':args.p99_limit_ms},'spec_sha256':hashlib.sha256(pathlib.Path(args.spec).read_bytes()).hexdigest(),'samples_per_route':args.samples,'concurrency':args.concurrency,'inventory':inventory,'results':results}
(out/'report.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2))
print('finished',len(results),'routes;',sum(r.get('category')=='business_success'for r in results),'normal business routes;',sum(r.get('concurrent_scenario_pass') for r in results),'passed concurrent latency scenarios (not full API acceptance)',flush=True)
