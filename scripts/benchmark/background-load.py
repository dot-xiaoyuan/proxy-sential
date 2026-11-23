#!/usr/bin/env python3
"""Bounded synthetic ingestion and export jobs on the disposable fixture only."""
import argparse, datetime, http.cookiejar, json, signal, time, urllib.parse, urllib.request, uuid

p=argparse.ArgumentParser()
p.add_argument('--ch',required=True)
p.add_argument('--api',default='http://127.0.0.1:28081/api/v1')
p.add_argument('--cookies',required=True)
p.add_argument('--rate',type=int,default=100)
p.add_argument('--seconds',type=int,default=600)
args=p.parse_args()
if not args.ch.startswith('http://127.0.0.1:28129') or not args.api.startswith('http://127.0.0.1:28081/api/v1') or not 1<=args.rate<=1000 or args.seconds<1:
    p.error('only the named disposable loopback fixture is allowed; rate must be 1..1000')
jar=http.cookiejar.MozillaCookieJar(args.cookies);jar.load(ignore_discard=True)
opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
csrf=''
def api(method,path,body=None):
    headers={'Content-Type':'application/json','X-CSRF-Token':csrf}
    req=urllib.request.Request(args.api+path,data=None if body is None else json.dumps(body).encode(),method=method,headers=headers)
    with opener.open(req,timeout=15) as response:return response.status,json.load(response)
_,identity=api('GET','/__benchmark__/identity')
if identity.get('fixture')!='proxy-sentinel-disposable-benchmark' or identity.get('database')!='sentinel_benchmark' or identity.get('isolated') is not True:
    p.error('disposable fixture attestation failed')
_,session=api('GET','/session');csrf=session['csrf_token']
params=urllib.parse.urlsplit(args.ch);query=urllib.parse.parse_qs(params.query)
query['date_time_input_format']=['best_effort'];query['async_insert']=['0']
ch=urllib.parse.urlunsplit(params._replace(query=urllib.parse.urlencode(query,doseq=True)))
def insert(table,rows):
    body=('INSERT INTO '+table+' FORMAT JSONEachRow\n'+'\n'.join(json.dumps(row,separators=(',',':')) for row in rows)).encode()
    with urllib.request.urlopen(urllib.request.Request(ch,data=body,method='POST'),timeout=20) as response:response.read()
run=uuid.uuid4().hex[:12];sensor='bench-scale-20260917';stopped=False
def stop(*_):
    global stopped
    stopped=True
signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
start=time.monotonic();total=0;jobs=0
for batch in range(args.seconds):
    if stopped:break
    began=time.monotonic();events=[];now=datetime.datetime.now(datetime.timezone.utc)
    for i in range(args.rate):
        n=batch*args.rate+i;stamp=(now-datetime.timedelta(microseconds=args.rate-i)).isoformat().replace('+00:00','Z')
        typ=['dns','http','tls'][n%3];ip='10.0.'+str(n%24000//250)+'.'+str(n%250+1)
        event_id=f'bench-load-{run}-{n}'
        domain=f'service-{n%40}.example.test'
        payload={'query':domain} if typ=='dns' else {'host':domain,'user_agent':'benchmark-agent'} if typ=='http' else {'sni':domain,'ja3':'benchmark-ja3','ja4':'benchmark-ja4'}
        events.append({'timestamp':stamp,'event_id':event_id,'schema_version':'v1','source':'benchmark-synthetic','source_event_type':typ,'type':typ,'sensor_id':sensor,'campus_id':'bench-campus','subject_ip':ip,'src_ip':ip,'dst_ip':'1.1.1.1','dst_port':443,'proto':'tcp','observer_json':json.dumps({'sensor_id':sensor}),'payload_json':json.dumps(payload),'flow_json':json.dumps({'ttl':64,'app_protocol':typ}),'raw_ref_json':'{}','confidence':.95})
    insert('normalized_events',events);total+=len(events)
    if batch%5==0:
        status,job=api('POST','/exports',{'kind':'risks','from':(now-datetime.timedelta(days=1)).isoformat(),'to':now.isoformat()})
        if status!=202 or not job.get('export_id'):raise RuntimeError('normal background export was not accepted')
        jobs+=1
    if batch%10==0:print(json.dumps({'run':run,'elapsed_seconds':round(time.monotonic()-start,2),'events':total,'export_jobs':jobs,'target_rate':args.rate}),flush=True)
    time.sleep(max(0,1-(time.monotonic()-began)))
print(json.dumps({'run':run,'elapsed_seconds':round(time.monotonic()-start,2),'events':total,'export_jobs':jobs,'completed':True}),flush=True)
