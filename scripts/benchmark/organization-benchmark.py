import concurrent.futures,http.cookiejar,json,pathlib,statistics,time,urllib.request
import argparse,urllib.parse
parser=argparse.ArgumentParser(description='Organization latency reproduction against a disposable local fixture; issues writes.')
parser.add_argument('--cookies',required=True)
parser.add_argument('--base',default='http://127.0.0.1:28081/api/v1')
parser.add_argument('--output',required=True)
parser.add_argument('--samples',type=int,default=5)
parser.add_argument('--concurrency',type=int,default=1)
args=parser.parse_args()
if urllib.parse.urlsplit(args.base).hostname not in ('127.0.0.1','localhost','::1') or args.samples<1 or args.concurrency<1:parser.error('use only an explicitly disposable localhost fixture, never a production forward')
jar=http.cookiejar.MozillaCookieJar(args.cookies);jar.load(ignore_discard=True)
def call(method,path,body=None):
 op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
 with op.open(args.base.rstrip('/')+'/session') as r:csrf=json.load(r)['csrf_token']
 req=urllib.request.Request(args.base.rstrip('/')+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Content-Type':'application/json','X-CSRF-Token':csrf})
 start=time.perf_counter()
 with op.open(req,timeout=60) as r:r.read();return {'ms':round((time.perf_counter()-start)*1000,3),'status':r.status}
def measure(label,n=5,workers=1):
 output={}
 for method,path,body in [('GET','/organization',None),('GET','/overview?window=24h',None),('POST','/organization/campuses',{'campus_id':'bench-campus','name':'Benchmark campus','code':'BENCH'})]:
  t=time.perf_counter()
  with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:samples=list(pool.map(lambda _:call(method,path,body),range(n)))
  vals=sorted(s['ms']for s in samples);output[method+' '+path]={'samples':samples,'mean_ms':statistics.mean(vals),'p50_ms':statistics.median(vals),'max_ms':max(vals),'wall_ms':round((time.perf_counter()-t)*1000,3),'concurrency':workers}
  print(label,method,path,output[method+' '+path]['mean_ms'],flush=True)
 p=pathlib.Path(args.output);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(output,indent=2))
if __name__=='__main__':
 measure('isolated',n=args.samples,workers=args.concurrency)
