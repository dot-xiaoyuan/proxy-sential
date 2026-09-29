import { http, HttpResponse } from 'msw'
import type { AppReport, LibraryStatus } from '../features/applications/api'
const library: LibraryStatus = {enabled:true,config:{enabled:true,update_url:'http://192.168.0.30:8081'},library:{version:'demo-v1',versions:['demo-v1','demo-v0'],rule_count:6,activated_at:new Date().toISOString()},job:{status:'completed',version:'demo-v1',processed:18},last_scan:new Date().toISOString(),retained_observations:18}
library.processing={storage:'database',realtime:{status:'completed',version:'demo-v1',processed:18,last_success:new Date().toISOString(),lag_seconds:2,batch_millis:25,retries:0},history:library.job,reconcile:{status:'completed',version:'demo-v1',processed:18,batch_millis:32,retries:0},query_millis:15}
const bucket={connection_count:1,upload_bytes:null,download_bytes:null,missing_meter_connections:1}
const report: AppReport={items:['微信','企业微信','抖音','哔哩哔哩','QQ','腾讯视频'].map((name,i)=>({application_id:`app-${i}`,name,category:'service',terminal_count:3+i,connection_count:5+i,observation_count:8+i,upload_bytes:i===4?null:10240*(i+1),download_bytes:i===4?null:102400*(i+1),missing_meter_connections:i===4?1:0,last_seen:new Date().toISOString()})),versions:{'demo-v1':18},dns_observations:3,unknown_observations:2,missing_connection_observations:1,unknown:bucket,multi_application:{...bucket,upload_bytes:100,download_bytes:200},observation_count:18,traffic_basis:'窗口内有观测连接的累计字节；部分缺失时仅合计已知计量，不代表精确区间增量'}
let exportPolls=0;let exportCancelled=false
let pullPolls=0
let pullCancelled=false
export const applicationHandlers=[
 http.get('/api/v1/application-library',()=>{const response=HttpResponse.json(library);if(library.job.requested_control){library.job.status=library.job.requested_control==='pause'?'paused':'cancelled';library.job.requested_control=''}return response}),
 http.post('/api/v1/application-library/reclassify',()=>{library.job.status='running';return HttpResponse.json(library)}),
 http.post('/api/v1/application-library/jobs/:operation',({params})=>{if(params.operation==='resume'){library.job.status='running';library.job.requested_control=''}else{library.job.requested_control=String(params.operation)}return HttpResponse.json(library)}),
 http.post('/api/v1/application-library/pull',()=>{pullPolls=0;pullCancelled=false;return HttpResponse.json({task_id:'library-pull-demo',kind:'/application-library/pull',status:'queued',created_at:new Date().toISOString()},{status:202})}),
 http.get('/api/v1/tasks/library-pull-demo',()=>HttpResponse.json({task_id:'library-pull-demo',kind:'/application-library/pull',status:pullCancelled?'cancelled':++pullPolls>=2?'completed':'running',created_at:new Date().toISOString(),result:pullCancelled?undefined:library,response_status:200})),
 http.post('/api/v1/tasks/library-pull-demo/cancel',()=>{pullCancelled=true;return HttpResponse.json({task_id:'library-pull-demo',kind:'/application-library/pull',status:'cancelled',created_at:new Date().toISOString()})}),
 http.post('/api/v1/application-library/:operation',()=>HttpResponse.json(library)),
 http.get('/api/v1/application-activity',({request})=>{const id=new URL(request.url).searchParams.get('application_id');return HttpResponse.json({...report,as_of:new Date().toISOString(),statistics_as_of:new Date().toISOString(),items:id?report.items.filter(i=>i.application_id===id):report.items})}),
 http.get('/api/v1/application-activity/observations',()=>HttpResponse.json({total:1,items:[{event_id:'example-1',timestamp:new Date().toISOString(),ip:'10.20.8.11',sensor_id:'demo-sensor',campus_id:'main',connection_id:'conn-'+ 'a'.repeat(64),domain:'long-subdomain.weixin.qq.com',source_field:'tls.sni',bundle_version:'demo-v1',match:{name:'微信',rule_id:'wechat-domain-1',confidence:0,source:'reviewed-fixture',source_version:'1'}}]})),
 http.get('/api/v1/application-activity/unknown-domains',()=>{exportPolls=0;exportCancelled=false;return HttpResponse.json({export_id:'application-export-demo',status:'queued',row_count:0},{status:202})}),
 http.get('/api/v1/exports/application-export-demo',()=>HttpResponse.json({export_id:'application-export-demo',status:exportCancelled?'cancelled':++exportPolls>=2?'completed':'running',row_count:2})),
 http.post('/api/v1/exports/application-export-demo/cancel',()=>{exportCancelled=true;return HttpResponse.json({export_id:'application-export-demo',status:'cancelled',row_count:0})}),
 http.get('/api/v1/exports/application-export-demo/download',()=>new HttpResponse('{"domain":"unknown.example.com","observation_count":2}\n',{headers:{'Content-Type':'application/x-ndjson','Content-Disposition':'attachment; filename="unknown-domains.jsonl"'}})),
]
