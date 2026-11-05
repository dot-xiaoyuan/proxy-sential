import { http, HttpResponse } from 'msw'
import { riskSnapshots } from './fixtures'

export function mockPagePosition(q: URLSearchParams,total: number,defaultLimit=20,maxLimit=100) {
  const page=Number(q.get('page')||1),limit=Number(q.get('limit')||defaultLimit)
  if(!Number.isInteger(page)||page<1||!Number.isInteger(limit)||limit<1||limit>maxLimit)return HttpResponse.json({code:'bad_pagination_query',message:'页码或每页条数无效'},{status:400})
  if(page>1&&(page-1)*limit>=total)return HttpResponse.json({code:'page_out_of_range',message:'该页已不存在，请刷新列表'},{status:400})
  return HttpResponse.json({page,limit,cursor:page===1?'':String((page-1)*limit),as_of:q.get('as_of')||new Date().toISOString()})
}

export function mockPageMetadata(q: URLSearchParams,total: number) {
  return HttpResponse.json({total,as_of:q.get('as_of')||new Date().toISOString()})
}

function relayItems(q:URLSearchParams){
  const timestamp=new Date(Date.parse(q.get('to')||new Date().toISOString())-10*60_000).toISOString()
  return Array.from({length:45},(_,index)=>{
    const ip=`10.20.${Math.floor(index/200)}.${index%200+11}`,domain=index%2===0?'api.yunwu.ai':'api.micuapi.ai'
    return {ip,account_id:`student-${11+index}`,first_seen:timestamp,last_seen:timestamp,event_count:index+1,domains:[domain],domain_names:{[domain]:index%2===0?'云雾 API':'米醋中转站'},events:[{event_id:`ai-relay-mock-${index+1}`,timestamp,domain,source:'handshake_tls',sensor_id:'mock-sensor'}]}
  }).filter(item=>(!q.get('ip')||item.ip===q.get('ip'))&&(!q.get('domain')||item.domains.some(domain=>domain.endsWith(q.get('domain')!)))&&(!q.get('sensor_id')||q.get('sensor_id')==='mock-sensor'))
}

function streamEvents(q:URLSearchParams){
  const scope=q.get('scope_id')||'',observed=new Date(Date.parse(q.get('to')||new Date().toISOString())-60_000).toISOString()
  return [{observed_at:observed,event_key:'mock-stream-event-1',protocol:q.get('protocol')||'ssdp',event_type:'device',source:'zeek',sensor_id:'mock-sensor',subject_ip:'192.0.2.8',src_ip:'192.0.2.8',dst_ip:'239.255.255.250',body_ref:{class:'evidence',month:observed.slice(0,7).replace('-',''),scope,key:'mock-stream-event-1',sha256:'a'.repeat(64)}}]
}

function riskItems(q:URLSearchParams){
  const account=q.get('subject_type')==='account'
  return [{...riskSnapshots[0],ip:account?'':'192.0.2.8',subject_type:account?'account':'ip',subject_id:account?'mock-account':'192.0.2.8',updated_at:new Date().toISOString()}].filter(item=>!q.get('level')||q.get('level')===item.level)
}

export const auxiliaryPaginationHandlers=[
  http.get('/api/v1/ai-relay/usages/position',({request})=>{const q=new URL(request.url).searchParams;return mockPagePosition(q,relayItems(q).length,20,50)}),
  http.get('/api/v1/ai-relay/usages',({request})=>{const q=new URL(request.url).searchParams,all=relayItems(q),limit=Number(q.get('limit')||20),offset=Number(q.get('cursor')||0),items=all.slice(offset,offset+limit);return HttpResponse.json({items,page:{limit,total:all.length,next_cursor:offset+items.length<all.length?String(offset+items.length):null},indicator_version:'mock-v1'})}),
  ...['metadata','position'].map(operation=>http.get(`/api/v1/events/stream-index/${operation}`,({request})=>{const q=new URL(request.url).searchParams;if(!q.get('scope_id'))return HttpResponse.json({code:'bad_stream_query',message:'scope_id is required'},{status:400});const total=streamEvents(q).length;return operation==='metadata'?mockPageMetadata(q,total):mockPagePosition(q,total,50)})),
  http.get('/api/v1/events/stream-index',({request})=>{const q=new URL(request.url).searchParams;if(!q.get('scope_id'))return HttpResponse.json({code:'bad_stream_query',message:'scope_id is required'},{status:400});return HttpResponse.json({events:streamEvents(q).slice(Number(q.get('cursor')||0),Number(q.get('cursor')||0)+Number(q.get('limit')||50))})}),
  ...['metadata','position'].map(operation=>http.get(`/api/v1/risks/stream-current/${operation}`,({request})=>{const q=new URL(request.url).searchParams,total=riskItems(q).length;return operation==='metadata'?mockPageMetadata(q,total):mockPagePosition(q,total)})),
  http.get('/api/v1/risks/stream-current',({request})=>{const q=new URL(request.url).searchParams;return HttpResponse.json({items:riskItems(q).slice(Number(q.get('cursor')||0),Number(q.get('cursor')||0)+Number(q.get('limit')||20)),accepted_after:'2026-10-26T02:24:31.585894Z'})}),
]
