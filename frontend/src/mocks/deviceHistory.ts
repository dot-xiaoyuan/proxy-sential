import { http, HttpResponse } from 'msw'
const at='2026-10-12T12:00:00Z'
export const deviceHistoryHandlers=[
 http.get('*/device-history/:kind/:id',({request,params})=>{
  const url=new URL(request.url);const raw=url.searchParams.has('group');const offset=Number(url.searchParams.get('offset')||0),limit=Number(url.searchParams.get('limit')||20)
  const items=Array.from({length:raw?27:3},(_,index)=>({id:`${params.kind}-${index}`,stream:String(params.id),first_seen:at,last_seen:at,count:raw?1:27,content:raw?{id:`event-${index}`,origin:'dns_sd',ip:'192.0.2.10',event_id:`event-${index}`,name:'HP LaserJet Pro MFP',capabilities:['printing']}: {ip:'192.0.2.10',origin:params.kind==='discovery'?'dns_sd':undefined,status:index===1?'likely':'confirmed',rule_version:'v1',confidence:index===1?65:90,name:'HP LaserJet Pro MFP',capabilities:['printing']}}))
  return HttpResponse.json({items:items.slice(offset,offset+limit),total:items.length,as_of:at})
 }),
 http.get('*/shared-access/network-context',()=>HttpResponse.json({})),
]
