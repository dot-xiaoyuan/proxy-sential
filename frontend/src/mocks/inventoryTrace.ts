import { http, HttpResponse } from 'msw'
import { macOSDevice, macOSProfile, manufacturerReferenceDevices } from './deviceRecognition'
import { domainOnlyDevice, domainOnlyProfile } from './brandInference'
import { deviceInventoriesByIp } from './fixtures'
import type { InventoryDetail, EndpointObservation } from '../shared/api/types'

function detailFor(id:string):InventoryDetail|undefined {
 const reference=manufacturerReferenceDevices.find(v=>v.endpoint_id===id)
 if(reference||id===macOSDevice.endpoint_id||id===domainOnlyDevice.endpoint_id){const original=id===domainOnlyDevice.endpoint_id?domainOnlyProfile:macOSProfile;const recognition=reference||original.recognition;return {profile:{...original,endpoint_id:id,endpoint:{...original.endpoint,endpoint_id:id},recognition,sessions:[],ip_history:[],access_history:[]},associations:[],association_counts:{account:recognition?.current_account?1:0,ip:recognition?.current_ip?1:0,access:recognition?.current_access_id?1:0},state:{complete:true,updating:false,as_of:new Date().toISOString()}}}
 for(const inventory of Object.values(deviceInventoriesByIp)){
  const d=inventory.devices.find(v=>(v.endpoint_id||v.device_id)===id);if(!d)continue
  const account=d.account_id||'',mac=d.signals.find(v=>v.kind==='mac')?.normalized_value||''
  const stamp=d.last_seen||inventory.last_seen||new Date().toISOString()
  return {profile:{endpoint_id:id,summary:'',endpoint:{endpoint_id:id,primary_mac:mac,entity_role:'endpoint',first_seen:d.first_seen||inventory.first_seen||stamp,last_seen:stamp,identity_confidence:d.confidence,attributes:{},registration_status:d.endpoint_id?'registered':'unregistered',owner_account:account,owner_name:account?'样本用户':'',owner_department:account?'网络中心':'',merge_status:'active'},accounts:account?[account]:[],sessions:[],ip_history:[],access_history:[],recognition:{endpoint_id:id,entity_role:'endpoint',registration_status:'unregistered',merge_status:'active',accounts:[],ips:[],access_ids:[],recognition_confidence:d.confidence,first_seen:stamp,identity_confidence:d.confidence,summary:'',current_account:account,current_account_candidates:account?[account]:[],current_account_conflict:false,current_access_id:d.access_id||'',current_ip:inventory.ip,primary_mac:mac,last_seen:stamp,brand:d.brand||'',model:d.model||'',os_family:d.os_family||'',brand_confidence:d.confidence,os_family_confidence:d.confidence,randomized_mac:false,recognition_conflict:false}},associations:[{kind:'ip',value:inventory.ip,source:'mock',first_seen:inventory.first_seen||stamp,last_seen:stamp,observation_count:42,session_count:1,confidence:d.confidence}],association_counts:{account:account?1:0,ip:1,access:d.access_id?1:0},state:{complete:true,updating:false,as_of:new Date().toISOString()}}
 }
}

export const inventoryTraceHandlers=[
 http.get('/api/v1/device-inventory/:endpointId',({params})=>{const detail=detailFor(decodeURIComponent(String(params.endpointId)));return detail?HttpResponse.json(detail):HttpResponse.json({error:'not found'},{status:404})}),
 http.get('/api/v1/endpoints/:endpointId/observations',({params,request})=>{
  const detail=detailFor(decodeURIComponent(String(params.endpointId)));if(!detail)return HttpResponse.json({error:'not found'},{status:404})
  const q=new URL(request.url).searchParams,kind=q.get('kind')||'account',limit=Math.min(100,Number(q.get('limit')||20)),offset=Number(q.get('cursor')||0)
  const value=kind==='account'?detail.profile.recognition?.current_account:kind==='ip'?detail.profile.recognition?.current_ip:detail.profile.recognition?.current_access_id
  const items:EndpointObservation[]=value&&(!q.get('value')||q.get('value')===value)?Array.from({length:45},(_,i)=>({kind:kind as EndpointObservation['kind'],value,record_id:`mock-${i}`,source:'mock',observed_at:new Date(Date.now()-i*60000).toISOString(),confidence:.9,evidence_state:i>20?'outside_retention':'not_checked',event_id:`mock-event-${i}`})):[]
  return HttpResponse.json({items:items.slice(offset,offset+limit),next_cursor:offset+limit<items.length?String(offset+limit):undefined,state:detail.state})
 }),
]
