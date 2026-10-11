import {http,HttpResponse} from 'msw'
const now=new Date().toISOString()
export const discoveryHandlers=[
 http.get("*/discovery/nodes",()=>HttpResponse.json({items:[{node:"sensor-test",available:true}]})),
 http.get("*/discovery/summary",()=>HttpResponse.json({window:"24h",infrastructure:1,active_responses:0,pending_association:0,passive_devices:3,service_devices:1,linked_endpoints:1,last_materialized_at:now,materializer_status:'ready'})),
 http.get('*/discovery/devices',({request})=>{
  const url=new URL(request.url);const mode=url.searchParams.get('mode');
  if(mode!=='passive')return HttpResponse.json({total:1,items:[{id:'fixture-ikuai',addresses:[],address_details:[],historical_addresses:[{value:'192.168.15.1',last_seen:'2026-09-18T08:00:00Z'}],mac:'00:e0:67:2a:4f:4f',name:'iKuai-X86',device_type:'router',category:'network',identity_kind:'link_layer_device',capabilities:['routing'],protocols:['lldp'],confidence:'strong',first_seen:now,last_seen:now,current:true,evidence_count:1,endpoint_id:'mac:00:e0:67:2a:4f:4f',observations:[{id:'fixture-lldp',mac:'00:e0:67:2a:4f:4f',name:'iKuai-X86',origin:'lldp',observed_at:now,valid_until:now,explanation:'LLDP 网络基础设施公告'}]}]})
  const items=[
   {id:'fixture-printer',primary_ip:'192.0.2.10',addresses:['192.0.2.10','fe80::20c:29ff:fe00:10'],address_details:[{value:'192.0.2.10',family:'ipv4',scope:'global',primary:true},{value:'fe80::20c:29ff:fe00:10',family:'ipv6',scope:'link_local',primary:false}],mac:'00:11:22:33:44:55',name:'HP LaserJet Pro MFP',device_type:'printer',category:'printer',identity_kind:'network_address',capabilities:['printing','scanning'],protocols:['dns_sd','arp'],confidence:'confirmed',first_seen:now,last_seen:now,current:true,evidence_count:3,endpoint_id:'mac:00:11:22:33:44:55',observations:[{id:'fixture-event',ip:'192.0.2.10',mac:'00:11:22:33:44:55',name:'HP LaserJet Pro MFP',origin:'dns_sd',observed_at:now,valid_until:now,explanation:'DNS-SD 服务响应与地址记录自动关联',device_type:'printer',capabilities:['printing','scanning']}]},
   {id:'fixture-layer',addresses:[],address_details:[],mac:'00:11:22:33:44:77',category:'identity_only',identity_kind:'link_layer_association',capabilities:[],protocols:['ieee1905_client'],confidence:'confirmed',first_seen:now,last_seen:now,current:true,evidence_count:1,observations:[{id:'fixture-layer-event',mac:'00:11:22:33:44:77',origin:'ieee1905_client',observed_at:now,valid_until:now,explanation:'IEEE 1905 客户关联公告'}]},
   {id:'fixture-ipv6',primary_ip:'fe80::20c:29ff:fe00:20',addresses:['fe80::20c:29ff:fe00:20'],address_details:[{value:'fe80::20c:29ff:fe00:20',family:'ipv6',scope:'link_local',primary:true}],mac:'00:11:22:33:44:88',category:'identity_only',identity_kind:'network_address',capabilities:[],protocols:['ndp'],confidence:'confirmed',first_seen:now,last_seen:now,current:true,evidence_count:1,observations:[]},
  ]
  const category=url.searchParams.get('category');const filtered=category?items.filter(item=>item.category===category):items
  return HttpResponse.json({total:filtered.length,facets:[{category:'all',count:3},{category:'mobile',count:0},{category:'tablet',count:0},{category:'desktop',count:0},{category:'printer',count:1},{category:'camera',count:0},{category:'network',count:0},{category:'media',count:0},{category:'identity_only',count:2}],items:filtered})
 }),
 ...['sources','tasks','scan-profiles'].map(path=>http.get(`*/discovery/${path}`,()=>HttpResponse.json({items:[]}))),
 http.post('*/discovery/preview',()=>HttpResponse.json({total:2,targets:['192.0.2.1','192.0.2.2'],active_enabled:false})),
]
