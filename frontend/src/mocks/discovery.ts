import {http,HttpResponse} from 'msw'
const now=new Date().toISOString()
export const discoveryHandlers=[
 http.get('*/discovery/types',()=>HttpResponse.json({version:'iot-evidence-v2',items:[{id:'printer',label:'打印机',category:'printer'},{id:'camera',label:'摄像机',category:'camera'},{id:'access_control',label:'门禁设备',category:'access_control'},{id:'sensor',label:'传感设备',category:'sensor'}]})),
 http.get('*/discovery/coverage',()=>HttpResponse.json({enabled:true,scope:'private',items:[{sensor_id:'sensor-test',protocol:'dns_sd',enabled:true,received:12,parsed:10,rejected:2,admitted:10,error:''}]})),
 http.get('*/discovery/statistics',()=>HttpResponse.json({pending_updates:0,oldest_pending_at:null,items:[{device_type:'printer',state:'identified',count:1,updated_at:now}]})),
 http.get('*/discovery/history',()=>HttpResponse.json({items:[],has_more:false,next_cursor:''})),
 http.get("*/discovery/nodes",()=>HttpResponse.json({items:[{node:"sensor-test",available:true}]})),
 http.get("*/discovery/summary",()=>HttpResponse.json({window:"24h",infrastructure:1,active_responses:0,pending_association:0,passive_devices:3,service_devices:1,linked_endpoints:1,last_materialized_at:now,materializer_status:'ready'})),
 http.get('*/discovery/devices',({request})=>{
  const url=new URL(request.url);const mode=url.searchParams.get('mode');
  if(mode!=='passive')return HttpResponse.json({next_cursor:'',has_more:false,items:[{id:'fixture-ikuai',addresses:[],address_details:[],historical_addresses:[{value:'192.168.15.1',last_seen:'2026-09-18T08:00:00Z'}],mac:'00:e0:67:2a:4f:4f',name:'iKuai-X86',device_type:'router',category:'network',identity_kind:'link_layer_device',capabilities:['routing'],protocols:['lldp'],confidence:'strong',first_seen:now,last_seen:now,current:true,evidence_count:1,endpoint_id:'mac:00:e0:67:2a:4f:4f',observations:[{id:'fixture-lldp',mac:'00:e0:67:2a:4f:4f',name:'iKuai-X86',origin:'lldp',observed_at:now,valid_until:now,explanation:'LLDP 网络基础设施公告'}]}]})
  const items=[
   {id:'fixture-printer',classification_status:'identified',last_device_type:'printer',model_name:'LaserJet Pro MFP',manufacturer:'HP',primary_ip:'192.0.2.10',addresses:['192.0.2.10','fe80::20c:29ff:fe00:10'],address_details:[{value:'192.0.2.10',family:'ipv4',scope:'global',primary:true},{value:'fe80::20c:29ff:fe00:10',family:'ipv6',scope:'link_local',primary:false}],mac:'00:11:22:33:44:55',name:'HP LaserJet Pro MFP',device_type:'printer',category:'printer',identity_kind:'network_address',capabilities:['printing','scanning'],protocols:['dns_sd','arp'],confidence:'confirmed',first_seen:now,last_seen:now,current:true,evidence_count:3,endpoint_id:'mac:00:11:22:33:44:55',observations:[{id:'fixture-event',ip:'192.0.2.10',mac:'00:11:22:33:44:55',name:'HP LaserJet Pro MFP',origin:'dns_sd',confidence:'strong',observed_at:now,valid_until:now,explanation:'DNS-SD 服务响应与地址记录自动关联',device_type:'printer',capabilities:['printing','scanning']}]},
   {id:'fixture-layer',addresses:[],address_details:[],mac:'00:11:22:33:44:77',category:'identity_only',identity_kind:'link_layer_association',capabilities:[],protocols:['ieee1905_client'],confidence:'confirmed',first_seen:now,last_seen:now,current:true,evidence_count:1,observations:[{id:'fixture-layer-event',mac:'00:11:22:33:44:77',origin:'ieee1905_client',observed_at:now,valid_until:now,explanation:'IEEE 1905 客户关联公告'}]},
   {id:'fixture-ipv6',primary_ip:'fe80::20c:29ff:fe00:20',addresses:['fe80::20c:29ff:fe00:20'],address_details:[{value:'fe80::20c:29ff:fe00:20',family:'ipv6',scope:'link_local',primary:true}],mac:'00:11:22:33:44:88',category:'identity_only',identity_kind:'network_address',capabilities:[],protocols:['ndp'],confidence:'confirmed',first_seen:now,last_seen:now,current:true,evidence_count:1,observations:[]},
  ]
  const category=url.searchParams.get('category');const scoped=url.searchParams.get('view')==='iot'?items.filter(item=>item.capabilities.some(c=>['printing','scanning','network_video','casting','media_rendering'].includes(c))):items;const filtered=category?scoped.filter(item=>item.category===category):scoped
  return HttpResponse.json({next_cursor:'',has_more:false,facets:[{category:'all',count:3},{category:'mobile',count:0},{category:'tablet',count:0},{category:'desktop',count:0},{category:'printer',count:1},{category:'camera',count:0},{category:'network',count:0},{category:'media',count:0},{category:'identity_only',count:2}],items:filtered,freshness:{status:'ready',lag_seconds:0,result_version:1}})
 }),
 http.get('*/discovery/sources',()=>HttpResponse.json({items:[
  {id:'core-sw-01',name:'核心交换机',node:'sensor-test',site:'主校区',domain:'教学网',address:'192.0.2.2',snmp_version:'3',interval_seconds:300,enabled:true,config_version:3},
  {id:'core-sw-02',name:'',node:'sensor-test',site:'主校区',domain:'办公网',address:'192.0.2.3',snmp_version:'2c',interval_seconds:600,enabled:false,config_version:1},
 ]})),
 http.get('*/discovery/scan-profiles',()=>HttpResponse.json({items:[
  {id:'scan-campus',node:'sensor-test',site:'主校区',domain:'教学网',version:2,trial_version:2,enabled:true,config:{allow:['192.0.2.0/24','198.51.100.0/24'],exclude:['192.0.2.1'],addresses:['fe80::1'],interface:'eth0',protocols:['icmp','arp'],sensitive:false,interval_seconds:86400}},
  {id:'scan-lab',node:'sensor-test',site:'实验区',domain:'实验网',version:4,trial_version:3,enabled:false,config:{allow:['203.0.113.0/24'],exclude:[],addresses:[],interface:'eth1',protocols:['icmp'],sensitive:true,interval_seconds:604800}},
 ]})),
 http.get('*/discovery/tasks',()=>HttpResponse.json({items:[
  {id:'task-1',source_id:'core-sw-01',status:'complete',created_at:now,result:{tables:[{name:'arp',count:128,complete:true},{name:'fdb',count:96,complete:true}]}},
  {id:'task-2',source_id:'core-sw-02',status:'failed',created_at:now,error:'SNMP 请求超时'},
  {id:'task-3',source_id:'core-sw-01',status:'running',created_at:now},
 ]})),
 http.post('*/discovery/preview',()=>HttpResponse.json({total:2,targets:['192.0.2.1','192.0.2.2'],active_enabled:false})),
]
