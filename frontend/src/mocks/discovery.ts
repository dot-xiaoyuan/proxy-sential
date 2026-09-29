import {http,HttpResponse} from 'msw'
const now=new Date().toISOString()
export const discoveryHandlers=[
 http.get("*/discovery/nodes",()=>HttpResponse.json({items:[{node:"sensor-test",available:true}]})),
 http.get("*/discovery/summary",()=>HttpResponse.json({window:"24h",infrastructure:1,active_responses:0,pending_association:1})),
 http.get('*/discovery/devices',()=>HttpResponse.json({total:1,items:[{id:'fixture-printer',association:'pending',observations:[{id:'fixture-event',ip:'192.0.2.10',mac:'00:11:22:33:44:55',origin:'fdb',port:'GigabitEthernet1/0/10',vlan:'10',observed_at:now,valid_until:now,explanation:'交换机表项，路径线索'}]}]})),
 ...['sources','tasks','scan-profiles'].map(path=>http.get(`*/discovery/${path}`,()=>HttpResponse.json({items:[]}))),
 http.post('*/discovery/preview',()=>HttpResponse.json({total:2,targets:['192.0.2.1','192.0.2.2'],active_enabled:false})),
]
