// Browser replay fixtures only. These records are not field observations.
import {http, HttpResponse} from 'msw'
import {worker} from './browser'

export function installHardwareReplay() {
  const now = new Date().toISOString()
  const evidenceAt = new Date(Date.now() - 3 * 86400_000).toISOString()
  const items = [
    {id:'hardware-printer',hardware_type:'printer',hardware_model:'Canon MF260 Series',hardware_type_status:'identified',hardware_model_status:'identified',activity_status:'stale',name:'回放多功能打印机',device_type:'printer',primary_ip:'192.0.2.10',mac:'00:11:22:33:44:55',capabilities:['printing','scanning'],protocols:['dns_sd','arp']},
    {id:'hardware-environment',hardware_type:'environment_monitor',hardware_model:'NetBotz 250',hardware_type_status:'identified',hardware_model_status:'identified',activity_status:'active',name:'回放环境监测设备',device_type:'environment_monitor',primary_ip:'192.0.2.20',mac:'00:11:22:33:44:66',capabilities:[],protocols:['snmp','arp']},
  ].map(item=>({...item,sensor_id:'sensor-test',site:'主校区',domain:'教学网',vlan:'20',category:item.device_type,classification_status:'identified',classification_version:'passive-hardware/v2',current:item.activity_status==='active',identity_kind:'scoped_mac',first_seen:evidenceAt,last_seen:now,evidence_count:1,current_addresses:item.activity_status==='active'?[item.primary_ip]:[],observations:[],type_evidence_at:evidenceAt,type_rule_version:'hardware-replay-v8',type_sources:[{source:item.protocols[0],rule_id:`fixture:${item.device_type}`,rule_version:'hardware-replay-v8',evidence_id:`source-event:${item.id}`,observed_at:evidenceAt}]}))
  const summary={metric_version:'passive-census/v2',scope:{sensor_id:'sensor-test'},window:'168h0m0s',status:'ready',as_of:now,available_from:evidenceAt,failed_batches:0,last_batch_rows:2,last_batch_ms:4,observed_ips:2,observed_ipv4:2,observed_ipv6:0,observed_macs:2,random_macs:0,incomplete_scope:0,active_bindings:1,identified_terminals:2,terminal_candidates:0,terminal_conflicts:0,terminal_expired:0,manually_verified:0,types:['printer','camera','recorder','access_control','voip_phone','environment_monitor','ups','pdu'].map(device_type=>({device_type,identified:['printer','environment_monitor'].includes(device_type)?1:0,candidate:0,conflict:0,expired:0}))}
  worker.use(
    http.get('*/discovery/devices',()=>HttpResponse.json({items,has_more:false,next_cursor:'',limit:20,window:'24h',classification_version:'passive-hardware/v2'})),
    http.get('*/discovery/devices/metadata',()=>HttpResponse.json({total:2,identified:2,candidate:0,conflict:0,expired:0,classification_version:'passive-hardware/v2',types:[{device_type:'printer',count:1},{device_type:'environment_monitor',count:1}],as_of:now,count_unit:'trusted_discovery_identity',window:'24h'})),
    http.get('*/discovery/census/summary',()=>HttpResponse.json(summary)),
    http.get('*/discovery/census/identifiers',()=>HttpResponse.json({items:[],has_more:false,next_cursor:''})),
  )
}
