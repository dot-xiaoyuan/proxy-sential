import {expect,it} from 'vitest'
import {groupDiscoveryEvidence} from './discoveryEvidenceGroups'
const now=Date.parse('2026-11-06T00:00:00Z')
const observation={id:'a',event_id:'event-a',origin:'dns_sd',source_id:'mirror',node:'sensor',site:'campus',domain:'office',vlan:'10',mac:'00:11:22:33:44:55',ip:'192.0.2.1',name:'printer',device_type:'printer',capabilities:['printing'],confidence:'strong',rule_version:'v1',observed_at:'2026-11-05T22:00:00Z',valid_until:'2026-11-06T01:00:00Z',explanation:'服务响应',evidence:{payload:{service_type:'_ipp._tcp',service_target:'printer.local',ttl:4500}}}
it('compacts identical facts while keeping first/last observation and all unique evidence references',()=>{
 const later={...observation,id:'b',event_id:'event-b',observed_at:'2026-11-05T23:00:00Z',valid_until:'2026-11-06T02:00:00Z'}
 const groups=groupDiscoveryEvidence([observation,later,observation],now)
 expect(groups).toHaveLength(1)
 expect(groups[0]).toMatchObject({count:2,firstSeen:observation.observed_at,lastSeen:later.observed_at,state:'current'})
 expect(groups[0].records.map(row=>row.event_id).sort()).toEqual(['event-a','event-b'])
})
it('does not merge distinct services, scopes, rule versions, withdrawals, or expiration states',()=>{
 const variants=[observation,{...observation,id:'scan',evidence:{payload:{service_type:'_uscan._tcp'}}},{...observation,id:'scope',vlan:'20'},{...observation,id:'rule',rule_version:'v2'},{...observation,id:'withdraw',withdrawn:true},{...observation,id:'expired',valid_until:'2026-11-05T23:00:00Z'}]
 expect(groupDiscoveryEvidence(variants,now)).toHaveLength(6)
})
it('compares payload object keys canonically but preserves meaningful array order and conflicting revisions',()=>{
 const a={...observation,evidence:{payload:{service_type:'_ipp._tcp',options:[1,3,6]}}}
 const b={...observation,id:'b',evidence:{payload:{options:[1,3,6],service_type:'_ipp._tcp'}}}
 const c={...observation,id:'c',evidence:{payload:{options:[6,3,1],service_type:'_ipp._tcp'}}}
 const correction={...a,device_type:'camera'}
 expect(groupDiscoveryEvidence([a,b,c,correction],now).map(g=>g.count).sort()).toEqual([1,1,2])
})
it('groups equal facts across different raw references while retaining both originals',()=>{
 const first={...observation,evidence:{...observation.evidence,raw_ref:{event_id:'raw-first',source_path:'capture/first',offset:100}}}
 const last={...observation,id:'second',observed_at:'2026-11-05T23:00:00Z',evidence:{...observation.evidence,raw_ref:{event_id:'raw-last',source_path:'capture/last',offset:200}}}
 const groups=groupDiscoveryEvidence([first,last],now)
 expect(groups).toHaveLength(1)
 expect(groups[0].count).toBe(2)
 expect(groups[0].records.map(r=>r.evidence?.raw_ref)).toEqual([first.evidence.raw_ref,last.evidence.raw_ref])
})
