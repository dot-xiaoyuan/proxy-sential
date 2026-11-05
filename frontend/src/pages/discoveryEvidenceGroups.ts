import type {components} from '../shared/api/generated'

export type EvidenceObservation=components['schemas']['DiscoveryObservation']
export type EvidenceGroup={key:string;origin:string;sample:EvidenceObservation;records:EvidenceObservation[];count:number;firstSeen:string;lastSeen:string;state:'current'|'expired'|'withdrawn'|'recorded'}
function canonical(value:unknown):unknown {
 if(Array.isArray(value))return value.map(canonical)
 if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).filter(([,v])=>v!==undefined).sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>[k,canonical(v)]))
 return value
}
function semanticContent(record:EvidenceObservation,state:EvidenceGroup['state']) {
 const excluded=new Set(['id','event_id','snapshot_id','observed_at','reported_at','valid_until','evidence'])
 const fields=Object.fromEntries(Object.entries(record).filter(([key])=>!excluded.has(key)))
 const evidence=Object.fromEntries(Object.entries(record.evidence??{}).filter(([key])=>!['event_id','timestamp','raw_ref'].includes(key)))
 return JSON.stringify(canonical({...fields,capabilities:[...(record.capabilities??[])].sort(),evidence,state}))
}
export function groupDiscoveryEvidence(records:EvidenceObservation[],now=Date.now()):EvidenceGroup[] {
 const groups=new Map<string,EvidenceGroup>()
 const references=new Map<string,Set<string>>()
 for(const record of records){
  const expiry=Date.parse(record.valid_until)
  const state=record.withdrawn?'withdrawn':Number.isFinite(expiry)?expiry>now?'current':'expired':'recorded'
  const key=semanticContent(record,state)
  let group=groups.get(key)
  if(!group){group={key,origin:record.origin,sample:record,records:[],count:0,firstSeen:record.observed_at,lastSeen:record.observed_at,state};groups.set(key,group);references.set(key,new Set())}
  const ids=references.get(key)!
  if(!ids.has(record.id)){group.records.push(record);ids.add(record.id)}
  group.count=group.records.length
  if(Date.parse(record.observed_at)<Date.parse(group.firstSeen))group.firstSeen=record.observed_at
  if(Date.parse(record.observed_at)>Date.parse(group.lastSeen))group.lastSeen=record.observed_at
 }
 return [...groups.values()].sort((a,b)=>Date.parse(b.lastSeen)-Date.parse(a.lastSeen)||a.key.localeCompare(b.key))
}
export function evidenceService(record:EvidenceObservation) {
 const value=record.evidence?.payload?.service_type
 return typeof value==='string'?value:''
}
