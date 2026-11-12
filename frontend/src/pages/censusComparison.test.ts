import { expect, it } from 'vitest'
import { compareCensus, normalizeIP, normalizeMAC, readComparisonCSV, type CensusRow } from './censusComparison'

const scope={scope_key:'scope-a',sensor_id:'sensor-204',campus_id:'east',access_domain:'access',vlan:'20',vrf:''}
const local:CensusRow[]=[
  {...scope,kind:'ip',value:'10.20.0.2'},
  {...scope,kind:'mac',value:'00:11:22:33:44:55'},
  {...scope,kind:'binding',value:'10.20.0.2|00:11:22:33:44:55',ip:'10.20.0.2',mac:'00:11:22:33:44:55'},
  {...scope,kind:'terminal',value:JSON.stringify(['identity','sensor-204','east','access','20','','mac','00:11:22:33:44:55']),effective_type:'printer',classification_status:'identified'},
]
const headers=['scope','ip','mac','type']
const mapping={scope:0,ip:1,mac:2,type:3}

it('parses quoted CSV fields and enforces local file limits',async()=>{
  const csv=await readComparisonCSV(new File(['\uFEFFscope,ip,mac,type\r\n"a,b",10.0.0.1,00-11-22-33-44-55,"打印\n机"\r\n'],'test.csv'))
  expect(csv.rows).toEqual([['a,b','10.0.0.1','00-11-22-33-44-55','打印\n机']])
  await expect(readComparisonCSV(new File(['a,b\n','x,y\n'.repeat(200_001)],'large.csv'))).rejects.toThrow('200,000 行')
})

it('compares same-scope MAC and reports type and binding differences without merging by IP',()=>{
  const same=compareCensus(local,{headers,rows:[['sensor-204|east|access|20|','10.20.0.2','00-11-22-33-44-55','printer']]},mapping)
  expect(same.filter(row=>row.result==='shared')).toHaveLength(1)
  const changed=compareCensus(local,{headers,rows:[['sensor-204|east|access|20|','10.20.0.2','00-11-22-33-44-66','camera']]},mapping)
  expect(changed.some(row=>row.result==='address_rebind')).toBe(true)
  expect(changed.some(row=>row.result==='shared')).toBe(false)
  const type=compareCensus(local,{headers,rows:[['sensor-204|east|access|20|','10.20.0.2','00:11:22:33:44:55','camera']]},mapping)
  expect(type.some(row=>row.result==='type_difference')).toBe(true)
})

it('keeps incomplete or different network scopes separate',()=>{
  const result=compareCensus(local,{headers,rows:[['20','10.20.0.2','00:11:22:33:44:55','printer']]},mapping)
  expect(result[0].result).toBe('scope_review')
  expect(normalizeMAC('ff:ff:ff:ff:ff:ff')).toBe('')
  expect(normalizeIP('10.300.0.1')).toBe('')
  const incomplete=compareCensus([{...local[0],vlan:''}],{headers,rows:[]},mapping)
  expect(incomplete[0].result).toBe('scope_review')
})

it('keeps multiple addresses on one MAC and reads terminal type from projected MAC',()=>{
  const dual:CensusRow[]=[...local,
    {...scope,kind:'ip',value:'2001:db8::2'},
    {...scope,kind:'binding',value:'2001:db8::2|00:11:22:33:44:55',ip:'2001:db8::2',mac:'00:11:22:33:44:55'},
  ]
  dual[3]={...dual[3],value:JSON.stringify(['identity','sensor-204','east','access','20','','endpoint','asset-1']),mac:'00:11:22:33:44:55'}
  const result=compareCensus(dual,{headers,rows:[['sensor-204|east|access|20|','2001:db8::2','00:11:22:33:44:55','打印机']]},mapping)
  expect(result.some(row=>row.result==='address_rebind')).toBe(false)
  expect(result.some(row=>row.result==='type_difference')).toBe(false)
  expect(result.some(row=>row.result==='shared'&&row.ip==='2001:db8::2')).toBe(true)
})

it('reports invalid and duplicate imported rows instead of silently dropping them',()=>{
  const result=compareCensus(local,{headers,rows:[
    ['sensor-204|east|access|20|','bad-ip','',''],
    ['sensor-204|east|access|20|','10.20.0.2','00:11:22:33:44:55','printer'],
    ['sensor-204|east|access|20|','10.20.0.2','00:11:22:33:44:55','camera'],
  ]},mapping)
  expect(result.filter(row=>row.result==='input_review')).toHaveLength(2)
  expect(result.some(row=>row.reason.includes('格式不合法'))).toBe(true)
  expect(result.some(row=>row.reason.includes('重复'))).toBe(true)
})
