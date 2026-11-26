import { expect, it, vi } from 'vitest'
import { discoveryCSV, fetchDiscoveryExport, readDiscoveryExport } from './discoveryExport'

it('accepts a complete snapshot with more than 2,000 rows', async () => {
  const lines = [JSON.stringify({record:'manifest',total:2401,snapshot_at:'2026-11-11T03:00:00Z'})]
  for (let index=0;index<2401;index++) lines.push(JSON.stringify({record:'item',item:{id:String(index)}}))
  lines.push(JSON.stringify({record:'end',count:2401,complete:true}))
  const bytes = new TextEncoder().encode(lines.join('\n')+'\n')
  const response = new Response(new ReadableStream({start(controller){controller.enqueue(bytes.slice(0,19));controller.enqueue(bytes.slice(19));controller.close()}}))
  const progress: number[] = []
  const result = await readDiscoveryExport<{id:string}>(response,count=>progress.push(count),item=>item.id)
  expect(result.items).toHaveLength(2401)
  expect(result.total).toBe(2401)
  expect(progress.at(-1)).toBe(2401)
})

it('rejects a truncated stream and a server error marker', async () => {
  await expect(readDiscoveryExport(new Response('{"record":"manifest","total":2}\n{"record":"item","item":{"id":"1"}}\n'))).rejects.toThrow('未收到完成校验')
  await expect(readDiscoveryExport(new Response('{"record":"manifest","total":1}\n{"record":"error","message":"读取失败"}\n'))).rejects.toThrow('读取失败')
})

it('exports the active filters without the current-page cursor', async () => {
  const fetcher = vi.spyOn(globalThis,'fetch').mockResolvedValue(new Response('{"record":"manifest","total":0}\n{"record":"end","count":0,"complete":true}\n'))
  try {
    await fetchDiscoveryExport(new URLSearchParams('mode=passive&type=camera&cursor=current-page&limit=20'))
    expect(String(fetcher.mock.calls[0][0])).toContain('type=camera')
    expect(String(fetcher.mock.calls[0][0])).not.toContain('cursor=current-page')
    expect(fetcher.mock.calls[0][1]).toMatchObject({credentials:'include'})
  } finally { fetcher.mockRestore() }
})

it('exports discovery rows with escaped CSV cells', () => {
  const csv = discoveryCSV([
    { id: 'mac:aa', name: 'A,"B"', mac: 'aa:bb', primary_ip: '10.0.0.1', device_type: 'camera', manufacturer: 'Hikvision', model_name: 'DS-2CD', classification_status: 'identified', evidence_count: 2 },
    { id: 'mac:cc', mac: 'cc:dd', current_addresses: ['10.0.0.2', 'fe80::1'], recognition: { device_type: 'access_point', brand: 'H3C', os_family: 'Linux', confidence: 0.9, rule_version: 'satori-1' }, classification_status: 'candidate' },
  ], { camera: '摄像机', access_point: '无线接入点' })
  expect(csv.startsWith('标识,名称,MAC,当前地址,设备类型,历史型号类型,型号自报时间,品牌,型号,操作系统,网络域,VLAN,采集传感器,证据状态,识别置信度,识别规则,窗口内首次观测,最近观测,证据数')).toBe(true)
  expect(csv).toContain('"A,""B"""')
  expect(csv).toContain('摄像机')
  expect(csv).toContain('10.0.0.2;fe80::1')
  expect(csv).toContain('发现线索')
  expect(csv).toContain('90%')
  expect(csv).toContain('satori-1')
  expect(csv).toContain('人工核实类型,人工核实型号,实物或台账依据,镜像覆盖核对,核实时间,核实人')
})

it('keeps expired product evidence separate from the effective type in CSV', () => {
  const csv = discoveryCSV([{id:'mac:printer',classification_status:'candidate',device_type:'camera',last_product_type:'printer',last_product_at:'2026-11-11T08:00:00Z'}],{camera:'摄像机',printer:'打印机'})
  expect(csv.split('\r\n')[1]).toMatch(/^mac:printer,,,,,打印机,2026-11-11T08:00:00Z,/)
  expect(csv.split('\r\n')[1]).not.toContain('摄像机')
})

it('exports the last observed IP in its own column when the current binding has expired', () => {
  const at = '2026-11-11T08:00:00Z'
  const [header, row] = discoveryCSV([{
    id: 'device', primary_ip: '192.0.2.7', current_addresses: [], last_observed_ip: '192.0.2.7', last_observed_ip_at: at,
  }], {}).split('\r\n').map(line => line.split(','))
  expect(row[header.indexOf('当前地址')]).toBe('')
  expect(row[header.indexOf('最后观测 IP')]).toBe('192.0.2.7')
  expect(row[header.indexOf('IP 观测时间')]).toBe(at)
})

it('exports the read-only review reason and leaves manual verification empty', () => {
  const csv = discoveryCSV([{id:'sample',review_reason:'address_only',review_observed_at:'2026-11-10T08:00:00Z'}],{})
  expect(csv).toContain('长期只有地址线索,2026-11-10T08:00:00Z,,,,,,')
})

it('exports retained hardware separately from activity and never restores a revoked type from legacy clues', () => {
  const csv = discoveryCSV([
    {id:'retained',classification_status:'expired',device_type:'camera',hardware_type:'printer',hardware_type_status:'identified',hardware_model:'Canon MF260 Series',type_evidence_at:'2026-11-09T08:00:00Z',activity_status:'stale',type_rule_version:'v8-test'},
    {id:'revoked',classification_status:'identified',device_type:'camera',hardware_type_status:'revoked',activity_status:'active'},
  ],{printer:'打印机',camera:'摄像机'})
  const lines=csv.split('\r\n')
  expect(lines[0]).toContain('硬件类型状态,类型依据时间,活动状态,硬件规则版本')
  expect(lines[1]).toContain('打印机')
  expect(lines[1]).toContain('Canon MF260 Series')
  expect(lines[1]).toContain('2026-11-09T08:00:00Z')
  expect(lines[2]).not.toContain('摄像机')
})

it('records the exact scope, timestamp and total in nonempty and empty downloads', () => {
  const manifest = {scope:'mode=passive&type=camera',snapshotAt:'2026-11-24T10:00:00Z',total:1}
  expect(discoveryCSV([{id:'one'}],{},manifest)).toContain('发现记录,mode=passive&type=camera,2026-11-24T10:00:00Z,1')
  expect(discoveryCSV([],{}, {...manifest,total:0})).toContain('导出摘要,mode=passive&type=camera,2026-11-24T10:00:00Z,0')
  expect(() => discoveryCSV([],{},manifest)).toThrow('清单不完整')
})

it('includes the attributed profile type and its basis in separate CSV fields', () => {
  const csv = discoveryCSV([{
    id:'profile', hardware_type_status:'candidate', classification_status:'candidate',
    type_evidence_state:'profile_typed', candidate_device_type:'mobile',
  }], {mobile:'手机'})
  const [headers, row] = csv.trim().split('\r\n').map(line => line.split(','))
  expect(row[headers.indexOf('设备类型')]).toBe('')
  expect(row[headers.indexOf('类型判断依据')]).toBe('画像识别')
  expect(row[headers.indexOf('画像类型')]).toBe('手机')
})
