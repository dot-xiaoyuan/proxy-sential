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
  expect(csv.startsWith('标识,名称,MAC,当前地址,设备类型,品牌,型号,操作系统,网络域,VLAN,采集传感器,证据状态,识别置信度,识别规则,窗口内首次观测,最近观测,证据数')).toBe(true)
  expect(csv).toContain('"A,""B"""')
  expect(csv).toContain('摄像机')
  expect(csv).toContain('10.0.0.2;fe80::1')
  expect(csv).toContain('发现线索')
  expect(csv).toContain('90%')
  expect(csv).toContain('satori-1')
})
