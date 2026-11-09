import { expect, it } from 'vitest'
import { discoveryCSV } from './discoveryExport'

it('exports discovery rows with escaped CSV cells', () => {
  const csv = discoveryCSV([
    { id: 'mac:aa', name: 'A,"B"', mac: 'aa:bb', primary_ip: '10.0.0.1', device_type: 'camera', manufacturer: 'Hikvision', model_name: 'DS-2CD', classification_status: 'identified', evidence_count: 2 },
    { id: 'mac:cc', mac: 'cc:dd', current_addresses: ['10.0.0.2', 'fe80::1'], recognition: { device_type: 'access_point', brand: 'H3C', os_family: 'Linux', confidence: 0.9 }, classification_status: 'candidate' },
  ], { camera: '摄像机', access_point: '无线接入点' })
  expect(csv.startsWith('标识,名称,MAC,当前地址,设备类型,品牌,型号,操作系统,网络域,VLAN,采集传感器,证据状态,首次观测,最近观测,证据数')).toBe(true)
  expect(csv).toContain('"A,""B"""')
  expect(csv).toContain('摄像机')
  expect(csv).toContain('10.0.0.2;fe80::1')
  expect(csv).toContain('发现线索')
})
