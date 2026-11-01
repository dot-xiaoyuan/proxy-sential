import { describe, expect, it } from 'vitest'
import { currentFlowTargets, flowBelongsToDevice, serviceBelongsToDevice, signalAddressMatchesDevice } from './discoveryServiceAttribution'

describe('镜像服务公告归属', () => {
  const device = { name: '', primary_ip: '10.202.157.235', current_addresses: ['10.202.157.235'] }

  it('不把同一网关 MAC 的其他主机公告挂到当前地址', () => {
    expect(serviceBelongsToDevice(device, { source_ip: '', service_target: 'LAPTOP-D5S9AJGK.local.' })).toBe(false)
    expect(serviceBelongsToDevice(device, { source_ip: '10.202.157.236', service_target: '' })).toBe(false)
  })

  it('允许当前地址或精确主机名匹配的公告', () => {
    expect(serviceBelongsToDevice(device, { source_ip: '10.202.157.235', service_target: '' })).toBe(true)
    expect(serviceBelongsToDevice({ ...device, name: 'LAPTOP-D5S9AJGK' }, { source_ip: '', service_target: 'laptop-d5s9ajgk.local.' })).toBe(true)
  })

  it('有明确来源地址时不以同名覆盖地址冲突', () => {
    expect(serviceBelongsToDevice({ ...device, name: 'LAPTOP-D5S9AJGK' }, { source_ip: '10.202.157.236', service_target: 'LAPTOP-D5S9AJGK.local.' })).toBe(false)
  })

  it('同一网关 MAC 的 TTL 不跨地址复用', () => {
    expect(signalAddressMatchesDevice(device, { ip: '10.202.157.236' })).toBe(false)
    expect(signalAddressMatchesDevice(device, { ip: '10.202.157.235' })).toBe(true)
    expect(signalAddressMatchesDevice(device, { ip: '' })).toBe(true)
  })
})

describe('被动目标端口的当前地址归属', () => {
  it('缺少传感器的异步状态行不生成 undefined 查询目标', () => {
    const current_addresses = ['10.202.51.48']
    expect(currentFlowTargets([
      { current_addresses },
      { sensor_id: '', current_addresses },
      { sensor_id: '  ', current_addresses },
      { sensor_id: 'sensor-a', current_addresses },
    ])).toEqual(['sensor-a|10.202.51.48'])
  })

  it('不查询历史地址，查询目标去重并保持稳定顺序', () => {
    expect(currentFlowTargets([
      { sensor_id: 'b', primary_ip: '192.0.2.1', current_addresses: [] },
      { sensor_id: 'b', primary_ip: '192.0.2.2' },
      { sensor_id: 'b', current_addresses: ['192.0.2.3', '', '192.0.2.3'] },
      { sensor_id: 'a', current_addresses: ['192.0.2.3'] },
    ])).toEqual(['a|192.0.2.3', 'b|192.0.2.3'])
  })

  it('同 IP 的其他传感器和历史地址不归属到当前设备', () => {
    const device = { sensor_id: 'sensor-a', current_addresses: ['192.0.2.3'], primary_ip: '192.0.2.2' }
    expect(flowBelongsToDevice(device, { sensor_id: 'sensor-a', src_ip: '192.0.2.3' })).toBe(true)
    expect(flowBelongsToDevice(device, { sensor_id: 'sensor-b', src_ip: '192.0.2.3' })).toBe(false)
    expect(flowBelongsToDevice(device, { sensor_id: 'sensor-a', src_ip: '192.0.2.2' })).toBe(false)
    expect(flowBelongsToDevice({ current_addresses: ['192.0.2.3'] }, { sensor_id: 'undefined', src_ip: '192.0.2.3' })).toBe(false)
  })
})
