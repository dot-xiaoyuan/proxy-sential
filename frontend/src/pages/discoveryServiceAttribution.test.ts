import { describe, expect, it } from 'vitest'
import { serviceBelongsToDevice, signalAddressMatchesDevice } from './discoveryServiceAttribution'

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
