import { describe, expect, it } from 'vitest'
import { getActivityOverviewByWindow } from './fixtures'

describe('getActivityOverviewByWindow', () => {
  it('不同窗口 (10m, 1h, 24h) 应返回不同事件数量与活跃 IP 数据以避免误判', () => {
    const data10m = getActivityOverviewByWindow('10m')
    const data1h = getActivityOverviewByWindow('1h')
    const data24h = getActivityOverviewByWindow('24h')

    expect(data10m.window).toBe('10m')
    expect(data1h.window).toBe('1h')
    expect(data24h.window).toBe('24h')

    expect(data10m.event_count).toBeLessThan(data1h.event_count)
    expect(data1h.event_count).toBeLessThan(data24h.event_count)

    expect(data10m.active_ip_count).toBeLessThan(data1h.active_ip_count)
    expect(data1h.active_ip_count).toBeLessThan(data24h.active_ip_count)

    expect(data10m.top_domains[0].count).toBeLessThan(data1h.top_domains[0].count)
    expect(data1h.top_domains[0].count).toBeLessThan(data24h.top_domains[0].count)
  })
})
