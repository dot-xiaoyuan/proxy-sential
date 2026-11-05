import { describe, expect, it } from 'vitest'
import { discoveryClassificationExplanation, discoveryNameClue } from './discoveryClassificationClues'

describe('discovery name clues', () => {
  it.each(['DESKTOP-ABC', 'laptop-204', 'WIN-204', 'Alice-MacBook', 'iMac-Office'])('keeps %s as a name clue without asserting use or OS', name => {
    const clue = discoveryNameClue(name)
    expect(clue?.label).toBe('电脑名称线索')
    expect(clue?.detail).toContain(`名称“${name}”`)
    expect(clue?.detail).toContain('不能据此确认设备类型、操作系统或用途')
    expect(clue).not.toHaveProperty('os_family')
    expect(clue).not.toHaveProperty('device_type')
  })
  it.each(['Huawei-AP', 'huawei', 'map-service', 'win-server', 'my-desktop-support', ''])('does not guess a type from generic or ambiguous name %s', name => {
    expect(discoveryNameClue(name)).toBeUndefined()
  })
  it('retains the matched model family only as evidence', () => {
    expect(discoveryNameClue('Alice-iPhone')?.label).toBe('移动设备名称线索')
    expect(discoveryNameClue('printer-204')?.label).toBe('打印设备名称线索')
  })
})

describe('discovery classification explanation', () => {
  it('explains address-only candidates without filling the device type', () => {
    expect(discoveryClassificationExplanation({ classification_status: 'candidate', protocols: ['arp', 'ndp'] })).toContain('仅有地址活动证据')
  })
  it('does not mistake DHCP evidence for an address-only candidate', () => {
    expect(discoveryClassificationExplanation({ classification_status: 'candidate', protocols: ['arp', 'dhcp'] })).toContain('现有分类证据不足')
  })
  it('keeps conflicts and expiry distinct from absent evidence', () => {
    expect(discoveryClassificationExplanation({ classification_status: 'conflict' })).toContain('互相冲突')
    expect(discoveryClassificationExplanation({ classification_status: 'expired' })).toContain('已过期')
  })
})
