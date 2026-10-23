import { describe, expect, it } from 'vitest'
import { formatClock, formatCount, formatDate, formatDateTime, formatPercent } from './format'

describe('formatDateTime', () => {
  it('缺失、零值、非法时间返回空串', () => {
    expect(formatDateTime()).toBe('')
    expect(formatDateTime(null)).toBe('')
    expect(formatDateTime('')).toBe('')
    expect(formatDateTime('0001-01-01T00:00:00Z')).toBe('')
    expect(formatDateTime('0000-00-00T00:00:00Z')).toBe('')
    expect(formatDateTime('not-a-time')).toBe('')
  })

  it('使用 zh-CN 24 小时制，不受运行环境语言影响', () => {
    const text = formatDateTime('2026-10-22T02:42:28Z')
    expect(text).toContain('2026')
    expect(text).not.toMatch(/AM|PM/i)
    expect(text).not.toContain('0001')
  })

  it('日期与时钟拆分与完整时间一致', () => {
    const value = '2026-10-22T02:42:28Z'
    expect(formatDate(value)).not.toBe('')
    expect(formatClock(value)).toMatch(/^\d{2}:\d{2}$/)
    expect(formatDateTime(value)).toContain(formatClock(value))
  })
})

describe('formatCount', () => {
  it('缺失和非法数字返回空串', () => {
    expect(formatCount()).toBe('')
    expect(formatCount(null)).toBe('')
    expect(formatCount(Number.NaN)).toBe('')
  })

  it('使用千分位', () => {
    expect(formatCount(12345)).toBe('12,345')
    expect(formatCount(0)).toBe('0')
  })
})

describe('formatPercent', () => {
  it('缺失值返回空串，按比例换算', () => {
    expect(formatPercent(undefined)).toBe('')
    expect(formatPercent(0.1234)).toBe('12.3%')
    expect(formatPercent(1, 0)).toBe('100%')
  })
})
