import { describe, expect, it } from 'vitest'

import { displayField, severityColor, statusColor, statusText } from './status'

describe('statusColor', () => {
  it('同一状态在全站使用同一颜色', () => {
    expect(statusColor('enabled')).toBe('green')
    expect(statusColor('active')).toBe('green')
    expect(statusColor('complete')).toBe('green')
    expect(statusColor('queued')).toBe('blue')
    expect(statusColor('awaiting_approval')).toBe('gold')
    expect(statusColor('partial')).toBe('orange')
    expect(statusColor('failed')).toBe('red')
    expect(statusColor('blocked')).toBe('red')
    expect(statusColor('expired')).toBe('default')
    expect(statusColor('disabled')).toBe('default')
  })

  it('空值和未映射状态不返回颜色', () => {
    expect(statusColor()).toBeUndefined()
    expect(statusColor(null)).toBeUndefined()
    expect(statusColor('some_domain_state')).toBeUndefined()
  })
})

describe('severityColor', () => {
  it('严重度使用固定色阶', () => {
    expect(severityColor('critical')).toBe('red')
    expect(severityColor('medium')).toBe('orange')
    expect(severityColor('low')).toBe('gold')
    expect(severityColor()).toBeUndefined()
  })
})

describe('statusText', () => {
  it('已知状态输出中文，未知状态原样保留供排查', () => {
    expect(statusText('running')).toBe('执行中')
    expect(statusText('custom_state')).toBe('custom_state')
    expect(statusText()).toBe('')
  })
})

describe('displayField', () => {
  it('缺省与占位内容返回空串，真实值原样保留', () => {
    expect(displayField('未知设备')).toBe('')
    expect(displayField('—')).toBe('')
    expect(displayField(' iPhone 15 ')).toBe(' iPhone 15 ')
    expect(displayField(undefined)).toBe('')
  })
})
