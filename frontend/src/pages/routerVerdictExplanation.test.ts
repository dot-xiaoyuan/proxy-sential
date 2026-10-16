import { describe, expect, it } from 'vitest'
import { routerVerdictExplanation } from './routerVerdictExplanation'

const sample = { status: 'likely' as const, role: 'router' as const, confidence: 100, independent_sources: 2, infrastructure: false, ambiguous: false, conflicts: [] as string[] }

describe('路由判定解释', () => {
  it('explains why a 100-point infrastructure observation is not confirmed', () => {
    expect(routerVerdictExplanation({ ...sample, infrastructure: true, conflicts: ['infrastructure_role'] })).toContain('基础设施设备')
  })
  it('keeps AP recognition separate from router confirmation', () => {
    expect(routerVerdictExplanation({ ...sample, role: 'ap' })).toContain('路由器确认不适用')
  })
  it('names the independent-source and association blockers', () => {
    const explanation = routerVerdictExplanation({ ...sample, independent_sources: 1, ambiguous: true })
    expect(explanation).toContain('关联不唯一')
    expect(explanation).toContain('独立证据来源不足')
  })
})
