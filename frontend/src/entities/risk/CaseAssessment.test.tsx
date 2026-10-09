import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, expect, it } from 'vitest'
import type { RiskCase } from '../../shared/api/types'
import { CaseAssessment } from './CaseAssessment'

afterEach(cleanup)
const item: RiskCase = { case_id: 'case-test', subject_type: 'ip', subject_id: '192.0.2.82', status: 'investigating', due_at: '', first_seen: '', last_seen: '', created_at: '', updated_at: '', risk_score: 24, risk_confidence: .68, assessment_level: 'normal', assessment_current: true, priority: 'high' }
it('人工高优先级不能把正常评估显示为红色风险', () => {
  const { container } = render(<CaseAssessment item={item} />)
  expect(screen.getByText('正常')).toBeInTheDocument()
  expect(screen.getByText('24 分')).toBeInTheDocument()
  expect(container.querySelector('.ant-tag-green')).toBeInTheDocument()
  expect(container.querySelector('.ant-tag-red')).toBeNull()
})
it('过期评估保留旧分数与置信度并弱化为历史', () => {
  const { container } = render(<CaseAssessment item={{ ...item, risk_score: 100, risk_confidence: .95, assessment_level: 'high', assessment_current: false }} showConfidence />)
  expect(screen.getByText('历史评估')).toBeInTheDocument()
  expect(screen.getByText('100 分 / 95%')).toHaveClass('ant-typography-secondary')
  expect(screen.queryByText('高风险')).toBeNull()
  expect(container.querySelector('.ant-tag-volcano')).toBeNull()
})
it('当前高风险保留明确风险提示', () => {
  render(<CaseAssessment item={{ ...item, risk_score: 95, assessment_level: 'high' }} />)
  expect(screen.getByText('高风险')).toBeInTheDocument()
})
