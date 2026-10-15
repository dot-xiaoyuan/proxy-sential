import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, expect, it } from 'vitest'
import type { BrandInference } from '../../shared/api/types'
import { BrandInferenceDetails, BrandInferenceLabel } from './BrandInferenceView'

afterEach(cleanup)

const complete: BrandInference = {
  status: 'inferred', brand: 'Apple', confidence: .65,
  explanation: '厂商设备服务达到重复观察门槛',
  rule_version: 'test-rules', window: '7d', as_of: '2026-10-16T00:00:00Z',
  candidates: [{ brand: 'Apple', confidence: .65, evidence: [{
    match: { domain: 'albert.apple.com', rule_domain: 'albert.apple.com', ecosystem: 'Apple', category: 'device', confidence: .65, source: 'test' },
    first_seen: '2026-10-15T00:00:00Z', last_seen: '2026-10-16T00:00:00Z', count: 3,
  }] }],
}

it.each([null, undefined])('waits for full evidence when the inventory summary has candidates=%s', candidates => {
  // The compact lookup projection omits candidates; decoding it into the Go
  // detail struct serializes that missing slice as null.
  const summary = { status: 'insufficient', confidence: 0, candidates } as unknown as BrandInference
  const { container, rerender } = render(<BrandInferenceDetails value={summary} />)
  expect(container).toBeEmptyDOMElement()
  rerender(<BrandInferenceDetails value={complete} />)
  expect(screen.getByRole('heading', { name: '推测品牌与依据' })).toBeInTheDocument()
  expect(screen.getByText('albert.apple.com', { selector: 'strong' })).toBeInTheDocument()
})

it('keeps an explicit insufficient-evidence explanation from a complete response', () => {
  render(<BrandInferenceDetails value={{ ...complete, status: 'insufficient', brand: undefined, confidence: 0, candidates: [], explanation: '设备服务证据未达到品牌推测门槛' }} />)
  expect(screen.getByText('设备服务证据未达到品牌推测门槛')).toBeInTheDocument()
  expect(screen.queryByText('推测 Apple')).not.toBeInTheDocument()
})

it.each([null, undefined])('shows the conflict status without requiring candidate details (%s)', candidates => {
  const summary = { status: 'conflict', confidence: 0, candidates } as unknown as BrandInference
  render(<BrandInferenceLabel value={summary} />)
  expect(screen.getByText('品牌线索冲突')).toBeInTheDocument()
})
