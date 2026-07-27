import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import type { Evidence } from '../../shared/api/types'
import { EvidenceList } from './EvidenceList'

const evidence: Evidence[] = [
  {
    evidence_id: 'evidence-test',
    ip: '10.0.0.1',
    type: 'multi_user_agent',
    window: '10m0s',
    score: 35,
    confidence: 0.85,
    severity: 'high',
    reason: '出现多个 User-Agent',
    samples: ['Mozilla/5.0', 'okhttp/4.12.0'],
    created_at: '2026-07-24T05:19:15Z',
  },
]

describe('EvidenceList', () => {
  it('renders evidence reason, id and samples', () => {
    render(<EvidenceList evidence={evidence} />)
    expect(screen.getByText('出现多个 User-Agent')).toBeInTheDocument()
    expect(screen.getByText('evidence-test')).toBeInTheDocument()
    expect(screen.getByText('okhttp/4.12.0')).toBeInTheDocument()
  })

  it('renders empty state', () => {
    render(<EvidenceList evidence={[]} />)
    expect(screen.getByText('暂无有效风险证据。')).toBeInTheDocument()
  })
})
