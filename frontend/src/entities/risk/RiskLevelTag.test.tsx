import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { RiskLevelTag } from './RiskLevelTag'

describe('RiskLevelTag', () => {
  it('renders confirmed level in Chinese', () => {
    render(<RiskLevelTag level="confirmed" />)
    expect(screen.getByText('极高风险')).toBeInTheDocument()
  })
})
