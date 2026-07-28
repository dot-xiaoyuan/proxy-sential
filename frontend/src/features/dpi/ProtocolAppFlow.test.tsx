import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { mockDpiProtocolFlows } from '../../mocks/fixtures'
import { ProtocolAppFlow } from './ProtocolAppFlow'

describe('ProtocolAppFlow', () => {
  it('正确渲染 DPI 协议与 L7 应用分层拓扑', () => {
    render(<ProtocolAppFlow items={mockDpiProtocolFlows} />)

    expect(screen.getByText(/DPI L7 应用与协议分层拓扑/)).toBeInTheDocument()
    expect(screen.getByText('TLS')).toBeInTheDocument()
    expect(screen.getByText('HTTP')).toBeInTheDocument()
    expect(screen.getByText('DNS')).toBeInTheDocument()
    expect(screen.getByText('P2P/Proxy')).toBeInTheDocument()
  })
})
