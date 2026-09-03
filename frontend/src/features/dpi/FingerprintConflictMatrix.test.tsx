import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { mockFingerprintConflicts } from '../../mocks/fixtures'
import { FingerprintConflictMatrix } from './FingerprintConflictMatrix'

describe('FingerprintConflictMatrix', () => {
  it('正确渲染多源指纹一致性列表且不显示设备估计数', () => {
    render(<FingerprintConflictMatrix items={mockFingerprintConflicts} />)

    expect(screen.getByText(/多源指纹一致性/)).toBeInTheDocument()
    expect(screen.getByText(/10.255.0.98/)).toBeInTheDocument()
    expect(screen.getByText(/TLS 客户端栈差异/)).toBeInTheDocument()
		expect(screen.queryByText(/估计设备数/)).not.toBeInTheDocument()
		expect(screen.queryByText(/UA 客户端碰撞/)).not.toBeInTheDocument()
  })

  it('没有冲突项时渲染暂无数据状态', () => {
    render(<FingerprintConflictMatrix items={[]} />)
    expect(screen.getByText(/当前窗口下暂无需要复核的多源指纹差异/)).toBeInTheDocument()
  })
})
