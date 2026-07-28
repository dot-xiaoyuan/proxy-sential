import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { mockFingerprintConflicts } from '../../mocks/fixtures'
import { FingerprintConflictMatrix } from './FingerprintConflictMatrix'

describe('FingerprintConflictMatrix', () => {
  it('正确渲染终端指纹冲突矩阵及其特征列表', () => {
    render(<FingerprintConflictMatrix items={mockFingerprintConflicts} />)

    expect(screen.getByText(/终端指纹冲突矩阵/)).toBeInTheDocument()
    expect(screen.getByText(/10.255.0.59/)).toBeInTheDocument()
    expect(screen.getByText(/UA 客户端碰撞/)).toBeInTheDocument()
    expect(screen.getByText(/JA3 \/ JA4 栈错配/)).toBeInTheDocument()
  })

  it('没有冲突项时渲染暂无数据状态', () => {
    render(<FingerprintConflictMatrix items={[]} />)
    expect(screen.getByText(/当前窗口下暂未捕获终端指纹冲突项/)).toBeInTheDocument()
  })
})
