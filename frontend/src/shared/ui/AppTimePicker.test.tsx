import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { AppTimePicker } from './AppTimePicker'

describe('AppTimePicker', () => {
  it('正确渲染 10m/1h/24h 选项与当前选中指示', () => {
    const handleChange = vi.fn()
    render(<AppTimePicker onQuickWindowChange={handleChange} quickWindow="1h" />)

    expect(screen.getByText('10 分钟')).toBeInTheDocument()
    expect(screen.getByText('1 小时')).toBeInTheDocument()
    expect(screen.getByText('24 小时')).toBeInTheDocument()
    expect(screen.getByText('窗口: 1h')).toBeInTheDocument()
  })
})
