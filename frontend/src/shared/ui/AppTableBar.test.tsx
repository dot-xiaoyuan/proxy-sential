import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { AppTableBar } from './AppTableBar'

describe('AppTableBar', () => {
  it('正确渲染搜索框与快捷筛选 Tag', () => {
    const handleSearch = vi.fn()
    const handleFilter = vi.fn()

    render(
      <AppTableBar
        filterOptions={[
          { key: 'confirmed', label: '确认代理', active: true },
          { key: 'high', label: '高风险', active: false },
        ]}
        onFilterToggle={handleFilter}
        onSearchChange={handleSearch}
        searchValue="10.255.0.59"
        totalCount={42}
      />,
    )

    expect(screen.getByPlaceholderText(/关键字快速检索/)).toBeInTheDocument()
    expect(screen.getByText('确认代理')).toBeInTheDocument()
    expect(screen.getByText('高风险')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
  })

  it('搜索或筛选请求进行中时给出加载反馈', () => {
    const { rerender } = render(<AppTableBar onSearchChange={() => {}} searchValue="router" searching />)
    expect(screen.getByPlaceholderText(/关键字快速检索/)).toHaveAttribute('aria-busy', 'true')
    expect(screen.getByLabelText('正在加载')).toBeInTheDocument()

    rerender(<AppTableBar onSearchChange={() => {}} searchValue="router" />)
    expect(screen.getByPlaceholderText(/关键字快速检索/)).toHaveAttribute('aria-busy', 'false')
    expect(screen.queryByLabelText('正在加载')).not.toBeInTheDocument()
  })
})
