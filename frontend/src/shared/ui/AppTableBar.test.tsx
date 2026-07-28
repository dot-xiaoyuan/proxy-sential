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
})
