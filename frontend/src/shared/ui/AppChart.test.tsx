import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { AppChart } from './AppChart'

describe('AppChart', () => {
  it('安全渲染图表容器并应用可访问标签与自定义类名', () => {
    render(
      <AppChart
        ariaLabel="共享趋势图"
        className="defense-trend-chart"
        option={{
          xAxis: { type: 'category', data: ['10:00', '10:05'] },
          yAxis: { type: 'value' },
          series: [{ name: '策略命中', type: 'bar', data: [1, 2] }],
        }}
      />,
    )
    const chart = screen.getByRole('img', { name: '共享趋势图' })
    expect(chart).toBeInTheDocument()
    expect(chart).toHaveClass('app-chart', 'defense-trend-chart')
  })
})
