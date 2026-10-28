import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, expect, it } from 'vitest'
import { freshRecognition } from '../../mocks/freshRecognition'
import { FreshRecognitionCoverage } from './FreshRecognitionCoverage'

afterEach(cleanup)
it('keeps new-input counts, actual protocol gaps and processing semantics distinct', () => {
  render(<FreshRecognitionCoverage data={freshRecognition} />)
  expect(screen.getByText('100 条标准事件')).toBeVisible()
  expect(screen.getByText('没有新输入的协议')).toBeVisible()
  expect(screen.getByText('RTSP · 字段待接入')).toBeVisible()
  expect(screen.getByText('ARP · 用于关联')).toBeVisible()
  expect(screen.getByText('超过 5 秒 4')).toBeVisible()
  expect(screen.getByText(/接口可见时间需另行逐事件验证/)).toBeVisible()
  expect(screen.queryByText(/未知|未识别|未获取|未关联|未观测/)).not.toBeInTheDocument()
})
it('distinguishes pending statistics, empty fresh input and stale statistics', () => {
  const { rerender } = render(<FreshRecognitionCoverage />)
  expect(screen.getByText('新鲜输入统计正在准备')).toBeVisible()
  rerender(<FreshRecognitionCoverage data={{ ...freshRecognition, status: 'stale', items: freshRecognition.items.filter(item => item.inputs === 0) }} />)
  expect(screen.getByText('起点之后暂无新标准发现事件')).toBeVisible()
  expect(screen.getByText(/统计已过期/)).toBeVisible()
})
