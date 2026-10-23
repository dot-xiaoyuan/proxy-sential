import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { AppEmptyState, AppErrorAlert } from './AppStateFeedback'

describe('AppErrorAlert', () => {
  it('统一渲染错误标题、说明与操作，并带 alert 语义', () => {
    render(<AppErrorAlert title="模板读取失败" message="请求超时" action={<button type="button">重试</button>} />)
    expect(screen.getByRole('alert')).toBeInTheDocument()
    expect(screen.getByText('模板读取失败')).toBeInTheDocument()
    expect(screen.getByText('请求超时')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '重试' })).toBeInTheDocument()
  })

  it('未提供说明时使用统一兜底文案', () => {
    render(<AppErrorAlert title="通道读取失败" />)
    expect(screen.getByText('通道读取失败')).toBeInTheDocument()
    expect(screen.getByText(/请求未完成/)).toBeInTheDocument()
  })
})

describe('AppEmptyState', () => {
  it('渲染调用方文案，未提供时使用统一兜底', () => {
    const { rerender } = render(<AppEmptyState description="暂无通知模板" />)
    expect(screen.getByText('暂无通知模板')).toBeInTheDocument()
    rerender(<AppEmptyState />)
    expect(screen.getByText('暂无符合筛选条件的数据记录')).toBeInTheDocument()
  })
})
