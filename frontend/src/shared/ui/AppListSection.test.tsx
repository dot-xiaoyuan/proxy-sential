import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { AppListSection } from './AppListSection'

describe('AppListSection', () => {
  it('错误优先于加载与空态', () => {
    render(
      <AppListSection isError isLoading isEmpty errorTitle="模板读取失败" errorMessage="请求超时" emptyText="暂无模板">
        <div>列表</div>
      </AppListSection>,
    )
    expect(screen.getByText('模板读取失败')).toBeInTheDocument()
    expect(screen.queryByText('列表')).not.toBeInTheDocument()
  })

  it('加载状态显示骨架屏', () => {
    render(
      <AppListSection isLoading isEmpty emptyText="暂无模板">
        <div>列表</div>
      </AppListSection>,
    )
    expect(screen.queryByText('列表')).not.toBeInTheDocument()
    expect(screen.queryByText('暂无模板')).not.toBeInTheDocument()
  })

  it('空列表显示统一空态', () => {
    render(
      <AppListSection isEmpty emptyText="暂无模板">
        <div>列表</div>
      </AppListSection>,
    )
    expect(screen.getByText('暂无模板')).toBeInTheDocument()
    expect(screen.queryByText('列表')).not.toBeInTheDocument()
  })

  it('有数据时渲染列表内容', () => {
    render(
      <AppListSection isEmpty={false} emptyText="暂无模板">
        <div>列表</div>
      </AppListSection>,
    )
    expect(screen.getByText('列表')).toBeInTheDocument()
    expect(screen.queryByText('暂无模板')).not.toBeInTheDocument()
  })
})
