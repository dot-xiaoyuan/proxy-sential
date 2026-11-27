import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'

import { AppDetailDrawer } from './AppDetailDrawer'

describe('AppDetailDrawer', () => {
  it('展示标题、完整详情链接并支持上一条/下一条切换', async () => {
    const onPrev = vi.fn()
    const onNext = vi.fn()
    const onClose = vi.fn()

    render(
      <MemoryRouter>
        <AppDetailDrawer
          open
          title="10.10.1.2"
          subtitle="account-001"
          detailHref="/shared-access/observations/obs-1"
          hasPrev={false}
          hasNext
          onPrev={onPrev}
          onNext={onNext}
          onClose={onClose}
        >
          <p>证据内容</p>
        </AppDetailDrawer>
      </MemoryRouter>,
    )

    expect(screen.getByText('10.10.1.2')).toBeVisible()
    expect(screen.getByText('证据内容')).toBeVisible()
    expect(screen.getByRole('link', { name: /完整详情/ })).toHaveAttribute(
      'href',
      '/shared-access/observations/obs-1',
    )
    expect(screen.getByRole('button', { name: '上一条' })).toBeDisabled()
    await userEvent.click(screen.getByRole('button', { name: '下一条' }))
    expect(onNext).toHaveBeenCalledTimes(1)
  })
})
