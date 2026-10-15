import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { DeviceCenterPage } from './DeviceCenterPage'

vi.mock('./DevicesPage', () => ({ DevicesPage: () => <div data-testid="terminal-panel">终端列表</div> }))
vi.mock('./RouterObservationsPanel', () => ({ RouterObservationsPanel: () => <div data-testid="network-panel">路由器列表</div> }))

const renderAt = (path: string) => render(<MemoryRouter initialEntries={[path]}><DeviceCenterPage /></MemoryRouter>)

describe('设备中心子菜单页面', () => {
  it('终端列表独立展示，不再出现标签页', () => {
    renderAt('/devices?tab=terminal')
    expect(screen.getByRole('heading', { name: '终端列表' })).toBeVisible()
    expect(screen.getByTestId('terminal-panel')).toBeVisible()
    expect(screen.queryByRole('tab')).toBeNull()
  })
  it('路由器独立展示', () => {
    renderAt('/devices?tab=network')
    expect(screen.getByRole('heading', { name: '路由器' })).toBeVisible()
    expect(screen.getByTestId('network-panel')).toBeVisible()
  })
  it('暂停的哑终端与发现线索链接回落到终端列表', () => {
    for (const tab of ['iot', 'records']) {
      const { unmount } = renderAt(`/devices?tab=${tab}`)
      expect(screen.getByRole('heading', { name: '终端列表' })).toBeVisible()
      unmount()
    }
  })
})
