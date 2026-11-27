import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { DeviceCenterPage } from './DeviceCenterPage'

vi.mock('./DevicesPage', () => ({
  DevicesPage: () => <div data-testid="terminal-panel">终端列表</div>,
}))
vi.mock('./RouterObservationsPanel', () => ({
  RouterObservationsPanel: () => <div data-testid="network-panel">路由器列表</div>,
}))

const renderAt = (path: string) =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/devices" element={<DeviceCenterPage />} />
      </Routes>
    </MemoryRouter>,
  )

describe('设备中心子菜单页面', () => {
  it('终端列表直接展示列表内容，不再出现标签页', () => {
    renderAt('/devices?tab=terminal')
    expect(screen.getByTestId('terminal-panel')).toBeVisible()
    expect(screen.queryByRole('tab')).toBeNull()
  })
  it('路由器独立展示', () => {
    renderAt('/devices?tab=network')
    expect(screen.getByTestId('network-panel')).toBeVisible()
  })
  it('旧的 IP 流量观察参数回退到终端列表', () => {
    renderAt('/devices?tab=ip&ip=10.157.2.191')
    expect(screen.getByTestId('terminal-panel')).toBeVisible()
  })
  it('旧的发现设备参数自动重定向到终端列表', () => {
    for (const tab of ['discovery', 'iot', 'records']) {
      const { unmount } = renderAt(`/devices?tab=${tab}`)
      expect(screen.getByTestId('terminal-panel')).toBeVisible()
      unmount()
    }
  })
})
