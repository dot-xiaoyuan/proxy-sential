import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { DeviceCenterPage } from './DeviceCenterPage'

vi.mock('./DevicesPage', () => ({ DevicesPage: () => <div data-testid="terminal-panel">终端列表</div> }))
vi.mock('./RouterObservationsPanel', () => ({ RouterObservationsPanel: () => <div data-testid="network-panel">路由器列表</div> }))

vi.mock('./PassiveDiscoveryPanel', () => ({ PassiveDiscoveryPanel: ({view}:{view:string}) => <div data-testid="discovery-panel">{view}</div> }))

const renderAt = (path: string) => render(<MemoryRouter initialEntries={[path]}><DeviceCenterPage /></MemoryRouter>)

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
  it('发现设备及旧链接展示发现面板', () => {
    for (const tab of ['discovery', 'iot', 'records']) {
      const { unmount } = renderAt(`/devices?tab=${tab}`)
      expect(screen.getByTestId('discovery-panel')).toHaveTextContent(tab === 'iot' ? 'iot' : 'records')
      expect(screen.queryByTestId('terminal-panel')).toBeNull()
      unmount()
    }
  })
})
