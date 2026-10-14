import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { DeviceCenterPage } from './DeviceCenterPage'

vi.mock('./DevicesPage', () => ({ DevicesPage: () => <div data-testid="terminal-panel">终端列表</div> }))
vi.mock('./RouterObservationsPanel', () => ({ RouterObservationsPanel: () => <div data-testid="network-panel">网络设备列表</div> }))
vi.mock('./PassiveDiscoveryPanel', () => ({ PassiveDiscoveryPanel: ({view}: {view:string}) => <div data-testid="discovery-panel">{view}</div> }))

function Location() {
  return <output data-testid="location">{useLocation().search}</output>
}

describe('设备中心入口', () => {
  it('统一展示设备中心并按标签切换已有查询面板', () => {
    render(<MemoryRouter initialEntries={['/devices']}><DeviceCenterPage /><Location /></MemoryRouter>)
    expect(screen.getByRole('heading', { name: '设备中心' })).toBeVisible()
    expect(screen.getByTestId('terminal-panel')).toBeVisible()
    fireEvent.click(screen.getByRole('tab', { name: '网络设备' }))
    expect(screen.getByTestId('network-panel')).toBeVisible()
    expect(screen.getByTestId('location')).toHaveTextContent('tab=network')
    fireEvent.click(screen.getByRole('tab', { name: '哑终端' }))
    expect(screen.getByTestId('discovery-panel')).toHaveTextContent('iot')
    fireEvent.click(screen.getByRole('tab', { name: '发现线索' }))
    expect(screen.getByTestId('discovery-panel')).toHaveTextContent('records')
  })
})
