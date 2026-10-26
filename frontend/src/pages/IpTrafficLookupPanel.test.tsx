import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { IpTrafficLookupPanel } from './IpTrafficLookupPanel'

vi.mock('../shared/api/queries', () => ({ useSession: () => ({ data: { permissions: ['events:read', 'risks:read'] } }) }))
vi.mock('../widgets/IpTrafficObservations', () => ({ IpTrafficObservations: ({ ip }: { ip: string }) => <output data-testid="selected-ip">{ip}</output> }))

function Location() { return <output data-testid="location">{useLocation().search}</output> }
function setup(url = '/devices?tab=ip') {
  return render(<MemoryRouter initialEntries={[url]}><IpTrafficLookupPanel /><Location /></MemoryRouter>)
}

describe('独立 IP 流量观察入口', () => {
  it('由完整 IP 查询观测并保留详情返回路径', () => {
    setup()
    fireEvent.change(screen.getByRole('textbox', { name: 'IP 地址' }), { target: { value: '10.157.2.191' } })
    fireEvent.click(screen.getByRole('button', { name: '查询 IP' }))
    expect(screen.getByTestId('selected-ip')).toHaveTextContent('10.157.2.191')
    expect(screen.getByTestId('location')).toHaveTextContent('ip=10.157.2.191')
    expect(screen.getByRole('link', { name: '查看完整 IP 详情' }).getAttribute('href')).toContain('return_to=')
  })
  it('拒绝不完整地址，保持已选择 IP 的观测', () => {
    setup('/devices?tab=ip&ip=10.157.2.191')
    fireEvent.change(screen.getByRole('textbox', { name: 'IP 地址' }), { target: { value: '10.157.2' } })
    fireEvent.click(screen.getByRole('button', { name: '查询 IP' }))
    expect(screen.getByRole('alert')).toHaveTextContent('完整有效')
    expect(screen.getByTestId('selected-ip')).toHaveTextContent('10.157.2.191')
  })
})
