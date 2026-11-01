import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import { PassiveDiscoveryPanel } from './PassiveDiscoveryPanel'

const request = vi.hoisted(() => vi.fn())
vi.mock('../shared/api/client', async importOriginal => {
  const actual = await importOriginal<typeof import('../shared/api/client')>()
  return { ...actual, request }
})

const device = {
  id: 'device-1',
  sensor_id: 'sensor-a',
  primary_ip: '192.0.2.10',
  current_addresses: ['192.0.2.10', '192.0.2.11'],
  last_observed_ip: '192.0.2.12',
  last_seen: '2026-11-01T12:00:00Z',
  classification_status: 'candidate',
  current: true,
  observations: [],
  protocols: ['arp'],
  capabilities: [],
}

function mockReads(observedPortResult: unknown = {
  items: {
    'sensor-a|192.0.2.10': [{
      sensor_id: 'sensor-a', src_ip: '192.0.2.10', proto: 'tcp', dst_port: 443,
      connection_outcome: 'syn_ack_observed', last_seen: '2026-11-01T12:00:00Z', evidence_id: 'flow-443',
    }],
  },
}, deviceRow = device) {
  request.mockImplementation((path: string) => {
    if (path.startsWith('/discovery/observed-ports?')) {
      return observedPortResult instanceof Error ? Promise.reject(observedPortResult) : Promise.resolve(observedPortResult)
    }
    if (path.startsWith('/discovery/devices?')) return Promise.resolve({ items: [deviceRow], total: 1, has_more: false })
    if (path === '/discovery/coverage') return Promise.resolve({ enabled: true, items: [] })
    if (path === '/discovery/statistics') return Promise.resolve({ items: [], pending_updates: 0 })
    if (path === '/discovery/types') return Promise.resolve({ items: [] })
    if (path.startsWith('/discovery/service-clues?')) return Promise.resolve({ items: {} })
    if (path.startsWith('/discovery/passive-signals?')) return Promise.resolve({ items: [] })
    if (path.startsWith('/discovery/history?')) return Promise.resolve({ items: [], has_more: false, next_cursor: '' })
    return Promise.resolve({ items: [] })
  })
}

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={client}><MemoryRouter><PassiveDiscoveryPanel view="records" /></MemoryRouter></QueryClientProvider>)
}

function observedCalls() {
  return request.mock.calls.map(([path]) => String(path)).filter(path => path.startsWith('/discovery/observed-ports?'))
}

afterEach(() => { cleanup(); request.mockReset() })

it('loads one current IP port clue only when its evidence detail opens', async () => {
  mockReads()
  renderPanel()
  await screen.findByText('192.0.2.10')
  expect(observedCalls()).toHaveLength(0)

  fireEvent.click(screen.getByRole('button', { name: '查看证据' }))
  await waitFor(() => expect(observedCalls()).toHaveLength(1))
  const targets = new URLSearchParams(observedCalls()[0].split('?')[1]).get('targets')
  expect(targets).toBe('sensor-a|192.0.2.10')
  expect(await screen.findByText('见 TCP SYN-ACK 443')).toBeInTheDocument()
  expect(screen.getByText(/近 2 小时目标端口线索/)).toBeInTheDocument()
})

it('shows a detail error when the selected IP port read fails', async () => {
  mockReads(new Error('read failed'))
  renderPanel()
  await screen.findByText('192.0.2.10')
  expect(screen.queryByText('读取目标端口线索失败')).not.toBeInTheDocument()

  fireEvent.click(screen.getByRole('button', { name: '查看证据' }))
  expect(await screen.findByText('读取目标端口线索失败')).toBeInTheDocument()
  expect(observedCalls()).toHaveLength(1)
})

it('does not query a historical address when the device has no current address', async () => {
  mockReads({ items: {} }, { ...device, current_addresses: [] })
  renderPanel()
  await screen.findByText('最后观测地址 · 192.0.2.12')
  fireEvent.click(screen.getByRole('button', { name: '查看证据' }))
  expect(observedCalls()).toHaveLength(0)
  expect(screen.queryByText('正在读取当前 IP 近 2 小时目标端口线索')).not.toBeInTheDocument()
})

it('distinguishes an empty current IP port read from a failed read', async () => {
  mockReads({ items: {} })
  renderPanel()
  await screen.findByText('192.0.2.10')
  fireEvent.click(screen.getByRole('button', { name: '查看证据' }))
  expect(await screen.findByText('当前 IP 近 2 小时的镜像端口聚合中无匹配记录')).toBeInTheDocument()
  expect(screen.queryByText('读取目标端口线索失败')).not.toBeInTheDocument()
})
