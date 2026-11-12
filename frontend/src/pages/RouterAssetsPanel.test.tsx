import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import { RouterObservationsPanel } from './RouterObservationsPanel'

const { request, observations } = vi.hoisted(() => ({ request: vi.fn(), observations: vi.fn() }))
vi.mock('../shared/api/client', async importOriginal => {
  const actual = await importOriginal<typeof import('../shared/api/client')>()
  return { ...actual, request, api: { ...actual.api, routerObservations: observations } }
})
afterEach(() => { cleanup(); request.mockReset(); observations.mockReset() })

const row = {
  id: 'mirror-router-1', endpoint_id: 'mac:02:00:00:00:00:01', mac: '02:00:00:00:00:01',
  name: '宿舍路由设备', device_type: 'router', classification_status: 'identified', category: 'network',
  current_addresses: ['192.0.2.10'], last_observed_ip: '192.0.2.9', primary_ip: '192.0.2.10',
  protocols: ['dhcp', 'ssdp'], capabilities: ['routing'], observations: [], evidence_count: 2,
  first_seen: '2026-11-05T12:00:00Z', last_seen: '2026-11-05T16:00:00Z', current: true,
}

function setup(entry = '/devices?tab=network&routers_view=router', candidates: Array<Record<string, unknown>> = []) {
  observations.mockResolvedValue({ items: [], page: { total: 0 } })
  request.mockImplementation((path: string) => {
    if (path.startsWith('/discovery/chassis-candidates')) return Promise.resolve({ items: candidates })
    return Promise.resolve({ items: [row], limit: 20, has_more: false, next_cursor: '', freshness: { status: 'unknown', source: 'stream', source_progress_status: 'unverified', processed_at: '2026-11-05T16:00:00Z' } })
  })
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={[entry]}><RouterObservationsPanel /></MemoryRouter></QueryClientProvider>)
}

it('shows discovered routers without requiring a risk or router-assessment record', async () => {
  setup()
  expect(await screen.findByText('宿舍路由设备')).toBeVisible()
  expect(screen.getByText(/来源进度尚未核验/)).toBeVisible()
  expect(screen.getByText(/不具备来源追平证明/)).toBeVisible()
  expect(screen.getByText('设备类型用于资产管理；违规与共享行为需另行核验。')).toBeVisible()
  await waitFor(() => expect(observations).toHaveBeenCalledWith(expect.objectContaining({ role: 'router', include_candidates: false })))
  const list = request.mock.calls.find(([path]) => String(path).startsWith('/discovery/devices?'))!
  const query = new URL(String(list[0]), 'http://localhost').searchParams
  expect(query.get('mode')).toBe('passive')
  expect(query.get('type')).toBe('router')
  expect(query.get('state')).toBeNull()
  expect(query.get('cursor')).toBeNull()
  expect(request.mock.calls.every(([path]) => !String(path).includes('/discovery/devices/metadata') && !String(path).includes('/discovery/devices/position'))).toBe(true)
  fireEvent.click(screen.getByRole('button', { name: '查看设备' }))
  expect(await screen.findByText('设备资料')).toBeInTheDocument()
  expect(screen.queryByText('确认违规')).not.toBeInTheDocument()
})

it('annotates an LLDP-only router with a same-chassis candidate', async () => {
  setup('/devices?tab=network&routers_view=router', [{
    neighbor_mac: row.mac, neighbor_name: 'iKuai-X86', partner_mac: '00:e0:67:2a:4f:4c',
    partner_ip: '192.168.0.1', confidence: 0.9, evidence: ['同厂商前缀 00:e0:67:2a:4f', 'MAC 相邻（末字节差 3）'],
  }])
  expect(await screen.findByText('疑似同一机箱：192.168.0.1 · 90%')).toBeVisible()
})

it('maps the access-point view to the discovery access_point type', async () => {
  setup('/devices?tab=network&routers_view=ap')
  await waitFor(() => expect(request).toHaveBeenCalled())
  const calls = request.mock.calls.map(([path]) => new URL(String(path), 'http://localhost')).filter(url => url.pathname === '/discovery/devices')
  expect(calls.length).toBeGreaterThan(0)
  expect(calls.every(url => url.searchParams.get('type') === 'access_point')).toBe(true)
})

it('loads route role evidence before passive asset classification', async () => {
  setup()
  await screen.findByText('宿舍路由设备')
  await waitFor(() => expect(observations).toHaveBeenCalledWith(expect.objectContaining({ role: 'router', include_candidates: false })))
  expect(screen.getByText('设备类型用于资产管理；违规与共享行为需另行核验。')).toBeVisible()
})

it('keeps every returned evidence reference in the grouped detail instead of truncating after ten', async () => {
  setup()
  await screen.findByText('宿舍路由设备')
  request.mockResolvedValue({ items: [{ ...row, observations: Array.from({ length: 12 }, (_, index) => ({ id: `arp-reference-${index}`, origin: 'arp', observed_at: row.last_seen, explanation: 'ARP 地址声明', ip: '192.0.2.10', mac: row.mac })) }], limit: 20, has_more: false, next_cursor: '' })
  fireEvent.click(screen.getByRole('button', { name: '刷新设备' }))
  await waitFor(() => expect(request.mock.calls.filter(([path]) => String(path).startsWith('/discovery/devices?')).length).toBeGreaterThanOrEqual(2))
  fireEvent.click(screen.getByRole('button', { name: '查看设备' }))
  expect(await screen.findByText(/本次摘要 12 条，按内容归并为 1 组/)).toBeInTheDocument()
  expect(screen.getByText('原始引用（12）')).toBeInTheDocument()
  expect(screen.getByText('arp-reference-11')).toBeInTheDocument()
})

it('keeps expired router classification explicitly historical and never displays its old address as current', async () => {
  setup()
  await screen.findByText('宿舍路由设备')
  request.mockResolvedValue({ items: [{ ...row, current: false, classification_status: 'expired', device_type: '', last_device_type: 'router', current_addresses: [] }], limit: 20, has_more: false, next_cursor: '' })
  fireEvent.click(screen.getByRole('button', { name: '刷新设备' }))
  expect(await screen.findByText('历史路由器')).toBeVisible()
  expect(screen.getByText('类型证据已过期')).toBeVisible()
  expect(screen.getByText('历史 IP：192.0.2.9')).toBeVisible()
  expect(screen.queryByText('192.0.2.10')).not.toBeInTheDocument()
})

it('uses opaque discovery cursors and resets the cursor when the asset search changes', async () => {
  setup()
  await screen.findByText('宿舍路由设备')
  request.mockImplementation((path: string) => {
    if (path.startsWith('/discovery/chassis-candidates')) return Promise.resolve({ items: [] })
    const query = new URL(path, 'http://localhost').searchParams
    return Promise.resolve({ items: Array.from({ length: 20 }, (_, index) => ({ ...row, id: `${query.get('cursor') || 'first'}-${index}` })), limit: 20, has_more: !query.has('cursor'), next_cursor: query.has('cursor') ? '' : 'opaque-router-cursor' })
  })
  fireEvent.click(screen.getByRole('button', { name: '刷新设备' }))
  const next = await screen.findByRole('button', { name: '下一页' })
  await waitFor(() => expect(next).toBeEnabled())
  fireEvent.click(next)
  await waitFor(() => expect(request.mock.calls.some(([path]) => String(path).includes('cursor=opaque-router-cursor'))).toBe(true))
  fireEvent.change(screen.getByPlaceholderText('搜索设备名称、IP 或 MAC'), { target: { value: '192.0.2.10' } })
  fireEvent.keyDown(screen.getByPlaceholderText('搜索设备名称、IP 或 MAC'), { key: 'Enter', code: 'Enter' })
  await waitFor(() => expect(request.mock.calls.some(([path]) => String(path).includes('search=192.0.2.10'))).toBe(true))
  for (const [path] of request.mock.calls.filter(([path]) => String(path).includes('search=192.0.2.10'))) expect(String(path)).not.toContain('cursor=')
})

it('shows the stream projection watermark when device data is delayed', async () => {
  setup()
  await screen.findByText('宿舍路由设备')
  request.mockResolvedValue({ items: [row], limit: 20, has_more: false, next_cursor: '', freshness: { status: 'delayed', source: 'stream', processed_at: '2026-11-05T16:00:00Z', processing_lag_seconds: 1200 } })
  fireEvent.click(screen.getByRole('button', { name: '刷新设备' }))
  expect(await screen.findByText(/设备投影处理延迟约 20 分钟.*最近完成于.*不具备来源追平证明/)).toBeVisible()
})
