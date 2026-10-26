import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { api } from '../shared/api/client'
import type { IpTrafficObservationPage } from '../shared/api/types'
import { IpTrafficObservations } from './IpTrafficObservations'
import { MemoryRouter } from 'react-router-dom'

vi.mock('../shared/api/client', () => ({ api: { ipTrafficObservations: vi.fn(), streamEventBody: vi.fn() } }))
const result: IpTrafficObservationPage = {
  ip: '10.157.2.191', source_owner: 'handshake-sidecar', status: 'ready', from: '2026-10-26T06:40:00Z', to: '2026-10-26T06:55:00Z', queried_at: '2026-10-26T06:55:01Z',
  source: { epoch: 'fresh', scope_id: 'scope', cutoff_at: '2026-10-26T06:38:56Z', state: 'active' },
  events: [{ observed_at: '2026-10-26T06:54:00Z', event_key: 'fresh:one', protocol: 'handshake', event_type: 'device', source: 'handshake-sidecar', sensor_id: 'sensor', subject_ip: '10.157.2.191', subject_mac: '90:fb:5d:a7:40:4b', body_ref: { class: 'evidence', month: '202610', scope: 'scope', key: 'fresh:one', sha256: 'a'.repeat(64) } }], next_cursor: 'next-page',
}
let client: QueryClient
beforeEach(() => { vi.clearAllMocks(); vi.mocked(api.ipTrafficObservations).mockResolvedValue(result); client = new QueryClient({ defaultOptions: { queries: { retry: false } } }) })
afterEach(() => { cleanup(); client.clear() })
function setup() { render(<MemoryRouter initialEntries={['/devices?tab=terminal&q=10.157.2.191']}><QueryClientProvider client={client}><IpTrafficObservations ip="10.157.2.191" identityLastSeen="2026-10-25T15:51:00Z" contextMac="90:fb:5d:a7:40:4b" /></QueryClientProvider></MemoryRouter>) }
it('自动限定 IP 和时间并按需读取正文，明确旧摘要与新观测语义', async () => {
  setup()
  await screen.findByText('本页 1 条观测摘要')
  const [ip, query] = vi.mocked(api.ipTrafficObservations).mock.calls[0]
  expect(ip).toBe('10.157.2.191')
  expect(Date.parse(query.to) - Date.parse(query.from)).toBe(15 * 60_000)
  expect(api.streamEventBody).not.toHaveBeenCalled()
  expect(screen.getByRole('link', { name: '查看该 MAC 的终端详情' })).toHaveAttribute('href', expect.stringContaining('tab=signals'))
  expect(screen.getByText('握手 MAC 与本终端一致')).toBeInTheDocument()
  expect(screen.getByText(/设备识别摘要早于本来源的接续起点/)).toBeInTheDocument()
  vi.mocked(api.streamEventBody).mockResolvedValue({ event_id: 'one', source: 'handshake-sidecar', type: 'device', timestamp: result.events[0].observed_at, observer: {}, subject: {mac:'90:fb:5d:a7:40:4b',ip:'10.157.2.191'}, flow: {}, confidence: .9, payload: { mac: '90:fb:5d:a7:40:4b', observed_count: 42, snis: ['api.miwifi.com'], user_agents: ['test-client'] } })
  fireEvent.click(screen.getByRole('button', { name: '查看观测内容' }))
  await screen.findByText('api.miwifi.com')
  expect(screen.getByText(/MiWiFi 服务访问/)).toBeInTheDocument()
  expect(screen.getByText('42')).toBeInTheDocument()
  expect(screen.getByText('90:fb:5d:a7:40:4b')).toBeInTheDocument()
})
it('翻页绑定原查询，刷新失败后隐藏旧页而不显示为空', async () => {
  setup(); await screen.findByText('本页 1 条观测摘要')
  fireEvent.click(screen.getByRole('button', { name: '下一页' }))
  await waitFor(() => expect(vi.mocked(api.ipTrafficObservations).mock.lastCall?.[1].cursor).toBe('next-page'))
  vi.mocked(api.ipTrafficObservations).mockRejectedValue(new Error('query budget exceeded'))
  fireEvent.click(screen.getByRole('button', { name: '刷新最近 15 分钟' }))
  await screen.findByText('流量观察读取失败')
  expect(screen.queryByText('本页 1 条观测摘要')).toBeNull()
  expect(screen.queryByText('该范围内没有已入库的观测摘要。')).toBeNull()
})
it('来源未接入与无记录分别展示', async () => {
  vi.mocked(api.ipTrafficObservations).mockResolvedValue({ ...result, status: 'source_unavailable', source: undefined, events: [] })
  setup(); await screen.findByText('该来源尚未登记新存查接续起点。')
  expect(screen.queryByText('该范围内没有已入库的观测摘要。')).toBeNull()
})
