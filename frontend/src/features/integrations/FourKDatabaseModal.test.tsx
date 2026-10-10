import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { FourKDatabaseModal } from './FourKDatabaseModal'

const initial = {
  connector_id: 'isolated-controller', host: '192.0.2.1', authorization_database_host: '192.0.2.10',
  online_redis_host: '192.0.2.11', catalog_redis_host: '192.0.2.12', event_redis_host: '192.0.2.13', northbound_api_host: '192.0.2.14',
  source: 'old-source', sensor_id: 'old-sensor', authorization_ready: true, reconcile_interval_hours: 6,
  connection_state: 'healthy', event_channel_state: 'waiting', channels: { authorization_database: 'healthy', online_redis: 'healthy', catalog_redis: 'healthy', event_redis: 'waiting', northbound_api: 'healthy', event_channel: 'waiting' },
  last_synced_at: '2026-10-01T01:00:00Z', identity_accounts: 81, identity_sessions: 81, products: 6, groups: 425, controls: 3,
}

const requests = vi.hoisted(() => ({ load: vi.fn(), update: vi.fn(), test: vi.fn(), sync: vi.fn(), refresh: vi.fn() }))
requests.load.mockResolvedValue(initial)

vi.mock('../../shared/api/client', () => ({
  api: { srun4KIntegration: requests.load, updateSRun4KIntegration: requests.update, createSRun4KIntegration: requests.update, testSRun4KIntegration: requests.test, syncSRun4KIntegration: requests.sync, refreshSRun4KAuthorization: requests.refresh },
  ApiError: class extends Error { status = 0 },
}))

afterEach(() => { cleanup(); vi.clearAllMocks(); requests.load.mockResolvedValue(initial) })

describe('4K channel configuration', () => {
  it('separates endpoint addresses and hides stale status while editing an endpoint', async () => {
    render(<FourKDatabaseModal connectorId="isolated-controller" onClose={() => undefined} />)
    const online = await screen.findByRole('textbox', { name: /在线清单 Redis 地址/ })
    await waitFor(() => expect(online).toHaveValue('192.0.2.11'))
    expect(screen.getByRole('textbox', { name: /授权数据库地址/ })).toHaveValue('192.0.2.10')
    expect(screen.getByRole('textbox', { name: /产品\/控制目录 Redis 地址/ })).toHaveValue('192.0.2.12')
    expect(screen.getByRole('textbox', { name: /上下线事件 Redis 地址/ })).toHaveValue('192.0.2.13')
    expect(screen.getByRole('textbox', { name: /北向 API 地址/ })).toHaveValue('192.0.2.14')
    expect(screen.getByText('通道状态')).toBeInTheDocument()
    fireEvent.change(online, { target: { value: '192.0.2.21' } })
    expect(await screen.findByText('在线清单地址变化')).toBeInTheDocument()
    expect(screen.queryByText('通道状态')).not.toBeInTheDocument()
    expect(screen.queryByText('最近同步摘要')).not.toBeInTheDocument()
    fireEvent.change(online, { target: { value: '192.0.2.11' } })
    expect(await screen.findByText('通道状态')).toBeInTheDocument()
    expect(requests.update).not.toHaveBeenCalled()
    expect(requests.test).not.toHaveBeenCalled()
    expect(requests.sync).not.toHaveBeenCalled()
  })

  it('refreshes the northbound authorization without showing secret material', async () => {
    requests.refresh.mockResolvedValueOnce({ ...initial, authorization_refreshed_at: '2026-10-10T01:00:00Z' })
    render(<FourKDatabaseModal connectorId="isolated-controller" onClose={() => undefined} />)
    fireEvent.click(await screen.findByRole('button', { name: '刷新北向授权' }))
    await waitFor(() => expect(requests.refresh).toHaveBeenCalledWith('isolated-controller'))
    expect(await screen.findByText('已验证并加密保存')).toBeInTheDocument()
    expect(screen.queryByText(/AppSecret|token|password/i)).not.toBeInTheDocument()
  })
})
