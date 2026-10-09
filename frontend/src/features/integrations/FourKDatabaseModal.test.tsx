import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { FourKDatabaseModal } from './FourKDatabaseModal'

const requests = vi.hoisted(() => ({
  load: vi.fn().mockResolvedValue({
    connector_id: 'isolated-controller', host: '192.0.2.1', source: 'old-source', sensor_id: 'old-sensor',
    reconcile_interval_hours: 6, connection_state: 'healthy', event_channel_state: 'waiting',
    channels: { authorization_database: 'healthy', redis: 'healthy', northbound_api: 'healthy', event_channel: 'waiting' },
    last_synced_at: '2026-10-01T01:00:00Z', identity_accounts: 81, identity_sessions: 81, products: 6, groups: 425, controls: 3,
  }),
  update: vi.fn(), test: vi.fn(), sync: vi.fn(),
}))

vi.mock('../../shared/api/client', () => ({
  api: { srun4KIntegration: requests.load, updateSRun4KIntegration: requests.update, testSRun4KIntegration: requests.test, syncSRun4KIntegration: requests.sync },
  ApiError: class extends Error { status = 0 },
}))

afterEach(cleanup)

describe('4K address editing', () => {
  it('shows summaries only for their saved host and restores them when the edit is reverted', async () => {
    render(<FourKDatabaseModal connectorId="isolated-controller" onClose={() => undefined} />)
    const host = await screen.findByRole('textbox', { name: /4K 地址/ })
    await waitFor(() => expect(host).toHaveValue('192.0.2.1'))
    expect(screen.getByText('最近同步摘要')).toBeInTheDocument()
    expect(screen.getByText('通道状态')).toBeInTheDocument()
    fireEvent.change(host, { target: { value: '192.0.2.2' } })
    expect(await screen.findByText('更换地址后将重新校验身份来源')).toBeInTheDocument()
    expect(screen.queryByText('最近同步摘要')).not.toBeInTheDocument()
    expect(screen.queryByText('通道状态')).not.toBeInTheDocument()
    fireEvent.change(host, { target: { value: '192.0.2.1' } })
    expect(await screen.findByText('最近同步摘要')).toBeInTheDocument()
    expect(screen.getByText('通道状态')).toBeInTheDocument()
    expect(screen.queryByText('更换地址后将重新校验身份来源')).not.toBeInTheDocument()
    expect(requests.update).not.toHaveBeenCalled()
    expect(requests.test).not.toHaveBeenCalled()
    expect(requests.sync).not.toHaveBeenCalled()
  })
})

it('shows the latest failed check after a successful directory sync and removes the obsolete probe', async () => {
  const initial = {
    connector_id: 'isolated-controller', host: '192.0.2.1', source: 'old-source', sensor_id: 'old-sensor',
    reconcile_interval_hours: 6, connection_state: 'healthy', event_channel_state: 'waiting',
    channels: { authorization_database: 'healthy', redis: 'healthy', northbound_api: 'healthy', event_channel: 'waiting' },
    identity_accounts: 81, identity_sessions: 81, products: 6, groups: 425, controls: 3,
  }
  requests.load.mockResolvedValueOnce(initial).mockResolvedValueOnce({ ...initial, connection_state: 'failed', event_channel_state: 'healthy', channels: { authorization_database: 'failed', redis: 'pending', northbound_api: 'pending', event_channel: 'healthy' } })
  requests.update.mockResolvedValueOnce(initial)
  requests.test.mockResolvedValueOnce({ connector_id: initial.connector_id, online_total: 81, channels: initial.channels, enforcement_ready: false })
  requests.sync.mockResolvedValueOnce({ connector_id: initial.connector_id, identity_accounts: 24, identity_sessions: 24, address_records: 48, products: 4, groups: 2, controls: 3, event_channel_state: 'healthy', connection_state: 'failed', enforcement_ready: false })
  render(<FourKDatabaseModal connectorId={initial.connector_id} onClose={() => undefined} />)
  await waitFor(() => expect(screen.getByRole('textbox', { name: /4K 地址/ })).toHaveValue(initial.host))
  fireEvent.click(screen.getByRole('button', { name: '保存并立即同步' }))
  expect(await screen.findByText('当前连接检查失败')).toBeInTheDocument()
  expect(screen.getByText('连接失败')).toBeInTheDocument()
  expect(screen.getByText('24个账号 / 24个会话 / 48个地址')).toBeInTheDocument()
  expect(screen.queryByText('通道检查')).not.toBeInTheDocument()
  expect(screen.queryByText('上线、下线事件通道等待接入')).not.toBeInTheDocument()
  expect(screen.queryByText('等待事件通道接入')).not.toBeInTheDocument()
})
