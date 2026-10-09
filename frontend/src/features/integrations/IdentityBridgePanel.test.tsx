import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { IdentityBridgePanel } from './IdentityBridgePanel'

const requests = vi.hoisted(() => ({
  bridge: vi.fn().mockResolvedValue({
    config: {
      bridge_id: 'ncu-legacy-4k', host: '222.204.3.225', config_version: 2,
      online_redis_addr: '222.204.3.225:16380', event_redis_addr: '222.204.3.227:16384',
      online_list: 'list:rad_online', event_list: 'list:antiproxy:127.0.0.1',
      processing_list: 'list:antiproxy:127.0.0.1:proxy-sentinel-processing', source: 'ncu-srun4k',
      sensor_id: 'ncu-auth-redis', campus_id: 'ncu', access_domain: 'campus-auth', batch_size: 500,
      reconcile_interval_seconds: 1800,
    },
    runtime: {
      state: 'switch_failed', active_host: '222.204.3.224', active_config_version: 1,
      active_online_redis_addr: '222.204.3.224:16380', online_channel_state: 'healthy',
      event_channel_state: 'healthy', snapshot_state: 'healthy', source_queue: 4, processing_queue: 2,
      online_members: 16266, online_sessions: 16260, committed_messages: 800, bad_messages: 1,
      event_consecutive_failures: 0, snapshot_consecutive_failures: 0, accounts: 4908, sessions: 16260,
      last_snapshot_at: '2026-10-09T10:00:00Z',
    },
    checked_at: '2026-10-09T10:01:00Z',
  }),
  runs: vi.fn().mockResolvedValue({
    items: [{ run_id: 'snapshot-1', kind: 'snapshot', status: 'completed', records_read: 16266, records_emitted: 16260, records_skipped: 6, records_malformed: 0, retry_count: 0, duration_ms: 2100, started_at: '2026-10-09T10:00:00Z' }],
    page: { limit: 20, next_cursor: null, total: 1 },
  }),
  update: vi.fn().mockResolvedValue({ bridge_id: 'ncu-legacy-4k', host: '222.204.3.226', config_version: 3, state: 'switching' }),
}))

vi.mock('../../shared/api/client', () => ({
  api: { identityBridge: requests.bridge, identityBridgeRuns: requests.runs, updateIdentityBridge: requests.update },
}))
vi.mock('../../shared/api/queries', () => ({ useSession: () => ({ data: {} }) }))
vi.mock('../../shared/auth/permissions', () => ({ can: () => true }))

afterEach(() => {
  cleanup()
  requests.update.mockClear()
})

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={client}><IdentityBridgePanel /></QueryClientProvider>)
}

describe('南昌4K认证同步', () => {
  it('同时展示期望地址、当前实际通道和服务端分页记录', async () => {
    renderPanel()
    expect(await screen.findByText('南昌 4K 认证同步')).toBeInTheDocument()
    expect(screen.getByText(/配置地址 222\.204\.3\.225，当前生效 222\.204\.3\.224/)).toBeInTheDocument()
    expect(screen.getByText('222.204.3.224:16380')).toBeInTheDocument()
    expect(screen.getAllByText('222.204.3.227:16384')).toHaveLength(2)
    expect(screen.getByText('16,266')).toBeInTheDocument()
    const recordCounts = await screen.findAllByText(/16,266 读取/)
    expect(recordCounts).toHaveLength(2)
    expect(recordCounts[1]).toHaveTextContent('16,266 读取 · 16,260 写入')
  })

  it('只提交管理员填写的4K主机地址', async () => {
    renderPanel()
    fireEvent.click(await screen.findByRole('button', { name: '修改4K地址' }))
    const input = await screen.findByRole('textbox', { name: /4K 地址/ })
    expect(input).toHaveValue('222.204.3.225')
    fireEvent.change(input, { target: { value: '222.204.3.226' } })
    fireEvent.click(screen.getByRole('button', { name: '保存并平滑切换' }))
    await waitFor(() => expect(requests.update).toHaveBeenCalledWith('222.204.3.226'))
  })
})
