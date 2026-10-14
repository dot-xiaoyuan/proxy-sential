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
      queue_sampled_at: '2026-10-09T10:01:00Z', quarantine_queue: 3,
      online_members: 16266, online_sessions: 16260, committed_messages: 800, bad_messages: 1,
      event_consecutive_failures: 0, snapshot_consecutive_failures: 0, accounts: 4908, sessions: 16260,
      last_snapshot_at: '2026-10-09T10:00:00Z', last_event_at: '2026-10-09T10:01:00Z',
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
  requests.bridge.mockClear()
  requests.runs.mockClear()
  requests.update.mockClear()
})

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={client}><IdentityBridgePanel /></QueryClientProvider>)
}

describe('南昌4K认证同步', () => {
  it('只展示同步状态、通道和数量摘要，不读取逐批同步记录', async () => {
    renderPanel()
    expect(await screen.findByText('深澜 4K 认证同步')).toBeInTheDocument()
    expect(screen.getByText('隔离消息 3 条待处理')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getByText('16,260')).toBeInTheDocument()
    expect(screen.getAllByText('正常')).toHaveLength(2)
    expect(screen.getByText('Redis 待接收')).toBeInTheDocument()
    const online = screen.getByText('权威在线清单').closest('details')
    expect(online).not.toHaveAttribute('open')
    fireEvent.click(screen.getByText('权威在线清单'))
    expect(online).toHaveAttribute('open')
    expect(screen.getByText('222.204.3.224:16380')).toBeInTheDocument()
    fireEvent.click(screen.getByText('更多运行信息'))
    expect(screen.getByText(/最近事件/)).toHaveTextContent(new Date('2026-10-09T10:01:00Z').toLocaleString())
    expect(screen.getByText(/最近全量/)).toHaveTextContent(new Date('2026-10-09T10:00:00Z').toLocaleString())
    expect(screen.queryByText('同步记录')).not.toBeInTheDocument()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
    expect(requests.runs).not.toHaveBeenCalled()
  })

  it('刷新只更新同步状态，不请求同步记录', async () => {
    renderPanel()
    fireEvent.click(await screen.findByRole('button', { name: '刷新认证状态' }))
    await waitFor(() => expect(requests.bridge).toHaveBeenCalledTimes(2))
    expect(requests.runs).not.toHaveBeenCalled()
  })

  it('同步异常仍展示阻塞原因，不引导用户查看已隐藏的记录', async () => {
    const data = await requests.bridge()
    requests.bridge.mockResolvedValueOnce({
      ...data,
      runtime: { ...data.runtime, snapshot_state: 'failed', last_error_type: 'unrecognized_error' },
    })
    renderPanel()
    expect(await screen.findByText('在线清单异常：同步失败')).toBeInTheDocument()
    expect(screen.queryByText(/全量校准记录/)).not.toBeInTheDocument()
    expect(requests.runs).not.toHaveBeenCalled()
  })

  it('刷新失败保留上次成功数据', async () => {
    renderPanel()
    expect(await screen.findByText('16,260')).toBeInTheDocument()
    requests.bridge.mockRejectedValueOnce(new Error('temporarily unavailable'))
    fireEvent.click(screen.getByRole('button', { name: '刷新认证状态' }))
    expect(await screen.findByText('刷新失败，显示上次数据')).toBeInTheDocument()
    expect(screen.getByText('16,260')).toBeInTheDocument()
  })

  it('只展示接入状态，由4K接入配置维护地址', async () => {
    renderPanel()
    expect(await screen.findByText('深澜 4K 认证同步')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '修改4K地址' })).not.toBeInTheDocument()
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(requests.update).not.toHaveBeenCalled()
  })
})
