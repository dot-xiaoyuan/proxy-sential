import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen } from '@testing-library/react'
import { App } from 'antd'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'

import { ActionsPage } from './ActionsPage'

const fixture = vi.hoisted(() => ({
  readOnly: true,
  bridge: { config: {}, runtime: { active_host: '222.204.3.224' } } as Record<string, unknown>,
  integrations: [{ connector_id: 'srun4k-office', authorization_database_host: '222.204.3.224', online_redis_host: '222.204.3.225', catalog_redis_host: '222.204.3.226', event_redis_host: '222.204.3.227', northbound_api_host: '222.204.3.227', authorization_ready: true, reconcile_interval_hours: 6, event_channel_state: 'waiting' }],
}))
vi.mock('../shared/api/client', () => ({ api: { identityBridge: vi.fn(async () => fixture.bridge), srun4KIntegrations: vi.fn(async () => ({ items: fixture.integrations })) } }))
vi.mock('../shared/api/queries', () => ({
  useSession: () => ({ data: { permissions: ['integrations:write'] } }),
  useActionConnectors: () => ({ data: { items: [], global_stop: false, read_only: fixture.readOnly }, isLoading: false, isError: false, refetch: vi.fn() }),
}))
vi.mock('../features/integrations/IdentityBridgePanel', () => ({ IdentityBridgePanel: ({integration,integrationAction}:{integration?:ReactNode;integrationAction?:ReactNode}) => <section>认证同步{integration}{integrationAction}</section> }))

afterEach(() => cleanup())
function renderPage() {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><App><ActionsPage /></App></QueryClientProvider>)
}

describe('4K分通道配置与全局只读保护', () => {
  it('只读模式仍允许管理员配置4K接入，但不开放处置连接器写入', async () => {
    fixture.readOnly = true
    fixture.integrations = [{ connector_id: 'srun4k-office', authorization_database_host: '222.204.3.224', online_redis_host: '222.204.3.225', catalog_redis_host: '222.204.3.226', event_redis_host: '222.204.3.227', northbound_api_host: '222.204.3.227', authorization_ready: true, reconcile_interval_hours: 6, event_channel_state: 'waiting' }]
    renderPage()
    expect(await screen.findByText('认证同步')).toBeInTheDocument()
    expect(await screen.findByText('222.204.3.224')).toBeInTheDocument()
    expect(screen.getByText('222.204.3.225')).toBeInTheDocument()
    expect(screen.getByText('只读')).toBeInTheDocument()
    expect(screen.queryByText('安全门槛')).not.toBeInTheDocument()
    expect(await screen.findByRole('button', { name: '配置接入' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '新增处置连接器' })).not.toBeInTheDocument()
    expect(screen.queryByRole('switch')).not.toBeInTheDocument()
  })

  it('已有4K接入时使用单一配置入口', async () => {
    fixture.readOnly = false
    fixture.integrations = [{ connector_id: 'srun4k-office', authorization_database_host: '222.204.3.224', online_redis_host: '222.204.3.225', catalog_redis_host: '222.204.3.226', event_redis_host: '222.204.3.227', northbound_api_host: '222.204.3.227', authorization_ready: true, reconcile_interval_hours: 6, event_channel_state: 'waiting' }]
    renderPage()
    await screen.findByText('认证同步')
    expect(await screen.findByRole('button', { name: '配置接入' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新增处置连接器' })).toBeInTheDocument()
  })

  it('尚无4K接入时提供新增入口', async () => {
    fixture.readOnly = false
    fixture.integrations = []
    renderPage()
    expect(await screen.findByRole('button', { name: '新增接入' })).toBeInTheDocument()
  })
})
