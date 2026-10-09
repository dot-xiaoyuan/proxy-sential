import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { SharedDeviceProfiles } from './SharedDeviceProfiles'

const request = vi.hoisted(() => vi.fn())
vi.mock('../shared/api/client', () => ({ request }))

const profile = {
  profile_id: 'profile-1', sensor_id: 'sensor', endpoint_id: 'endpoint-1', mac: '00:11:22:33:44:55', ip: '192.0.2.1',
  display_name: 'TP-Link AX3000', brand: 'TP-Link', model: 'AX3000', role: 'router', confidence: 90,
  identity_conflict: false, identity_state: 'supported', identity_current: true,
  identity_at: '2026-10-09T06:00:00Z', identity_expires_at: '2026-10-10T06:00:00Z',
  identity_evidence_id: '', identity_assessment_id: 'assessment-1', identity_basis: 'DHCP 路由器型号证据',
  address_state: 'verified', current_shared: false, shared_confidence: 0, address_only: false,
  auth_bindings: [{ session_id: 'session-1', account_id: 'student-1', assigned_ips: ['198.51.100.8'], source: 'ncu-srun4k', match_basis: 'exact_endpoint', ambiguous: false }],
  latest_account_id: 'student-1', latest_account_at: '2026-10-09T06:01:00Z', latest_account_active: false,
  latest_account_match_basis: 'exact_endpoint', account_conflict: false,
  first_seen: '2026-10-09T05:00:00Z', last_observed_at: '2026-10-09T06:01:00Z', materialized_at: '2026-10-09T06:01:01Z',
}

function setup() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={client}><MemoryRouter><SharedDeviceProfiles /></MemoryRouter></QueryClientProvider>)
}

afterEach(() => { cleanup(); request.mockReset() })

describe('共享设备持久化档案', () => {
  it('初始化阶段直接展示持久化档案口径和空状态', async () => {
    request.mockResolvedValue({ items: [], page: { limit: 20, total: 0 }, checked_at: '2026-10-09T06:02:00Z', as_of: '2026-10-09T06:02:00Z', freshness_state: 'initializing', pending_jobs: 0 })
    setup()
    expect(await screen.findByText('正在建立新的设备档案')).toBeInTheDocument()
    expect(screen.getByText('暂无设备身份档案')).toBeInTheDocument()
    expect(screen.getByText(/本次上线不回填旧记录/)).toBeInTheDocument()
  })

  it('直接展示最后观测和最新账号，不再展示请求时流量状态', async () => {
    request.mockResolvedValue({ items: [profile], page: { limit: 20, total: 1 }, checked_at: '2026-10-09T06:02:00Z', as_of: '2026-10-09T06:02:00Z', freshness_state: 'fresh', materialized_at: '2026-10-09T06:01:01Z', pending_jobs: 0 })
    setup()
    await screen.findAllByText('TP-Link AX3000')
    expect(screen.getAllByText(/最后观测/).length).toBeGreaterThan(0)
    expect(screen.getAllByText('student-1').length).toBeGreaterThan(0)
    expect(screen.queryByText('最近有流量')).not.toBeInTheDocument()
    expect(screen.queryByText(/未识别|未获取|未知/)).not.toBeInTheDocument()
  })

  it('只在用户点击时刷新，并按需读取档案历史', async () => {
    request.mockImplementation((url: string) => Promise.resolve(url.includes('/profile-1')
      ? { profile, history: [{ kind: 'projection', observed_at: '2026-10-09T06:01:00Z', snapshot: profile }] }
      : { items: [profile], page: { limit: 20, total: 1 }, checked_at: '2026-10-09T06:02:00Z', as_of: '2026-10-09T06:02:00Z', freshness_state: 'fresh', pending_jobs: 0 }))
    setup()
    await screen.findAllByText('TP-Link AX3000')
    const initialCalls = request.mock.calls.length
    fireEvent.click(screen.getByRole('button', { name: /刷新/ }))
    await waitFor(() => expect(request.mock.calls.length).toBe(initialCalls + 1))
    fireEvent.click(screen.getAllByRole('button', { name: '档案历史' })[0])
    await screen.findByText('设备档案历史')
    await waitFor(() => expect(request.mock.calls.some(([url]) => String(url).includes('/profile-1'))).toBe(true))
    expect(screen.getByText('账号 student-1')).toBeInTheDocument()
  })
})
