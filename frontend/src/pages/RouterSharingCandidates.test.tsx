import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import { RouterSharingCandidates } from './RouterSharingCandidates'

const request = vi.hoisted(() => vi.fn())
vi.mock('../shared/api/client', () => ({ request }))
afterEach(() => { cleanup(); request.mockReset() })

function setup(entry = '/shared-access?tab=routers') {
  request.mockResolvedValue({ items: [{ profile_id: 'likely-router', brand: 'TP-Link', model: 'AX3000', router_status: 'likely', identity_current: true, latest_account_id: 'student-1' }], page: { total: 1 } })
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={[entry]}><RouterSharingCandidates /></MemoryRouter></QueryClientProvider>)
}

it('默认读取有账号的有效路由线索并保留待确认语义', async () => {
  setup()
  await screen.findByText('TP-Link AX3000')
  const query = new URL(request.mock.calls[0][0], 'http://localhost').searchParams
  expect(query.get('role')).toBe('router')
  expect(query.get('identity_state')).toBe('supported')
  expect(query.get('has_account')).toBe('true')
  expect(query.get('router_status') || '').toBe('')
  expect(screen.getAllByText('身份待确认').length).toBeGreaterThan(0)
  expect(screen.queryByText('路由器身份已确认')).not.toBeInTheDocument()
  expect(screen.getByText('共享关系待核验')).toBeInTheDocument()
})

it('允许通过链接限定已确认身份并保留账号分组', async () => {
  setup('/shared-access?tab=routers&router_status=confirmed&router_accounts=empty')
  await waitFor(() => expect(request).toHaveBeenCalled())
  const query = new URL(request.mock.calls[0][0], 'http://localhost').searchParams
  expect(query.get('router_status')).toBe('confirmed')
  expect(query.get('has_account')).toBe('false')
})
