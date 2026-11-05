import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import { TerminalRegistrationPanel, type RegistrationRow } from './TerminalRegistrationPanel'

const request = vi.hoisted(() => vi.fn())
vi.mock('../shared/api/client', async importOriginal => {
  const actual = await importOriginal<typeof import('../shared/api/client')>()
  return { ...actual, request }
})

const row: RegistrationRow = {
  endpoint_id: 'mac:00:11:22:33:44:55', primary_mac: '00:11:22:33:44:55',
  registration_status: 'registered', owner_name: '张老师', owner_account: 'teacher',
  owner_department: '图书馆', asset_tag: 'ASSET-204', ownership_class: 'school_asset',
  registration_note: '服务台打印机', registration_updated_at: '2026-11-05T12:00:00Z',
  registration_updated_by: '管理员', registered_at: '2026-11-05T12:00:00Z', last_seen: '', source: 'local',
  merge_status: 'active', merged_into_endpoint_id: '', split_from_endpoint_id: '',
  registration_details: { name: '图书馆打印机', device_type: 'printer', location: '一层服务台', registered_ip: '192.0.2.20' },
}

function Location() {
  return <output data-testid="location">{useLocation().search}</output>
}

function renderPanel(initialEntry = '/devices?discovery_view=registrations') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  client.setQueryData(['session'], { user: { id: 'admin', name: '管理员' }, role: 'admin', permissions: ['endpoints:write'], csrf_token: 'csrf' })
  const onCreate = vi.fn()
  const onEdit = vi.fn()
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[initialEntry]}><TerminalRegistrationPanel onCreate={onCreate} onEdit={onEdit} /><Location /></MemoryRouter></QueryClientProvider>)
  return { onCreate, onEdit }
}

function mockReads(items: RegistrationRow[] = [row], total = 123) {
  request.mockImplementation((path: string) => {
    if (path.startsWith('/endpoints/registrations/position')) {const q=new URL(path,'http://localhost').searchParams;return Promise.resolve({page:Number(q.get('page')),limit:Number(q.get('limit')),cursor:'opaque-page-two'})}
    if (path === '/discovery/types') return Promise.resolve({ items: [{ id: 'printer', label: '打印机' }] })
    if (path.startsWith('/endpoints/registrations/metadata')) return Promise.resolve({ total, as_of: '2026-11-05T12:00:00Z' })
    if (path.startsWith('/endpoints/registrations?')) return Promise.resolve({ items, next_cursor: '', has_more: false, limit: 20, as_of: '2026-11-05T12:00:00Z' })
    return Promise.resolve({})
  })
}

afterEach(() => { cleanup(); request.mockReset() })

it('shows an independent registration count and supplies the complete selected record for editing', async () => {
  mockReads()
  const { onEdit } = renderPanel()
  expect(await screen.findByText('共 123 条登记记录')).toBeVisible()
  expect(await screen.findByText('图书馆打印机')).toBeVisible()
  expect(screen.getByText('打印机')).toBeVisible()
  expect(screen.getByText('张老师 · teacher')).toBeVisible()
  expect(screen.getByText('图书馆')).toBeVisible()
  expect(screen.getByText('一层服务台')).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: '编辑登记' }))
  expect(onEdit).toHaveBeenCalledWith(row)
  expect(request.mock.calls.some(([path]) => path === '/endpoints/registrations/metadata')).toBe(true)
})

it('locates an arbitrary page with one opaque cursor, resets on search, and retains the registration view', async () => {
  mockReads()
  const baseImplementation = request.getMockImplementation()!
  request.mockImplementation((path: string) => {
    if (path.startsWith('/endpoints/registrations?')) {
      const query = new URLSearchParams(path.split('?')[1])
      const secondPage = query.has('cursor')
      const searched = query.has('search')
      return Promise.resolve({
        items: secondPage ? [{ ...row, endpoint_id: 'second', registration_details: { name: '第二页设备' } }] : searched ? [row] : Array.from({ length: 20 }, (_, index) => ({ ...row, endpoint_id: `first-${index}` })),
        next_cursor: secondPage || searched ? '' : 'opaque-page-two', has_more: !secondPage && !searched, limit: 20, as_of: '2026-11-05T12:00:00Z',
      })
    }
    return baseImplementation(path)
  })
  renderPanel('/devices?discovery_view=registrations&registration_status=registered&registration_ownership=school_asset')
  await screen.findByText('共 123 条登记记录')
  fireEvent.click(screen.getByTitle('4'))
  expect(await screen.findByText('第二页设备')).toBeVisible()
  const positions=request.mock.calls.map(([path])=>String(path)).filter(path=>path.includes('/position'))
  expect(positions).toHaveLength(1)
  expect(positions[0]).toContain('page=4')
  const cursorCall = request.mock.calls.map(([path]) => String(path)).find(path => path.includes('cursor='))!
  expect(new URLSearchParams(cursorCall.split('?')[1]).get('cursor')).toBe('opaque-page-two')
  const input = screen.getByRole('textbox', { name: '搜索名称、MAC、资产编号或责任人' })
  fireEvent.change(input, { target: { value: '图书馆' } })
  fireEvent.keyDown(input, { key: 'Enter', code: 'Enter', charCode: 13 })
  await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('registration_search='))
  await waitFor(() => expect(request.mock.calls.some(([path]) => String(path).includes('search=') && String(path).startsWith('/endpoints/registrations?'))).toBe(true))
  const searches = request.mock.calls.map(([path]) => String(path)).filter(path => path.includes('search='))
  for (const path of searches) {
    const query = new URLSearchParams(path.split('?')[1])
    expect(query.get('search')).toBe('图书馆')
    expect(query.get('status')).toBe('registered')
    expect(query.get('ownership_class')).toBe('school_asset')
    expect(query.has('cursor')).toBe(false)
  }
  expect(screen.getByTestId('location')).toHaveTextContent('discovery_view=registrations')
})

it('guides an empty ledger to independent registration and leaves absent fields blank', async () => {
  mockReads([], 0)
  const { onCreate } = renderPanel()
  expect(await screen.findByText('还没有登记设备')).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: '登记第一台设备' }))
  expect(onCreate).toHaveBeenCalledOnce()
})

it('keeps records visible if the independent count request fails', async () => {
  mockReads([{ ...row, ownership_class: 'unknown', registration_details: {} }])
  const baseImplementation = request.getMockImplementation()!
  request.mockImplementation((path: string) => path.startsWith('/endpoints/registrations/metadata') ? Promise.reject(new Error('统计暂不可用')) : baseImplementation(path))
  renderPanel()
  expect(await screen.findByText('读取登记数量失败')).toBeVisible()
  expect(await screen.findByText('00:11:22:33:44:55')).toBeVisible()
  expect(screen.queryByText('unknown')).not.toBeInTheDocument()
  expect(screen.queryByText('未知')).not.toBeInTheDocument()
})
