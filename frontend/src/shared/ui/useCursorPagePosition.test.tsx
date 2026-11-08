import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { request } from '../api/client'
import { useCursorPagePosition } from './useCursorPagePosition'
vi.mock('../api/client', () => ({ request: vi.fn() }))
const call = vi.mocked(request)
function wrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>
}
describe('useCursorPagePosition', () => {
  beforeEach(() => vi.clearAllMocks())
  it('首页直接读取列表，不调用目标页定位', () => {
    const { result } = renderHook(() => useCursorPagePosition({ path: '/list/position', query: 'type=router', page: 1, pageSize: 20 }), { wrapper: wrapper() })
    expect(result.current.ready).toBe(true)
    expect(result.current.cursor).toBeUndefined()
    expect(call).not.toHaveBeenCalled()
  })
  it('远跳只请求一次目标页边界，包含所有筛选和页长', async () => {
    call.mockResolvedValue({ page: 42, limit: 50, cursor: 'opaque-page-42', as_of: '2026-11-06T00:00:00Z' })
    const { result } = renderHook(() => useCursorPagePosition({ path: '/list/position', query: 'type=router&state=expired&cursor=old', page: 42, pageSize: 50 }), { wrapper: wrapper() })
    await waitFor(() => expect(result.current.ready).toBe(true))
    expect(call).toHaveBeenCalledTimes(1)
    expect(call.mock.calls[0][0]).toBe('/list/position?type=router&state=expired&page=42&limit=50')
    expect(result.current.cursor).toBe('opaque-page-42')
  })
  it('定位失败不能用空游标回退首页', async () => {
    call.mockRejectedValue(new Error('定位失败'))
    const { result } = renderHook(() => useCursorPagePosition({ path: '/list/position', query: '', page: 7, pageSize: 20 }), { wrapper: wrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.ready).toBe(false)
    expect(result.current.cursor).toBeUndefined()
  })
  it('拒绝空游标及不匹配目标页的响应', async () => {
    call.mockResolvedValue({ page: 1, limit: 20, cursor: '' })
    const { result } = renderHook(() => useCursorPagePosition({ path: '/list/position', query: '', page: 7, pageSize: 20 }), { wrapper: wrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.ready).toBe(false)
  })
  it('改变筛选不能复用前一组游标', async () => {
    call.mockImplementation(async (path) => String(path).includes('type=router') ? { page: 7, limit: 20, cursor: 'router-page-7' } : new Promise(() => {}))
    const { result, rerender } = renderHook(({ type }) => useCursorPagePosition({ path: '/list/position', query: `type=${type}`, page: 7, pageSize: 20 }), { initialProps: { type: 'router' }, wrapper: wrapper() })
    await waitFor(() => expect(result.current.ready).toBe(true))
    rerender({ type: 'access_point' })
    expect(result.current.ready).toBe(false)
    expect(result.current.cursor).toBeUndefined()
  })
})
