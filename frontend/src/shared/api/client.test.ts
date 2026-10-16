import { describe, expect, it, vi } from 'vitest'
import { getApiBase, request, setUnauthorizedHandler } from './client'

describe('getApiBase', () => {
  it('当未配置 VITE_API_BASE 时返回默认值 /api/v1', () => {
    vi.stubEnv('VITE_API_BASE', '')
    expect(getApiBase()).toBe('/api/v1')
  })

  it('当配置 VITE_API_BASE 时返回指定的绝对基地址并处理末尾斜杠', () => {
    vi.stubEnv('VITE_API_BASE', 'http://192.168.0.30:18080/api/v1/')
    expect(getApiBase()).toBe('http://192.168.0.30:18080/api/v1')

    vi.stubEnv('VITE_API_BASE', 'http://192.168.0.30:18080/api/v1')
    expect(getApiBase()).toBe('http://192.168.0.30:18080/api/v1')
  })
})

describe('request 401 handling', () => {
  it('非认证接口返回 401 时通知会话失效', async () => {
    const handler = vi.fn()
    setUnauthorizedHandler(handler)
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('unauthorized', { status: 401 })))
    await expect(request('/overview')).rejects.toMatchObject({ status: 401 })
    expect(handler).toHaveBeenCalledTimes(1)
  })

  it('认证接口返回 401 不触发会话失效，避免登录页循环', async () => {
    const handler = vi.fn()
    setUnauthorizedHandler(handler)
    vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => new Response('bad password', { status: 401 })))
    await expect(request('/auth/login', { method: 'POST' })).rejects.toMatchObject({ status: 401 })
    await expect(request('/session')).rejects.toMatchObject({ status: 401 })
    expect(handler).not.toHaveBeenCalled()
  })
})
