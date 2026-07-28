import { describe, expect, it, vi } from 'vitest'
import { getApiBase } from './client'

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
