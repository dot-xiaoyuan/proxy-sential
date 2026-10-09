import { describe, expect, it } from 'vitest'
import { proxySentinelTheme } from './theme'

describe('Proxy Sentinel design tokens', () => {
  it('keeps the shared layout and component baseline stable', () => {
    expect(proxySentinelTheme.cssVar).toEqual({ key: 'proxy-sentinel', prefix: 'ps' })
    expect(proxySentinelTheme.token).toMatchObject({
      borderRadius: 8,
      colorBgLayout: '#f8fafc',
      colorBorder: '#e2e8f0',
      colorPrimary: '#2257a7',
      colorText: '#0f172a',
      colorTextSecondary: '#475569',
      controlHeight: 32,
      fontSize: 14,
    })
  })
})
