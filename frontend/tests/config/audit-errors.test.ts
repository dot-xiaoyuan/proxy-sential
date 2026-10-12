import { expect, test } from 'vitest'
import { runtimeFindings } from '../e2e/support/runtime-findings'

test('页面能渲染也必须因控制台或真实 API 错误判为失败', () => {
  const errors = runtimeFindings({
    pageErrors: [], consoleErrors: ['render warning\nstack'], mockErrors: [],
    unmockedRequests: [{ url: '/api/v1/devices', status: 500 }],
  })
  expect(errors).toEqual([
    { kind: 'console-error', detail: 'render warning' },
    { kind: 'api-error', detail: '真实网络接口 500 /api/v1/devices' },
  ])
})

test('JS 与模拟接口错误同样计入失败，零错误记录保持通过', () => {
  expect(runtimeFindings({ pageErrors: ['TypeError'], consoleErrors: [], mockErrors: [{ url: '/api/v1/events', status: 404 }], unmockedRequests: [] })).toHaveLength(2)
  expect(runtimeFindings({ pageErrors: [], consoleErrors: [], mockErrors: [], unmockedRequests: [] })).toEqual([])
})
