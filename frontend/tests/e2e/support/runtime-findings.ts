export type RuntimeEvidence = {
  pageErrors: string[]
  consoleErrors: string[]
  mockErrors: { url: string; status: number }[]
  unmockedRequests: { url: string; status: number }[]
}

export function runtimeFindings(evidence: RuntimeEvidence) {
  return [
    ...evidence.pageErrors.map((error) => ({ kind: 'js-error', detail: error.split('\n')[0] })),
    ...evidence.consoleErrors.map((error) => ({ kind: 'console-error', detail: error.split('\n')[0] })),
    ...evidence.mockErrors.map((item) => ({ kind: 'api-error', detail: `mock 接口 ${item.status} ${item.url}` })),
    ...evidence.unmockedRequests.map((item) => ({ kind: 'api-error', detail: `真实网络接口 ${item.status} ${item.url}` })),
  ]
}
