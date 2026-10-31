#!/usr/bin/env node
/*
 * Live page-load benchmark against an already-running Proxy Sentinel UI.
 *
 * Required: PAGE_TOKEN (an authenticated proxy_sentinel_session token).
 * Optional: BASE_URL (default http://222.204.3.184:8088), ITERATIONS (default 2),
 *           TIMEOUT_MS (default 20000), OUTPUT (default artifacts/benchmark/page-load.json),
 *           CHROME_PATH (default macOS Chrome).
 *
 * This is a read-only benchmark: it only navigates GET pages and records timings.
 */
import { createRequire } from 'node:module'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

const requireFromFrontend = createRequire(new URL('../../frontend/package.json', import.meta.url))
const { chromium } = requireFromFrontend('@playwright/test')

const baseURL = (process.env.BASE_URL || 'http://222.204.3.184:8088').replace(/\/$/, '')
const token = process.env.PAGE_TOKEN
const iterations = Math.max(1, Number(process.env.ITERATIONS || 2))
const timeout = Math.max(1000, Number(process.env.TIMEOUT_MS || 20000))
const output = process.env.OUTPUT || 'artifacts/benchmark/page-load.json'
const chromePath = process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
if (!token) {
  console.error('PAGE_TOKEN is required')
  process.exit(2)
}

const routes = [
  '/overview',
  '/devices?tab=terminal',
  '/devices?tab=discovery',
  '/devices?tab=network',
  '/activity?section=applications',
  '/activity?section=access',
  '/activity?section=technical',
  '/shared-access?tab=devices',
  '/shared-access?tab=associations',
  '/shared-access?tab=reviews',
  '/cases',
  '/audit',
  '/events',
  '/policies',
  '/settings/rules',
  '/settings/sources?tab=diagnostics',
  '/settings/notifications',
  '/settings/behavior-reports',
]

function percentile(values, p) {
  if (!values.length) return null
  const sorted = [...values].sort((a, b) => a - b)
  return sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)]
}

function nowMs() { return Number(process.hrtime.bigint() / 1000000n) }

const browser = await chromium.launch({ executablePath: chromePath, headless: true, args: ['--no-sandbox'] })
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true })
const host = new URL(baseURL).hostname
await context.addCookies([{ name: 'proxy_sentinel_session', value: token, domain: host, path: '/' }])

const samples = []
for (let iteration = 1; iteration <= iterations; iteration++) {
  for (const route of routes) {
    const page = await context.newPage()
    const pageErrors = []
    const consoleErrors = []
    const requestFailures = []
    const apiSamples = []
    const requestStarted = new WeakMap()
    page.on('request', (request) => { if (request.url().includes('/api/')) requestStarted.set(request, Date.now()) })
    page.on('pageerror', (error) => pageErrors.push(error.message))
    page.on('console', (message) => { if (message.type() === 'error') consoleErrors.push(message.text().slice(0, 300)) })
    page.on('requestfailed', (request) => requestFailures.push({ url: request.url().slice(0, 300), error: request.failure()?.errorText || 'failed' }))
    page.on('response', (response) => {
      if (!response.url().includes('/api/')) return
      const startedRequest = requestStarted.get(response.request())
      const timing = response.request().timing()
      const measured = startedRequest ? Date.now() - startedRequest : (timing.responseEnd > 0 ? timing.responseEnd : null)
      apiSamples.push({
        url: new URL(response.url()).pathname + new URL(response.url()).search,
        status: response.status(),
        ms: measured,
      })
    })
    const started = nowMs()
    let navigationMs = null
    let timedOut = false
    let error = ''
    try {
      await page.goto(baseURL + route, { waitUntil: 'domcontentloaded', timeout })
      navigationMs = nowMs() - started
      // Bounded render settle after the JS entry has loaded. Do not include
      // background pollers in the page-load metric.
      await page.waitForTimeout(1200)
    } catch (cause) {
      timedOut = true
      error = cause instanceof Error ? cause.message : String(cause)
    }
    const totalMs = nowMs() - started
    const slowApis = apiSamples.filter((item) => item.ms !== null && item.ms >= 500).sort((a, b) => b.ms - a.ms)
    const failedApis = apiSamples.filter((item) => item.status >= 400)
    samples.push({ iteration, route, timedOut, error, navigationMs, totalMs, apiCount: apiSamples.length, failedApis, slowApis, pageErrors, consoleErrors, requestFailures })
    await page.close()
  }
}
await browser.close()

const byRoute = new Map()
for (const sample of samples) {
  if (!byRoute.has(sample.route)) byRoute.set(sample.route, [])
  byRoute.get(sample.route).push(sample)
}
const summary = [...byRoute.entries()].map(([route, items]) => {
  const totals = items.map((item) => item.totalMs)
  const navigations = items.map((item) => item.navigationMs).filter((value) => value !== null)
  return {
    route,
    runs: items.length,
    timeouts: items.filter((item) => item.timedOut).length,
    p50Ms: percentile(totals, 50),
    p95Ms: percentile(totals, 95),
    maxMs: Math.max(...totals),
    navP50Ms: percentile(navigations, 50),
    navP95Ms: percentile(navigations, 95),
    failedApis: [...new Map(items.flatMap((item) => item.failedApis.map((api) => [`${api.status} ${api.url}`, api])).map(([key, api]) => [key, api])).values()],
    slowApis: [...new Map(items.flatMap((item) => item.slowApis.map((api) => [`${api.url}`, api])).map(([key, api]) => [key, api])).values()].slice(0, 5),
    consoleErrors: [...new Set(items.flatMap((item) => item.consoleErrors))].slice(0, 5),
  }
}).sort((a, b) => b.p95Ms - a.p95Ms)

const result = {
  baseURL,
  generatedAt: new Date().toISOString(),
  iterations,
  timeoutMs: timeout,
  routes: summary,
  samples,
}
await mkdir(path.dirname(output), { recursive: true })
await writeFile(output, JSON.stringify(result, null, 2) + '\n')
const markdown = [
  `# Page load benchmark`,
  '',
  `- base: ${baseURL}`,
  `- iterations: ${iterations}`,
  `- timeout: ${timeout} ms`,
  `- generated: ${result.generatedAt}`,
  '',
  '| route | nav p50 ms | nav p95 ms | total p50 ms | total p95 ms | timeouts | failed APIs | slow APIs |',
  '|---|---:|---:|---:|---:|---:|---|---|',
  ...summary.map((row) => `| ${row.route} | ${row.navP50Ms} | ${row.navP95Ms} | ${row.p50Ms} | ${row.p95Ms} | ${row.timeouts} | ${row.failedApis.length} | ${row.slowApis.length} |`),
].join('\n') + '\n'
await writeFile(output.replace(/\.json$/, '.md'), markdown)
console.log(markdown)
console.log(`wrote ${output}`)
if (summary.some((row) => row.timeouts > 0)) process.exitCode = 1
