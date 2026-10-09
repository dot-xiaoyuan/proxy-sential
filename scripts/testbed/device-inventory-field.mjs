// Read-only field acceptance. Credentials and session cookies stay in memory.
import { createRequire } from 'node:module'
import { mkdir, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
const require = createRequire(new URL('../../frontend/package.json', import.meta.url))
const { chromium, request } = require('@playwright/test')
const baseURL = 'http://222.204.3.184:18080'
const output = resolve(process.argv[2] || 'artifacts/device-inventory-field-20261009')
await mkdir(output, { recursive: true })
process.stdout.write('Web administrator password (not saved): ')
if (process.stdin.isTTY) process.stdin.setRawMode(true)
const password = await new Promise(resolvePassword => {
  let value = ''
  const read = chunk => {
    for (const character of chunk.toString()) {
      if (character === '\r' || character === '\n') {
        process.stdin.off('data', read)
        if (process.stdin.isTTY) process.stdin.setRawMode(false)
        process.stdin.pause()
        process.stdout.write('\n')
        resolvePassword(value)
        return
      }
      value += character
    }
  }
  process.stdin.on('data', read)
})
const api = await request.newContext({ baseURL, timeout: 30_000 })
const login = await api.post('/api/v1/auth/login', { data: { username: 'admin', password } })
if (!login.ok()) throw new Error(`Administrator login failed: HTTP ${login.status()}`)
const session = await login.json()
const samples = []
async function read(url) {
  const start = performance.now()
  const response = await api.get(url)
  const body = await response.body()
  if (!response.ok()) throw new Error(`Acceptance read failed: HTTP ${response.status()}`)
  const sample = { ms: performance.now() - start, bytes: body.length, server_timing: response.headers()['server-timing'] || '' }
  samples.push(sample)
  return { sample, data: JSON.parse(body.toString()) }
}
const list = '/api/v1/device-inventory?view=recent&window=24h&limit=20&include_metadata=false'
const first = await read(list + '&refresh=true')
if (first.data.items.length !== 20 || Object.hasOwn(first.data.page, 'total')) throw new Error('Lightweight list contract mismatch')
const metadata = await read('/api/v1/device-inventory/metadata?view=recent&window=24h&refresh=true')
function percentiles(values) {
  const sorted = values.toSorted((a, b) => a - b)
  return Object.fromEntries([50, 95, 99].map(p => [`p${p}`, sorted[Math.ceil(sorted.length * p / 100) - 1]]))
}
async function batch(count, concurrency) {
  const durations = []; const cache = {}; let bytesMax = 0; let next = 0
  await Promise.all(Array.from({ length: concurrency }, async () => {
    while (next++ < count) {
      const { sample } = await read(list)
      durations.push(sample.ms); bytesMax = Math.max(bytesMax, sample.bytes)
      const state = sample.server_timing.includes('cache;desc="reused"') ? 'reused' : 'miss'
      cache[state] = (cache[state] || 0) + 1
    }
  }))
  return { samples: durations.length, concurrency, ...percentiles(durations), cache, bytes_max: bytesMax }
}
const serial = await batch(100, 1)
const concurrent = await batch(100, 20)
const bypass = []
for (let i = 0; i < 5; i++) bypass.push((await read(list + '&refresh=true')).sample)
const sharedPage = await read('/api/v1/shared-access/devices?limit=20&cursor=0')
const apiResult = { target: baseURL, checked_at: new Date().toISOString(), list_first_bypassed: first.sample, total: metadata.data.total, metadata: metadata.sample, serial, concurrent, bypass, shared_profiles: { items: sharedPage.data.items.length, freshness: sharedPage.data.freshness_state, pending_jobs: sharedPage.data.pending_jobs } }
await writeFile(resolve(output, 'api-acceptance.json'), JSON.stringify(apiResult, null, 2))
await writeFile(resolve(output, 'request-samples.json'), JSON.stringify(samples, null, 2))
console.log(JSON.stringify({ total: metadata.data.total, first: first.sample, metadata: metadata.sample, serial, concurrent, shared_profiles: apiResult.shared_profiles }, null, 2))
const browser = await chromium.launch({ headless: true })
const state = await api.storageState()
const ui = []
try {
  for (const [width, height] of [[390, 844], [743, 774], [1280, 800], [1440, 900]]) {
    const context = await browser.newContext({ baseURL, viewport: { width, height }, storageState: state })
    const page = await context.newPage()
    const errors = []; const failures = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('response', response => { if (response.status() >= 400) failures.push({ status: response.status(), path: new URL(response.url()).pathname }) })
    await page.goto('/devices?view=recent&window=24h&page=1')
    const rows = width < 992 ? '.device-mobile-card' : '.device-desktop-table .ant-table-row'
    await page.locator(rows).first().waitFor({ timeout: 30_000 })
    await page.screenshot({ path: resolve(output, `devices-${width}.png`), fullPage: true })
    const inventory = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth > innerWidth + 2,
      controls: [...document.querySelectorAll('.device-inventory-page .ant-btn,.device-inventory-page .ant-tag')].filter(node => getComputedStyle(node).whiteSpace !== 'nowrap' || getComputedStyle(node).flexShrink !== '0').map(node => node.className),
      access_clipped: [...document.querySelectorAll('.device-context-cell .brand-evidence-wrap[title]')].filter(node => node.scrollWidth > node.clientWidth + 1).length,
      icons: [...document.querySelectorAll('.device-semantic-icon')].map(node => ({ width: node.getBoundingClientRect().width, height: node.getBoundingClientRect().height, glyph: node.querySelector('svg')?.getBoundingClientRect().width })),
      measurements: performance.getEntriesByType('measure').filter(entry => entry.name.startsWith('device-inventory')).map(entry => ({ name: entry.name, ms: entry.duration })),
      resources: performance.getEntriesByType('resource').filter(entry => entry.name.includes('/api/v1/device-inventory')).map(entry => ({ path: new URL(entry.name).pathname, ms: entry.duration, ttfb: entry.responseStart - entry.requestStart, download: entry.responseEnd - entry.responseStart, stages: entry.serverTiming?.map(stage => ({ name: stage.name, ms: stage.duration, state: stage.description })) })),
    }))
    if (width >= 1280) {
      await page.goto('/overview')
      await page.getByText('资产与画像', { exact: true }).click()
      await page.getByRole('link', { name: '终端画像', exact: true }).click()
      await page.locator(rows).first().waitFor({ timeout: 30_000 })
      await page.waitForFunction(() => performance.getEntriesByName('device-inventory-visible').length > 0)
      inventory.sidebar_ms = await page.evaluate(() => performance.getEntriesByName('device-inventory-visible').at(-1).duration)
    }
    await page.goto('/shared-access?tab=devices')
    if (sharedPage.data.items.length) await page.locator('.shared-profile-mobile-row').first().waitFor({ timeout: 30_000 })
    else await page.getByText('暂无设备身份档案', { exact: true }).waitFor({ timeout: 30_000 })
    const profiles = await page.evaluate(() => {
      const rows = [...document.querySelectorAll('.shared-profile-mobile-row')]
      const coordinates = rows.map(row => [...row.querySelectorAll('.shared-profile-mobile-block')].map(block => Math.round(block.getBoundingClientRect().left)))
      return {
        overflow: document.documentElement.scrollWidth > innerWidth + 2,
        rows: rows.length,
        empty_auth_rows: rows.filter(row => row.querySelector('.shared-profile-block-empty')).length,
        coordinates,
        header: [...document.querySelectorAll('.shared-profile-column-heading>span')].map(column => Math.round(column.getBoundingClientRect().left)),
        controls: [...document.querySelectorAll('.shared-profile-panel .ant-btn,.shared-profile-panel .ant-tag,.shared-profile-actions a')].filter(node => getComputedStyle(node).whiteSpace !== 'nowrap' || getComputedStyle(node).flexShrink !== '0').map(node => node.className),
        alignment_verified: rows.length > 1,
      }
    })
    if (width >= 1280 && profiles.coordinates.some(columns => JSON.stringify(columns) !== JSON.stringify(profiles.header))) throw new Error(`Cross-row alignment mismatch at ${width}`)
    if (inventory.overflow || inventory.access_clipped || inventory.controls.length || inventory.icons.some(icon => icon.width !== 24 || icon.height !== 24 || icon.glyph !== 18) || profiles.overflow || profiles.controls.length || errors.length || failures.length) throw new Error(`UI acceptance failed at ${width}: ${JSON.stringify({inventory, profiles, errors, failures})}`)
    await page.screenshot({ path: resolve(output, `shared-profiles-${width}.png`), fullPage: true })
    ui.push({ width, height, inventory, profiles, errors, failures })
    await context.close()
  }
} finally {
  await browser.close()
  await api.post('/api/v1/auth/logout', { headers: { 'X-CSRF-Token': session.csrf_token || '' } })
  await api.dispose()
}
const result = { ...apiResult, ui, caveats: ['Backend cache bypass is not a cold PostgreSQL or OS buffer test.', 'API durations include the client-to-field network round trip.', 'Browser UI contexts have fresh React Query caches; sidebar measurements reuse the browser assets.', 'Shared profile alignment cannot be verified with empty field rows; mixed-row mock regression covers this separately.'] }
await writeFile(resolve(output, 'acceptance.json'), JSON.stringify(result, null, 2))
await writeFile(resolve(output, 'request-samples.json'), JSON.stringify(samples, null, 2))
console.log(JSON.stringify({ output, total: result.total, first_ms: first.sample.ms, bytes: first.sample.bytes, metadata_ms: metadata.sample.ms, serial, concurrent, sidebar: ui.filter(item => item.inventory.sidebar_ms).map(item => ({ width: item.width, ms: item.inventory.sidebar_ms })) }, null, 2))
