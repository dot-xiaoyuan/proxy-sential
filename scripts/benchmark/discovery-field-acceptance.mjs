#!/usr/bin/env node
/*
 * node scripts/benchmark/discovery-field-acceptance.mjs [ui|export|peak|offpeak]
 * PAGE_TOKEN is an existing 204 session. Alternatively set PS204_USERNAME
 * and PS204_PASSWORD for one normal audited login. No login values are saved.
 * SSH authenticates to root@222.204.3.204 using the operator's existing setup.
 * PS204_OUTPUT selects a NEW local result directory. CHROME_PATH is optional.
 * Peak and offpeak are separate runs at their respective field time windows.
 */
import { execFile } from 'node:child_process'
import { createRequire } from 'node:module'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

process.umask(0o077)
const mode = process.argv[2] || 'ui'
if (!['ui', 'export', 'peak', 'offpeak'].includes(mode)) throw new Error('模式应为 ui、export、peak 或 offpeak')
const dir = path.dirname(fileURLToPath(import.meta.url))
const output = process.env.PS204_OUTPUT || path.join('artifacts', '204-field-' + mode + '-' + new Date().toISOString().replaceAll(':', ''))
await mkdir(path.dirname(output), {recursive:true})
await mkdir(output, {mode:0o700})
const temp = await mkdtemp(path.join(tmpdir(), 'ps204-'))
const socket = path.join(temp, 's')
const host = 'root@222.204.3.204'
const sshArgs = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'LogLevel=ERROR',
  '-o', 'ClearAllForwardings=yes', '-o', 'ControlMaster=auto', '-o', 'ControlPersist=30', '-S', socket, host]
const origin = 'http://127.0.0.1:18080'
const python = await readFile(path.join(dir, 'discovery_field_request.py'), 'utf8')
const command = "python3 -c '" + python.replaceAll("'", "'\\''") + "'"
const report = {mode, started_at:new Date().toISOString(), host:host.split('@')[1], transport:'SSH exec / host loopback HTTP', pages:[], samples:[], errors:[]}

function run(file, args, input, timeout = 120_000) {
  return new Promise((resolve, reject) => {
    const child = execFile(file, args, {encoding:'buffer', timeout, maxBuffer:260 * 1024 * 1024}, (error, stdout) => {
      // Errors can include the input command or response. Keep diagnostics free of credentials.
      if (error) reject(new Error(file + ' 失败 (' + (error.signal || error.code || 'exit') + ')'))
      else resolve(stdout)
    })
    child.stdin.on('error', () => {})
    child.stdin.end(input)
  })
}

async function http(method, target, headers = {}, body) {
  const bytes = await run('ssh', [...sshArgs, command], JSON.stringify({method, path:target, headers, body}))
  const line = bytes.indexOf(10)
  if (line < 0) throw new Error('现场 HTTP 响应头缺失')
  const meta = JSON.parse(bytes.subarray(0, line).toString())
  meta.headers = Object.fromEntries(Object.entries(meta.headers).map(([k,v]) => [k.toLowerCase(),v]))
  return {...meta, body:bytes.subarray(line + 1)}
}

async function authenticate() {
  let token = process.env.PAGE_TOKEN
  if (!token) {
    const username = process.env.PS204_USERNAME, password = process.env.PS204_PASSWORD
    if (!username || !password) throw new Error('需要本地 PAGE_TOKEN 或 PS204_USERNAME 和 PS204_PASSWORD')
    const login = await http('POST', '/api/v1/auth/login', {'content-type':'application/json'}, JSON.stringify({username,password}))
    if (login.status !== 200) throw new Error('现场登录 HTTP ' + login.status)
    token = /^proxy_sentinel_session=([^;]+)/.exec(login.headers['set-cookie'] || '')?.[1]
  }
  if (!token || !/^[^\s;,\r\n]+$/.test(token)) throw new Error('现场会话 cookie 无效')
  const session = await http('GET', '/api/v1/session', {cookie:'proxy_sentinel_session=' + token})
  if (session.status !== 200) throw new Error('已有会话 HTTP ' + session.status)
  const permissions = JSON.parse(session.body).permissions || []
  if (!permissions.includes('identity:read')) throw new Error('会话缺少 identity:read')
  return token
}

async function inspectExport(page) {
  await page.getByRole('button', {name:'操作', exact:true}).click()
  // Subscribe before the click. A server-side stream error yields no download event.
  const downloaded = page.waitForEvent('download', {timeout:120_000}).catch(() => null)
  const [response] = await Promise.all([
    page.waitForResponse(r => new URL(r.url()).pathname === '/api/v1/discovery/devices/export', {timeout:120_000}),
    page.getByRole('menuitem', {name:'导出全部筛选结果'}).click(),
  ])
  if (response.status() !== 200) throw new Error('发现导出 HTTP ' + response.status())
  const {manifest, end, scope} = exportByPage.get(page) || {}
  if (!manifest || !end) throw new Error('导出响应缺少首尾记录')
  if (end.record !== 'end' || !end.complete) throw new Error('导出流未完成 ' + (end.message || end.record))
  const download = await downloaded
  if (!download || await download.failure()) throw new Error('完整导出流已返回，浏览器未生成 CSV')
  const file = path.join(output, 'discovery.csv')
  await download.saveAs(file)
  const result = await run('python3', [path.join(dir,'discovery_export_audit.py'), file],
    JSON.stringify({manifest, end, scope}))
  return JSON.parse(result)
}

async function inspectPage(context, width, height, [name, route, endpoint, selector]) {
  const page = await context.newPage()
  page.setDefaultTimeout(45_000)
  const row = {name, width, height, errors:[]}
  report.pages.push(row)
  page.on('response', r => { if (r.status() >= 400) row.errors.push(r.status() + ' ' + new URL(r.url()).pathname) })
  page.on('requestfailed', r => row.errors.push((r.failure()?.errorText || 'requestfailed') + ' ' + new URL(r.url()).pathname))
  page.on('console', m => { if (m.type() === 'error') row.errors.push('console error ' + (m.location().url ? new URL(m.location().url).pathname : '')) })
  page.on('pageerror', e => row.errors.push('page error ' + e.name))
  try {
    await page.setViewportSize({width,height})
    const [data] = await Promise.all([
      page.waitForResponse(r => new URL(r.url()).pathname === '/api/v1/' + endpoint),
      page.goto(origin + route, {waitUntil:'domcontentloaded'}),
    ])
    if (data.status() !== 200 || await data.finished()) throw new Error('数据请求失败 ' + endpoint)
    await page.locator(selector).first().waitFor({state:'visible'})
    await page.waitForLoadState('networkidle', {timeout:60_000})
    row.dom = await page.evaluate(() => {
      const visible = e => e.getClientRects().length > 0 && e.getBoundingClientRect().width > 0
      const container = document.querySelector('.passive-discovery-panel, .coverage-content, .data-report-page')
      const controls = [...container.querySelectorAll('button.ant-btn, .ant-tag')].filter(visible)
      return {
        document_width:document.documentElement.scrollWidth, viewport_width:innerWidth,
        content_right:Math.round(container.getBoundingClientRect().right),
        controls:controls.length,
        wrapping_controls:controls.filter(e => getComputedStyle(e).whiteSpace !== 'nowrap').length,
        shrinkable_controls:controls.filter(e => getComputedStyle(e).flexShrink !== '0').length,
        selected:[...document.querySelectorAll('.ant-menu-item-selected, .ant-segmented-item-selected')].filter(visible).map(e => {
          const style = getComputedStyle(e)
          return {color:style.color, background:style.backgroundColor}
        }),
      }
    })
    await page.screenshot({path:path.join(output, name + '-' + width + '.png'), animations:'disabled', fullPage:true, mask:[page.locator('.user-session-badge')]})
    if (row.dom.document_width > width + 2 || row.dom.content_right > width + 2) row.errors.push('页面横向溢出')
    if (row.dom.wrapping_controls || row.dom.shrinkable_controls) row.errors.push('操作控件折行或压缩样式')
    if (name === 'discovery' && width === 1440) report.csv = await inspectExport(page)
  } catch (error) {
    row.errors.push(error.name === 'TimeoutError' ? '等待页面、数据或下载超时' : error.message.split('\n')[0])
  } finally {
    await page.close()
  }
}

// The largest export can exceed Chromium's DevTools body cache. Extract its
// boundary records from the exact bytes passed to the browser.
const exportByPage = new WeakMap()
function rememberExport(page, body, url) {
  const first = body.indexOf(10)
  let last = body.length
  while (last > 0 && [10,13].includes(body[last-1])) last--
  if (first < 0 || last <= first) return
  const manifest = JSON.parse(body.subarray(0, first))
  const end = JSON.parse(body.subarray(body.lastIndexOf(10,last-1)+1,last))
  const scope = url.searchParams.toString()
  exportByPage.set(page, {manifest, end, scope})
  report.export_stream = {scope, manifest_total:manifest.total, snapshot_at:manifest.snapshot_at, end:end.record, end_count:end.count, complete:end.complete}
}

async function ui(token) {
  const require = createRequire(new URL('../../frontend/package.json', import.meta.url))
  const {chromium} = require('@playwright/test')
  const browser = await chromium.launch({executablePath:process.env.CHROME_PATH, headless:true})
  try {
    const context = await browser.newContext({serviceWorkers:'block', acceptDownloads:true})
    await context.route('**/*', async route => {
      const request = route.request()
      const url = new URL(request.url())
      if (url.origin !== origin || !['GET','HEAD'].includes(request.method())) return route.abort('blockedbyclient')
      try {
        const res = await http(request.method(), url.pathname + url.search, {
          accept:await request.headerValue('accept') || '*/*',
          cookie:'proxy_sentinel_session=' + token,
        })
        if (res.status === 200 && url.pathname === '/api/v1/discovery/devices/export') {
          rememberExport(request.frame().page(), res.body, url)
        }
        const headers = {...res.headers}
        for (const name of ['connection','transfer-encoding','content-length','set-cookie']) delete headers[name]
        await route.fulfill({status:res.status, headers, body:res.body})
      } catch { await route.abort('failed').catch(() => {}) }
    })
    const routes = [
      ['discovery', '/devices?tab=discovery', 'discovery/devices', '.passive-ledger-table'],
      ['coverage', '/devices/coverage', 'discovery/devices/coverage-report', '.coverage-content'],
      ['global', '/reports/data', 'discovery/devices/metadata', '.data-report-discovery-body'],
    ]
    if (mode === 'export') {
      await inspectPage(context,1440,900,routes[0])
      return
    }
    for (const [width,height] of [[390,844],[1280,800],[1440,900]]) {
      for (const route of routes) {
        await inspectPage(context,width,height,route)
        await save()
      }
    }
  } finally { await browser.close() }
}

async function save() {
  await writeFile(path.join(output, 'report.json'), JSON.stringify(report,null,2) + '\n')
}

function percentiles(values) {
  const sorted = [...values].sort((a,b) => a - b)
  const at = p => sorted[Math.ceil(p * sorted.length) - 1]
  return {count:sorted.length,p50:at(0.5),p95:at(0.95),p99:at(0.99)}
}

async function fieldPerformance(token) {
  const basePath = '/api/v1/discovery/devices'
  const scope = {mode:'passive', identity_scope:'devices', window:'24h'}
  const headers = {cookie:'proxy_sentinel_session=' + token}
  const first = await http('GET', basePath + '?' + new URLSearchParams({...scope,limit:'20'}), headers)
  if (first.status !== 200) throw new Error('首屏预检 HTTP ' + first.status)
  const cursor = JSON.parse(first.body).next_cursor
  if (!cursor) throw new Error('首屏无次页游标')
  await writeFile(path.join(output,'second-page.cursor'), cursor + '\n')
  const cases = [
    ['首屏','',{...scope,limit:'20'}], ['次页','',{...scope,limit:'20',cursor}],
    ['类型筛选','',{...scope,limit:'20',type:'printer'}],
    ['VLAN 筛选','',{...scope,limit:'20',vlan:'998'}],
    ['统计','/metadata',scope], ...['24h','168h','720h'].map(window => ['覆盖 ' + window,'/coverage-report',{window}]),
  ]
  for (const [name,suffix,params] of cases) {
    const row = {name, started_at:new Date().toISOString(), errors:[], observations:[]}
    report.samples.push(row)
    const target = basePath + suffix + '?' + new URLSearchParams(params)
    const queryJournal = 'journalctl -u proxy-sentinel-control-plane.service --no-pager -o cat'
    const marker = await run('ssh',[...sshArgs, queryJournal + ' -n 1 --show-cursor'], '')
    const anchor = /^-- cursor: ([a-zA-Z0-9=;_-]+)$/m.exec(marker.toString())?.[1]
    if (!anchor) throw new Error('无法取得控制面 journal 游标')
    for (let i = 0; i < 200; i++) {
      const t = performance.now()
      const res = await http('GET',target,headers)
      const endToEnd = Math.round((performance.now() - t) * 100) / 100
      if (res.status !== 200) { row.errors.push('HTTP ' + res.status + '，成功 ' + i + ' 次'); break }
      const payload = JSON.parse(res.body)
      if (suffix === '' ? !Array.isArray(payload.items) : !payload.as_of) throw new Error('返回数据契约不完整')
      row.observations.push({loopback_ms:res.loopback_ms, end_to_end_ms:endToEnd})
    }
    const route = '/discovery/devices' + suffix
    const journal = await run('ssh', [...sshArgs,queryJournal + " --after-cursor='" + anchor + "' -g 'discovery_http route=' --quiet"], '')
    const timings = [...journal.toString().matchAll(/discovery_http route=(\S+) window_hours=(\S+) status=(\d+) elapsed_ms=(\d+)/g)]
      .filter(m => m[1] === route && Number(m[2]) === parseInt(params.window) && m[3] === '200').map(m => Number(m[4]))
    if (timings.length === row.observations.length && timings.length > 0) {
      row.server_ms = percentiles(timings)
      row.server_observations_ms = timings
    }
    else row.errors.push('同窗口服务端日志为 ' + timings.length + ' 条，无法精确归属')
    for (const key of ['loopback_ms','end_to_end_ms']) row[key] = percentiles(row.observations.map(v => v[key]))
    row.finished_at = new Date().toISOString()
    row.meets_loopback = row.observations.length === 200 && row.loopback_ms.p95 <= 500 && row.loopback_ms.p99 <= 1000
    row.meets_server = row.server_ms ? row.server_ms.p95 <= 500 && row.server_ms.p99 <= 1000 : null
    row.meets_end_to_end = row.observations.length === 200 && row.end_to_end_ms.p95 <= 500 && row.end_to_end_ms.p99 <= 1000
    await save()
  }
}

try {
  const release = () => run('ssh', [...sshArgs,'readlink -f /opt/proxy-sentinel/current'], '').then(value => value.toString().trim())
  report.release = await release()
  const ready = await http('GET','/readyz')
  const anonymous = await http('GET','/api/v1/session')
  report.preflight = {ready_http:ready.status, anonymous_session_http:anonymous.status}
  const token = await authenticate()
  if (mode === 'ui' || mode === 'export') await ui(token)
  else await fieldPerformance(token)
  if (await release() !== report.release) report.errors.push('采样期间现场版本已切换')
} catch (error) {
  report.errors.push(error.message.split('\n')[0])
} finally {
  report.finished_at = new Date().toISOString()
  report.passed = report.errors.length === 0 && (['ui','export'].includes(mode)
    ? report.pages.length === (mode === 'ui' ? 9 : 1) && report.pages.every(p => !p.errors.length) && !!report.csv
    : report.samples.length === 8 && report.samples.every(s => !s.errors.length && s.meets_end_to_end))
  await save()
  await run('ssh', ['-S',socket,'-O','exit',host], '').catch(() => {})
  await rm(temp, {recursive:true,force:true})
  console.log(path.join(output,'report.json'))
  if (!report.passed) process.exitCode = 1
}
