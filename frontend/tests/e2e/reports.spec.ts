import { expect, test } from '@playwright/test'

const viewports = [[390, 844], [1280, 800], [1440, 900]] as const

for (const [width, height] of viewports) {
  test(`报表数据与布局 ${width}×${height}`, async ({ page }, testInfo) => {
    const errors: string[] = []
    const failed: string[] = []
    const requests: string[] = []
    page.on('pageerror', (error) => errors.push(error.message))
    page.on('console', (message) => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('response', (response) => {
      if (response.url().includes('/api/v1/') && response.status() >= 400) failed.push(response.url())
    })
    page.on('request', (request) => {
      if (request.url().includes('/api/v1/')) requests.push(`${request.method()} ${new URL(request.url()).pathname}`)
    })
    await page.setViewportSize({ width, height })
    await page.addInitScript(() => {
      const fetch = window.fetch
      window.fetch = async (...args) => {
        if (String(args[0]).includes('/api/v1/shared-access/status')) {
          const now = new Date().toISOString()
          return Response.json({
            checked_at: now,
            collection: { state: 'partial', sources: [
              { source: 'packet-sidecar', state: 'healthy', sensor_id: '184-mirror', covered_to: now },
              { source: 'handshake-sidecar', state: 'partial', sensor_id: '184-mirror', covered_to: now },
            ] },
            materialization: { state: 'healthy', pending: 0, completed_at: now, source_progress: [
              { source: 'handshake-sidecar', state: 'healthy', pending_segments: 0, pending_bytes: 0, reported_at: now, last_shared_confirmed_at: now },
            ] },
            policy: { matched: 0, insufficient: 11, coverage_partial: 9, expired: 1 },
            attribution: { insufficient: 2 },
          })
        }
        return fetch(...args)
      }
    })
    await page.goto('/reports')
    await expect(page.getByRole('heading', { name: '系统报表' })).toBeVisible()
    const menu = page.getByRole('navigation', { name: '报表分类' })
    const outcome = page.getByRole('region', { name: '共享判定结果' })
    await expect(outcome.locator('dd').first()).toHaveText('0')
    await expect(page.getByRole('region', { name: '共享证据覆盖' }).getByText('覆盖不足', { exact: true }).first()).toBeVisible()
    await expect(page.getByRole('region', { name: '近期镜像观测' }).getByText('候选待核验')).toBeVisible()
    expect(requests.some((request) => /audit-logs|activity\/reports/.test(request))).toBe(false)
    await page.screenshot({ path: testInfo.outputPath('共享识别.png'), fullPage: true })

    for (const [tab, title, text] of [
      ['风险与处置', '近期策略判定', '仅记录，未执行'],
      ['终端与认证', '终端投影 · 近 24 小时', '终端列表索引'],
      ['流量与访问', '访问排行', '可归类事件'],
      ['资源与审计', '近期操作审计', '查看审计日志'],
    ]) {
      await menu.getByRole('link', { name: tab }).click()
      await expect(menu.getByRole('link', { name: tab })).toHaveAttribute('aria-current', 'page')
      await expect(page.getByRole('region', { name: title }).getByText(text, { exact: tab !== '风险与处置' })).toBeVisible()
      await expect(page.locator('.report-panel .app-loading-state')).toHaveCount(0)
      await expect(page.locator('.report-panel [role=alert]')).toHaveCount(0)
    }

    await menu.getByRole('link', { name: '链路与积压' }).click()
    await page.getByText('握手采集', { exact: true }).click()
    await expect(page.getByText('最近共享收据')).toBeVisible()
    await expect(page.getByText('实时接纳待处理')).toBeVisible()
    await expect(page.locator('.report-panel .app-loading-state')).toHaveCount(0)
    const probe = await page.locator('.reports-page').evaluate((root) => {
      const selected = root.querySelector('.report-nav a[aria-current]')!
      const active = getComputedStyle(selected)
      const luminance = (value: string) => value.match(/[\d.]+/g)!.slice(0, 3).reduce((total, item, index) => {
        const c = Number(item) / 255
        return total + [0.2126, 0.7152, 0.0722][index] * (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4)
      }, 0)
      return {
        documentOverflow: document.documentElement.scrollWidth > innerWidth + 1,
        panelsOverflow: [...root.querySelectorAll('.report-panels, .report-panel, .report-facts')].some((element) => element.scrollWidth > element.clientWidth + 1),
        wrappingControls: [...root.querySelectorAll('.report-nav a, .report-refresh, .report-link, .report-status')].filter((element) => {
          const style = getComputedStyle(element)
          return style.whiteSpace !== 'nowrap' || style.flexShrink !== '0'
        }).length,
        columns: getComputedStyle(root.querySelector('.report-panels')!).gridTemplateColumns.split(' ').length,
        contrast: (luminance(active.backgroundColor) + 0.05) / (luminance(active.color) + 0.05),
        placeholder: /未识别|未获取|未关联|未观测|未知/.test(root.textContent ?? ''),
      }
    })
    expect(probe.documentOverflow).toBe(false)
    expect(probe.panelsOverflow).toBe(false)
    expect(probe.wrappingControls).toBe(0)
    expect(probe.columns).toBe(width <= 560 ? 1 : 2)
    expect(probe.contrast).toBeGreaterThanOrEqual(4.5)
    expect(probe.placeholder).toBe(false)
    expect(requests.every((request) => request.startsWith('GET '))).toBe(true)
    expect(failed).toEqual([])
    expect(errors).toEqual([])
    await page.screenshot({ path: testInfo.outputPath('链路与积压.png'), fullPage: true })
    await testInfo.attach('DOM 布局检查', { body: JSON.stringify(probe), contentType: 'application/json' })
  })
}

test('报表按权限加载并区分读取失败和空记录', async ({ page }) => {
  await page.addInitScript(() => {
    const fetch = window.fetch
    const audit = { available: false, requests: [] as string[] }
    Reflect.set(window, 'reportAuditFixture', audit)
    window.fetch = async (...args) => {
      const url = String(args[0])
      if (url.includes('/api/v1/')) audit.requests.push(url)
      if (url.endsWith('/api/v1/session')) {
        return Response.json({ user: { id: 'audit-reader', name: '审计员' }, role: 'viewer', permissions: ['audit:read'] })
      }
      if (url.includes('/api/v1/audit-logs?')) {
        return audit.available ? Response.json({ logs: [] }) : Response.json({ code: 'read_audit_logs_failed' }, { status: 503 })
      }
      return fetch(...args)
    }
  })
  await page.goto('/reports?section=pipeline')
  const navigation = page.getByRole('navigation', { name: '报表分类' })
  await expect(navigation.getByRole('link')).toHaveCount(1)
  await expect(navigation.getByRole('link', { name: '资源与审计' })).toHaveAttribute('aria-current', 'page')
  await expect(page.getByText('近期操作审计读取失败')).toBeVisible()
  await expect(page.getByText('暂无记录', { exact: true })).toHaveCount(0)
  await page.evaluate(() => { Reflect.get(window, 'reportAuditFixture').available = true })
  await page.getByRole('button', { name: '刷新报表' }).click()
  await expect(page.getByText('暂无记录', { exact: true })).toBeVisible()
  const requested: string[] = await page.evaluate(() => Reflect.get(window, 'reportAuditFixture').requests)
  expect(new Set(requested.map((url) => url.split('?')[0]))).toEqual(new Set(['/api/v1/session', '/api/v1/audit-logs']))
})
