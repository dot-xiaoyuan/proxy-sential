import { expect, test } from '@playwright/test'

for (const [width, height] of [[390, 844], [1280, 800], [1440, 900]]) {
  test(`防代理报表数据与布局 ${width}×${height}`, async ({ page }, testInfo) => {
    const errors: string[] = []
    const unexpectedResponses: string[] = []
    await page.addInitScript(() => {
      const fetch = window.fetch
      const requests: string[] = []
      Reflect.set(window, 'defenseReportRequests', requests)
      window.fetch = async (...args) => {
        const url = String(args[0])
        if (url.startsWith('/api/v1/')) requests.push(`${args[1]?.method ?? 'GET'} ${url}`)
        if (url.endsWith('/api/v1/shared-access/status')) {
          const now = new Date().toISOString()
          return Response.json({
            checked_at: now,
            collection: { state: 'partial', sources: [
              { source: 'packet-sidecar', state: 'healthy', sensor_id: '184-mirror', covered_to: now },
              { source: 'handshake-sidecar', state: 'partial', sensor_id: '184-mirror', covered_to: now },
            ] },
            materialization: { pending: 0, failed: 0 },
            policy: { coverage_partial: 9 },
            attribution: { insufficient: 2 },
          })
        }
        return fetch(...args)
      }
    })
    page.on('pageerror', (error) => errors.push(error.message))
    page.on('console', (message) => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('response', (response) => {
      if (response.url().includes('/api/v1/') && response.status() >= 400) unexpectedResponses.push(response.url())
    })
    await page.setViewportSize({ width, height })
    await page.goto('/reports')
    await expect(page.getByRole('heading', { name: '防代理报表' })).toBeVisible()
    const routers = page.getByRole('region', { name: '路由器识别分布' })
    await expect(routers.locator('meter')).toHaveCount(3)
    await expect(routers.locator('.report-total strong')).toHaveText('34')
    await expect(routers.getByRole('link', { name: '查看路由器观察' })).toHaveAttribute('href', '/devices?tab=network&routers_view=router')
    const trend = page.getByRole('region', { name: '镜像共享判定趋势' })
    await expect(trend.locator('.defense-trend-chart canvas')).toBeVisible()
    await expect(trend.getByText('每 5 分钟的判定记录数', { exact: false })).toBeVisible()
    const selector = page.getByRole('combobox', { name: '共享趋势时间窗口' })
    await selector.click()
    await page.getByRole('option', { name: '近 15 分钟' }).click()
    await expect(page).toHaveURL(/window=15m/)
    await expect(page.getByRole('option', { name: '近 15 分钟' })).toBeHidden()
    await expect(trend.getByText('每 1 分钟的判定记录数', { exact: false })).toBeVisible()
    await expect(trend.getByRole('link', { name: '查看策略判定明细' })).toHaveAttribute('href', /decision_from=.+decision_to=/)
    const shared = page.getByRole('region', { name: '当前镜像共享行为' })
    await expect(shared.locator('.report-total strong')).toHaveText('8')
    await expect(shared.getByText('已确认共享')).toBeVisible()
    const coverage = page.getByRole('region', { name: '共享识别卡点' })
    await expect(coverage.getByText('握手采集')).toBeVisible()
    await expect(coverage.getByText('覆盖不足', { exact: true }).first()).toBeVisible()
    await expect(coverage.locator('meter')).toHaveCount(4)
    await expect(page.locator('.reports-page table')).toHaveCount(0)

    const requests: string[] = await page.evaluate(() => Reflect.get(window, 'defenseReportRequests'))
    expect(new Set(requests)).toEqual(new Set([
      'GET /api/v1/session',
      'GET /api/v1/router-observations/summary',
      'GET /api/v1/shared-access/status',
      'GET /api/v1/shared-access/observations/summary',
      'GET /api/v1/policy-decisions/shared-trend?window=1h',
      'GET /api/v1/policy-decisions/shared-trend?window=15m',
    ]))
    const probe = await page.locator('.reports-page').evaluate((root) => ({
      documentOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      panelsOverflow: [...root.querySelectorAll('.report-panels, .report-panel, .report-facts, .report-coverage-grid')].some((element) => element.scrollWidth > element.clientWidth + 1),
      wrappingControls: [...root.querySelectorAll('.report-refresh, .report-link, .report-status')].filter((element) => {
        const style = getComputedStyle(element)
        return style.whiteSpace !== 'nowrap' || style.flexShrink !== '0'
      }).length,
      columns: getComputedStyle(root.querySelector('.report-panels')!).gridTemplateColumns.split(' ').length,
      placeholder: /未识别|未获取|未关联|未观测|未知/.test(root.textContent ?? ''),
    }))
    expect(probe.documentOverflow).toBe(false)
    expect(probe.panelsOverflow).toBe(false)
    expect(probe.wrappingControls).toBe(0)
    expect(probe.columns).toBe(width <= 560 ? 1 : 2)
    expect(probe.placeholder).toBe(false)
    if (width > 560) {
      const contrast = await page.locator('.ant-menu-item-selected').evaluate((item) => {
        const lightness = (color: string) => color.match(/[\d.]+/g)!.slice(0, 3).reduce((sum, value, index) => {
          const c = Number(value) / 255
          return sum + [0.2126, 0.7152, 0.0722][index] * (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4)
        }, 0)
        const bg = lightness(getComputedStyle(item).backgroundColor)
        const fg = lightness(getComputedStyle(item.querySelector('a')!).color)
        return (Math.max(bg, fg) + 0.05) / (Math.min(bg, fg) + 0.05)
      })
      expect(contrast).toBeGreaterThanOrEqual(4.5)
    }
    expect(errors).toEqual([])
    expect(unexpectedResponses).toEqual([])
    await page.screenshot({ path: testInfo.outputPath('防代理报表.png'), fullPage: true, animations: 'disabled' })
    await testInfo.attach('DOM 布局检查', { body: JSON.stringify(probe), contentType: 'application/json' })
  })
}

test('共享统计读取失败与空窗口分开，并按权限加载', async ({ page }) => {
  await page.addInitScript(() => {
    const fetch = window.fetch
    const fixture = { available: false, requests: [] as string[] }
    Reflect.set(window, 'defenseFixture', fixture)
    window.fetch = async (...args) => {
      const url = String(args[0])
      if (url.startsWith('/api/v1/')) fixture.requests.push(url)
      if (url.endsWith('/api/v1/session')) {
        return Response.json({ user: { id: 'policy-reader', name: '策略查看员' }, role: 'viewer', permissions: ['policies:read'] })
      }
      if (url.includes('/api/v1/policy-decisions/shared-trend?')) {
        if (!fixture.available) return Response.json({ code: 'shared_trend_unavailable' }, { status: 503 })
        return Response.json({ from: '2026-11-22T23:00:00+08:00', to: '2026-11-23T00:00:00+08:00', bucket_minutes: 5, buckets: [] })
      }
      return fetch(...args)
    }
  })
  await page.goto('/reports')
  await expect(page.getByText('镜像共享判定趋势读取失败')).toBeVisible()
  await expect(page.getByText('窗口内暂无已记录的判定')).toHaveCount(0)
  await expect(page.getByRole('region', { name: '路由器识别分布' })).toHaveCount(0)
  await page.evaluate(() => { Reflect.get(window, 'defenseFixture').available = true })
  await page.getByRole('button', { name: '刷新报表' }).click()
  await expect(page.getByText('窗口内暂无已记录的判定')).toBeVisible()
  const requests: string[] = await page.evaluate(() => Reflect.get(window, 'defenseFixture').requests)
  expect(new Set(requests)).toEqual(new Set(['/api/v1/session', '/api/v1/policy-decisions/shared-trend?window=1h']))
})
