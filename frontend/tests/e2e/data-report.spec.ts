import { expect, test } from '@playwright/test'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  test(`global data report shows the four datasets at ${viewport.width}`, async ({ page }, info) => {
    const failures: string[] = []
    const requests: URL[] = []
    page.on('pageerror', error => failures.push(error.message))
    page.on('console', entry => { if (entry.type() === 'error') failures.push(entry.text()) })
    page.on('response', response => { if (response.status() >= 400) failures.push(`${response.status()} ${response.url()}`) })
    page.on('request', request => requests.push(new URL(request.url())))
    await page.setViewportSize(viewport)
    await page.goto('/settings/system-report')
    await expect(page).toHaveURL(/\/reports\/data$/)
    await expect(page.getByRole('heading', { name: '全局数据报表' })).toBeVisible()

    const report = page.locator('.data-report-page')
    await expect(report.locator('.data-report-metrics dd')).toHaveCount(4)
    await expect(report.locator('.data-report-metrics')).toContainText('发现记录')
    const discovered = report.getByRole('region', { name: '发现设备' })
    await expect(discovered.getByRole('heading', { name: '识别构成' })).toBeVisible()
    await expect(discovered.getByRole('link', { name: /打印机|摄像机|摄像头/ }).first()).toBeVisible()
    await expect(report.getByRole('region', { name: '网络访问' })).toContainText('活跃 IP')
    await expect(report.getByRole('region', { name: '应用识别' })).toContainText('腾讯视频')
    await expect(report.getByRole('region', { name: '终端台账' }).getByRole('link', { name: '终端列表' }))
      .toHaveAttribute('href', '/devices?tab=terminal&view=recent&window=24h')
    await expect(report.locator('time')).toHaveCount(4)
    expect(requests.some(url => url.pathname === '/api/v1/system/status')).toBe(false)

    await page.screenshot({ path: info.outputPath(`data-report-${viewport.width}.png`), fullPage: true, animations: 'disabled' })
    const probe = await report.evaluate(element => {
      const visible = [...element.querySelectorAll<HTMLElement>('a, button, .ant-segmented-item, .data-report-panel')]
        .every(item => item.scrollWidth <= item.clientWidth + 2 && item.getBoundingClientRect().right <= innerWidth + 1)
      const luminosity = (color: string) => (color.match(/\d+/g) ?? []).slice(0, 3).map(Number).reduce((sum, value, index) => {
        const channel = value / 255
        return sum + (channel <= .04045 ? channel / 12.92 : ((channel + .055) / 1.055) ** 2.4) * [0.2126, 0.7152, 0.0722][index]
      }, 0)
      const styles = getComputedStyle(element.querySelector('.ant-segmented-item-selected')!)
      const button = getComputedStyle(element.querySelector('button')!)
      const list = getComputedStyle(element.querySelector('.data-report-panel')!)
      return {
        visible,
        overflow: document.documentElement.scrollWidth > innerWidth + 2,
        contrast: (luminosity(styles.backgroundColor) + .05) / (luminosity(styles.color) + .05),
        refreshNoWrap: button.whiteSpace,
        refreshNoShrink: button.flexShrink,
        panelPadding: list.paddingInlineStart,
        discoveryInView: element.querySelector('.data-report-discovery h2')!.getBoundingClientRect().top < innerHeight,
      }
    })
    expect(probe).toMatchObject({
      visible: true, overflow: false, refreshNoWrap: 'nowrap', refreshNoShrink: '0',
      panelPadding: viewport.width === 390 ? '14px' : '20px', discoveryInView: true,
    })
    expect(probe.contrast).toBeGreaterThanOrEqual(4.5)

    const initialEvents = await report.locator('.data-report-metrics dd').first().textContent()
    await report.getByText('近 7 天', { exact: true }).click()
    await expect(page).toHaveURL(/window=7d/)
    await expect(report.locator('.data-report-metrics dd')).toHaveCount(4)
    await expect(report.locator('.data-report-metrics dd').first()).not.toHaveText(initialEvents ?? '')
    await expect(discovered.getByRole('link', { name: '覆盖报表' })).toHaveAttribute('href', '/devices/coverage?window=168h')
    await expect(discovered.getByRole('link', { name: '待核实' })).toHaveAttribute(
      'href', '/devices?tab=discovery&discovery_window=168h&discovery_state=candidate',
    )
    expect(requests.some(url => url.pathname.endsWith('/discovery/devices/metadata') &&
      url.searchParams.get('window') === '168h' && url.searchParams.get('overview') === 'false' &&
      url.searchParams.get('identity_scope') === 'devices')).toBe(true)
    const updated = page.waitForRequest(request => request.url().includes('/application-activity?window=7d'))
    await report.getByRole('button', { name: '刷新' }).click()
    await updated
    expect(failures).toEqual([])
    await discovered.getByRole('link', { name: '覆盖报表' }).click()
    await expect(page).toHaveURL(/\/devices\/coverage\?window=168h/)
    await expect(page.getByRole('heading', { name: '发现覆盖报表' })).toBeVisible()
  })
}

test('disabled application observations and failed discovery remain distinct from a real zero', async ({ page }) => {
  await page.addInitScript(() => {
    const original = window.fetch
    window.fetch = (...args) => {
      const path = new URL(String(args[0]), window.location.href).pathname
      const headers = { 'Content-Type': 'application/json' }
      if (path.endsWith('/application-activity')) {
        return Promise.resolve(new Response(JSON.stringify({ code: 'applications_disabled' }), { status: 503, headers }))
      }
      if (path.endsWith('/discovery/devices/metadata')) {
        return Promise.resolve(new Response(JSON.stringify({ code: 'read_discovery_failed' }), { status: 504, headers }))
      }
      if (path.endsWith('/device-inventory/metadata')) {
        return Promise.resolve(new Response(JSON.stringify({ total: 0, facets: { brands: [], os_families: [] } }), { headers }))
      }
      return original(...args)
    }
  })
  await page.goto('/reports/data')
  await expect(page.getByRole('region', { name: '应用识别' })).toContainText('应用观测尚未启用')
  await expect(page.getByRole('region', { name: '发现设备' })).toContainText('发现统计读取失败')
  await expect(page.getByRole('region', { name: '终端台账' })).toContainText('当前范围没有终端记录')
  await expect(page.locator('.data-report-metric').filter({ hasText: '近期终端' }).locator('dd strong')).toHaveText('0')
  await expect(page.locator('.data-report-metric').filter({ hasText: /应用观测|发现记录/ }).locator('dd')).toHaveCount(0)
})

test('a DPI-only viewer receives the traffic and application panels', async ({ page }) => {
  const identityRequests: string[] = []
  page.on('request', request => {
    if (/\/api\/v1\/(discovery\/|device-inventory)/.test(request.url())) identityRequests.push(request.url())
  })
  await page.addInitScript(() => {
    const original = window.fetch
    window.fetch = (...args) => {
      if (String(args[0]).endsWith('/api/v1/session')) return Promise.resolve(new Response(JSON.stringify({
        user: { id: 'viewer', name: '报表查看员' }, role: 'viewer', permissions: ['dpi:read'],
      }), { headers: { 'Content-Type': 'application/json' } }))
      return original(...args)
    }
  })
  await page.goto('/reports/data')
  await expect(page.getByRole('region', { name: '网络访问' })).toContainText('活跃 IP')
  await expect(page.getByRole('region', { name: '应用识别' })).toContainText('应用排行')
  await expect(page.getByRole('region', { name: '终端台账' })).toHaveCount(0)
  await expect(page.getByRole('region', { name: '发现设备' })).toHaveCount(0)
  expect(identityRequests).toEqual([])
})
