import { expect, test } from '@playwright/test'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  test(`global data report shows the three datasets at ${viewport.width}`, async ({ page }, info) => {
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
    await expect(report.locator('.data-report-metrics dd strong')).toHaveCount(3)
    await expect(report.locator('.data-report-metrics')).toContainText('发现记录')
    const discovered = report.getByRole('region', { name: '发现设备' })
    await expect(discovered.getByRole('heading', { name: '识别构成' })).toBeVisible()
    await expect(discovered.getByRole('link', { name: /打印机|摄像机|摄像头/ }).first()).toBeVisible()
    await expect(report.getByRole('region', { name: '网络访问' })).toContainText('活跃 IP')
    await expect(report.getByRole('region', { name: '应用识别' })).toHaveCount(0)
    await expect(report.locator('.data-report-metrics')).not.toContainText('应用观测')
    await expect(report.getByRole('region', { name: '终端台账' }).getByRole('link', { name: '终端列表' }))
      .toHaveAttribute('href', '/devices?tab=terminal&view=recent&window=24h')
    await expect(report.locator('time')).toHaveCount(3)
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

    const initialEvents = await report.locator('.data-report-metrics dd strong').first().textContent()
    await report.getByText('近 7 天', { exact: true }).click()
    await expect(page).toHaveURL(/window=7d/)
    await expect(report.locator('.data-report-metrics dd strong')).toHaveCount(3)
    await expect(report.locator('.data-report-metrics dd strong').first()).not.toHaveText(initialEvents ?? '')
    await expect(discovered.getByRole('link', { name: '覆盖报表' })).toHaveAttribute('href', '/devices/coverage?window=168h')
    await expect(discovered.getByRole('link', { name: '候选记录' })).toHaveAttribute(
      'href', '/devices?tab=discovery&discovery_window=168h&discovery_state=candidate',
    )
    expect(requests.some(url => url.pathname.endsWith('/discovery/devices/metadata') &&
      url.searchParams.get('window') === '168h' && url.searchParams.get('overview') === 'false' &&
      url.searchParams.get('identity_scope') === 'devices')).toBe(true)
    expect(requests.some(url => url.pathname.endsWith('/activity/overview') &&
      url.searchParams.get('window') === '7d' && url.searchParams.get('view') === 'summary')).toBe(true)
    const updated = page.waitForRequest(request => request.url().includes('/activity/overview?window=7d'))
    await report.getByRole('button', { name: '刷新' }).click()
    await updated
    expect(requests.some(url => /\/api\/v1\/application-(activity|library)/.test(url.pathname))).toBe(false)
    expect(failures).toEqual([])
    await discovered.getByRole('link', { name: '覆盖报表' }).click()
    await expect(page).toHaveURL(/\/devices\/coverage\?window=168h/)
    await expect(page.getByRole('heading', { name: '发现覆盖报表' })).toBeVisible()
  })

  test(`old links open the remaining pages at ${viewport.width}`, async ({ page }, info) => {
    const failures: string[] = []
    const removedRequests: string[] = []
    page.on('pageerror', error => failures.push(error.message))
    page.on('console', entry => { if (entry.type() === 'error') failures.push(entry.text()) })
    page.on('response', response => { if (response.status() >= 400) failures.push(`${response.status()} ${response.url()}`) })
    page.on('request', request => {
      if (/\/api\/v1\/application-(activity|library)/.test(new URL(request.url()).pathname)) {
        removedRequests.push(request.url())
      }
    })
    await page.setViewportSize(viewport)
    const pages = [
      { path: '/activity?section=applications', visible: '应用协议', removed: '应用访问', shot: 'access' },
      { path: '/settings/rules?tab=application-domains', visible: '设备特征库', removed: '应用域名特征库', shot: 'rules' },
      { path: '/ips/10.255.0.59?tab=applications', visible: '终端识别', removed: '应用访问', shot: 'ip' },
    ]
    for (const { path, visible, removed, shot } of pages) {
      await page.goto(path)
      await expect(page.getByRole('tab', { name: visible })).toBeVisible()
      await expect(page.getByRole('tab', { name: removed })).toHaveCount(0)
      await page.screenshot({
        path: info.outputPath(`without-application-${shot}-${viewport.width}.png`),
        fullPage: true,
        animations: 'disabled',
      })
      const probe = await page.getByRole('tab', { name: visible }).evaluate(tab => ({
        viewport: innerWidth,
        document: document.documentElement.scrollWidth,
        tabFits: tab.scrollWidth <= tab.clientWidth + 2,
      }))
      expect(probe.document).toBeLessThanOrEqual(probe.viewport + 2)
      expect(probe.tabFits).toBe(true)
    }
    expect(removedRequests).toEqual([])
    expect(failures).toEqual([])
  })
}

test('both reports show an animated loading state and recover after a timeout', async ({ page }, info) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/audit')
  await page.getByRole('button', { name: '退出' }).waitFor()
  await page.evaluate(() => {
    const original = window.fetch
    const blocked = new Set(['/api/v1/activity/overview', '/api/v1/discovery/devices/coverage-report'])
    window.fetch = (...args) => {
      const path = new URL(String(args[0]), window.location.href).pathname
      if (blocked.has(path)) {
        return new Promise(resolve => window.addEventListener('fail-report-request', () => {
          blocked.delete(path)
          resolve(new Response('{}', { status: 504, headers: { 'Content-Type': 'application/json' } }))
        }, { once: true }))
      }
      return original(...args)
    }
  })
  const checks = [
    { route: '/reports/data', label: '正在读取网络访问统计…', error: '网络访问统计读取超时', ready: '活跃 IP', shot: 'global' },
    { route: '/devices/coverage', label: '正在读取覆盖总览…', error: '覆盖总览读取超时', ready: '发现与识别', shot: 'coverage' },
  ]
  for (const { route, label, error, ready, shot } of checks) {
    await page.evaluate(target => {
      history.pushState({}, '', target)
      window.dispatchEvent(new PopStateEvent('popstate'))
    }, route)
    const content = route === '/reports/data'
      ? page.getByRole('region', { name: '网络访问' })
      : page.getByRole('tabpanel')
    const feedback = content.locator('.app-loading-state')
    await expect(feedback).toContainText(label)
    await expect(feedback.locator('.ant-skeleton-active')).toBeVisible()
    await expect(page.getByRole('button', { name: '刷新' })).toHaveClass(/ant-btn-loading/)
    await feedback.scrollIntoViewIfNeeded()
    await page.screenshot({ path: info.outputPath(`loading-${shot}-390.png`), animations: 'disabled' })
    await page.evaluate(() => window.dispatchEvent(new Event('fail-report-request')))
    await expect(content).toContainText(error)
    await expect(feedback).toHaveCount(0)
    await page.getByRole('button', { name: '刷新' }).click()
    await expect(content).not.toContainText(error)
    await expect(content).toContainText(ready)
    await expect(feedback).toHaveCount(0)
  }
})

test('failed discovery remains distinct from a real zero', async ({ page }) => {
  await page.addInitScript(() => {
    const original = window.fetch
    window.fetch = (...args) => {
      const path = new URL(String(args[0]), window.location.href).pathname
      const headers = { 'Content-Type': 'application/json' }
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
  await expect(page.getByRole('region', { name: '发现设备' })).toContainText('发现统计读取失败')
  await expect(page.getByRole('region', { name: '终端台账' })).toContainText('当前范围没有终端记录')
  await expect(page.locator('.data-report-metric').filter({ hasText: '近期终端' }).locator('dd strong')).toHaveText('0')
  await expect(page.locator('.data-report-metric').filter({ hasText: '发现记录' }).locator('dd')).toHaveCount(0)
})

test('a DPI-only viewer receives the traffic panel', async ({ page }) => {
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
  await expect(page.getByRole('region', { name: '终端台账' })).toHaveCount(0)
  await expect(page.getByRole('region', { name: '发现设备' })).toHaveCount(0)
  expect(identityRequests).toEqual([])
})

test('global report counts profile types and keeps IP-only product evidence separate', async ({page}, info) => {
  await page.goto('/reports/data')
  const discovered = page.getByRole('region', {name:'发现设备'})
  await expect(discovered.getByRole('heading', {name:'识别构成'})).toBeVisible()
  await page.evaluate(async () => {
    const module = '/src/mocks/hardwareReplay.ts'
    const {installHardwareReplay} = await import(module)
    installHardwareReplay()
  })
  await page.getByRole('button',{name:'刷新'}).click()
  await expect(discovered).toContainText('已有类型判断 4 个')
  await expect(discovered).toContainText('80%')
  await expect(discovered.getByRole('link',{name:'画像识别',exact:true})).toHaveAttribute('href',/discovery_state=profile_typed$/)
  await expect(discovered.getByRole('link',{name:'仅 IP 自报，设备归属待核实'})).toHaveAttribute('href',/discovery_state=ip_product_only$/)
  await expect(discovered.getByRole('link',{name:'暂无类型线索'})).toHaveAttribute('href',/discovery_state=no_type_clue$/)
  await expect(discovered.getByRole('link',{name:'手机',exact:true})).toHaveAttribute('href',/discovery_state=profile_typed&discovery_type=mobile$/)
  await expect(discovered.getByRole('heading',{name:'IP 自报的产品类型'})).toBeVisible()
  for (const [width,height] of [[390,844],[1280,800],[1440,900]]) {
    await page.setViewportSize({width,height})
    expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(width+2)
    await discovered.screenshot({path:info.outputPath(`profile-report-${width}.png`),animations:'disabled'})
  }
})
