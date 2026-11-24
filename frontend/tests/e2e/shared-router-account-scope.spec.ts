import { expect, test } from '@playwright/test'
import { writeFile } from 'node:fs/promises'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  test(`184 navigation and sharing verification filters ${viewport.width}`, async ({ page }, info) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`) })
    await page.setViewportSize(viewport)
    await page.addInitScript(() => {
      const original = window.fetch.bind(window)
      window.fetch = async (input, init) => {
        const raw = typeof input === 'string' ? input : input instanceof Request ? input.url : input.href
        const url = new URL(raw, location.origin)
        if (url.pathname.endsWith('/session')) {
          const response = await original(input, init)
          const session = await response.json()
          return Response.json({ ...session, device_discovery_menu_hidden: true })
        }
        if (url.pathname.endsWith('/shared-access/observations')) {
          const response = await original(input, init)
          const data = await response.json()
          return Response.json({ ...data, items: data.items.map((row: object) => ({
            ...row, status: 'candidate', confidence: 59, signal_groups: ['router_identity', 'ttl_path', 'tls_stack'],
            strong_anchor: '', device_lower_bound: 0,
          })) })
        }
        if (!url.pathname.endsWith('/shared-access/devices')) return original(input, init)
        const stamp = new Date().toISOString()
        const router = { profile_id: 'router-no-account', display_name: 'TP-Link TL-WDR5620', brand: 'TP-Link', model: 'TL-WDR5620', role: 'router', role_source: 'assessment', router_status: 'likely', identity_current: true, identity_state: 'supported', identity_expires_at: new Date(Date.now() + 86400000).toISOString(), mac: '58:41:20:e6:3d:0f', ip: '192.0.2.19', last_observed_at: stamp, latest_account_id: '', auth_bindings: [], current_shared: false }
        const linkedRouter = { ...router, profile_id: 'router-with-account', display_name: 'TP-Link TL-WR886N', model: 'TL-WR886N', mac: '02:00:00:00:00:20', ip: '192.0.2.20', latest_account_id: 'demo-account' }
        const scope = url.searchParams.get('has_account')
        const rows = [router, linkedRouter].filter(row => scope === null ||
          (url.searchParams.get('cursor') === '0' && scope === String(Boolean(row.latest_account_id))))
        return new Response(JSON.stringify({ items: rows, page: { total: url.searchParams.has('has_account') ? rows.length : 55, limit: Number(url.searchParams.get('limit')) }, as_of: stamp, freshness_state: 'fresh' }), { headers: { 'Content-Type': 'application/json' } })
      }
    })
    for (const tab of ['routers', 'devices', 'associations']) {
      await page.goto(`/shared-access?tab=${tab}`)
      if (tab === 'associations') {
        await expect(page.getByText('路由器身份依据', { exact: true }).first()).toBeVisible()
        await expect(page.getByText('共享行为待核验', { exact: true })).toBeVisible()
        await expect(page.getByText(/优先核对认证出口上的路由器/)).toBeVisible()
      } else {
        await expect(page.getByText('TP-Link TL-WDR5620', { exact: true })).toBeVisible()
        await expect(page.getByText('已确认当前共享', { exact: true })).toHaveCount(0)
      }
      if (tab === 'routers') {
        await expect(page.getByText('共享关系待核验', { exact: true })).toHaveCount(2)
        await expect(page.getByRole('link', { name: '查看路由器资产' })).toHaveAttribute('href', '/devices?tab=network&routers_view=router')
      }
      const probe = await page.evaluate(() => {
        const panel = document.querySelector('.shared-access-page')!
        const controls = [...panel.querySelectorAll('.ant-btn,.ant-tag,.ant-segmented-item')].filter(element => element.getBoundingClientRect().width > 0)
        const selected = panel.querySelector('.ant-segmented-item-selected')
        const luminance = (color: string) => {
          const c = (color.match(/[\d.]+/g) ?? []).slice(0, 3).map(Number).map(v => v / 255).map(v => v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4)
          return c[0] * .2126 + c[1] * .7152 + c[2] * .0722
        }
        const fg = selected ? luminance(getComputedStyle(selected).color) : 0
        const bg = selected ? luminance(getComputedStyle(selected).backgroundColor === 'rgba(0, 0, 0, 0)' ? 'rgb(255, 255, 255)' : getComputedStyle(selected).backgroundColor) : 1
        return { overflow: document.documentElement.scrollWidth > innerWidth + 2, controls: controls.filter(e => getComputedStyle(e).whiteSpace !== 'nowrap' || getComputedStyle(e).flexShrink !== '0').map(e => e.textContent), rowDisplay: getComputedStyle(panel.querySelector('tr[data-row-key]')!).display, selectedContrast: (Math.max(fg, bg) + .05) / (Math.min(fg, bg) + .05) }
      })
      await writeFile(info.outputPath(`${tab}-dom.json`), JSON.stringify({ viewport, probe, errors }, null, 2))
      await page.screenshot({ path: info.outputPath(`${tab}.png`), fullPage: true, animations: 'disabled' })
      await page.locator(".surface").filter({ has: page.locator("tr[data-row-key]") }).screenshot({ path: info.outputPath(`${tab}-records.png`), animations: "disabled" })
      expect(probe.overflow).toBe(false)
      expect(probe.controls).toEqual([])
      expect(probe.selectedContrast).toBeGreaterThanOrEqual(4.5)
      if (viewport.width < 560) expect(probe.rowDisplay).not.toBe('table-row')
    }
    await page.goto('/shared-access?tab=routers&router_sharing_page=2&router_sharing_limit=50')
    const scopes = [
      { label: '有关联账号', value: 'linked', rows: ['TP-Link TL-WR886N'] },
      { label: '无关联账号', value: 'empty', rows: ['TP-Link TL-WDR5620'] },
      { label: '全部账号范围', value: 'all', rows: ['TP-Link TL-WDR5620', 'TP-Link TL-WR886N'] },
    ]
    for (const scope of scopes) {
      await page.getByText(scope.label, { exact: true }).click()
      await expect(page).toHaveURL(url => url.searchParams.get('router_accounts') === scope.value &&
        !url.searchParams.has('router_sharing_page') && url.searchParams.get('router_sharing_limit') === '50' &&
        url.searchParams.get('tab') === 'routers')
      for (const name of ['TP-Link TL-WDR5620', 'TP-Link TL-WR886N']) {
        await expect(page.getByText(name, { exact: true })).toHaveCount(scope.rows.includes(name) ? 1 : 0)
      }
    }
    if (viewport.width < 560) await page.getByRole('button', { name: '打开导航' }).click()
    await page.getByRole('menuitem', { name: /设备中心$/ }).click()
    await expect(page.getByRole('link', { name: '终端列表', exact: true })).toBeVisible()
    await expect(page.getByRole('link', { name: '路由器', exact: true })).toBeVisible()
    await expect(page.getByRole('link', { name: '发现设备', exact: true })).toHaveCount(0)
    await page.screenshot({ path: info.outputPath('navigation.png'), fullPage: true, animations: 'disabled' })
    expect(errors).toEqual([])
  })
}
