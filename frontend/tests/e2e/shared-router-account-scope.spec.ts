import { expect, test } from '@playwright/test'
import { writeFile } from 'node:fs/promises'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  test(`router verification includes records without authentication ${viewport.width}`, async ({ page }, info) => {
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
        if (!url.pathname.endsWith('/shared-access/devices')) return original(input, init)
        const stamp = new Date().toISOString()
        const rows = url.searchParams.get('has_account') === 'true' ? [] : [{ profile_id: 'router-no-account', display_name: 'TP-Link TL-WDR5620', brand: 'TP-Link', model: 'TL-WDR5620', role: 'router', role_source: 'assessment', router_status: 'likely', identity_current: true, identity_state: 'supported', identity_expires_at: new Date(Date.now() + 86400000).toISOString(), mac: '58:41:20:e6:3d:0f', ip: '222.204.90.19', last_observed_at: stamp, latest_account_id: '', auth_bindings: [], current_shared: false }]
        return new Response(JSON.stringify({ items: rows, page: { total: rows.length, limit: 20 }, as_of: stamp, freshness_state: 'fresh' }), { headers: { 'Content-Type': 'application/json' } })
      }
    })
    for (const tab of ['routers', 'devices']) {
      await page.goto(`/shared-access?tab=${tab}`)
      await expect(page.getByText('TP-Link TL-WDR5620', { exact: true })).toBeVisible()
      await expect(page.getByText('已确认当前共享', { exact: true })).toHaveCount(0)
      if (tab === 'routers') {
        await expect(page.getByText('共享关系待核验', { exact: true })).toBeVisible()
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
    await page.goto('/shared-access?tab=routers&router_accounts=linked')
    await expect(page.getByText('当前筛选下暂无路由器记录；可切换身份状态或账号范围，历史信息可在共享终端档案查看。')).toBeVisible()
    expect(errors).toEqual([])
  })
}
