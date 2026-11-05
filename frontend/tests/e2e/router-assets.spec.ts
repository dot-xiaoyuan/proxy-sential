import { expect, test } from '@playwright/test'
import { writeFile } from 'node:fs/promises'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  test(`discovered router assets remain separate from role evidence ${viewport.width}`, async ({ page }, info) => {
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
        if (!url.pathname.endsWith('/discovery/devices') && !url.pathname.endsWith('/discovery/devices/metadata')) return original(input, init)
        const stamp = new Date().toISOString()
        const type = url.searchParams.get('type') || 'router'
        const response = url.pathname.endsWith('/metadata') ? { total: 61, as_of: stamp, count_unit: 'trusted_discovery_identity' } : {
          items: [
            { id: 'router-current', mac: '02:20:40:00:00:04', name: '教学楼路由设备', device_type: type, category: 'network', identity_kind: 'link_layer_device', manufacturer: 'Huawei', model_name: 'AR6120', classification_status: 'identified', first_seen: stamp, last_seen: stamp, current: true, current_addresses: ['192.0.2.41'], primary_ip: '192.0.2.41', last_observed_ip: '192.0.2.41', protocols: ['lldp', 'dhcp'], capabilities: ['routing'], observations: [], evidence_count: 2, domain: '教学网', vlan: '20' },
            { id: 'router-expired', mac: '02:20:40:00:00:05', name: '历史路由记录', device_type: '', last_device_type: type, category: 'network', identity_kind: 'link_layer_device', classification_status: 'expired', first_seen: stamp, last_seen: stamp, current: false, current_addresses: [], primary_ip: '192.0.2.42', last_observed_ip: '192.0.2.42', protocols: ['dhcp'], capabilities: [], observations: [], evidence_count: 1 },
          ], limit: 20, next_cursor: '', has_more: false,
        }
        return new Response(JSON.stringify(response), { headers: { 'Content-Type': 'application/json' } })
      }
    })
    await page.goto('/devices?tab=network&routers_view=router')
    await expect(page.getByText('共 61 条设备记录', { exact: true })).toBeVisible()
    await expect(page.getByText('教学楼路由设备', { exact: true })).toBeVisible()
    await expect(page.getByText('历史路由器', { exact: true })).toBeVisible()
    await expect(page.getByText('历史 IP：192.0.2.42', { exact: true })).toBeVisible()
    await expect(page.getByText('设备类型用于资产管理；违规与共享行为需另行核验。', { exact: true })).toBeVisible()
    await expect(page.getByRole('button', { name: '下一页', exact: true })).toBeDisabled()
    await expect(page.getByRole('button', { name: '上一页', exact: true })).toBeDisabled()
    await expect(page.getByTitle('2', { exact: true })).toHaveCount(0)
    const probe = await page.evaluate(() => {
      const panel = document.querySelector('.router-observations-panel')!
      const controls = [...panel.querySelectorAll('.ant-btn,.ant-tag')].filter(element => element.getBoundingClientRect().width > 0)
      const selected = panel.querySelector('.ant-segmented-item-selected')!
      const foreground = getComputedStyle(selected).color
      const background = getComputedStyle(selected).backgroundColor
      const luminance = (color: string) => {
        const values = (color.match(/[\d.]+/g) ?? []).slice(0, 3).map(Number).map(value => value / 255).map(value => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4)
        return values[0] * 0.2126 + values[1] * 0.7152 + values[2] * 0.0722
      }
      const fg = luminance(foreground)
      const bg = luminance(background === 'rgba(0, 0, 0, 0)' ? 'rgb(255, 255, 255)' : background)
      return {
        overflow: document.documentElement.scrollWidth > innerWidth + 2,
        panelOverflow: panel.scrollWidth > panel.clientWidth + 2,
        controls: controls.filter(element => getComputedStyle(element).whiteSpace !== 'nowrap' || getComputedStyle(element).flexShrink !== '0').map(element => element.textContent),
        compressedButtons: controls.filter(element => element.matches('.ant-btn') && element.getBoundingClientRect().width < 50).map(element => element.textContent),
        clippedButtons: controls.filter(element => element.matches('.ant-btn') && element.getBoundingClientRect().right > panel.getBoundingClientRect().right + 2).map(element => element.textContent),
        rowDisplay: getComputedStyle(panel.querySelector('tr[data-row-key]')!).display,
        selectedContrast: (Math.max(fg, bg) + 0.05) / (Math.min(fg, bg) + 0.05),
      }
    })
    await writeFile(info.outputPath('router-assets-dom.json'), JSON.stringify({ viewport, probe, errors }, null, 2))
    await page.screenshot({ path: info.outputPath('router-assets.png'), fullPage: true, animations: 'disabled' })
    await page.locator('.cursor-pagination').screenshot({ path: info.outputPath('router-assets-pagination.png'), animations: 'disabled' })
    expect(probe.overflow).toBe(false)
    expect(probe.panelOverflow).toBe(false)
    expect(probe.controls).toEqual([])
    expect(probe.compressedButtons).toEqual([])
    expect(probe.clippedButtons).toEqual([])
    expect(probe.selectedContrast).toBeGreaterThanOrEqual(4.5)
    if (viewport.width < 560) expect(probe.rowDisplay).not.toBe('table-row')
    await page.getByRole('button', { name: '查看设备', exact: true }).first().click()
    await expect(page.getByRole('dialog', { name: '设备资料' })).toBeVisible()
    await expect(page.getByRole('dialog', { name: '设备资料' })).toHaveCSS('opacity', '1')
    await expect(page.getByRole('link', { name: '在发现设备中查看' })).toHaveAttribute('href', /discovery_search=02/)
    await page.screenshot({ path: info.outputPath('router-asset-details.png'), fullPage: true, animations: 'disabled' })
    expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 2)).toBe(false)
    expect(errors).toEqual([])
  })
}
