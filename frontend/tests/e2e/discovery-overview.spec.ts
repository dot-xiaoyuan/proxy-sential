import { expect, test } from '@playwright/test'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }, { width: 1481, height: 1169 }]) {
  test(`discovery overview ${viewport.width}x${viewport.height}`, async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', entry => { if (entry.type() === 'error') errors.push(entry.text()) })
    page.on('response', response => {
      if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`)
    })
    await page.setViewportSize(viewport)
    await page.addInitScript(() => {
      const fetchMock = window.fetch.bind(window)
      window.fetch = async (input, init) => {
        const response = await fetchMock(input, init)
        const requested = input instanceof Request ? input.url : input
        if (!response.ok) return response
        const path = new URL(requested, location.origin).pathname
        if (path.endsWith('/discovery/devices')) {
          const sample = await response.json()
          const at = new Date().toISOString()
          const addressRows = ['3193/20', '2851/22'].map(vlan => ({
            id: `ssdp-${vlan}`, sensor_id: 'campus-204', domain: 'enp3s0f0', vlan,
            primary_ip: '192.168.1.1', last_observed_ip: '192.168.1.1', addresses: ['192.168.1.1'], current_addresses: [],
            hardware_type_status: 'candidate', classification_status: 'candidate', category: 'identity_only',
            protocols: ['ssdp'], capabilities: ['routing'], observations: [], current: true, first_seen: at, last_seen: at,
          }))
          return Response.json({ ...sample, items: [...addressRows, ...sample.items] })
        }
        if (!path.endsWith('/discovery/devices/metadata')) return response
        const sample = await response.json()
        const typeCounts = (types: Record<string, number>) =>
          Object.entries(types).map(([device_type, count]) => ({ device_type, count }))
        return Response.json({
          ...sample, total: 6872, identified: 341, candidate: 6494, conflict: 0, expired: 37,
          classification_version: 'passive-hardware/v2',
          types: typeCounts({access_point:238, camera:33, printer:31, router:11, laptop:10, access_control:5, media_player:5, recorder:4, desktop:2, voip_phone:2}),
          candidate_types: typeCounts({mobile:1290, desktop:579, tablet:192, router:108, access_point:29, virtual:27, printer:10, switch:4, server:2, firewall:1, iot_device:1, smart_tv:1}),
          ip_product_types: typeCounts({switch:67, voip_phone:9, wireless_distribution_host:1}),
        })
      }
    })
    await page.goto('/devices?tab=discovery')
    const overview = page.getByLabel('发现设备总览')
    await expect(overview).toBeVisible()
    await expect(overview.locator('.discovery-type-row').first()).not.toBeVisible()
    const firstRow = page.locator('.passive-ledger-table tr.ant-table-row').first()
    await expect(firstRow).toBeVisible()
    const collapsed = await overview.evaluate(panel => ({ height: panel.getBoundingClientRect().height, top: panel.getBoundingClientRect().top }))
    expect(collapsed.height).toBeLessThan(viewport.width === 390 ? 130 : 85)
    const rowTop = await firstRow.evaluate(row => row.getBoundingClientRect().top)
    expect(rowTop).toBeGreaterThan(collapsed.top)
    expect(rowTop).toBeLessThan(viewport.width === 390 ? viewport.height : 550)
    await expect(firstRow.getByRole('button', { name: '地址线索' })).toBeVisible()
    await expect(firstRow.getByText('192.168.1.1', { exact: true })).toHaveCount(1)
    await expect(firstRow.getByText('VLAN 3193/20')).toBeVisible()
    await page.screenshot({ path: test.info().outputPath('list-first.png'), animations: 'disabled' })
    await firstRow.getByRole('button', { name: '地址线索' }).click()
    const detail = page.getByRole('dialog', { name: '设备详情' })
    await expect(detail).toContainText('不同 VLAN 可以重复使用同一地址')
    await expect(detail.getByText('当前地址', { exact: true })).toHaveCount(0)
    await page.keyboard.press('Escape')
    await expect(detail).not.toBeVisible()
    await overview.getByRole('button', { name: '统计与类型线索' }).click()
    await expect(overview.getByRole('button', { name: '收起统计' })).toHaveAttribute('aria-expanded', 'true')
    await expect(overview.locator('.discovery-stat-card')).toHaveCount(7)
    await expect(overview.locator('.discovery-type-row').first()).toBeVisible()
    await expect(overview.getByLabel('IP 产品类型线索')).toBeVisible()
    const probe = await page.evaluate(() => {
      const panel = document.querySelector('.discovery-overview') as HTMLElement
      const cards = [...panel.querySelectorAll<HTMLElement>('.discovery-stat-card')]
      const rows = [...panel.querySelectorAll<HTMLElement>('.discovery-type-row')]
      const style = getComputedStyle(panel)
      const chart = panel.querySelector('.discovery-type-chart')!.getBoundingClientRect()
      const profiles = panel.querySelector('[aria-label="画像类型线索"]')!.getBoundingClientRect()
      const products = panel.querySelector('[aria-label="IP 产品类型线索"]')!.getBoundingClientRect()
      const selected = document.querySelector('.terminal-type-shortcuts [aria-pressed="true"]')!
      const luminance = (color: string) => (color.match(/[\d.]+/g) ?? []).slice(0,3).map(value=>Number(value)/255)
        .map(value=>value<=0.04045?value/12.92:((value+0.055)/1.055)**2.4)
        .reduce((sum,value,i)=>sum+value*[0.2126,0.7152,0.0722][i],0)
      const foreground = luminance(getComputedStyle(selected).color)
      const background = luminance(getComputedStyle(selected).backgroundColor)
      return {
        documentOverflow: document.documentElement.scrollWidth > innerWidth + 2,
        panelOverflow: panel.scrollWidth > panel.clientWidth + 2,
        padding: style.paddingLeft,
        radius: style.borderTopLeftRadius,
        borderColor: style.borderTopColor,
        cardsNoWrap: cards.every(card => getComputedStyle(card).whiteSpace === 'nowrap' && getComputedStyle(card).flexShrink === '0'),
        rowsInsidePanel: rows.every(row => row.getBoundingClientRect().right <= panel.getBoundingClientRect().right + 1),
        clueGroupsHaveCompactSpacing: [profiles.top-chart.bottom, products.top-profiles.bottom].every(gap => gap <= 16),
        selectedContrastPasses: (Math.max(foreground,background)+0.05)/(Math.min(foreground,background)+0.05)>=4.5,
      }
    })
    expect(probe).toEqual({
      documentOverflow: false,
      panelOverflow: false,
      padding: viewport.width === 390 ? '14px' : '20px',
      radius: '8px',
      borderColor: 'rgb(226, 232, 240)',
      cardsNoWrap: true,
      rowsInsidePanel: true,
      clueGroupsHaveCompactSpacing: true,
      selectedContrastPasses: true,
    })
    await test.info().attach('dom-audit', {body:JSON.stringify({viewport, collapsed, rowTop, probe, errors}, null, 2), contentType:'application/json'})
    await page.screenshot({ path: test.info().outputPath('statistics-expanded.png'), animations: 'disabled' })
    if (viewport.width === 390) {
      await overview.locator('.discovery-type-chart').scrollIntoViewIfNeeded()
      await page.screenshot({ path: test.info().outputPath('types-mobile.png'), animations: 'disabled' })
    }
    expect(errors).toEqual([])
  })
}
