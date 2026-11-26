import { expect, test } from '@playwright/test'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }, { width: 1175, height: 1169 }]) {
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
        const {pathname:path, searchParams} = new URL(requested, location.origin)
        const addressView = searchParams.get('identity_scope') === 'address_clues'
        if (path.endsWith('/discovery/devices')) {
          const sample = await response.json()
          const at = new Date().toISOString()
          const addressRows = ['3193/20', '2851/22'].map(vlan => ({
            id: `ssdp-${vlan}`, sensor_id: 'campus-204', domain: 'enp3s0f0', vlan,
            primary_ip: '192.168.1.1', last_observed_ip: '192.168.1.1', addresses: ['192.168.1.1'], current_addresses: [],
            hardware_type_status: 'candidate', classification_status: 'candidate', category: 'identity_only',
            protocols: ['ssdp'], capabilities: ['routing'], observations: [], current: true, first_seen: at, last_seen: at,
          }))
          const productRow = {
            ...addressRows[0], id:'product-switch', vlan:'4005', protocols:['snmp'], capabilities:[],
            primary_ip:'192.0.2.52', last_observed_ip:'192.0.2.52', addresses:['192.0.2.52'],
            product_clues:[{ip:'192.0.2.52',type:'switch',manufacturer:'Ruijie Networks Co., Ltd. (formerly Start Network Technology Co., Ltd.)',model:'S5310-24SFP4XS-E',
              event_id:'fixture-snmp',observed_at:at,attribution:'response_ip',rule_version:'fixture'}],
          }
          const virtualRow = {
            ...addressRows[0], id:'fixture-virtual-nic', vlan:'2706', mac:'bc:24:11:ed:70:89',
            primary_ip:'192.0.2.53', last_observed_ip:'192.0.2.53', addresses:['192.0.2.53'], current_addresses:['192.0.2.53'],
            protocols:['arp'], capabilities:[], candidate_device_type:'virtual_machine',
          }
          return Response.json({ ...sample, items: addressView ? addressRows : [productRow, virtualRow, ...sample.items] })
        }
        if (!path.endsWith('/discovery/devices/metadata')) return response
        const sample = await response.json()
        const typeCounts = (types: Record<string, number>) =>
          Object.entries(types).map(([device_type, count]) => ({ device_type, count }))
        return Response.json({
          ...sample, ...(addressView?{total:2,identified:0,candidate:2,conflict:0,expired:0,profile_typed:0,ip_product_only:1,no_type_clue:1,revoked:0}:{total:6872,identified:341,candidate:6494,conflict:0,expired:37,profile_typed:2244,ip_product_only:77,no_type_clue:4173,revoked:37}),
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
    await expect(page.getByRole('button', { name: '192.168.1.1', exact:true })).toHaveCount(0)
    const virtualRow = page.getByRole('row').filter({has:page.getByRole('button',{name:'bc:24:11:ed:70:89',exact:true})})
    await expect(virtualRow.getByText('bc:24:11:ed:70:89', {exact:true})).toHaveCount(1)
    await expect(virtualRow.getByText('虚拟化线索')).toBeVisible()
    await virtualRow.getByRole('button',{name:'查看详情'}).click()
    const detail = page.getByRole('dialog', {name:'设备详情'})
    await expect(detail).toContainText('可能来自虚拟机或虚拟网卡')
    await page.keyboard.press('Escape')
    await expect(detail).not.toBeVisible()
    const productRow = page.getByRole('row').filter({ has: page.getByText('S5310-24SFP4XS-E', { exact: true }) })
    await expect(productRow.getByText('产品线索 · 归属待核实')).toBeVisible()
    await expect(productRow.locator('td[data-label="设备类型"]')).toHaveText('交换机')
    await expect(productRow).not.toContainText('Ruijie Networks')
    const printer = page.getByRole('row').filter({has:page.getByText('HP LaserJet Pro MFP',{exact:true})})
    const vendor = printer.locator('td[data-label="厂商 / 系统"]')
    await expect(vendor.getByText('HP',{exact:true})).toBeVisible()
    await expect(vendor.locator('.brand-logo-tag')).toHaveCount(0)
    const cellProbe = await vendor.evaluate(cell => ({
      overflow: cell.scrollWidth > cell.clientWidth+2,
      vendorRows: [...cell.querySelectorAll('.terminal-vendor-value')].map(el => ({
        whiteSpace:getComputedStyle(el).whiteSpace, textOverflow:getComputedStyle(el).textOverflow,
      })),
    }))
    expect(cellProbe.overflow).toBe(false)
    expect(cellProbe.vendorRows).toEqual([
      {whiteSpace:'nowrap',textOverflow:'ellipsis'},
      {whiteSpace:'nowrap',textOverflow:'ellipsis'},
    ])
    if (viewport.width <= 560) {
      const toolbar = page.getByLabel('发现设备筛选工具栏')
      const filters = await toolbar.getByRole('button', {name:'筛选',exact:true}).boundingBox()
      const actions = await toolbar.getByRole('button', {name:'操作',exact:true}).boundingBox()
      expect(Math.abs(filters!.y-actions!.y)).toBeLessThan(3)
    }
    await page.screenshot({ path: test.info().outputPath('list-first.png'), animations: 'disabled' })
    await productRow.getByRole('button', {name:'查看详情'}).click()
    const productDialog = page.getByRole('dialog', {name:'设备详情'})
    await expect(productDialog.getByLabel('IP 产品证据')).toContainText('Ruijie Networks Co., Ltd.')
    await page.keyboard.press('Escape')
    await expect(productDialog).not.toBeVisible()
    const typePicker = page.getByRole('combobox', { name: '设备类型' })
    await typePicker.click()
    const popup = page.locator('.discovery-type-popup:visible')
    await expect(popup.getByRole('option', { name: /^打印机/ })).toBeVisible()
    await expect.poll(() => popup.evaluate(panel => {
      const box = panel.getBoundingClientRect()
      return {
        wideEnough: box.width >= 240, withinViewport: box.left >= 0 && box.right <= innerWidth + 1,
        clipped: [...panel.querySelectorAll<HTMLElement>('.discovery-type-option > span:first-child, .discovery-type-option-counts > span')].some(label => label.scrollWidth > label.clientWidth+1),
        wraps: [...panel.querySelectorAll('.discovery-type-option > span:first-child, .discovery-type-option-counts > span')].some(label => getComputedStyle(label).whiteSpace !== 'nowrap'),
      }
    })).toEqual({ wideEnough: true, withinViewport: true, clipped: false, wraps: false })
    await page.screenshot({ path: test.info().outputPath('type-picker.png'), animations: 'disabled' })
    await page.keyboard.press('Escape')
    await expect(popup).not.toBeVisible()
    await page.getByRole('button', {name:'筛选',exact:true}).click()
    const filter = page.getByRole('dialog', {name:'筛选发现记录'})
    await expect(filter.getByLabel('证据状态')).toBeVisible()
    const filterOverflow = await filter.evaluate(el => el.scrollWidth > el.clientWidth+2)
    expect(filterOverflow).toBe(false)
    await page.screenshot({path:test.info().outputPath('filter-drawer.png'),animations:'disabled'})
    await filter.getByRole('button',{name:'查看结果'}).click()
    await expect(filter).not.toBeVisible()
    await page.getByRole('button',{name:'视图',exact:true}).click()
    await page.getByRole('menuitem',{name:'地址线索',exact:true}).click()
    await expect(page).toHaveURL(/discovery_identity_scope=address_clues/)
    await expect(page.getByRole('button', {name:'192.168.1.1',exact:true})).toHaveCount(2)
    await expect(firstRow.getByText('192.168.1.1',{exact:true})).toHaveCount(1)
    await expect(firstRow.getByText('VLAN 3193/20')).toBeVisible()
    await expect(firstRow.getByText('SSDP',{exact:true})).toBeVisible()
    await expect(firstRow.locator('td[data-label="设备类型"], td[data-label="厂商 / 系统"]')).toHaveCount(0)
    await expect(productRow).toHaveCount(0)
    const addressOverflow = await firstRow.evaluate(row=>({
      document: document.documentElement.scrollWidth > innerWidth+2,
      row: row.scrollWidth > row.clientWidth+2,
    }))
    expect(addressOverflow).toEqual({document:false,row:false})
    await page.screenshot({path:test.info().outputPath('address-clues.png'),animations:'disabled'})
    await firstRow.getByRole('button', { name: '192.168.1.1' }).click()
    await expect(detail).toContainText('不同 VLAN 可以重复使用同一地址')
    await expect(detail.getByText('当前地址', { exact: true })).toHaveCount(0)
    await page.keyboard.press('Escape')
    await expect(detail).not.toBeVisible()
    await page.getByRole('button',{name:'视图',exact:true}).click()
    await page.getByRole('menuitem',{name:'全部发现',exact:true}).click()
    await overview.getByRole('button', { name: '统计与类型线索' }).click()
    await expect(overview.getByRole('button', { name: '收起统计' })).toHaveAttribute('aria-expanded', 'true')
    await expect(overview.locator('.discovery-stat-card')).toHaveCount(9)
    await expect(overview.locator('.discovery-type-row').first()).toBeVisible()
    await expect(overview.getByLabel('IP 产品类型线索')).toBeVisible()
    await expect(overview.getByRole('button', { name: /缺少类型线索 4173/ })).toBeVisible()
    await expect(overview).toContainText('已有类型判断 2,585')
    await expect(overview).not.toContainText('待核实 6494')
    const probe = await page.evaluate(() => {
      const panel = document.querySelector('.discovery-overview') as HTMLElement
      const cards = [...panel.querySelectorAll<HTMLElement>('.discovery-stat-card')]
      const rows = [...panel.querySelectorAll<HTMLElement>('.discovery-type-row')]
      const style = getComputedStyle(panel)
      const chart = panel.querySelector('.discovery-type-chart')!.getBoundingClientRect()
      const profiles = panel.querySelector('[aria-label="画像识别类型"]')!.getBoundingClientRect()
      const products = panel.querySelector('[aria-label="IP 产品类型线索"]')!.getBoundingClientRect()
      return {
        documentOverflow: document.documentElement.scrollWidth > innerWidth + 2,
        panelOverflow: panel.scrollWidth > panel.clientWidth + 2,
        padding: style.paddingLeft,
        radius: style.borderTopLeftRadius,
        borderColor: style.borderTopColor,
        cardsNoWrap: cards.every(card => getComputedStyle(card).whiteSpace === 'nowrap' && getComputedStyle(card).flexShrink === '0'),
        rowsInsidePanel: rows.every(row => row.getBoundingClientRect().right <= panel.getBoundingClientRect().right + 1),
        clueGroupsHaveCompactSpacing: [profiles.top-chart.bottom, products.top-profiles.bottom].every(gap => gap <= 16),
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
