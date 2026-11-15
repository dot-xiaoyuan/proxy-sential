import { expect, test } from '@playwright/test'

test('review filter stays readable at the required viewports', async ({ page }) => {
  const consoleErrors: string[] = []
  const networkErrors: string[] = []
  page.on('console', entry => { if (entry.type() === 'error') consoleErrors.push(entry.text()) })
  page.on('response', response => { if (response.status() >= 400) networkErrors.push(`${response.status()} ${response.url()}`) })

  for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
    await page.setViewportSize(viewport)
    await page.goto('/discovery?discovery_review_reason=conflict')
    await expect(page.getByLabel('待核实原因')).toBeVisible()
    await expect(page.locator('.passive-ledger-table')).toBeVisible()
    await page.screenshot({ path: `test-results/discovery-review-${viewport.width}x${viewport.height}.png`, fullPage: true })
    const probe = await page.evaluate(() => ({
      documentOverflow: document.documentElement.scrollWidth > innerWidth + 2,
      badButtons: [...document.querySelectorAll('.ant-btn')].filter(button => {
        const style = getComputedStyle(button)
        return style.whiteSpace !== 'nowrap' || style.flexShrink !== '0'
      }).length,
      tableRows: document.querySelectorAll('.passive-ledger-table .ant-table-row').length,
      selectedContrast: (() => {
        const selected = document.querySelector('.ant-menu-item-selected')
        if (!selected) return 0
        const rgb = (value: string) => (value.match(/[\d.]+/g) ?? []).slice(0, 3).map(Number)
        const luminance = (channels: number[]) => channels.map(channel => {
          const normalized = channel / 255
          return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4
        }).reduce((sum, channel, index) => sum + channel * [0.2126, 0.7152, 0.0722][index], 0)
        const foreground = luminance(rgb(getComputedStyle(selected).color))
        const background = luminance(rgb(getComputedStyle(selected).backgroundColor))
        return (Math.max(foreground, background) + 0.05) / (Math.min(foreground, background) + 0.05)
      })(),
    }))
    expect(probe.documentOverflow).toBe(false)
    expect(probe.badButtons).toBe(0)
    expect(probe.tableRows).toBeGreaterThan(0)
    expect(probe.selectedContrast).toBeGreaterThanOrEqual(4.5)
    await page.locator('.passive-ledger-table').scrollIntoViewIfNeeded()
    await page.screenshot({ path: `test-results/discovery-review-list-${viewport.width}x${viewport.height}.png`, animations: 'disabled' })
  }
  expect(consoleErrors).toEqual([])
  expect(networkErrors).toEqual([])
})

test('confirmed type overview has one entry per type at the required viewports', async ({page}) => {
  const consoleErrors:string[]=[],networkErrors:string[]=[]
  page.on('console',entry=>{if(entry.type()==='error')consoleErrors.push(entry.text())})
  page.on('response',response=>{if(response.status()>=400)networkErrors.push(`${response.status()} ${response.url()}`)})
  for(const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]){
    await page.setViewportSize(viewport)
    await page.goto('/discovery')
    await page.locator('.discovery-overview-details > summary').click()
    const overview=page.getByLabel('发现设备总览')
    await expect(overview).toContainText('已识别类型（合计')
    const probe=await overview.evaluate(element=>({
      labels:[...element.querySelectorAll('.discovery-overview-type')].map(button=>(button.textContent??'').replace(/\s+\d+$/, '').trim()),
      overflow:element.scrollWidth>element.clientWidth+2,
      badButtons:[...element.querySelectorAll('.ant-btn')].filter(button=>{const style=getComputedStyle(button);return style.whiteSpace!=='nowrap'||style.flexShrink!=='0'}).length,
    }))
    expect(probe.labels.length).toBeGreaterThan(0)
    expect(new Set(probe.labels).size).toBe(probe.labels.length)
    expect(probe.overflow).toBe(false)
    expect(probe.badButtons).toBe(0)
    await page.screenshot({path:`test-results/discovery-types-${viewport.width}x${viewport.height}.png`,fullPage:true})
    await overview.locator('.discovery-overview-type').first().click()
    await expect(page).toHaveURL(/discovery_state=identified/)
  }
  expect(consoleErrors).toEqual([])
  expect(networkErrors).toEqual([])
})

test('device type shortcuts remain visible and usable after filtering to printers', async ({page}, testInfo) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  page.on('console', entry => { if (entry.type() === 'error') errors.push(entry.text()) })
  page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`) })
  for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
    await page.setViewportSize(viewport)
    await page.goto('/discovery?discovery_type=printer&discovery_state=identified')
    const shortcuts = page.getByRole('navigation', { name: '快捷设备类型' })
    await expect(shortcuts.getByRole('button', { name: '打印机', pressed: true })).toBeVisible()
    for (const name of ['手机', '路由器', '无线 AP', '交换机']) {
      await expect(shortcuts.getByRole('button', { name, exact: true })).toBeVisible()
    }
    const probe = await shortcuts.evaluate(element => {
      const bounds = element.getBoundingClientRect()
      const selected = element.querySelector('button[aria-pressed="true"]')
      const luminance = (color: string) => (color.match(/[\d.]+/g) ?? []).slice(0, 3).map(value => {
        const channel = Number(value) / 255
        return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4
      }).reduce((sum, channel, index) => sum + channel * [0.2126, 0.7152, 0.0722][index], 0)
      const foreground = selected ? luminance(getComputedStyle(selected).color) : 0
      const background = selected ? luminance(getComputedStyle(selected).backgroundColor) : 0
      return {
        documentOverflow: document.documentElement.scrollWidth > innerWidth + 2,
        regionOverflow: element.scrollWidth > element.clientWidth + 2,
        selectedContrast: (Math.max(foreground, background) + 0.05) / (Math.min(foreground, background) + 0.05),
        clippedButtons: [...element.querySelectorAll('button')].filter(button => {
          const style = getComputedStyle(button)
          const rect = button.getBoundingClientRect()
          return rect.left < bounds.left - 1 || rect.right > bounds.right + 1 || style.whiteSpace !== 'nowrap' || style.flexShrink !== '0'
        }).length,
      }
    })
    expect(probe).toMatchObject({ documentOverflow: false, regionOverflow: false, clippedButtons: 0 })
    expect(probe.selectedContrast).toBeGreaterThanOrEqual(4.5)
    await shortcuts.screenshot({ path: testInfo.outputPath(`type-shortcuts-${viewport.width}x${viewport.height}.png`), animations: 'disabled' })
    await shortcuts.getByRole('button', { name: '手机', exact: true }).click()
    await expect(page).toHaveURL(/discovery_type=mobile/)
    await expect(page).not.toHaveURL(/discovery_state=identified/)
    await expect(shortcuts.getByRole('button', { name: '手机', pressed: true })).toBeVisible()
  }
  expect(errors).toEqual([])
})
