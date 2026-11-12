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
