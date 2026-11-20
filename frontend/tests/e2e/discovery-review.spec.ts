import { expect, test } from '@playwright/test'

test('review filter stays readable at the required viewports', async ({ page }) => {
  const consoleErrors: string[] = []
  const networkErrors: string[] = []
  page.on('console', entry => { if (entry.type() === 'error') consoleErrors.push(entry.text()) })
  page.on('response', response => { if (response.status() >= 400) networkErrors.push(`${response.status()} ${response.url()}`) })

  for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
    await page.setViewportSize(viewport)
    await page.goto('/discovery?discovery_review_reason=conflict')
    await expect(page.getByLabel('已应用筛选')).toContainText('类型证据冲突')
    await page.getByRole('button',{name:/^筛选/}).click()
    await expect(page.getByLabel('待核实原因')).toBeVisible()
    await page.getByRole('button',{name:'关闭筛选'}).click()
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
    await overview.getByRole('button',{name:'统计与类型线索'}).click()
    await expect(overview).toContainText('已识别类型（合计')
    const probe=await overview.evaluate(element=>({
      labels:[...element.querySelectorAll('.discovery-type-row')].map(button=>(button.textContent??'').replace(/\s+\d+$/, '').trim()),
      overflow:element.scrollWidth>element.clientWidth+2,
      badButtons:[...element.querySelectorAll('.ant-btn')].filter(button=>{const style=getComputedStyle(button);return style.whiteSpace!=='nowrap'||style.flexShrink!=='0'}).length,
    }))
    expect(probe.labels.length).toBeGreaterThan(0)
    expect(new Set(probe.labels).size).toBe(probe.labels.length)
    expect(probe.overflow).toBe(false)
    expect(probe.badButtons).toBe(0)
    await page.screenshot({path:`test-results/discovery-types-${viewport.width}x${viewport.height}.png`,fullPage:true})
    await overview.locator('.discovery-type-row').first().click()
    await expect(page).toHaveURL(/discovery_state=identified/)
  }
  expect(consoleErrors).toEqual([])
  expect(networkErrors).toEqual([])
})

test('devices can be filtered by multiple types while preserving evidence state', async ({page}) => {
  for (const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]) {
    await page.setViewportSize(viewport)
    await page.goto('/discovery?discovery_type=printer&discovery_state=identified')
    const chips = page.getByLabel('已应用筛选')
    await expect(chips).toContainText('打印机')
    await page.getByRole('combobox',{name:'设备类型'}).click()
    const popup = page.locator('.discovery-type-popup:visible')
    const printer = popup.getByRole('option',{name:/^打印机/})
    await expect(printer).toHaveAttribute('aria-selected','true')
    const contrast = await printer.evaluate(selected => {
      const luminance = (color: string) => (color.match(/[\d.]+/g) ?? []).slice(0, 3).map(value => Number(value) / 255)
        .map(value => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4)
        .reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index], 0)
      const foreground = luminance(getComputedStyle(selected).color)
      const background = luminance(getComputedStyle(selected).backgroundColor)
      return (Math.max(foreground, background) + 0.05) / (Math.min(foreground, background) + 0.05)
    })
    expect(contrast).toBeGreaterThanOrEqual(4.5)
    await popup.getByRole('option',{name:/^手机/}).click()
    await expect(page).toHaveURL(/discovery_type=printer%2Cmobile/)
    await expect(page).toHaveURL(/discovery_state=identified/)
    await expect(chips).toContainText('打印机、手机')
    await page.keyboard.press('Escape')
    await chips.getByRole('button',{name:'移除类型筛选'}).click()
    await expect(page).not.toHaveURL(/discovery_type=/)
  }
})
