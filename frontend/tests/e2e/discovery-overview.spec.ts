import { expect, test } from '@playwright/test'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  test(`discovery overview ${viewport.width}x${viewport.height}`, async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('response', response => {
      if (response.status() >= 500) errors.push(`${response.status()} ${response.url()}`)
    })
    await page.setViewportSize(viewport)
    await page.goto('/devices?tab=discovery')
    const overview = page.getByLabel('发现设备总览')
    await expect(overview).toBeVisible()
    await expect(overview.locator('.discovery-stat-card')).toHaveCount(4)
    await expect(overview.locator('.discovery-type-row').first()).toBeVisible()
    const probe = await page.evaluate(() => {
      const panel = document.querySelector('.discovery-overview') as HTMLElement
      const cards = [...panel.querySelectorAll<HTMLElement>('.discovery-stat-card')]
      const rows = [...panel.querySelectorAll<HTMLElement>('.discovery-type-row')]
      const style = getComputedStyle(panel)
      return {
        documentOverflow: document.documentElement.scrollWidth > innerWidth + 2,
        panelOverflow: panel.scrollWidth > panel.clientWidth + 2,
        padding: style.paddingLeft,
        radius: style.borderTopLeftRadius,
        borderColor: style.borderTopColor,
        cardsNoWrap: cards.every(card => getComputedStyle(card).whiteSpace === 'nowrap' && getComputedStyle(card).flexShrink === '0'),
        rowsInsidePanel: rows.every(row => row.getBoundingClientRect().right <= panel.getBoundingClientRect().right + 1),
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
    })
    await page.screenshot({ path: `/tmp/204-discovery-overview-${viewport.width}x${viewport.height}.png`, fullPage: true, animations: 'disabled' })
    if (viewport.width === 390) {
      await overview.locator('.discovery-type-chart').scrollIntoViewIfNeeded()
      await page.screenshot({ path: '/tmp/204-discovery-overview-390x844-types.png', animations: 'disabled' })
    }
    expect(errors).toEqual([])
  })
}
