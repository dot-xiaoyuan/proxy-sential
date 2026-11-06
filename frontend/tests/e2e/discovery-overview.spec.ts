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
    await expect(overview).toContainText('发现身份')
    await expect(overview).toContainText('明确类型')
    await expect(overview.locator('.discovery-overview-metrics > div')).toHaveCount(5)
    await expect(overview.locator('.discovery-overview-type').first()).toBeVisible()
    const probe = await page.evaluate(() => {
      const panel = document.querySelector('.discovery-overview') as HTMLElement
      const chips = [...panel.querySelectorAll<HTMLElement>('.discovery-overview-type')]
      const style = getComputedStyle(panel)
      return {
        documentOverflow: document.documentElement.scrollWidth > innerWidth + 2,
        panelOverflow: panel.scrollWidth > panel.clientWidth + 2,
        padding: style.paddingLeft,
        radius: style.borderTopLeftRadius,
        borderColor: style.borderTopColor,
        chipsWrap: chips.every(chip => getComputedStyle(chip).whiteSpace === 'nowrap' && getComputedStyle(chip).flexShrink === '0'),
      }
    })
    expect(probe).toEqual({
      documentOverflow: false,
      panelOverflow: false,
      padding: viewport.width === 390 ? '14px' : '20px',
      radius: '8px',
      borderColor: 'rgb(226, 232, 240)',
      chipsWrap: true,
    })
    await page.screenshot({ path: `/tmp/204-discovery-overview-${viewport.width}x${viewport.height}.png`, fullPage: true, animations: 'disabled' })
    if (viewport.width === 390) {
      await overview.locator('.discovery-overview-types').scrollIntoViewIfNeeded()
      await page.screenshot({ path: '/tmp/204-discovery-overview-390x844-types.png', animations: 'disabled' })
    }
    expect(errors).toEqual([])
  })
}
