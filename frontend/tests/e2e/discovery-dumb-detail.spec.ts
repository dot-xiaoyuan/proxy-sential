import { expect, test } from '@playwright/test'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  test(`dumb terminal overview and detail sections ${viewport.width}x${viewport.height}`, async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', entry => { if (entry.type() === 'error') errors.push(entry.text()) })
    page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`) })
    await page.setViewportSize(viewport)
    await page.goto('/devices?tab=discovery&discovery_capability=dumb')
    const overview = page.getByLabel('哑终端总览')
    await expect(overview).toBeVisible()
    await expect(overview.locator('.discovery-stat-card')).toHaveCount(7)
    const probe = await page.evaluate(() => {
      const panel = document.querySelector('.discovery-dumb-overview') as HTMLElement
      const cards = [...panel.querySelectorAll<HTMLElement>('.discovery-stat-card')]
      return {
        documentOverflow: document.documentElement.scrollWidth > innerWidth + 2,
        panelOverflow: panel.scrollWidth > panel.clientWidth + 2,
        cardsNoWrap: cards.every(card => getComputedStyle(card).whiteSpace === 'nowrap' && getComputedStyle(card).flexShrink === '0'),
        cardsInside: cards.every(card => card.getBoundingClientRect().right <= panel.getBoundingClientRect().right + 1),
      }
    })
    expect(probe).toEqual({ documentOverflow: false, panelOverflow: false, cardsNoWrap: true, cardsInside: true })
    await page.screenshot({ path: `/tmp/204-dumb-overview-${viewport.width}x${viewport.height}.png`, fullPage: true, animations: 'disabled' })

    await page.goto('/devices?tab=discovery')
    await page.getByRole('button', { name: /^(筛选|更多筛选)/ }).click()
    const vlan = page.getByRole('combobox', { name: 'VLAN' })
    await expect(vlan).toBeVisible()
    const panelProbe = await page.evaluate(() => {
      const panel = document.querySelector('.app-filter-panel') as HTMLElement
      return { overflow: panel.scrollWidth > panel.clientWidth + 2, documentOverflow: document.documentElement.scrollWidth > innerWidth + 2 }
    })
    expect(panelProbe).toEqual({ overflow: false, documentOverflow: false })
    await page.getByRole('button', { name: viewport.width === 390 ? '关闭筛选' : '收起筛选' }).click()
    await page.getByRole('button', { name: '查看详情' }).first().click()
    const modal = page.locator('.discovery-evidence-modal')
    await expect(modal.locator('.discovery-detail-section').first()).toBeVisible()
    const modalProbe = await modal.evaluate(element => ({
      overflow: element.scrollWidth > element.clientWidth + 2,
      sections: [...element.querySelectorAll('.discovery-detail-section h5')].map(heading => heading.textContent),
    }))
    expect(modalProbe.overflow).toBe(false)
    expect(modalProbe.sections.length).toBeGreaterThan(0)
    await page.screenshot({ path: `/tmp/204-detail-${viewport.width}x${viewport.height}.png`, fullPage: true, animations: 'disabled' })
    expect(errors).toEqual([])
  })
}
