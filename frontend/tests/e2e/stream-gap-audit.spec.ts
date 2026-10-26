import { expect, test } from '@playwright/test'

test('audited source gap stays readable at the three required viewports', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  page.on('response', response => { if (response.url().includes('/api/v1/') && response.status() >= 500) errors.push(`${response.status()} ${response.url()}`) })
  for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
    await page.setViewportSize(viewport)
    for (const route of ['/cases', '/shared-access?tab=associations']) {
      await page.goto(route)
      const notice = page.getByLabel('新存查链历史缺口')
      await expect(notice).toBeVisible()
      await expect(notice).toContainText('553,000,000 字节')
      const probe = await notice.evaluate(element => {
        const style = getComputedStyle(element)
        return { documentOverflow: document.documentElement.scrollWidth > innerWidth + 2, noticeOverflow: element.scrollWidth > element.clientWidth + 2, padding: style.paddingLeft, border: style.borderTopColor, textWrap: getComputedStyle(element.querySelector('p')!).overflowWrap }
      })
      expect(probe.documentOverflow).toBe(false)
      expect(probe.noticeOverflow).toBe(false)
      expect(probe.padding).toBe(viewport.width === 390 ? '14px' : '20px')
      expect(probe.border).toBe('rgb(226, 232, 240)')
      expect(probe.textWrap).toBe('anywhere')
      await page.screenshot({ path: `test-results/stream-gap-${route.startsWith('/cases') ? 'cases' : 'shared'}-${viewport.width}.png`, fullPage: true })
    }
  }
  expect(errors).toEqual([])
})
