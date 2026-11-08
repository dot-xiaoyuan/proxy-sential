import { expect, test } from '@playwright/test'

test('audited source gap stays readable at the three required viewports', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  page.on('response', response => { if (response.url().includes('/api/v1/') && response.status() >= 500) errors.push(`${response.status()} ${response.url()}`) })
  for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
    await page.setViewportSize(viewport)
    for (const route of ['/cases', '/shared-access?tab=associations']) {
      await page.goto(route)
      // 审计结论从列表顶部的常驻块改为标题行入口，展开后仍能逐条核对。
      await page.getByRole('button', { name: '历史缺口' }).click()
      const notice = page.getByLabel('新存查链历史缺口')
      await expect(notice).toBeVisible()
      await expect(notice).toContainText('567,763,339 字节')
      await expect(notice).toContainText('44,764 条')
      await expect(notice).toContainText('此前审计取消 40,504 个主体')
      const probe = await notice.evaluate(element => ({
        documentOverflow: document.documentElement.scrollWidth > innerWidth + 2,
        noticeOverflow: element.scrollWidth > element.clientWidth + 2,
        textWrap: getComputedStyle(element.querySelector('p')!).overflowWrap,
      }))
      expect(probe.documentOverflow).toBe(false)
      expect(probe.noticeOverflow).toBe(false)
      expect(probe.textWrap).toBe('anywhere')
      await page.screenshot({ path: `test-results/stream-gap-${route.startsWith('/cases') ? 'cases' : 'shared'}-${viewport.width}.png`, fullPage: true })
      await page.keyboard.press('Escape')
    }
  }
  expect(errors).toEqual([])
})
