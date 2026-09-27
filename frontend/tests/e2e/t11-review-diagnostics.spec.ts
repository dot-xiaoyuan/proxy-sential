import { expect, test } from '@playwright/test'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  for (const route of ['/shadow-runs', '/devices/attribution']) {
    test(`${route} ${viewport.width}x${viewport.height} layout and controls`, async ({ page }, testInfo) => {
      await page.setViewportSize(viewport)
      await page.goto(route)
      await page.waitForLoadState('networkidle')
      if (route === '/shadow-runs') {
        await expect(page.getByRole('heading', { name: '每日复核样本' })).toBeVisible()
        await expect(page.getByText('报告生成于')).toBeVisible()
      } else {
        await expect(page.getByRole('heading', { name: '终端归属诊断' })).toBeVisible()
        await expect(page.locator(viewport.width < 560 ? '.attribution-diagnostic-card' : '.attribution-diagnostic-table').getByText('缺少身份').first()).toBeVisible()
      }
      const probe = await page.evaluate(() => {
        const rootOverflow = document.documentElement.scrollWidth - window.innerWidth
        const controls = [...document.querySelectorAll('.ant-btn, .ant-tag')].filter(element => {
          const style = getComputedStyle(element)
          return style.whiteSpace !== 'nowrap' || style.flexShrink !== '0'
        }).map(element => element.textContent?.trim())
        const surfaces = [...document.querySelectorAll('.page, .surface')].filter(element => {
          const style = getComputedStyle(element)
          return style.overflowX !== 'auto' && style.overflowX !== 'scroll' && element.scrollWidth > element.clientWidth + 2
        }).map(element => element.className)
        return { rootOverflow, controls, surfaces, cards: document.querySelectorAll(routeForCards()).length }
        function routeForCards() { return location.pathname === '/shadow-runs' ? '.shadow-sample-card' : '.attribution-diagnostic-card' }
      })
      expect(probe.rootOverflow).toBeLessThanOrEqual(2)
      expect(probe.controls).toEqual([])
      expect(probe.surfaces).toEqual([])
      expect(probe.cards).toBeGreaterThan(0)
      await page.screenshot({ path: testInfo.outputPath(`${route.slice(1).replaceAll('/', '-')}-${viewport.width}.png`), fullPage: true })
      if (viewport.width === 390 && route === '/shadow-runs') {
        await page.locator('.shadow-sample-card').first().scrollIntoViewIfNeeded()
        await page.screenshot({ path: testInfo.outputPath('shadow-review-card-390.png') })
      }
    })
  }
}

test('reviewing a shadow sample immediately changes its local status', async ({ page }) => {
  await page.goto('/shadow-runs')
  await page.getByRole('button', { name: '查看与复核' }).first().click()
  await expect(page.getByText('evidence-high-59')).toBeVisible()
  await page.getByLabel('复核结论').click()
  await page.getByTitle('确认代理').click()
  await page.getByLabel('复核原因').fill('人工核对事件与会话证据')
  await page.getByRole('button', { name: '提交标注' }).click()
  await expect(page.getByText('标注已写入审计队列')).toBeVisible()
  await page.getByRole('button', { name: '关闭' }).click()
  await expect(page.getByText('已确认').first()).toBeVisible()
})
