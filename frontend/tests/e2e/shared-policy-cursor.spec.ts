import { expect, test } from '@playwright/test'

test('策略执行游标分页在三个视口可读且无溢出', async ({ page }) => {
  const errors: string[] = []
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
  page.on('requestfailed', request => errors.push(`${request.method()} ${request.url()}: ${request.failure()?.errorText}`))
  for (const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]) {
    await page.setViewportSize(viewport)
    await page.goto('/actions?tab=decisions')
    await expect(page.getByText('共享行为与策略命中')).toBeVisible()
    const pagination = page.locator('.shared-policy-cursor-pagination')
    await expect(pagination).toBeVisible()
    await page.screenshot({path:`/tmp/ps184-shared-policy-${viewport.width}x${viewport.height}.png`,fullPage:true})
    const probe = await pagination.evaluate(element => ({
      documentOverflow: document.documentElement.scrollWidth > innerWidth + 2,
      paginationOverflow: element.scrollWidth > element.clientWidth + 2,
      buttons: [...element.querySelectorAll('button')].map(button => ({whiteSpace:getComputedStyle(button).whiteSpace,shrink:getComputedStyle(button).flexShrink})),
    }))
    expect(probe.documentOverflow).toBe(false)
    expect(probe.paginationOverflow).toBe(false)
    expect(probe.buttons.every(button => button.whiteSpace === 'nowrap' && button.shrink === '0')).toBe(true)
  }
  expect(errors).toEqual([])
})
