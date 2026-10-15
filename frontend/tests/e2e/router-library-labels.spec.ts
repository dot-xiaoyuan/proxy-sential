import { test, expect } from '@playwright/test'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  test(`router list shows open-source library labels ${viewport.width}`, async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    await page.setViewportSize(viewport)
    await page.goto('/devices?tab=network')
    await expect(page.getByRole('heading', { name: '路由器', exact: true })).toBeVisible()
    // Desktop and mobile lists both render the recognition block; only the visible one counts.
    await expect(page.locator('.router-library:visible').filter({ hasText: 'Recog 命中' }).first()).toBeVisible()
    await expect(page.locator('.router-library:visible').filter({ hasText: 'WhatWeb 命中' }).first()).toBeVisible()
    const probe = await page.evaluate(() => {
      const tags = [...document.querySelectorAll('.router-library')].filter(tag => tag.getBoundingClientRect().width > 0) as HTMLElement[]
      return tags.map(tag => ({ whiteSpace: getComputedStyle(tag).whiteSpace, shrink: getComputedStyle(tag).flexShrink }))
    })
    expect(probe.every(tag => tag.whiteSpace === 'nowrap' && tag.shrink === '0')).toBe(true)
    expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 2)).toBe(false)
    expect(errors).toEqual([])
  })
}
