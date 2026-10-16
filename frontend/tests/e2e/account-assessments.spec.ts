import { expect, test } from '@playwright/test'
import { writeFile } from 'node:fs/promises'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }]) {
  test(`assessment list layout ${viewport.width}`, async ({ page }, info) => {
    await page.setViewportSize(viewport)
    const errors: string[] = []
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`) })
    await page.goto('/accounts')
    await expect(page.getByRole('heading', { name: '用户研判' })).toBeVisible()
    await expect(page.locator('.account-tag-proxy:visible')).toBeVisible()
    const probe = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth + 2,
      controls: [...document.querySelectorAll('.account-assessment-page .ant-btn,.account-assessment-page .ant-tag')].map(element => ({ whiteSpace: getComputedStyle(element).whiteSpace, flexShrink: getComputedStyle(element).flexShrink })),
      desktopVisible: getComputedStyle(document.querySelector('.account-assessment-table')!).display !== 'none',
      mobileVisible: getComputedStyle(document.querySelector('.account-assessment-mobile')!).display !== 'none',
      text: document.querySelector('.account-assessment-page')?.textContent ?? '',
    }))
    expect(probe.overflow).toBe(false)
    expect(probe.controls.every(control => control.whiteSpace === 'nowrap' && control.flexShrink === '0')).toBe(true)
    expect(probe.mobileVisible).toBe(viewport.width < 560)
    expect(probe.desktopVisible).toBe(viewport.width >= 560)
    expect(probe.text).not.toMatch(/未识别|未获取|未知|\d+\s*%/)
    expect(errors).toEqual([])
    await writeFile(info.outputPath('dom.json'), JSON.stringify(probe, null, 2))
    await page.screenshot({ path: info.outputPath('list.png'), fullPage: true })
  })
}

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
test(`assessment detail evidence hierarchy at ${viewport.width}`, async ({ page }, info) => {
  await page.setViewportSize(viewport)
  const errors: string[] = []
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
  page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`) })
  await page.goto('/accounts/2026000123')
  await expect(page.getByRole('heading', { name: '2026000123' })).toBeVisible()
  await expect(page.getByText('当前有效研判存在代理行为依据')).toBeVisible()
  await expect(page.getByRole('heading', { name: '研判历史' })).toBeVisible()
  await expect(page.getByText('暂无不同于当前标签的历史结论或人工复核；重复刷新记录已归并。')).toBeVisible()
  const probe = await page.evaluate(() => ({
    overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth + 2,
    controls: [...document.querySelectorAll('.account-assessment-detail .ant-btn,.account-assessment-detail .ant-tag')].map(element => ({ whiteSpace: getComputedStyle(element).whiteSpace, flexShrink: getComputedStyle(element).flexShrink })),
    text: document.querySelector('.account-assessment-detail')?.textContent ?? '',
  }))
  expect(probe.overflow).toBe(false)
  expect(probe.controls.every(control => control.whiteSpace === 'nowrap' && control.flexShrink === '0')).toBe(true)
  expect(probe.text).not.toMatch(/未识别|未获取|未知|\d+\s*%/)
  expect(errors).toEqual([])
  await writeFile(info.outputPath('dom.json'), JSON.stringify(probe, null, 2))
  await page.screenshot({ path: info.outputPath('detail.png'), fullPage: true })
})
}
