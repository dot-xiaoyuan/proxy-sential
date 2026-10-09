import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

for (const [width, height] of [[390, 844], [1280, 800], [1440, 900]]) test(`4K automatic onboarding ${width}`, async ({ page }) => {
  await page.setViewportSize({ width, height })
  await page.goto('/settings/actions')
  await expect(page.getByRole('button', { name: '配置与同步4K' }).first()).toBeVisible()
  await page.getByRole('button', { name: '配置与同步4K' }).first().click()
  const dialog = page.getByRole('dialog')
  await dialog.getByRole('textbox', { name: '4K 地址' }).fill('192.0.2.190')
  await expect(dialog.getByRole('spinbutton', { name: '全量校准周期（小时）' })).toHaveValue('6')
  await expect(dialog.getByText('数据库用户名')).toHaveCount(0)
  await expect(dialog.getByText('校区 / 测试范围')).toHaveCount(0)
  await dialog.getByRole('button', { name: '保存并立即同步' }).click()
  await expect(dialog.getByText('通道检查')).toBeVisible()
  await expect(dialog.getByText('正常', { exact: true })).toHaveCount(3)
  await expect(dialog.getByText('最近同步摘要')).toBeVisible()
  await expect(dialog.getByText('12个账号 / 16个会话 / 18个地址')).toBeVisible()
  await expect(dialog.getByText('等待事件通道接入', { exact: true }).first()).toBeVisible()
  await dialog.locator('.four-k-database-result').scrollIntoViewIfNeeded()
  const probe = await dialog.evaluate(el => {
    const result = el.querySelector('.four-k-database-result')!
    return {
      resultBottom: result.getBoundingClientRect().bottom,
      bodyBottom: el.querySelector('.ant-modal-body')!.getBoundingClientRect().bottom,
      titleTop: el.querySelector('.ant-modal-title')!.getBoundingClientRect().top,
      footerBottom: el.querySelector('.ant-modal-footer')!.getBoundingClientRect().bottom,
      overflow: el.scrollWidth > el.clientWidth + 2,
      pageOverflow: document.documentElement.scrollWidth > window.innerWidth + 2,
      controls: [...el.querySelectorAll('.ant-btn,.ant-tag')].filter(e => { const style = getComputedStyle(e); return style.whiteSpace !== 'nowrap' || style.flexShrink !== '0' }).map(e => e.textContent),
      inlineStyles: el.querySelectorAll('.four-k-database-content [style]').length,
      radius: getComputedStyle(result).borderRadius,
      padding: getComputedStyle(result).paddingTop,
    }
  })
  expect(probe.resultBottom).toBeLessThanOrEqual(probe.bodyBottom + 2)
  expect(probe.titleTop).toBeGreaterThanOrEqual(0); expect(probe.footerBottom).toBeLessThanOrEqual(height)
  expect(probe.overflow).toBe(false); expect(probe.pageOverflow).toBe(false); expect(probe.controls).toEqual([])
  expect(probe.radius).toBe('8px'); expect(probe.padding).toBe(width === 390 ? '14px' : '20px')
  const dir = path.resolve('test-results/four-k-database'); await mkdir(dir, { recursive: true })
  await writeFile(path.join(dir, `dom-${width}.json`), JSON.stringify(probe, null, 2))
  await page.screenshot({ path: path.join(dir, `${width}.png`), fullPage: false, animations: 'disabled' })
  await dialog.getByRole('button', { name: /^关\s*闭$/ }).click()
  await page.getByRole('button', { name: '配置与同步4K' }).first().click()
  await expect(page.getByRole('dialog').getByRole('textbox', { name: '4K 地址' })).toHaveValue('192.0.2.190')
  await expect(page.getByRole('dialog').getByRole('button', {name: '保存并立即同步'})).toBeVisible()
})
