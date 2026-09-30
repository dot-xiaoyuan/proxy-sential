import { expect, test } from '@playwright/test'
import path from 'node:path'

const artifactDir = '/Users/yuantong/.gemini/antigravity-ide/brain/e6a8c8d0-1e8f-4b59-996f-0c4e9e39d20a'

test.describe('Responsive Visual Snapshots & Strict DOM Internal Anti-Overflow Checks', () => {
  test('capture 1440x900 overview page', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/overview')
    await expect(page.getByRole('heading', { name: '高校网络风险运营工作台' })).toBeVisible()
    await page.screenshot({ path: path.join(artifactDir, 'overview-1440x900.png'), fullPage: true })
  })

  test('capture 1280x800 cases page', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 })
    await page.goto('/cases')
    await expect(page.getByRole('heading', { name: '风险案件' })).toBeVisible()
    await page.screenshot({ path: path.join(artifactDir, 'cases-1280x800.png'), fullPage: true })
  })

  test('capture 390x844 ip detail page with strict DOM internal container overflow checks', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto('/ips/10.255.0.59')
    await expect(page.getByRole('heading', { name: '10.255.0.59' })).toBeVisible()
    await page.getByRole('tab', { name: '证据与技术信息' }).click()
    await expect(page.getByRole('heading', { name: '证据时间线' })).toBeVisible()

    // 1. 全局 Document 根层级防溢出
    const docOverflow = await page.evaluate(() => ({
      scrollWidth: document.documentElement.scrollWidth,
      innerWidth: window.innerWidth,
    }))
    expect(docOverflow.scrollWidth).toBeLessThanOrEqual(docOverflow.innerWidth + 2)

    // 2. DOM 内部主要容器溢出检测 (.page, .surface, .details-grid, .sample-list, .evidence-item)
    const overflowingContainers = await page.evaluate(() => {
      const selectors = ['.page', '.surface', '.details-grid', '.sample-list', '.evidence-item', '.ant-table-content']
      const failures: Array<{ selector: string; scrollWidth: number; clientWidth: number }> = []

      for (const sel of selectors) {
        const elements = document.querySelectorAll(sel)
        elements.forEach((el, index) => {
          const style = window.getComputedStyle(el)
          const isScrollable = style.overflowX === 'auto' || style.overflowX === 'scroll'
          if (!isScrollable && el.scrollWidth > el.clientWidth + 2) {
            failures.push({
              selector: `${sel}[${index}]`,
              scrollWidth: el.scrollWidth,
              clientWidth: el.clientWidth,
            })
          }
        })
      }
      return failures
    })

    expect(overflowingContainers).toEqual([])

    await page.screenshot({ path: path.join(artifactDir, 'ip-detail-390x844.png'), fullPage: true })
  })

  test('capture 390x844 rules page with strict DOM internal container overflow checks', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto('/settings/rules')
    await expect(page.getByRole('heading', { name: '规则与特征库' })).toBeVisible()

    // 1. 全局 Document 根层级防溢出
    const docOverflow = await page.evaluate(() => ({
      scrollWidth: document.documentElement.scrollWidth,
      innerWidth: window.innerWidth,
    }))
    expect(docOverflow.scrollWidth).toBeLessThanOrEqual(docOverflow.innerWidth + 2)

    // 2. DOM 内部主要容器溢出检测
    const overflowingContainers = await page.evaluate(() => {
      const selectors = ['.page', '.surface', '.details-grid', '.sample-list', '.evidence-item', '.ant-table-content']
      const failures: Array<{ selector: string; scrollWidth: number; clientWidth: number }> = []

      for (const sel of selectors) {
        const elements = document.querySelectorAll(sel)
        elements.forEach((el, index) => {
          const style = window.getComputedStyle(el)
          const isScrollable = style.overflowX === 'auto' || style.overflowX === 'scroll'
          if (!isScrollable && el.scrollWidth > el.clientWidth + 2) {
            failures.push({
              selector: `${sel}[${index}]`,
              scrollWidth: el.scrollWidth,
              clientWidth: el.clientWidth,
            })
          }
        })
      }
      return failures
    })

    expect(overflowingContainers).toEqual([])

    await page.screenshot({ path: path.join(artifactDir, 'rules-390x844.png'), fullPage: true })
  })
})
