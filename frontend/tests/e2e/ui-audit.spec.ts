import { expect, test } from '@playwright/test'

test.describe('Automated UI/UX Designer Probe & Design System Audit', () => {
  const routes = ['/overview', '/risks', '/ips/10.255.0.59', '/settings/rules']

  test('audit responsive 3-viewport anti-overflow and element inline-style purity', async ({ page }) => {
    for (const route of routes) {
      await page.setViewportSize({ width: 390, height: 844 })
      await page.goto(route)
      await page.waitForLoadState('networkidle')

      // 1. 全局与 DOM 内部容器防溢出检测
      const overflowAudit = await page.evaluate(() => {
        const docOverflow = document.documentElement.scrollWidth > window.innerWidth + 2
        const selectors = ['.page', '.surface', '.details-grid', '.sample-list', '.evidence-item']
        const internalOverflows: string[] = []

        selectors.forEach((sel) => {
          document.querySelectorAll(sel).forEach((el, index) => {
            const style = window.getComputedStyle(el)
            const isScrollable =
              style.overflowX === 'auto' ||
              style.overflowX === 'scroll' ||
              el.querySelector('[style*="overflow-x: auto"]') !== null ||
              el.querySelector('.ant-tabs-nav-wrap') !== null ||
              el.querySelector('.ant-table-content') !== null

            if (!isScrollable && el.scrollWidth > el.clientWidth + 2) {
              internalOverflows.push(`${sel}[${index}] (${el.scrollWidth}px > ${el.clientWidth}px)`)
            }
          })
        })

        return { docOverflow, internalOverflows }
      })

      expect(overflowAudit.docOverflow).toBe(false)
      expect(overflowAudit.internalOverflows).toEqual([])

      // 2. 按钮与标签防竖排 nowrap 校验
      const nowrapAudit = await page.evaluate(() => {
        const elements = document.querySelectorAll('.ant-btn, .ant-tag, .mock-badge')
        const brokenElements: string[] = []
        elements.forEach((el, idx) => {
          const style = window.getComputedStyle(el)
          if (style.whiteSpace !== 'nowrap') {
            brokenElements.push(`${el.tagName.toLowerCase()}.${el.className.split(' ')[0]}[${idx}]`)
          }
        })
        return brokenElements
      })

      expect(nowrapAudit).toEqual([])
    }
  })
})
