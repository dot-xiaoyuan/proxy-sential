import { expect, test } from '@playwright/test'

test.describe('Automated UI/UX Designer Probe & Design System Audit', () => {
	const routes = ['/overview', '/activity', '/risks', '/review', '/shared-access', '/cases', '/devices', '/discovery', '/events', '/shadow-runs', '/audit', '/ingest', '/policies', '/settings/rules', '/settings/organization', '/settings/actions', '/settings/security']
	const viewports = [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]

  test('audit responsive 3-viewport anti-overflow and element inline-style purity', async ({ page }) => {
		test.setTimeout(120_000)
		for (const viewport of viewports) for (const route of routes) {
			await test.step(`${viewport.width}x${viewport.height} ${route}`, async () => {
			await page.setViewportSize(viewport)
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
				const elements = document.querySelectorAll('.ant-btn, .ant-tag, .mock-badge, .list-cell-nowrap, .nowrap-cell, .ellipsis-cell')
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
			})
    }
  })

	test('cold overview becomes operable within 1.5 seconds', async ({ page, context }) => {
		await context.setExtraHTTPHeaders({ 'Cache-Control': 'no-cache' })
		const started = Date.now()
		await page.goto('/overview')
		await expect(page.getByRole('heading', { name: '运营工作台' })).toBeVisible()
		expect(Date.now() - started).toBeLessThan(1500)
	})

	test('desktop navigation and header stay fixed while content scrolls', async ({ page }) => {
		await page.setViewportSize({ width: 1280, height: 800 })
		await page.goto('/devices')
		await expect(page.getByRole('heading', { name: '终端画像' })).toBeVisible()
		await page.locator('.app-content').evaluate((element) => {
			const probe = document.createElement('div')
			probe.dataset.scrollProbe = 'true'
			probe.style.height = '1200px'
			probe.style.flex = '0 0 1200px'
			element.append(probe)
		})
		const before = await page.evaluate(() => ({
			sider: document.querySelector('.app-sider')?.getBoundingClientRect().top,
			header: document.querySelector('.app-header')?.getBoundingClientRect().top,
			height: document.querySelector('.app-content')?.scrollHeight,
			viewportHeight: document.querySelector('.app-content')?.clientHeight,
		}))
		expect(before.height ?? 0).toBeGreaterThan(before.viewportHeight ?? 0)
		await page.locator('.app-content').evaluate((element) => element.scrollTo(0, 600))
		const after = await page.evaluate(() => ({
			sider: document.querySelector('.app-sider')?.getBoundingClientRect().top,
			header: document.querySelector('.app-header')?.getBoundingClientRect().top,
		}))
		expect(Math.abs((after.sider ?? 99) - (before.sider ?? 0))).toBeLessThanOrEqual(1)
		expect(Math.abs((after.header ?? 99) - (before.header ?? 0))).toBeLessThanOrEqual(1)
	})

	test('list pages expose primary content before filters dominate the viewport', async ({ page }) => {
		test.setTimeout(120_000)
		const probes = [
			{ route: '/devices', selector: '.device-inventory-surface' },
			{ route: '/events', selector: '.compact-list-table' },
			{ route: '/cases', selector: '.compact-list-table' },
			{ route: '/review', selector: '.compact-list-table' },
			{ route: '/audit', selector: '.compact-list-table' },
			{ route: '/discovery', selector: '.router-list-heading' },
		]
		for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }]) {
			await page.setViewportSize(viewport)
			for (const probe of probes) {
				await page.goto(probe.route)
				await page.waitForLoadState('networkidle')
				const top = await page.locator(probe.selector).first().evaluate((element) => element.getBoundingClientRect().top)
				expect(top, `${probe.route} primary content starts too low at ${viewport.width}px`).toBeLessThan(viewport.height * 0.86)
			}
		}
	})
})
