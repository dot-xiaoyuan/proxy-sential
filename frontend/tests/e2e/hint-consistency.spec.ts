import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

const viewports = [
  { width: 390, height: 844 },
  { width: 1280, height: 800 },
  { width: 1440, height: 900 },
]

// Routes whose page-level prose banner was replaced by the shared fact strip.
const routes: { url: string; name: string }[] = [
  { url: '/policies/whitelist', name: 'whitelist' },
  { url: '/policies/blacklist', name: 'blacklist' },
  { url: '/policies', name: 'policies' },
  { url: '/policies/destination-targets', name: 'destination-targets' },
  { url: '/settings/notifications', name: 'notifications' },
  { url: '/settings/behavior-reports', name: 'behavior-reports' },
]

for (const viewport of viewports) {
  test(`hint consistency ${viewport.width}`, async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', (error) => errors.push(error.message))
    await page.setViewportSize(viewport)
    const dir = path.resolve('../artifacts/releases/hint-consistency-20261014', `mock-${viewport.width}`)
    await mkdir(dir, { recursive: true })
    const probes: unknown[] = []

    for (const route of routes) {
      await page.goto(route.url)
      await expect(page.locator('.app-fact-bar')).toBeVisible()
      await expect(page.locator('.ant-spin-spinning')).toHaveCount(0)
      const probe = await page.evaluate(() => {
        const bar = document.querySelector('.app-fact-bar')
        const items = [...document.querySelectorAll('.app-fact-bar-item')]
        return {
          overflow: document.documentElement.scrollWidth > innerWidth + 2,
          itemCount: items.length,
          itemHeight: items.map((item) => Math.round(item.getBoundingClientRect().height)),
          barWidth: bar ? Math.round(bar.getBoundingClientRect().width) : 0,
          proseBanners: [...document.querySelectorAll('.ant-alert-info .ant-alert-description')]
            .filter((node) => (node.textContent ?? '').length > 40).length,
          color: bar ? getComputedStyle(bar).color : '',
          fontSize: bar ? getComputedStyle(bar).fontSize : '',
        }
      })
      expect(probe.overflow).toBe(false)
      expect(probe.proseBanners).toBe(0)
      probes.push({ route: route.name, ...probe })
      await page.screenshot({ path: path.join(dir, `${route.name}.png`), fullPage: true, animations: 'disabled' })
    }

    await writeFile(path.join(dir, 'dom.json'), JSON.stringify({ probes, errors }, null, 2))
    expect(errors).toEqual([])
  })
}
