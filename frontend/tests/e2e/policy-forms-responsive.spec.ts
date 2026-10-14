import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

/**
 * 策略与验证下的配置表单在不同视口下必须：只有一个滚动容器、主操作始终可达、
 * 不出现页面级横向溢出。560px 以下切换为整屏工作表，以上保留居中弹窗。
 */
const viewports = [
  { width: 390, height: 844 },
  { width: 743, height: 774 },
  { width: 1280, height: 800 },
  { width: 1440, height: 900 },
]

const forms = [
  { name: 'whitelist', route: '/policies/whitelist', open: '新增白名单' },
  { name: 'blacklist', route: '/policies/blacklist', open: '新增黑名单' },
  { name: 'exceptions', route: '/policies/exceptions', open: '新增例外' },
  { name: 'destination-targets', route: '/policies/destination-targets', open: '新增规则' },
  { name: 'policy-strategy', route: '/policies', open: '新建设备配额策略' },
]

for (const viewport of viewports) {
  test(`policy form shell ${viewport.width}x${viewport.height}`, async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', (error) => errors.push(error.message))
    await page.setViewportSize(viewport)
    const dir = path.resolve('../artifacts/releases/policy-form-shell-20261014', `mock-${viewport.width}`)
    await mkdir(dir, { recursive: true })
    const probes: unknown[] = []
    const isSheet = viewport.width <= 560

    for (const form of forms) {
      await page.goto(form.route)
      await page.getByRole('button', { name: form.open, exact: true }).click()
      // Only the dialog opened by this step counts; a closing dialog from the
      // previous step must never be the one measured.
      const dialog = page.locator('.app-form-modal:visible')
      await expect(dialog).toHaveCount(1)
      await expect(dialog.locator('.ant-spin-spinning')).toHaveCount(0)

      // The primary action must be reachable without scrolling the page.
      await expect(dialog.locator('.ant-modal-footer').getByRole('button').last()).toBeInViewport()

      const probe = {
        viewportHeight: await page.evaluate(() => innerHeight),
        overflow: await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 2),
        // offsetHeight is layout height: getBoundingClientRect would report the
        // mid-flight value while the dialog is still scaling in.
        contentHeight: await dialog.locator('.ant-modal-container').evaluate((el) => (el as HTMLElement).offsetHeight),
        bodyOverflow: await dialog.locator('.ant-modal-body').evaluate((el) => el.scrollWidth > el.clientWidth + 2),
        bodyScrolls: await dialog.locator('.ant-modal-body').evaluate((el) => el.scrollHeight > el.clientHeight),
        headerPosition: await dialog.locator('.ant-modal-header').evaluate((el) => getComputedStyle(el).position),
        placeholders: await dialog.evaluate((el) => /未识别|未获取|未关联|未观测/.test(el.textContent ?? '')),
      }

      expect(probe.overflow, '页面级横向溢出').toBe(false)
      expect(probe.bodyOverflow, '表单容器横向溢出').toBe(false)
      expect(probe.placeholders, '出现了禁用占位文案').toBe(false)
      if (isSheet) {
        // Full-height sheet: one scroll container, header and footer on screen.
        expect(probe.contentHeight, `小屏未使用整屏工作表：${form.name} 高 ${probe.contentHeight} / 视口 ${probe.viewportHeight}`).toBeGreaterThanOrEqual(probe.viewportHeight - 2)
      } else {
        expect(probe.contentHeight, `宽屏不应占满整屏：${form.name} 高 ${probe.contentHeight} / 视口 ${probe.viewportHeight}`).toBeLessThan(probe.viewportHeight - 20)
      }

      probes.push({ form: form.name, ...probe })
      await page.screenshot({ path: path.join(dir, `${form.name}.png`), animations: 'disabled' })
      await page.keyboard.press('Escape')
      await expect(page.locator('.app-form-modal:visible')).toHaveCount(0)
    }

    await writeFile(path.join(dir, 'dom.json'), JSON.stringify({ probes, errors }, null, 2))
    expect(errors).toEqual([])
  })
}
