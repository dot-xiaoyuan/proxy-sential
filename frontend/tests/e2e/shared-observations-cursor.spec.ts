import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

for (const [width, height] of [
  [390, 844],
  [1280, 800],
  [1440, 900],
]) {
  test(`shared observations cursor and layout ${width}`, async ({ page }) => {
    await page.setViewportSize({ width, height })
    const errors: string[] = []
    page.on('pageerror', (error) => errors.push(error.message))
    page.on('console', (message) => {
      if (message.type() === 'error') errors.push(message.text())
    })
    page.on('response', (response) => {
      if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`)
    })
    await page.addInitScript(() => {
      const originalFetch = window.fetch
      const requestedCursors: string[] = []
      ;(window as typeof window & { __testCursors?: string[] }).__testCursors = requestedCursors
      window.fetch = async (...args) => {
        const url = String(args[0])
        if (!url.includes('/shared-access/observations?')) return originalFetch(...args)
        const query = new URL(url, location.origin).searchParams
        const cursor = query.get('cursor') ?? ''
        requestedCursors.push(cursor)
        if (query.get('view') !== 'traffic')
          throw new Error('mirror traffic view was not requested')
        const item = {
          observation_id: cursor ? 'second' : 'first',
          sensor_id: 'sensor-test',
          campus_id: 'campus-test',
          access_domain: 'mirror',
          ip: cursor ? '192.0.2.2' : '192.0.2.1',
          status: 'candidate',
          confidence: 59,
          account_id: cursor ? undefined : 'mirror-account-' + 'a'.repeat(55),
          signal_groups: ['router_identity', 'tls_stack'],
          review_reason: cursor
            ? 'DHCP 型号记录缺少匹配字段，无法确认路由器角色'
            : '型号仅来自 DHCP 主机名，缺少独立路由器角色证据',
          reasons: [],
          conflicts: [],
          coverage_state: 'partial',
          rule_version: 'shared-behavior/v13',
          current: true,
          first_seen: '2026-11-12T03:50:00Z',
          last_seen: '2026-11-12T04:00:00Z',
          window_start: '2026-11-12T03:50:00Z',
          window_end: '2026-11-12T04:00:00Z',
          expires_at: '2026-12-12T04:10:00Z',
          router: {},
          score_components: [],
          feature_samples: {},
          event_ids: [],
          known_device_count: 0,
          known_devices: [],
        }
        return new Response(
          JSON.stringify({
            items: [item],
            page: { limit: 20, has_more: !cursor, next_cursor: cursor ? null : 'cursor-2' },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        )
      }
    })
    await page.goto('/shared-access')
    await expect(page.getByText('192.0.2.1')).toBeVisible()
    await expect(page.getByText('mirror-account-' + 'a'.repeat(55))).toBeVisible()
    await expect(page.getByText('多种 TLS 指纹', { exact: true })).toBeVisible()
    await expect(page.getByText('共享行为待核验', { exact: true })).toBeVisible()
    await expect(page.getByText('本页 1 条', { exact: true })).toBeVisible()
    await expect(
      page.getByText('型号仅来自 DHCP 主机名，缺少独立路由器角色证据', { exact: true }),
    ).toBeVisible()
    const probe = await page.evaluate(() => {
      const account = document.querySelector('.shared-behavior-account')!
      const tab = document.querySelector('[role="tab"][aria-selected="true"]')!
      let background = 'rgb(255, 255, 255)'
      for (let element: Element | null = tab; element; element = element.parentElement) {
        const color = getComputedStyle(element).backgroundColor
        if (color !== 'rgba(0, 0, 0, 0)' && color !== 'transparent') {
          background = color
          break
        }
      }
      const luminance = (color: string) =>
        (color.match(/[\d.]+/g) ?? [])
          .slice(0, 3)
          .map(Number)
          .map((value) => value / 255)
          .map((value) => (value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4))
          .reduce((value, channel, index) => value + channel * [0.2126, 0.7152, 0.0722][index], 0)
      const colors = [luminance(getComputedStyle(tab).color), luminance(background)].sort(
        (a, b) => b - a,
      )
      return {
        overflow: document.documentElement.scrollWidth > innerWidth + 2,
        accountOverflow: account.scrollWidth > account.clientWidth + 1,
        contrast: (colors[0] + 0.05) / (colors[1] + 0.05),
        controls: [...document.querySelectorAll('.ant-btn,.ant-tag')]
          .filter((element) => {
            const style = getComputedStyle(element)
            return style.whiteSpace !== 'nowrap' || style.flexShrink !== '0'
          })
          .map((element) => element.textContent),
      }
    })
    expect(probe.overflow).toBe(false)
    expect(probe.accountOverflow).toBe(false)
    expect(probe.contrast).toBeGreaterThanOrEqual(4.5)
    expect(probe.controls).toEqual([])
    expect(errors).toEqual([])
    const dir = path.resolve('test-results/shared-observations')
    await mkdir(dir, { recursive: true })
    await writeFile(path.join(dir, `dom-${width}.json`), JSON.stringify(probe, null, 2))
    await page.screenshot({
      path: path.join(dir, `page-${width}.png`),
      fullPage: true,
      animations: 'disabled',
    })
    await page.getByRole('button', { name: '下一页' }).click()
    await expect(page.getByText('192.0.2.2')).toBeVisible()
    await expect(
      page.getByText('DHCP 型号记录缺少匹配字段，无法确认路由器角色', { exact: true }),
    ).toBeVisible()
    expect(
      await page.evaluate(
        () => (window as typeof window & { __testCursors?: string[] }).__testCursors,
      ),
    ).toContain('cursor-2')
  })
}
