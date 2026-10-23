import { expect, test } from '@playwright/test'
import { writeFile } from 'node:fs/promises'

for (const [width, height] of [[390, 844], [1280, 800], [1440, 900]]) {
  test(`共享发现账号范围与可信度 ${width}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height })
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`) })
    page.on('requestfailed', request => { if (request.failure()?.errorText !== 'net::ERR_ABORTED') errors.push(request.failure()?.errorText || request.url()) })
    await page.addInitScript(() => {
      const original = window.fetch.bind(window)
      window.fetch = async (input, init) => {
        const url = new URL(typeof input === 'string' ? input : input instanceof Request ? input.url : input.href, location.href)
        if (url.pathname === '/api/v1/shared-access/reviews') return Response.json({ items: [], next_cursor: '' })
        if (url.pathname !== '/api/v1/shared-access/devices') return original(input, init)
        const base = { sensor_id: 'test', role: 'router', role_source: 'assessment', identity_state: 'supported', identity_current: true, identity_expires_at: new Date(Date.now() + 3600000).toISOString(), last_observed_at: new Date().toISOString(), latest_account_at: new Date().toISOString(), ip: '192.0.2.1', identity_conflict: false, account_conflict: false, current_shared: false, auth_bindings: [] }
        const items = [
          { ...base, profile_id: 'likely', brand: 'TP-Link', model: 'AX3000', mac: '00:11:22:33:44:55', router_status: 'likely', latest_account_id: 'student-1', identity_assessment_id: 'a1' },
          { ...base, profile_id: 'candidate', brand: 'Huawei', model: 'AX3', mac: '00:11:22:33:44:66', router_status: 'candidate', latest_account_id: 'student-2' },
          { ...base, profile_id: 'unlinked', brand: 'ZTE', model: 'NoAccount', mac: '00:11:22:33:44:77', router_status: 'likely', latest_account_id: '' },
        ].filter(item => (!url.searchParams.get('router_status') || item.router_status === url.searchParams.get('router_status')) && (!url.searchParams.has('has_account') || Boolean(item.latest_account_id) === (url.searchParams.get('has_account') === 'true')))
        return Response.json({ items, page: { total: items.length, limit: 20 }, freshness_state: 'fresh' })
      }
    })

    const audit = async (name: string) => {
      const probe = await page.evaluate(() => {
        const visible = (element: Element) => element.getBoundingClientRect().width > 0 && element.getBoundingClientRect().height > 0
        const selected = document.querySelector('.page-section-tabs .ant-tabs-tab-active .ant-tabs-tab-btn')!
        let background: Element | null = selected
        let backgroundColor = 'rgb(255, 255, 255)'
        while (background) {
          const color = getComputedStyle(background).backgroundColor
          if (color !== 'rgba(0, 0, 0, 0)' && color !== 'transparent') { backgroundColor = color; break }
          background = background.parentElement
        }
        const luminance = (color: string) => {
          const channels = color.match(/[\d.]+/g)!.slice(0, 3).map(Number).map(value => value / 255 <= .04045 ? value / 255 / 12.92 : ((value / 255 + .055) / 1.055) ** 2.4)
          return channels[0] * .2126 + channels[1] * .7152 + channels[2] * .0722
        }
        const levels = [luminance(getComputedStyle(selected).color), luminance(backgroundColor)].sort((a, b) => a - b)
        return {
          overflow: document.documentElement.scrollWidth > innerWidth + 2,
          controls: [...document.querySelectorAll('.shared-access-page .ant-btn,.shared-access-page .ant-tag')].filter(visible).filter(element => getComputedStyle(element).whiteSpace !== 'nowrap' || getComputedStyle(element).flexShrink !== '0').map(element => element.textContent),
          contrast: (levels[1] + .05) / (levels[0] + .05),
          tableDisplay: [...document.querySelectorAll('.shared-access-page .ant-table-tbody > tr')].filter(visible).map(element => getComputedStyle(element).display),
          surfaces: [...document.querySelectorAll('.shared-access-page > .surface')].filter(visible).map(element => ({ radius: getComputedStyle(element).borderRadius, padding: getComputedStyle(element).padding, border: getComputedStyle(element).borderColor })),
        }
      })
      await page.screenshot({ path: testInfo.outputPath(`${name}.png`), fullPage: true, animations: 'disabled' })
      await writeFile(testInfo.outputPath(`${name}-probe.json`), JSON.stringify({ ...probe, errors }, null, 2))
      expect(probe.overflow).toBe(false)
      expect(probe.controls).toEqual([])
      expect(probe.contrast).toBeGreaterThanOrEqual(4.5)
      if (width === 390) expect(probe.tableDisplay.every(display => display !== 'table-row')).toBe(true)
      expect(errors).toEqual([])
    }

    await page.goto('/shared-access?tab=routers')
    await expect(page.getByText('TP-Link AX3000', { exact: true })).toBeVisible()
    await expect(page.getByText('身份待确认', { exact: true })).toBeVisible()
    await expect(page.getByText('身份线索', { exact: true })).toBeVisible()
    await expect(page.getByText('共享关系待核验', { exact: true })).toHaveCount(2)
    await expect(page.getByText('NoAccount', { exact: false })).toHaveCount(0)
    await audit('routers')
    await page.getByRole('combobox', { name: '路由身份状态' }).click()
    await page.getByTitle('身份已确认', { exact: true }).click()
    await expect(page.getByText(/当前筛选下暂无路由器记录/)).toBeVisible()
    await page.getByRole('tab', { name: '共享终端档案', exact: true }).click()
    await expect(page.getByText('仅显示有认证账号的档案')).toBeVisible()
    await expect(page.getByText('student-1', { exact: true })).toBeVisible()
    await expect(page.getByText('student-2', { exact: true })).toBeVisible()
    await expect(page.getByText('NoAccount', { exact: false })).toHaveCount(0)
    await audit('profiles')
    await page.goto('/shared-access?tab=reviews')
    await expect(page.getByText(/只读观察模式不生成此队列/)).toBeVisible()
    await audit('reviews')
  })
}
