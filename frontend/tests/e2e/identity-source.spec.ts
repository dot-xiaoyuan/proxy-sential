import { test, expect } from '@playwright/test'
for (const [width, height] of [[390, 844], [1280, 800], [1440, 900]]) test(`4K onboarding does not expose manual identity scope ${width}`, async ({ page }) => {
  await page.setViewportSize({ width, height })
  await page.addInitScript(() => {
    const original = window.fetch
    let configuration = { kind: 'online_equipment', source: '4k:office', sensor_id: 'office-sensor', campus_id: '', access_domain: '', user_cidrs: [] as string[], enabled: true, max_records: 10000 }
    let version = 0
    window.fetch = async (...args) => {
      const url = String(args[0])
      if (url.includes('/identity-source')) {
        if (args[1]?.method === 'PUT') { const value = JSON.parse(String(args[1].body)); configuration = value.configuration; version++ }
        return new Response(JSON.stringify({ configuration, config_version: version, token_configured: false, state: 'not_configured', blocker: 'inventory_completeness_unproven' }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      const response = await original(...args)
      if (url.endsWith('/actions/connectors') && (!args[1]?.method || args[1].method === 'GET')) {
        const result = await response.clone().json()
        result.items = result.items.map((item: object) => ({ ...item, connector_type: 'srun4k' }))
        return new Response(JSON.stringify(result), { status: response.status, headers: { 'Content-Type': 'application/json' } })
      }
      return response
    }
  })
  await page.goto('/settings/actions')
  await expect(page.getByRole('button', { name: '高级身份范围' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: '身份来源与范围' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: '配置与同步4K' }).first()).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 2)).toBe(false)
})
