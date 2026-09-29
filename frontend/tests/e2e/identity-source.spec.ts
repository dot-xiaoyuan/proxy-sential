import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

for (const [width, height] of [[390, 844], [1280, 800], [1440, 900]]) test(`managed identity scope ${width}`, async ({ page }) => {
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
  await page.getByRole('button', { name: '身份来源与范围' }).first().click()
  const dialog = page.getByRole('dialog')
  await dialog.getByLabel('校区 / 测试范围').fill('office-test')
  await dialog.getByLabel('接入域', { exact: true }).fill('office-lan')
  await dialog.getByLabel('受控用户网段（CIDR）').fill('192.168.0.0/24')
  const probe = await dialog.evaluate(el => ({ overflow: document.documentElement.scrollWidth > innerWidth + 2, footerBottom: el.querySelector('.ant-modal-footer')!.getBoundingClientRect().bottom, controls: [...el.querySelectorAll('.ant-btn,.ant-tag')].filter(e => getComputedStyle(e).whiteSpace !== 'nowrap' || getComputedStyle(e).flexShrink !== '0').map(e => e.textContent) }))
  expect(probe.overflow).toBe(false); expect(probe.footerBottom).toBeLessThanOrEqual(height); expect(probe.controls).toEqual([])
  const dir = path.resolve('test-results/identity-source'); await mkdir(dir, { recursive: true })
  await writeFile(path.join(dir, `dom-${width}.json`), JSON.stringify(probe, null, 2))
  await page.screenshot({ path: path.join(dir, `${width}.png`), animations: 'disabled' })
  await dialog.getByRole('button', { name: /^保\s*存$/ }).click()
  await expect(dialog).toHaveCount(0)
  await page.getByRole('button', { name: '身份来源与范围' }).first().click()
  await expect(page.getByRole('dialog').getByLabel('校区 / 测试范围')).toHaveValue('office-test')
})
