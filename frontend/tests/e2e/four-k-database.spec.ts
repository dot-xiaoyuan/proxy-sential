import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

for (const [width, height] of [[390, 844], [1280, 800], [1440, 900]]) test(`4K database authorization ${width}`, async ({ page }) => {
  await page.setViewportSize({ width, height })
  await page.goto('/settings/actions')
  await expect(page.getByRole('button', { name: '4K 数据库授权' }).first()).toBeVisible()
  await page.evaluate(() => {
    const original = window.fetch
    let configuration = { host: '', port: 3306, database: '', username: '', tls: false, authorization_id: undefined as number | undefined }
    let configured = false
    window.fetch = async (...args) => {
      if (String(args[0]).includes('/tasks/4k-check-test')) return new Response(JSON.stringify({ task_id: '4k-check-test', kind: 'authorization-check', created_at: new Date().toISOString(), status: 'completed', response_status: 200, result: { read_only: true, authorization_id: 7, app_id: 'sentinel-app', organization: '测试授权', expires_at: 0, management_api_verified: false, checked_at: new Date().toISOString() } }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      if (!String(args[0]).includes('/4k-database')) return original(...args)
      const method = args[1]?.method ?? 'GET'
      if (method === 'PUT') {
        const value = JSON.parse(String(args[1]?.body))
        configuration = { ...value, password: undefined }; configured = true
      }
      const result = method === 'POST' ? { task_id: '4k-check-test', kind: 'authorization-check', created_at: new Date().toISOString(), status: 'queued' } : { configuration, password_configured: configured, credential_source: '4k_database' }
      return new Response(JSON.stringify(result), { status: method === 'POST' ? 202 : 200, headers: { 'Content-Type': 'application/json' } })
    }
  })
  await page.getByRole('button', { name: '4K 数据库授权' }).first().click()
  const dialog = page.getByRole('dialog')
  await dialog.getByRole('textbox', { name: '数据库地址' }).fill('192.0.2.190')
  await dialog.getByRole('textbox', { name: /数据库名$/ }).fill('srun')
  await dialog.getByRole('textbox', { name: '数据库用户名' }).fill('readonly')
  await dialog.getByLabel(/数据库密码$/).fill('isolated-secret')
  await dialog.getByRole('button', { name: '保存并检查授权' }).click()
  await expect(dialog.getByText('只读授权检查通过')).toBeVisible()
  await expect(dialog.getByText('sentinel-app', { exact: true })).toBeVisible()
  await expect(dialog.getByLabel('数据库密码（留空保持不变）')).toHaveValue('')
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
  await page.getByRole('button', { name: '4K 数据库授权' }).first().click()
  await expect(page.getByRole('dialog').getByRole('textbox', { name: '数据库地址' })).toHaveValue('192.0.2.190')
  await expect(page.getByRole('dialog').getByLabel('数据库密码（留空保持不变）')).toHaveValue('')
  await page.getByRole('dialog').getByRole('button', {name: /^保\s*存$/}).click()
  await expect(page.getByRole('dialog')).toHaveCount(0)
})
