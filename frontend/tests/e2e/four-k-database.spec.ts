import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

for (const [width, height] of [
  [390, 844],
  [1280, 800],
  [1440, 900],
]) {
  test(`4K credential configuration ${width}`, async ({ page }) => {
    await page.setViewportSize({ width, height })
    const errors: string[] = []
    page.on('pageerror', (error) => errors.push(error.message))
    page.on('console', (message) => {
      if (message.type() === 'error' && !message.text().startsWith('Warning: [antd: List]')) {
        errors.push(message.text())
      }
    })
    page.on('response', (response) => {
      if (response.status() >= 400)
        errors.push(`HTTP ${response.status()} ${new URL(response.url()).pathname}`)
    })
    await page.goto('/settings/actions')
    await page.getByRole('button', { name: '配置接入', exact: true }).click()
    const dialog = page.getByRole('dialog')
    const account = dialog.getByLabel('授权数据库只读账号')
    const mysql = dialog.getByLabel('授权数据库密码')
    const redis = dialog.getByLabel('Redis 接入密码')
    const certificate = dialog.getByLabel('北向服务端证书 PEM')
    await expect(dialog.getByLabel('授权数据库地址')).toHaveValue('192.168.0.224')
    await expect(account).toBeEnabled()
    await expect(mysql).toHaveAttribute('type', 'password')
    await expect(redis).toHaveAttribute('type', 'password')
    await expect(certificate).toBeEnabled()
    await account.fill('fixture-reader')
    await mysql.fill('fixture-database-password')
    await redis.fill('fixture-redis-password')
    const stored = page.waitForResponse(
      (response) =>
        response.request().method() === 'PUT' &&
        /\/integrations\/srun4k\/[^/]+$/.test(response.url()),
    )
    await dialog.getByRole('button', { name: '保存并测试' }).click()
    const response = await stored
    expect(response.ok()).toBe(true)
    expect(response.request().postDataJSON().credentials).toEqual({
      database_username: 'fixture-reader',
      database_password: 'fixture-database-password',
      redis_password: 'fixture-redis-password',
    })
    expect(await response.text()).not.toMatch(/fixture-(database|redis)-password/)
    await expect(dialog.getByText('连接测试')).toBeVisible()
    await expect(mysql).toHaveValue('')
    await expect(redis).toHaveValue('')

    await account.scrollIntoViewIfNeeded()
    const probe = await dialog.evaluate((el) => ({
      width: window.innerWidth,
      pageOverflow: document.documentElement.scrollWidth > window.innerWidth + 2,
      bodyOverflow: [...el.querySelectorAll('.ant-modal-body,.four-k-database-form')].some(
        (node) => node.scrollWidth > node.clientWidth + 2,
      ),
      footerBottom: el.querySelector('.ant-modal-footer')!.getBoundingClientRect().bottom,
      columns: getComputedStyle(el.querySelector('.four-k-database-form')!).gridTemplateColumns,
      buttons: [...el.querySelectorAll('.ant-modal-footer button')].map((button) => ({
        nowrap: getComputedStyle(button).whiteSpace === 'nowrap',
        flexShrink: getComputedStyle(button).flexShrink,
      })),
    }))
    expect(probe.pageOverflow).toBe(false)
    expect(probe.bodyOverflow).toBe(false)
    expect(probe.footerBottom).toBeLessThanOrEqual(height)
    expect(probe.columns.split(' ')).toHaveLength(width < 560 ? 1 : 2)
    expect(probe.buttons.every((button) => button.nowrap && button.flexShrink === '0')).toBe(true)
    expect(errors).toEqual([])
    const dir = path.resolve('test-results/four-k-database')
    await mkdir(dir, { recursive: true })
    await page.screenshot({ path: path.join(dir, `${width}.png`), animations: 'disabled' })
    await writeFile(
      path.join(dir, `dom-${width}.json`),
      JSON.stringify({ ...probe, errors }, null, 2),
    )
  })
}
