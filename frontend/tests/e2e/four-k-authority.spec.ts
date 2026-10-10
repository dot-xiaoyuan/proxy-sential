import { expect, test } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

for (const [width, height] of [[390, 844], [1280, 800], [1440, 900]]) {
  test(`4K split endpoint configuration ${width}`, async ({ page }) => {
    await page.setViewportSize({ width, height })
    const errors: string[] = []
    const warnings: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => {
      if (message.type() !== 'error') return
      if (message.text().startsWith('Warning: [antd: List]')) warnings.push(message.text())
      else errors.push(message.text())
    })
    await page.goto('/settings/actions')
    await expect(page.getByText('深澜 4K 通道接入')).toBeVisible()
    await expect(page.getByText('192.168.0.224', { exact: true })).toBeVisible()
    await expect(page.getByText('192.168.0.225', { exact: true })).toBeVisible()
    await expect(page.getByText('192.168.0.226', { exact: true })).toBeVisible()
    await expect(page.getByText('192.168.0.227', { exact: true })).toHaveCount(2)
    await expect(page.getByRole('button', { name: '配置接入', exact: true })).toBeVisible()
    const pageProbe = await page.locator('main.page').evaluate(el => ({
      overflow: document.documentElement.scrollWidth > window.innerWidth + 2,
      controls: [...el.querySelectorAll('.ant-btn,.ant-tag,.ant-badge')].filter(e => {
        const style = getComputedStyle(e)
        return style.whiteSpace !== 'nowrap' || style.flexShrink !== '0'
      }).map(e => e.textContent),
      endpointWrap: getComputedStyle(el.querySelector('.four-k-endpoint-value')!).overflowWrap,
      cardBorder: getComputedStyle(el.querySelector('.four-k-authority-card')!).borderColor,
      cardRadius: getComputedStyle(el.querySelector('.four-k-authority-card')!).borderRadius,
      cardPadding: getComputedStyle(el.querySelector('.four-k-authority-card .ant-card-body')!).paddingTop,
      placeholders: /未识别|未获取|未知|未关联|未观测|(?:^|\n)\s*[—-]\s*(?:\n|$)/.test((el as HTMLElement).innerText),
    }))
    const dir = path.resolve('test-results/four-k-split-config')
    await mkdir(dir, { recursive: true })
    expect(pageProbe.overflow).toBe(false)
    expect(pageProbe.controls).toEqual([])
    expect(pageProbe.endpointWrap).toBe('anywhere')
    expect(pageProbe.cardBorder).toBe('rgb(226, 232, 240)')
    expect(pageProbe.cardRadius).toBe('8px')
    expect(pageProbe.cardPadding).toBe(width <= 560 ? '14px' : '20px')
    expect(pageProbe.placeholders).toBe(false)
    await page.screenshot({ path: path.join(dir, `top-${width}.png`), fullPage: false, animations: 'disabled' })
    await page.locator('.four-k-authority-card').scrollIntoViewIfNeeded()
    await page.screenshot({ path: path.join(dir, `page-${width}.png`), fullPage: false, animations: 'disabled' })
    await page.getByRole('button', { name: '配置接入', exact: true }).click()
    const dialog = page.getByRole('dialog')
    await expect(dialog.getByRole('textbox', { name: /授权数据库地址/ })).toHaveValue('192.168.0.224')
    await expect(dialog.getByRole('textbox', { name: /在线清单 Redis 地址/ })).toHaveValue('192.168.0.225')
    await expect(dialog.getByRole('textbox', { name: /产品\/控制目录 Redis 地址/ })).toHaveValue('192.168.0.226')
    await expect(dialog.getByRole('textbox', { name: /上下线事件 Redis 地址/ })).toHaveValue('192.168.0.227')
    await expect(dialog.getByRole('textbox', { name: /北向 API 地址/ })).toHaveValue('192.168.0.227')
    await expect(dialog.getByText('已验证并加密保存')).toBeVisible()
    await expect(dialog.getByText(/AppSecret|token|password/i)).toHaveCount(0)
    const probe = await dialog.evaluate(el => ({
      overflow: el.scrollWidth > el.clientWidth + 2,
      pageOverflow: document.documentElement.scrollWidth > window.innerWidth + 2,
      controls: [...el.querySelectorAll('.ant-btn,.ant-tag,.ant-badge')].filter(e => {
        const style = getComputedStyle(e)
        return style.whiteSpace !== 'nowrap' || style.flexShrink !== '0'
      }).map(e => e.textContent),
      border: getComputedStyle(el.querySelector('.four-k-database-result')!).borderColor,
      radius: getComputedStyle(el.querySelector('.four-k-database-result')!).borderRadius,
      formColumns: getComputedStyle(el.querySelector('.four-k-database-form')!).gridTemplateColumns,
      placeholders: /未识别|未获取|未知|未关联|未观测|(?:^|\n)\s*[—-]\s*(?:\n|$)/.test((el as HTMLElement).innerText),
    }))
    await writeFile(path.join(dir, `dom-${width}.json`), JSON.stringify({ page: pageProbe, dialog: probe, errors, warnings }, null, 2))
    await page.screenshot({ path: path.join(dir, `dialog-${width}.png`), fullPage: false, animations: 'disabled' })
    expect(probe.overflow).toBe(false)
    expect(probe.pageOverflow).toBe(false)
    expect(probe.controls).toEqual([])
    expect(probe.border).toBe('rgb(226, 232, 240)')
    expect(probe.radius).toBe('8px')
    expect(probe.formColumns.split(' ').length).toBe(width <= 560 ? 1 : 2)
    expect(probe.placeholders).toBe(false)
    expect(errors).toEqual([])
  })
}
