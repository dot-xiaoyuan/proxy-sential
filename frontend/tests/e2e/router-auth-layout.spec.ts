import { expect, test } from '@playwright/test'

const viewports = [
  { width: 390, height: 844, name: 'mobile' },
  { width: 1280, height: 800, name: 'laptop' },
  { width: 1440, height: 900, name: 'desktop' },
]

test('router authentication bindings pass responsive visual and DOM probes', async ({ page }) => {
  test.setTimeout(90_000)
  for (const viewport of viewports) {
    await page.setViewportSize(viewport)
    await page.goto('/discovery?tab=routers')
    await expect(page.locator('.router-auth-identity:visible').getByText('20260001')).toBeVisible()
    const authOnly = page.getByRole('checkbox', { name: '只看有认证身份' })
    await expect(authOnly).toBeVisible()
    await authOnly.check()
    await page.getByRole('button', { name: /查\s*询/ }).click()
    await expect(page).toHaveURL(/router_has_auth_binding=true/)
    await expect(page.getByText(/1 条当前路由候选/)).toBeVisible()
    const probe = await page.evaluate(() => {
      const overflow = document.documentElement.scrollWidth > window.innerWidth + 2
      const vertical = [...document.querySelectorAll('.ant-btn, .ant-tag')].filter(element => {
        const style = getComputedStyle(element)
        return style.whiteSpace !== 'nowrap' || style.flexShrink !== '0'
      }).length
      const auth = [...document.querySelectorAll('.router-auth-identity')].find(element => element.getBoundingClientRect().width > 0)
      const authStyle = auth ? getComputedStyle(auth) : null
      return {
        overflow,
        vertical,
        authVisible: Boolean(auth && auth.getBoundingClientRect().width > 0),
        authWrap: authStyle?.overflowWrap,
        bodyBackground: getComputedStyle(document.body).backgroundColor,
      }
    })
    expect(probe).toMatchObject({ overflow: false, vertical: 0, authVisible: true, authWrap: 'anywhere' })
    expect(probe.bodyBackground).not.toBe('rgb(0, 0, 0)')
    await page.screenshot({ path: `../artifacts/ncu-auth-${viewport.name}-${viewport.width}x${viewport.height}.png`, fullPage: true })
  }
})
