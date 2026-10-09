import { expect, test } from '@playwright/test'
for (const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]) {
 test(`4K directory sync stays separate from policy actions ${viewport.width}`,async({page})=>{
  await page.setViewportSize(viewport)
  await page.goto('/policies')
  await expect(page.getByRole('button',{name:'生成导入预览'})).toHaveCount(0)
  await page.goto('/settings/actions')
  await expect(page.getByRole('button',{name:'配置 4K 接入'})).toBeVisible()
  await expect(page.getByRole('button',{name:'配置与同步4K'}).first()).toBeVisible()
  await expect(page.getByRole('button',{name:'高级身份范围'})).toHaveCount(0)
  const probe=await page.locator('.actions-connectors').evaluate(element=>({
   documentOverflow:document.documentElement.scrollWidth>innerWidth+2,
   badControls:[...element.querySelectorAll('.ant-btn,.ant-tag')].filter(control=>{const style=getComputedStyle(control);return style.whiteSpace!=='nowrap'||style.flexShrink!=='0'}).map(control=>control.textContent),
  }))
  expect(probe.documentOverflow).toBe(false)
  expect(probe.badControls).toEqual([])
 })
}
