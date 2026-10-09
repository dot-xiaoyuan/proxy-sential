import { test, expect } from '@playwright/test'
import { writeFile } from 'node:fs/promises'
for (const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]) {
 test(`device names ${viewport.width}`,async({page},info)=>{
  await page.setViewportSize(viewport)
  await page.goto('/devices')
  await expect(page.locator('.device-ledger-primary').filter({visible:true,hasText:'office-mac41.local'}).first()).toBeVisible()
  await page.screenshot({path:info.outputPath('names-list.png'),fullPage:true})
  await page.goto('/devices/mac%3A00%3A1b%3A21%3A00%3A00%3A41')
  await page.getByRole('tab',{name:'设备识别',exact:true}).click()
  await expect(page.locator('.device-name-panel')).toContainText('office-mac41.local')
  await expect(page.locator('.device-name-evidence')).toContainText('fixture-name-event')
  await page.getByRole('button',{name:'编辑备注'}).click()
  await page.getByRole('textbox',{name:'设备备注'}).fill('设备备注测试')
  await page.getByRole('button',{name:/确.*定/}).click()
  await expect(page.locator('.device-name-panel .device-name-view')).toContainText('设备备注测试')
  await page.getByRole('button',{name:'清除备注'}).click()
  await expect(page.locator('.device-name-panel .device-name-view')).toContainText('office-mac41.local')
  await page.screenshot({path:info.outputPath('names-detail.png'),fullPage:true})
  const probe=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth+2,buttons:[...document.querySelectorAll('.device-name-panel .ant-btn')].map(el=>({wrap:getComputedStyle(el).whiteSpace,shrink:getComputedStyle(el).flexShrink})),padding:getComputedStyle(document.querySelector('.device-name-panel')!).padding,radius:getComputedStyle(document.querySelector('.device-name-panel')!).borderRadius}))
  await writeFile(info.outputPath('name-dom.json'),JSON.stringify(probe,null,2))
  expect(probe.overflow).toBe(false);expect(probe.radius).toBe('8px');expect(probe.padding).toBe(viewport.width<560?'14px':'20px')
  expect(probe.buttons.every(b=>b.wrap==='nowrap'&&b.shrink==='0')).toBe(true)
 })
}
