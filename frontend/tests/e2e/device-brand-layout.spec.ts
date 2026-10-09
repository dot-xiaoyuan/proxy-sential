import { expect, test } from '@playwright/test'
import { writeFile } from 'node:fs/promises'

for(const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]) {
 test(`device layout and evidence ${viewport.width}`,async({page},info)=>{
  await page.setViewportSize(viewport)
  await page.goto('/devices?view=history')
  const list=viewport.width<560?'.device-mobile-cards':'.device-desktop-table'
  await expect(page.locator(`${list} .device-semantic-icon`).first()).toBeVisible()
  await expect(page.locator(`${list} .device-os-icon`).first()).toBeVisible()
  await expect(page.locator(`${list} .device-mac-vendor`)).toHaveCount(0)
  await expect(page.locator(`${list} .device-mac-link`).filter({hasText:'50:2b:73:d9:70:34'})).toHaveAttribute('title',/Dell/)
  if(viewport.width>=560){await expect(page.locator('.device-desktop-table th').first()).toHaveText('终端');await expect(page.locator('.device-desktop-table th')).toHaveText(['终端','网络身份','最近观测','操作'])}
  else {await expect(page.locator('.device-desktop-table')).toBeHidden();await expect(page.locator('.device-mobile-card').first().locator(':scope > *').first()).toHaveClass(/device-identity-cell/)}
  const probe=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth+2,controls:[...document.querySelectorAll('.device-inventory-page .ant-btn,.device-inventory-page .ant-tag')].map(e=>({wrap:getComputedStyle(e).whiteSpace,shrink:getComputedStyle(e).flexShrink})),radius:getComputedStyle(document.querySelector('.device-filter-bar')!).borderRadius,icons:[...document.querySelectorAll('.device-semantic-icon')].slice(0,6).map(e=>({width:getComputedStyle(e).width,height:getComputedStyle(e).height,glyphWidth:getComputedStyle(e.querySelector('svg')!).width,glyphHeight:getComputedStyle(e.querySelector('svg')!).height}))}))
  expect(probe.overflow).toBe(false);expect(probe.radius).toBe('8px');expect(probe.controls.every(c=>c.wrap==='nowrap'&&c.shrink==='0')).toBe(true);expect(probe.icons.every(icon=>icon.width==='24px'&&icon.height==='24px'&&icon.glyphWidth==='18px'&&icon.glyphHeight==='18px')).toBe(true)
  await writeFile(info.outputPath('dom.json'),JSON.stringify(probe,null,2))
  await page.screenshot({path:info.outputPath('list.png')})
  await page.locator('.device-filter-disclosure summary').click();await expect(page.getByPlaceholder('院系')).toBeVisible()
  await page.locator('.device-filter-disclosure summary').click()
  await page.getByRole('button',{name:'列设置'}).click();await page.getByRole('checkbox',{name:'归属 / 接入'}).check();await page.getByRole('heading',{name:'终端列表'}).click()
  await page.reload();await expect.poll(()=>page.evaluate(()=>localStorage.getItem('device-extra-columns'))).toContain('context')
 })
}
test('recent scope, URL filters and detail return',async({page})=>{
 await page.goto('/devices')
 await expect(page).toHaveURL(/view=recent/)
 await expect(page).toHaveURL(/window=24h/)
 await expect(page.locator('.device-desktop-table tbody tr')).toHaveCount(5)
 await page.getByText('全部历史',{exact:true}).click()
 await expect(page.locator('.device-desktop-table tbody tr')).toHaveCount(7)
 await expect(page.getByText('10 分钟',{exact:true})).toHaveCount(0)
 await page.getByPlaceholder('搜索设备名称、MAC、IP 或账号').fill('00:1b:21:00:00:41')
 await expect(page).toHaveURL(/q=00/)
 await page.reload();await expect(page.getByPlaceholder('搜索设备名称、MAC、IP 或账号')).toHaveValue('00:1b:21:00:00:41')
 await page.locator('.device-desktop-table .device-mac-link').click()
 await expect(page.getByRole('heading',{name:/office-mac41.local.*198.18.90.41/})).toBeVisible()
 await expect(page.locator('.device-name-panel')).toHaveCount(0)
 await page.getByRole('tab',{name:'设备识别',exact:true}).click()
 await expect(page.locator('.device-name-panel')).toBeVisible()
 await page.getByRole('link',{name:'返回终端列表'}).click()
 await expect(page).toHaveURL(/view=history/)
 await expect(page.getByPlaceholder('搜索设备名称、MAC、IP 或账号')).toHaveValue('00:1b:21:00:00:41')
})
test('exact IP match annotation and OS filter',async({page})=>{
 await page.goto('/devices?view=recent&q=198.18.90.41&os_family=macOS')
 await expect(page.locator('.device-desktop-table .device-mac-link')).toHaveCount(1)
 await expect(page.locator('.device-desktop-table .device-match-caption')).toHaveText('最近 IP 命中')
 await expect(page.locator('.device-desktop-table .device-inference-tag')).toContainText('macOS · 系统线索')
 await page.getByPlaceholder('搜索设备名称、MAC、IP 或账号').fill('198.18.90.4')
 await expect(page.locator('.device-desktop-table .device-mac-link')).toHaveCount(0)
})

test('loads only the current list query and defers recognition diagnostics',async({page})=>{
 let inventoryRequests=0,summaryRequests=0
 page.on('request',request=>{if(request.url().includes('/api/v1/device-inventory'))inventoryRequests++;if(request.url().includes('/api/v1/device-recognition/summary'))summaryRequests++})
 await page.goto('/devices?view=history')
 await expect(page.locator('.device-desktop-table tbody tr').first()).toBeVisible()
 await page.waitForTimeout(700)
 expect(inventoryRequests).toBe(1)
 expect(summaryRequests).toBe(0)
 await page.getByText('识别质量与接入诊断',{exact:true}).click()
 await expect(page.locator('.recognition-coverage-strip')).toBeVisible()
 expect(summaryRequests).toBe(1)
 await page.getByRole('button',{name:'刷新数据'}).click()
 await expect.poll(()=>inventoryRequests).toBe(2)
})
