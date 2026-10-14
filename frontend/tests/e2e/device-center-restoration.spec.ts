import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

for(const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]){
 test(`device center routes and four datasets ${viewport.width}`,async({page})=>{
  const errors:string[]=[]
  page.on('pageerror',e=>errors.push(e.message))
  await page.addInitScript(()=>{
   const original=window.fetch.bind(window)
   ;(window as unknown as {centerRequests:string[]}).centerRequests=[]
   window.fetch=(input,init)=>{const url=typeof input==='string'?input:input instanceof Request?input.url:input.href;(window as unknown as {centerRequests:string[]}).centerRequests.push(url);return original(input,init)}
  })
  await page.setViewportSize(viewport)
  const dir=path.resolve('../artifacts/releases/device-center-ui-20261014',`mock-${viewport.width}`)
  await mkdir(dir,{recursive:true})
  await page.goto('/devices?view=history')
  await expect(page.getByRole('heading',{name:'设备中心',exact:true})).toBeVisible()
  const probes=[]
  for(const label of ['终端','网络设备','哑终端','发现线索']){
   await page.getByRole('tab',{name:label,exact:true}).click()
   await expect(page.getByRole('tab',{name:label,exact:true})).toHaveAttribute('aria-selected','true')
   if(label==='网络设备') await expect(page.locator('.router-observations-panel')).toContainText('Huawei')
   if(label==='终端') await expect(page.locator('.device-inventory-page')).toBeVisible()
   if(label==='发现线索') await expect(page.locator('.passive-discovery-panel')).toContainText('近 24 小时被动发现线索')
   await expect(page.locator('.ant-spin-spinning')).toHaveCount(0)
   if(label==='哑终端') await expect(page.getByText('HP LaserJet Pro MFP').filter({visible:true}).first()).toBeVisible()
   const probe=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth+2,controls:[...document.querySelectorAll('.device-center-page .ant-btn,.device-center-page .ant-tag')].filter(e=>e.getBoundingClientRect().width>0).map(e=>({nowrap:getComputedStyle(e).whiteSpace,shrink:getComputedStyle(e).flexShrink})),placeholders:/未识别|未获取|未关联|未观测/.test(document.querySelector('.device-center-page')?.textContent??'')}))
   expect(probe.overflow).toBe(false);expect(probe.placeholders).toBe(false)
   expect(probe.controls.every(x=>x.nowrap==='nowrap'&&x.shrink==='0')).toBe(true)
   probes.push({label,...probe});await page.screenshot({path:path.join(dir,`${label}.png`),fullPage:true,animations:'disabled'})
  }
  const requests=await page.evaluate(()=>(window as unknown as {centerRequests:string[]}).centerRequests)
  expect(requests.some(url=>url.includes('view=iot'))).toBe(true)
  expect(requests.filter(url=>url.includes('/discovery/devices')).every(url=>!url.includes('offset='))).toBe(true)
  await page.goto('/discovery?tab=devices')
  await expect(page).toHaveURL(/\/devices\?tab=records/)
  await expect(page.getByRole('tab',{name:'发现线索',exact:true})).toHaveAttribute('aria-selected','true')
  await writeFile(path.join(dir,'dom.json'),JSON.stringify({probes,errors},null,2));expect(errors).toEqual([])
 })
}
