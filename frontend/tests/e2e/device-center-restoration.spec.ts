import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

for(const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]){
 test(`device center submenu pages ${viewport.width}`,async({page})=>{
  const errors:string[]=[]
  page.on('pageerror',e=>errors.push(e.message))
  await page.addInitScript(()=>{
   const original=window.fetch.bind(window)
   ;(window as unknown as {centerRequests:string[]}).centerRequests=[]
   window.fetch=(input,init)=>{const url=typeof input==='string'?input:input instanceof Request?input.url:input.href;(window as unknown as {centerRequests:string[]}).centerRequests.push(url);return original(input,init)}
  })
  await page.setViewportSize(viewport)
  const dir=path.resolve('../artifacts/device-center-submenus-20261015',`mock-${viewport.width}`)
  await mkdir(dir,{recursive:true})
  const probes=[]
  for(const label of ['终端列表','路由器']){
   await page.goto(label==='路由器'?'/devices?tab=network':'/devices?tab=terminal')
   if(viewport.width>=1280) await expect(page.getByRole('menuitem',{name:label,exact:true})).toBeVisible()
   await expect(page.getByRole('heading',{name:label,exact:true})).toBeVisible()
   await expect(page.getByRole('tab')).toHaveCount(0)
   if(label==='路由器') await expect(page.locator('.router-observations-panel')).toContainText('Huawei')
   if(label==='终端列表') await expect(page.locator('.device-inventory-page')).toBeVisible()
   await expect(page.locator('.ant-spin-spinning')).toHaveCount(0)
   const probe=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth+2,controls:[...document.querySelectorAll('.device-center-page .ant-btn,.device-center-page .ant-tag')].filter(e=>e.getBoundingClientRect().width>0).map(e=>({nowrap:getComputedStyle(e).whiteSpace,shrink:getComputedStyle(e).flexShrink})),placeholders:/未识别|未获取|未关联|未观测/.test(document.querySelector('.device-center-page')?.textContent??'')}))
   expect(probe.overflow).toBe(false);expect(probe.placeholders).toBe(false)
   expect(probe.controls.every(x=>x.nowrap==='nowrap'&&x.shrink==='0')).toBe(true)
   probes.push({label,...probe});await page.screenshot({path:path.join(dir,`${label}.png`),fullPage:true,animations:'disabled'})
  }
  // 哑终端与发现线索暂停：旧链接回落到终端列表
  await page.goto('/devices?tab=iot')
  await expect(page.getByRole('heading',{name:'终端列表',exact:true})).toBeVisible()
  await writeFile(path.join(dir,'dom.json'),JSON.stringify({probes,errors},null,2));expect(errors).toEqual([])
 })
}
