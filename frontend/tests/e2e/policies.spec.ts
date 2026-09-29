import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
for(const width of [390,1280,1440]) test(`policy forms and inventory ${width}`,async({page})=>{
 await page.setViewportSize({width,height:width===390?844:width===1280?800:900})
 await page.goto('/policies')
 await expect(page.getByText('教职工设备配额',{exact:true})).toBeVisible()
 await page.getByLabel('试算账号').fill('staff-001')
 await page.getByRole('button',{name:'策略试算',exact:true}).click()
 await expect(page.getByText('覆盖不足，无法完整判断在线设备数',{exact:true})).toBeVisible()
 const folder=path.resolve('test-results/policy-visuals');await mkdir(folder,{recursive:true})
 await page.screenshot({path:path.join(folder,`page-${width}.png`),fullPage:true,animations:'disabled'})
 await page.getByRole('button',{name:'新建策略',exact:true}).click()
 await expect(page.getByRole('dialog')).toBeVisible()
 await page.getByRole('dialog').getByLabel('触发类型').click()
 await page.getByText('共享上网风险',{exact:true}).last().click()
 await page.getByRole('button',{name:'添加动作阶段',exact:true}).click()
 await expect(page.getByRole('dialog').getByText('强制下线',{exact:true})).toBeVisible()
 const probe=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth+2,bad:[...document.querySelectorAll('.policies-page .ant-btn,.policies-page .ant-tag,.policy-stage .ant-btn')].filter(e=>{const c=getComputedStyle(e);return c.whiteSpace!=='nowrap'||c.flexShrink!=='0'}).map(e=>e.textContent),card:getComputedStyle(document.querySelector('.policies-page .ant-card')!).borderRadius,padding:getComputedStyle(document.querySelector('.policies-page .ant-card-body')!).paddingTop,columns:getComputedStyle(document.querySelector('.policy-form-grid')!).gridTemplateColumns}))
 await writeFile(path.join(folder,`dom-${width}.json`),JSON.stringify(probe,null,2))
 expect(probe.overflow).toBe(false);expect(probe.bad).toEqual([]);expect(probe.card).toBe('8px');expect(probe.padding).toBe(width===390?'14px':'20px')
 await expect(page.getByRole('dialog').getByRole('button',{name:'确 定'})).toBeInViewport()
 await page.screenshot({path:path.join(folder,`form-${width}.png`),animations:'disabled'})
})
