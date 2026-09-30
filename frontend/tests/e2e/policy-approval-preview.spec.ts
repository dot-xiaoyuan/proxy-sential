import { test,expect } from '@playwright/test'
import {mkdir,writeFile} from 'node:fs/promises'
import path from 'node:path'
for(const [width,height] of [[390,844],[1280,800],[1440,900]])test(`policy approval ${width}`,async({page})=>{
 await page.setViewportSize({width,height});await page.goto('/actions?tab=executions')
 await page.getByRole('button',{name:'确认执行',exact:true}).first().click()
 const dialog=page.getByRole('dialog')
 await expect(dialog.getByText('账号：staff-001',{exact:true})).toBeVisible()
 await expect(dialog.getByText('地址：192.0.2.7',{exact:true})).toBeVisible()
 const probe=await dialog.evaluate(el=>({overflow:el.scrollWidth>el.clientWidth+2,bad:[...el.querySelectorAll('.ant-btn')].filter(e=>{const s=getComputedStyle(e);return s.whiteSpace!=='nowrap'||s.flexShrink!=='0'}).map(e=>e.textContent),radius:getComputedStyle(el.querySelector('.native-observation')!).borderRadius,padding:getComputedStyle(el.querySelector('.native-observation')!).paddingTop}))
 expect(probe.overflow).toBe(false);expect(probe.bad).toEqual([]);expect(probe.radius).toBe('8px');expect(probe.padding).toBe(width===390?'14px':'20px')
 const dir=path.resolve('test-results/policy-approval-preview');await mkdir(dir,{recursive:true});await writeFile(path.join(dir,`dom-${width}.json`),JSON.stringify(probe,null,2));await dialog.screenshot({path:path.join(dir,`${width}.png`),animations:'disabled'})
 await page.evaluate(()=>{const original=window.fetch;window.fetch=(...args)=>String(args[0]).endsWith('/approve')?Promise.resolve(new Response(JSON.stringify({message:'changed'}),{status:409,headers:{'Content-Type':'application/json'}})):original(...args)})
 await dialog.getByRole('button',{name:'确认上述内容并提交'}).click();await expect(dialog.getByText('确认未完成',{exact:true})).toBeVisible();await expect(dialog.getByRole('button',{name:'确认上述内容并提交'})).toBeDisabled()
 await dialog.getByRole('button',{name:'刷新确认内容'}).click();await expect(dialog.getByRole('button',{name:'确认上述内容并提交'})).toBeEnabled()
})
