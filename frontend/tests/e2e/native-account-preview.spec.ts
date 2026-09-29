import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
for (const [width,height] of [[390,844],[1280,800],[1440,900]]) test(`native account preview ${width}`,async({page})=>{
 await page.setViewportSize({width,height});await page.goto('/settings/actions')
 await expect(page.getByRole('button',{name:'账号会话预览'}).first()).toBeVisible()
 await page.evaluate(()=>{const original=window.fetch;window.fetch=(...args)=>String(args[0]).includes('/account-preview?')?Promise.resolve(new Response(JSON.stringify({coverage:'configured_source_only',observed_at:'2026-09-16T03:00:00Z',plan:{account:'lab-student',campus_id:'测试园区',access_domain:'实验接入域',fingerprint:'a'.repeat(64),sessions:[{target:{session_id:'source-instance:long-session-'.repeat(3)},addresses:['192.0.2.7','2001:db8::7']},{target:{session_id:'source-instance:second'},addresses:['192.0.2.8']}]}}),{status:200,headers:{'Content-Type':'application/json'}})):original(...args)})
 await page.getByRole('button',{name:'账号会话预览'}).first().click();const dialog=page.getByRole('dialog')
 await dialog.getByRole('textbox',{name:'预览账号'}).fill('lab-student');await dialog.getByRole('button',{name:'查询会话'}).click()
 await expect(dialog.getByText('本次查询返回 2 个会话',{exact:true})).toBeVisible();await expect(dialog.getByText(/192.0.2.7、2001:db8::7/)).toBeVisible()
 const probe=await dialog.evaluate(el=>({overflow:el.scrollWidth>el.clientWidth+2,bad:[...el.querySelectorAll('.ant-btn,.ant-tag')].filter(e=>{const s=getComputedStyle(e);return s.whiteSpace!=='nowrap'||s.flexShrink!=='0'}).map(e=>e.textContent),radius:getComputedStyle(el.querySelector('.native-observation')!).borderRadius,padding:getComputedStyle(el.querySelector('.native-observation')!).paddingTop}))
 expect(probe.overflow).toBe(false);expect(probe.bad).toEqual([]);expect(probe.radius).toBe('8px');expect(probe.padding).toBe(width===390?'14px':'20px')
 const dir=path.resolve('test-results/native-account-preview');await mkdir(dir,{recursive:true});await writeFile(path.join(dir,`dom-${width}.json`),JSON.stringify(probe,null,2));await dialog.screenshot({path:path.join(dir,`${width}.png`),animations:'disabled'})
 await page.evaluate(()=>{window.fetch=()=>Promise.reject(new Error('unavailable'))});await dialog.getByRole('button',{name:'查询会话'}).click()
 await expect(dialog.getByText('无法生成会话预览',{exact:true})).toBeVisible();await expect(dialog.getByText('本次查询返回 2 个会话',{exact:true})).toHaveCount(0)
})
