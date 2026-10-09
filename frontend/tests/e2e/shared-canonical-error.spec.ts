import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
for (const [width,height] of [[390,844],[1280,800],[1440,900]]) test(`shared canonical error ${width}`,async({page})=>{
 await page.setViewportSize({width,height})
 await page.addInitScript(()=>{
  const original=window.fetch
  window.fetch=async(...args)=>{
   if(String(args[0]).includes('/simulate'))return new Response(JSON.stringify({account_id:'fixture-account',inventory:{total:0,mobile:0,pc:0,other:0,uncertain_sessions:0,coverage_complete:true},explanations:[],evaluations:[{policy_id:'fixture-policy',input:{known:false,violated:false,reasons:['shared_evidence_insufficient_or_expired']},shared_evaluation:[{id:'fixture-window',ip:'192.0.2.1',state:'insufficient',quantity_known:false,sensor_id:'fixture-sensor',reasons:['standard_event_encoding_failed','shared_observation_conflict'],signal_groups:[]}]}]}),{status:200,headers:{'Content-Type':'application/json'}})
   return original(...args)
  }
 })
 await page.goto('/policies')
 await page.getByLabel('试算账号').fill('fixture-account')
 await page.getByRole('button',{name:'策略试算',exact:true}).first().click()
 await expect(page.getByText('观测数据格式异常，证据窗口不完整、观测记录存在冲突',{exact:true})).toBeVisible()
 await expect(page.getByText('standard_event_encoding_failed')).toHaveCount(0)
 await page.getByText('观测数据格式异常，证据窗口不完整、观测记录存在冲突',{exact:true}).scrollIntoViewIfNeeded()
 const probe=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth+2,badControls:[...document.querySelectorAll('.ant-btn,.ant-tag,.ant-badge')].filter(e=>{const s=getComputedStyle(e);return s.whiteSpace!=='nowrap'||s.flexShrink!=='0'}).map(e=>e.textContent),placeholderText:/未识别|未获取|未关联|未观测/.test(document.body.innerText),diagnosticColor:getComputedStyle([...document.querySelectorAll('p')].find(e=>e.textContent?.includes('观测数据格式异常'))!).color}))
 expect(probe.overflow).toBe(false);expect(probe.badControls).toEqual([]);expect(probe.placeholderText).toBe(false)
 const dir=path.resolve('test-results/shared-canonical-error');await mkdir(dir,{recursive:true});await writeFile(path.join(dir,`dom-${width}.json`),JSON.stringify(probe,null,2));await page.screenshot({path:path.join(dir,`${width}.png`),fullPage:true,animations:'disabled'})
})
