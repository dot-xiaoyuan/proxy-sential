import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

for (const [width,height] of [[390,844],[1280,800],[1440,900]]) test(`manual confirmation ${width}`,async({page})=>{
 await page.setViewportSize({width,height})
 await page.addInitScript(()=>{
  const original=window.fetch
  const preview={review_id:'manual-review',connector_id:'office',evidence_version:2,identity_version:7,config_version:'shared-v3',fingerprint:'approved',ready:true,blockers:[],plan:{account:'yuantong',campus_id:'office-test',access_domain:'office-lan',sessions:[{target:{session_id:'session-'+ 'a'.repeat(100),raw_online_id:'171'},addresses:['192.168.0.93']},{target:{session_id:'second-session',raw_online_id:'172'},addresses:['192.168.0.94']}]}}
  let phase='preview';let confirmed=false
  window.fetch=async(...args)=>{
   const url=String(args[0]);let value:unknown;let status=200
   if(url.endsWith('/session'))value={authenticated:true,user:{user_id:'admin',username:'admin',role:'admin'},permissions:['cases:read','cases:write','actions:read','actions:execute','actions:revoke','integrations:write','events:read','overview:read']}
   else if(url.includes('/disconnect-preview')){phase='preview';value={task_id:'preview-job',status:'queued'};status=202}
   else if(url.endsWith('/disconnect')){const body=JSON.parse(String(args[1]?.body));if(!body.authorize_designated_test||body.fingerprint!=='approved')throw new Error('invalid explicit authorization');phase='confirm';confirmed=true;value={task_id:'confirm-job',status:'queued'};status=202}
   else if(url.includes('/tasks/'))value={task_id:phase==='preview'?'preview-job':'confirm-job',status:'completed',result:phase==='preview'?preview:{grant_id:'grant',action_ids:['action-one','action-two'],accepted_is_not_offline:true}}
   else if(url.includes('/shared-access/')){
    if(url.includes('/status'))value={identity:[],checked_at:new Date().toISOString(),collection:{state:'healthy'},materialization:{state:'healthy'},policy:{state:'blocked'},controller:{state:'blocked'}}
    else if(url.includes('/evidence'))value={items:[],next_cursor:''}
    else if(url.includes('/executions'))value={items:confirmed?[{action_id:'action-one',evidence_version:2,status:'pending',created_at:new Date().toISOString()}]:[],next_cursor:''}
    else value={review_id:'manual-review',account_id:'yuantong',campus_id:'office-test',access_domain:'office-lan',session_generation:'generation',episode:1,latest_version:2,latest_result:{state:'basis_present',signal_groups:['UA','TTL','TLS'],reasons:[],quantity_known:false,device_lower_bound:0},coverage_state:'verified'}
   }else return original(...args)
   return new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json'}})
  }
 })
 await page.goto('/shared-access/reviews/manual-review')
 await page.getByRole('button',{name:'获取下线预览'}).click()
 await expect(page.getByText('原始在线 ID：171')).toBeVisible()
 await page.getByRole('button',{name:'确认指定会话下线'}).click()
 const dialog=page.getByRole('dialog')
 await expect(dialog.getByRole('button',{name:'提交人工下线'})).toBeDisabled()
 await dialog.getByRole('checkbox').check()
 const probe=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth+2,controls:[...document.querySelectorAll('.ant-btn,.ant-tag')].filter(e=>getComputedStyle(e).whiteSpace!=='nowrap'||getComputedStyle(e).flexShrink!=='0').map(e=>e.textContent)}))
 expect(probe.overflow).toBe(false);expect(probe.controls).toEqual([])
 const footerBottom=await dialog.locator('.ant-modal-footer').evaluate(el=>el.getBoundingClientRect().bottom);expect(footerBottom).toBeLessThanOrEqual(height)
 const dir=path.resolve('test-results/shared-disconnect');await mkdir(dir,{recursive:true});await writeFile(path.join(dir,`dom-${width}.json`),JSON.stringify(probe,null,2));await page.screenshot({path:path.join(dir,`${width}.png`),fullPage:false,animations:'disabled'})
 await dialog.getByRole('button',{name:'提交人工下线'}).click()
 await expect(dialog).toHaveCount(0)
 await expect(page.getByText('动作已持久化，执行结果见下方逐会话记录')).toBeVisible()
})
