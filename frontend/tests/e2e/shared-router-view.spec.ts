import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
for (const [width,height] of [[390,844],[704,774],[1280,800],[1440,900]]) test(`router identity is distinct from shared proof ${width}`,async({page})=>{
 await page.setViewportSize({width,height})
 const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text())});page.on('response',r=>{if(r.status()>=400)errors.push(`${r.status()} ${r.url()}`)})
 await page.addInitScript(()=>{const original=window.fetch;window.fetch=async(...args)=>{
  const url=String(args[0]);if(!url.includes('/shared-access/devices?'))return original(...args)
  const base={role:'router',identity_state:'supported',identity_current:true,identity_expires_at:new Date(Date.now()+3600000).toISOString(),last_observed_at:new Date().toISOString(),ip:'192.168.1.1',account_conflict:false,current_shared:true}
  const items=[{...base,profile_id:'r1',brand:'TP-Link',model:'TL-WR842N',mac:'00:11:22:33:44:55',router_status:'confirmed',identity_assessment_id:'a1',latest_account_id:'account-one',account_conflict:true},{...base,profile_id:'r2',brand:'Huawei',model:'AX3',mac:'00:11:22:33:44:66',router_status:'candidate',identity_assessment_id:'a2'}].filter(item=>url.includes('has_account=true')?!!item.latest_account_id:!item.latest_account_id)
  return new Response(JSON.stringify({items,page:{total:items.length,limit:20},freshness_state:'fresh'}),{headers:{'Content-Type':'application/json'}})
 }})
 await page.goto('/shared-access?tab=observations')
 await expect(page.getByText('TL-WR842N',{exact:false})).toBeVisible()
 await expect(page.getByText('00:11:22:33:44:55',{exact:false})).toBeVisible()
 await expect(page.getByText('00:11:22:33:44:66',{exact:false})).toHaveCount(0)
 await expect(page.getByText('关联账号：account-one',{exact:true})).toBeVisible()
 await expect(page.getByText('账号关联有冲突',{exact:true})).toBeVisible()
 await expect(page.getByText('共享关系待核验',{exact:true})).toHaveCount(1)
 await expect(page.getByText('已确认当前共享',{exact:true})).toHaveCount(0)
 const probe=await page.evaluate(()=>({paginationBelowRows:document.querySelector('.router-sharing-row:last-child')!.getBoundingClientRect().bottom<=document.querySelector('.router-sharing-candidates .app-server-pagination')!.getBoundingClientRect().top,overflow:document.documentElement.scrollWidth>innerWidth+1,controls:[...document.querySelectorAll('main .ant-btn, main .ant-tag')].filter(e=>getComputedStyle(e).whiteSpace!=='nowrap'||getComputedStyle(e).flexShrink!=='0').map(e=>e.textContent)}))
 expect(probe.paginationBelowRows).toBe(true);expect(probe.overflow).toBe(false);expect(probe.controls).toEqual([]);expect(errors).toEqual([])
 const dir=path.resolve('../artifacts/router-account-groups-20261016/mock-ui');await mkdir(dir,{recursive:true});await writeFile(path.join(dir,`routers-${width}.json`),JSON.stringify(probe));await page.screenshot({path:path.join(dir,`linked-${width}.png`),fullPage:true,animations:'disabled'})
 await page.getByRole('tab',{name:'无关联账号',exact:true}).click()
 await expect(page.getByText('00:11:22:33:44:66',{exact:false})).toBeVisible()
 await expect(page.getByText('关联账号：account-one',{exact:true})).toHaveCount(0)
 await expect(page.getByText('共享关系待核验',{exact:true})).toHaveCount(1)
 expect(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1)).toBe(false)
 await page.screenshot({path:path.join(dir,`empty-${width}.png`),fullPage:true,animations:'disabled'})
 await page.reload();await expect(page.getByRole('tab',{name:'无关联账号',exact:true})).toHaveAttribute('aria-selected','true')
})
