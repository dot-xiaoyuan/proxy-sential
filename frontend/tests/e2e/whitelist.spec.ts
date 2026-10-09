import { test, expect } from '@playwright/test'
import { mkdir,writeFile } from 'node:fs/promises'
import path from 'node:path'

async function installWhitelist(page:import('@playwright/test').Page,readonly=false){
 await page.addInitScript(({readonly})=>{
  const original=window.fetch
  const stamp='2026-10-01T00:00:00Z'
  const base={reason:'教学实验设备，保留观测但不执行策略动作',enabled:true,revision:1,valid_from:stamp,created_by:'admin',updated_by:'admin',created_at:stamp,updated_at:stamp}
  const rows=[{...base,entry_id:'v6',type:'network',value:'2001:db8:abcd:1234::/64'},{...base,entry_id:'mac',type:'mac',value:'aa:bb:cc:dd:ee:ff'},{...base,entry_id:'group',type:'group',value:'teaching-group',campus_id:'ncu',access_domain:'wired'},{...base,entry_id:'expired',type:'account',value:'old-lab-account',expires_at:'2026-10-02T00:00:00Z'}] as Record<string,unknown>[]
  window.fetch=async(...args)=>{
   const url=String(args[0]);if(readonly&&url.endsWith('/session'))return new Response(JSON.stringify({user:{id:'viewer',name:'只读查看员'},role:'viewer',permissions:['policies:read']}),{status:200,headers:{'Content-Type':'application/json'}})
   if(!url.includes('/whitelist'))return original(...args)
   const u=new URL(url,location.origin),method=args[1]?.method||'GET'
   const response=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}})
   if(method==='GET'){const keyword=u.searchParams.get('keyword')||'',kind=u.searchParams.get('type')||'';const items=rows.filter(r=>(!keyword||String(r.value).includes(keyword))&&(!kind||r.type===kind));return response({items,page:{total:items.length,limit:20},checked_at:new Date().toISOString()})}
   const value=JSON.parse(String(args[1]?.body||'{}')),parts=u.pathname.split('/').filter(Boolean),index=parts.indexOf('whitelist'),id=parts[index+1],op=parts[index+2]
   if(!id){const next={...base,...value,entry_id:'new-vip',valid_from:value.valid_from||new Date().toISOString(),revision:1};rows.push(next);return response(next,201)}
   const existing=rows.find(r=>r.entry_id===id)!;if(value.revision!==existing.revision)return response({error:{message:'版本冲突'}},409)
   if(op){existing.enabled=op==='enable';existing.revision=Number(existing.revision)+1}else Object.assign(existing,value,{revision:Number(existing.revision)+1})
   return response(existing)
  }
 },{readonly})
}

for(const [width,height] of [[390,844],[1280,800],[1440,900]])test(`whitelist management ${width}`,async({page})=>{
 await page.setViewportSize({width,height});await installWhitelist(page);await page.goto('/policies/whitelist')
 await expect(page.getByRole('heading',{name:'白名单',exact:true})).toBeVisible()
 await expect(page.getByText('2001:db8:abcd:1234::/64',{exact:true})).toBeVisible()
 await expect(page.getByText('已过期',{exact:true})).toBeVisible()
 const dir=path.resolve('test-results/whitelist');await mkdir(dir,{recursive:true})
 const audit=async(name:string)=>{const probe=await page.evaluate(()=>({width:innerWidth,overflow:document.documentElement.scrollWidth>innerWidth+2,controls:[...document.querySelectorAll('.ant-btn,.ant-tag')].filter(e=>getComputedStyle(e).whiteSpace!=='nowrap'||getComputedStyle(e).flexShrink!=='0').map(e=>e.textContent),missingLabels:/未识别|未获取|未关联|未观测|未知/.test(document.querySelector('main')?.textContent||''),cards:[...document.querySelectorAll('.whitelist-card')].map(e=>({padding:getComputedStyle(e).padding,border:getComputedStyle(e).borderColor,radius:getComputedStyle(e).borderRadius}))}));expect(probe.overflow).toBe(false);expect(probe.controls).toEqual([]);expect(probe.missingLabels).toBe(false);await writeFile(path.join(dir,`${name}-${width}.json`),JSON.stringify(probe,null,2));await page.screenshot({path:path.join(dir,`${name}-${width}.png`),fullPage:true,animations:'disabled'})}
 await audit('list')
 await page.getByRole('button',{name:'新增白名单',exact:true}).click()
 await page.getByLabel('匹配值',{exact:true}).fill('teaching-vip')
 await page.getByLabel('豁免原因',{exact:true}).fill('课程验证专用账号')
 await audit('form')
 await page.getByRole('button',{name:'保存白名单',exact:true}).click();await expect(page.getByRole('dialog')).toBeHidden()
 const row=page.locator('.whitelist-card').filter({hasText:'teaching-vip'})
 await expect(row).toContainText('生效中')
 await row.getByRole('button',{name:/^停\s*用$/}).click();await expect(row).toContainText('已停用')
 await row.getByRole('button',{name:/^编\s*辑$/}).click()
 await page.getByLabel('豁免原因',{exact:true}).fill('更新课程验证原因')
 await page.getByRole('button',{name:'保存白名单',exact:true}).click();await expect(page.getByRole('dialog')).toBeHidden();await expect(row).toContainText('更新课程验证原因')
 await row.getByRole('button',{name:/^启\s*用$/}).click();await expect(row).toContainText('生效中')
 await audit('updated')
})

test('whitelist read permission cannot edit',async({page})=>{
 await installWhitelist(page,true);await page.goto('/policies/whitelist')
 await expect(page.getByText('2001:db8:abcd:1234::/64',{exact:true})).toBeVisible()
 await expect(page.getByRole('button',{name:'新增白名单',exact:true})).toBeDisabled()
 await expect(page.getByRole('button',{name:/^编\s*辑$/})).toHaveCount(4)
 for(const button of await page.getByRole('button',{name:/^编\s*辑$/}).all())await expect(button).toBeDisabled()
})
