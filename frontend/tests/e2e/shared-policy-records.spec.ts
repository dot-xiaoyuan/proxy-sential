import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
for (const [width, height] of [[390,844],[704,774],[1280,800],[1440,900]]) test(`shared observe records ${width}`, async ({page}) => {
 const errors: string[] = []
 page.on('pageerror', error => errors.push(error.message))
 page.on('console', msg => { if(msg.type()==='error') errors.push(msg.text()) })
 page.on('response', response => { if(response.status() >= 400) errors.push(`${response.status()} ${response.url()}`) })
 await page.setViewportSize({width,height})
 await page.goto('/shared-access?tab=decisions')
 await expect(page.getByText('campus-student-001')).toBeVisible()
 await expect(page.getByRole('button',{name:/确认执行|下线|撤销/})).toHaveCount(0)
 const dir=path.resolve('../artifacts/shared-router-view-20261016/records-ui');await mkdir(dir,{recursive:true})
 await page.screenshot({path:path.join(dir,`top-${width}.png`),fullPage:true,animations:'disabled'})
 await page.getByText('查看证据与版本',{exact:true}).click()
 await expect(page.getByText('设备数量下界：2')).toBeVisible()
 const probe = await page.evaluate(() => {
  const root = document.querySelector('.shared-records')!
  const item = document.querySelector('.shared-record-item')!
  const tab = document.querySelector('.ant-tabs-tab-active .ant-tabs-tab-btn')!
  const controls = [...root.querySelectorAll('.ant-btn,.ant-tag')].filter(el => getComputedStyle(el).whiteSpace!=='nowrap'||getComputedStyle(el).flexShrink!=='0').map(el=>el.textContent)
  const luminance=(color:string)=>{const rgb=(color.match(/[\d.]+/g)||[]).slice(0,3).map(Number).map(v=>{const c=v/255;return c<=0.04045?c/12.92:((c+0.055)/1.055)**2.4});return 0.2126*rgb[0]+0.7152*rgb[1]+0.0722*rgb[2]}
  const selectedBackground=getComputedStyle(tab.parentElement!).backgroundColor
  const foreground=luminance(getComputedStyle(tab).color),background=luminance(selectedBackground==='rgba(0, 0, 0, 0)'?'rgb(248,250,252)':selectedBackground)
  const contrast=(Math.max(foreground,background)+0.05)/(Math.min(foreground,background)+0.05)
  return {contrast,overflow:document.documentElement.scrollWidth>innerWidth+1,controls,padding:getComputedStyle(item).paddingTop,radius:getComputedStyle(item).borderRadius,border:getComputedStyle(item).borderColor,selectedColor:getComputedStyle(tab).color,selectedBackground:getComputedStyle(tab.parentElement!).backgroundColor,identifierWrap:getComputedStyle(root.querySelector('.shared-record-id')!).overflowWrap}
 })
 expect(probe.contrast).toBeGreaterThanOrEqual(4.5);expect(probe.overflow).toBe(false);expect(probe.controls).toEqual([]);expect(probe.padding).toBe(width===390?'14px':'20px');expect(probe.radius).toBe('8px');expect(probe.identifierWrap).toBe('anywhere')
 await writeFile(path.join(dir,`dom-${width}.json`),JSON.stringify(probe,null,2));await page.screenshot({path:path.join(dir,`records-${width}.png`),fullPage:true,animations:'disabled'})
 await page.getByLabel('记录结果').click();await page.getByText('归责或覆盖不足',{exact:true}).click()
 await expect(page.getByText('身份快照索引尚未就绪，等待新快照')).toBeVisible()
 await expect(page.getByText('2001:db8:1234:5678:90ab:cdef:1234:5678',{exact:true})).toHaveCount(0)
 await page.getByText('查看采集处理进度（不属于策略命中）',{exact:true}).click()
 await expect(page.getByText('失败待重试',{exact:true})).toBeVisible()
 expect(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1)).toBe(false)
 await page.screenshot({path:path.join(dir,`insufficient-${width}.png`),fullPage:true,animations:'disabled'})
 await page.getByRole('button',{name:'下一页',exact:true}).click();await expect(page.getByRole('button',{name:'上一页',exact:true})).toBeEnabled()
 await page.goto('/policies')
 const builtin = page.locator('.ant-card').filter({has:page.getByText('共享确认记录',{exact:true})})
 await expect(builtin.getByRole('switch')).toBeDisabled();await expect(builtin.getByText('原定动作：下线',{exact:true})).toBeVisible();await expect(builtin.getByText('仅记录，未执行',{exact:true})).toBeVisible();await expect(builtin.getByRole('button',{name:'编辑策略'})).toHaveCount(0)
 await page.screenshot({path:path.join(dir,`policy-${width}.png`),fullPage:true,animations:'disabled'})
 expect(errors).toEqual([])
})

test('pending jobs do not replace the empty matched record list',async({page})=>{
 await page.setViewportSize({width:704,height:774})
 await page.addInitScript(()=>{const original=window.fetch;window.fetch=async(...args)=>{
  const url=String(args[0]);if(!url.includes('/policy-decisions?'))return original(...args)
  const processing=url.includes('include_processing=true')?Array.from({length:30},(_,i)=>({ip:`192.0.2.${i+1}`,state:'processing',first_received_at:new Date().toISOString()})):[]
  return new Response(JSON.stringify({items:[],next_cursor:'',processing,processing_has_more:true}),{headers:{'Content-Type':'application/json'}})
 }})
 await page.goto('/shared-access?tab=decisions')
 await expect(page.getByText('当前筛选暂无策略命中记录',{exact:true})).toBeVisible()
 await expect(page.getByText('192.0.2.1',{exact:true})).toHaveCount(0)
 await expect(page.getByText('采集数据待处理，结果尚未生成',{exact:true})).toHaveCount(0)
 await page.getByText('查看采集处理进度（不属于策略命中）',{exact:true}).click()
 await expect(page.locator('.shared-record-processing li')).toHaveCount(5)
 await expect(page.getByText('192.0.2.30',{exact:true})).toHaveCount(0)
 await expect(page.getByText('当前筛选暂无策略命中记录',{exact:true})).toBeVisible()
 await page.getByRole('button',{name:'查看未通过评估',exact:true}).click()
 await expect(page.getByText('当前筛选暂无评估记录',{exact:true})).toBeVisible()
})

for (const [width,height] of [[390,844],[704,774],[1280,800],[1440,900]]) test(`repeated reasons stay bounded ${width}`,async({page})=>{
 const errors:string[]=[]
 page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text())});page.on('response',r=>{if(r.status()>=400)errors.push(String(r.status()))})
 await page.setViewportSize({width,height})
 await page.addInitScript(()=>{const original=window.fetch;window.fetch=async(...args)=>{
  if(!String(args[0]).includes('/policy-decisions?'))return original(...args)
  return new Response(JSON.stringify({items:[{decision_id:'repeated',observation_id:'obs',policy_revision:2,evidence_version:'v1',account_id:'',ip:'192.0.2.1',campus_id:'ncu',access_domain:'campus-auth',evaluated_at:'2026-10-16T03:07:24Z',result:'insufficient',reasons:[...Array(500).fill('feature_value_limit'),'incomplete_shared_observation_window',...Array.from({length:80},(_,i)=>`capture_interval_incomplete:collector-${i}`)],evidence:{rule_version:'13',from:'2026-10-16T03:00:00Z',to:'2026-10-16T03:05:00Z',records:Array.from({length:200},(_,i)=>({event_id:`event-${i}`,source:'handshake'}))}}],next_cursor:''}),{headers:{'Content-Type':'application/json'}})
 }})
 await page.goto('/shared-access?tab=decisions&decision_result=insufficient')
 await expect(page.getByText('特征数量达到采集上限',{exact:true})).toBeVisible()
 await expect(page.getByText('共 500 次',{exact:true})).toBeVisible()
 const item=page.locator('.shared-record-item')
 expect((await item.boundingBox())!.height).toBeLessThan(520)
 await expect(item.locator('.shared-record-reason:visible')).toHaveCount(2)
 const dir=path.resolve('../artifacts/shared-record-layout-20261016/mock-ui');await mkdir(dir,{recursive:true})
 await page.screenshot({path:path.join(dir,`collapsed-${width}.png`),fullPage:true})
 await page.getByText('其他原因（80 类）',{exact:true}).click()
 await page.getByText('查看证据与版本',{exact:true}).click()
 const probe=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth+1,scrolls:[...document.querySelectorAll('.shared-record-detail-scroll')].map(e=>({height:e.clientHeight,content:e.scrollHeight,overflow:getComputedStyle(e).overflowY})),controls:[...document.querySelectorAll('.shared-records .ant-btn,.shared-records .ant-tag')].filter(e=>getComputedStyle(e).whiteSpace!=='nowrap'||getComputedStyle(e).flexShrink!=='0').map(e=>e.textContent)}))
 expect(probe.overflow).toBe(false);expect(probe.controls).toEqual([])
 for(const s of probe.scrolls){expect(s.height).toBeLessThanOrEqual(240);expect(s.content).toBeGreaterThan(s.height);expect(s.overflow).toBe('auto')}
 await page.screenshot({path:path.join(dir,`expanded-${width}.png`),fullPage:true});await writeFile(path.join(dir,`dom-${width}.json`),JSON.stringify(probe,null,2));expect(errors).toEqual([])
})
