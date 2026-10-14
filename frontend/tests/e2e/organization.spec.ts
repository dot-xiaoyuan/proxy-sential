import { expect, test, type Page } from '@playwright/test'
import { writeFile } from 'node:fs/promises'
async function replay(page:Page) {
 await page.addInitScript(()=>{
  const campuses=[{campus_id:'ncu',code:'NCU-QH',name:'南昌大学（前湖校区）',enabled:true}]
  const buildings=Array.from({length:30},(_,i)=>({building_id:`dorm-${i}`,campus_id:'ncu',code:`D-${i}`,name:`${i<4?'慧源':i<18?'修贤':'天健'}${i+1}栋`,enabled:true}))
  buildings.push(...['图书馆','行政楼','体育馆','游泳馆','基础实验大楼','理生楼','材料楼','信工楼','机电楼','建工楼','校医院'].map((name,i)=>({building_id:`landmark-${i}`,campus_id:'ncu',code:`L-${i}`,name,enabled:true})))
  const data:Record<string,Array<Record<string,unknown>>>={campuses,buildings,network_zones:['慧源社区','修贤社区','天健社区','康健社区'].map((name,i)=>({network_zone_id:`zone-${i}`,campus_id:'ncu',name,cidrs:[],ssids:[],vlans:[],enabled:true})),access_points:[]}
  const original=window.fetch;let fail=true
  window.fetch=async(...args)=>{
   const url=new URL(String(args[0]),location.origin)
   const json=(value:unknown,status=200)=>new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json'}})
   if(url.pathname==='/api/v1/session')return json({user:{id:'admin',name:'管理员'},role:'admin',permissions:['organization:read','organization:write']})
   if(url.pathname==='/api/v1/organization'){const kind=url.searchParams.get('kind');return json(kind?{items:data[kind],page:{total:data[kind].length,limit:20,next_cursor:null}}:data)}
   if(url.pathname.startsWith('/api/v1/organization/')){
    const kind=url.pathname.split('/').pop()!.replaceAll('-','_'),item=JSON.parse(String(args[1]?.body))
    if(item.name==='失败重试校区'&&fail){fail=false;return json({error:{message:'回放保存故障'}},500)}
    const id=({campuses:'campus_id',buildings:'building_id',network_zones:'network_zone_id',access_points:'access_point_id'} as Record<string,string>)[kind]
    const index=data[kind].findIndex(existing=>existing[id]===item[id]);if(index<0)data[kind].push(item);else data[kind][index]=item
    return json(item,201)
   }
   return original(...args)
  }
 })
}
test('save failure is visible and retry updates campus and zone lists',async({page})=>{
 const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));page.on('console',e=>{if(e.type()==='error')errors.push(e.text())})
 await replay(page);await page.goto('/settings/organization')
 await page.getByRole('button',{name:'新增校区',exact:true}).click()
 const modal=page.getByRole('dialog')
 await modal.getByLabel('校区名称').fill('失败重试校区');await modal.getByRole('button',{name:/保\s*存/,exact:true}).click()
 await expect(modal.getByText('保存失败：回放保存故障')).toBeVisible();await expect(modal.getByLabel('校区名称')).toHaveValue('失败重试校区')
 await modal.getByRole('button',{name:/保\s*存/,exact:true}).click();await expect(modal).not.toBeVisible();await expect(page.getByRole('heading',{name:'失败重试校区'})).toBeVisible()
 await page.getByRole('tab',{name:'网段与位置映射'}).click();await page.getByRole('button',{name:'编辑映射'}).first().click()
 await modal.getByLabel('IP 网段').fill('10.20.0.0/24，10.21.0.0/24');await modal.getByText('高级设置：SSID / VLAN（选填）').click();await modal.getByLabel('SSID（选填）').fill('QH-Test');await modal.getByRole('button',{name:/保\s*存/,exact:true}).click()
 await expect(page.getByText('IP 网段 10.20.0.0/24、10.21.0.0/24')).toBeVisible();await expect(page.getByText('SSID QH-Test')).toBeVisible();expect(errors).toEqual([])
})
for(const [width,height]of [[390,844],[1280,800],[1440,900]])test(`directory and editor layout ${width}`,async({page},info)=>{
 const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));page.on('console',e=>{if(e.type()==='error')errors.push(e.text())});page.on('response',r=>{if(r.status()>=400)errors.push(`${r.status()} ${r.url()}`)})
 await replay(page);await page.setViewportSize({width,height});await page.goto('/settings/organization');await expect(page.getByText('1 个校区 · 41 栋楼宇 · 4 个区域 · 0 个接入点')).toBeVisible()
 const probes=[]
 for(const view of ['campus','buildings','zones','editor']){
  if(view==='buildings')await page.getByText('查看楼宇',{exact:true}).click()
  if(view==='zones')await page.getByRole('tab',{name:'网段与位置映射'}).click()
  if(view==='editor')await page.getByRole('button',{name:'编辑映射'}).first().click()
  await page.waitForTimeout(350)
  const probe=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth+2,controls:[...document.querySelectorAll('.ant-btn,.ant-tag,.ant-badge')].filter(e=>e.getBoundingClientRect().width>0).map(e=>({text:e.textContent,nowrap:getComputedStyle(e).whiteSpace,shrink:getComputedStyle(e).flexShrink,right:e.getBoundingClientRect().right})),cards:[...document.querySelectorAll('.organization-page .ant-card')].map(e=>({border:getComputedStyle(e).borderColor,radius:getComputedStyle(e).borderRadius,padding:getComputedStyle(e.querySelector('.ant-card-body')!).padding})),headings:[...document.querySelectorAll('.organization-page h3,.organization-page h4,.organization-page h5')].map(e=>({size:getComputedStyle(e).fontSize,weight:getComputedStyle(e).fontWeight})),selected:[...document.querySelectorAll('.ant-tabs-tab-active .ant-tabs-tab-btn')].map(e=>({color:getComputedStyle(e).color})),forbidden:/未识别|未获取|未关联|未观测|未知/.test(document.querySelector('.organization-page')?.textContent||'')}))
  probes.push({view,...probe});expect(probe.overflow).toBe(false);expect(probe.forbidden).toBe(false)
  for(const c of probe.controls){expect(c.nowrap,c.text??'').toBe('nowrap');expect(c.shrink).toBe('0');expect(c.right).toBeLessThanOrEqual(width+2)}
  for(const selected of probe.selected){const rgb=(selected.color.match(/\d+/g)||[]).slice(0,3).map(Number).map(v=>{const s=v/255;return s<=.04045?s/12.92:((s+.055)/1.055)**2.4});const luminance=rgb[0]*.2126+rgb[1]*.7152+rgb[2]*.0722;expect(1.05/(luminance+.05)).toBeGreaterThanOrEqual(4.5)}
  for(const c of probe.cards){expect(c.border).toBe('rgb(226, 232, 240)');expect(c.radius).toBe('8px');expect(c.padding).toBe(width<560?'14px':'20px')}
  await page.screenshot({path:info.outputPath(`${view}-${width}.png`),fullPage:true,animations:'disabled'})
 }
 await writeFile(info.outputPath('dom-probes.json'),JSON.stringify({width,height,probes,errors},null,2));expect(errors).toEqual([])
})

for(const [width,height] of [[390,844],[1280,800],[1440,900]])test(`configure administration building CIDRs without VLAN or AP ${width}`,async({page},info)=>{
 await replay(page);await page.setViewportSize({width,height});await page.goto('/settings/organization')
 await page.getByText('查看楼宇',{exact:true}).click()
 const building=page.locator('.organization-building').filter({has:page.getByText('行政楼',{exact:true})})
 await building.getByRole('button',{name:'配置网段'}).click()
 const modal=page.getByRole('dialog')
 await expect(modal.getByText('行政楼',{exact:true})).toBeVisible()
 await modal.getByLabel('IP 网段',{exact:true}).fill('222.204.88.0/23')
 await expect(modal.getByLabel('VLAN（选填）')).not.toBeVisible()
 await expect(modal.getByLabel('SSID（选填）')).not.toBeVisible()
 await page.screenshot({path:info.outputPath(`building-cidr-editor-${width}.png`),fullPage:true,animations:'disabled'})
 await modal.getByRole('button',{name:/保\s*存/}).click();await expect(modal).not.toBeVisible()
 await expect(building.getByText('222.204.88.0/23',{exact:true})).toBeVisible()
 await building.getByRole('button',{name:'编辑网段'}).click()
 await expect(modal.getByLabel('IP 网段',{exact:true})).toHaveValue('222.204.88.0/23')
 await modal.getByLabel('IP 网段',{exact:true}).fill('222.204.88.0/23\n2001:db8::/64')
 await modal.getByRole('button',{name:/保\s*存/}).click();await expect(modal).not.toBeVisible()
 await expect(building.getByText('2001:db8::/64',{exact:true})).toBeVisible()
 await building.scrollIntoViewIfNeeded()
 await page.screenshot({path:info.outputPath(`building-cidr-saved-${width}.png`),fullPage:true,animations:'disabled'})
 await page.getByRole('tab',{name:'网段与位置映射'}).click()
 await expect(page.getByText('IP 网段 222.204.88.0/23、2001:db8::/64')).toBeVisible()
 await expect(page.getByText(/0 个接入点/)).toBeVisible()
})
