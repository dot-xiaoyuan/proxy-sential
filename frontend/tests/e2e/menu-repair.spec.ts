import {test,expect,type Page} from '@playwright/test'
import {mkdir,writeFile} from 'node:fs/promises'
import path from 'node:path'

const read=['policies:read','risks:read','evidence:read','events:read','shadow:read','audit:read','ingest:read','dpi:read','cases:read','identity:read','organization:read','actions:read','exports:read']
async function session(page:Page,role:string,failures:string[]=[]){
 const permissions=[...read,...(role==='viewer'?[]:['labels:create','cases:write','exports:create']),...(role==='operator'||role==='admin'?['actions:execute','actions:revoke','endpoints:write']:[]),...(role==='admin'?['users:manage','rules:reload','integrations:write','policies:manage','policies:authorize','device-fingerprint-library:update','organization:write']:[])]
 await page.addInitScript(({role,permissions,failures})=>{
 const original=window.fetch;window.fetch=async(...args)=>{const url=String(args[0]);if(url.includes('/api/v1/session'))return new Response(JSON.stringify({user:{id:role,name:role},role,permissions}),{headers:{'Content-Type':'application/json'}});if(failures.some(fragment=>url.includes(fragment)))return new Response(JSON.stringify({message:'回放接口故障'}),{status:500,headers:{'Content-Type':'application/json'}});return original(...args)}
 },{role,permissions,failures})
}

for(const window of ['7d','30d'])test(`event filters preserve ${window} and return context`,async({page})=>{
 await page.goto(`/events?window=${window}&app_protocol=http2&sensor_id=sensor-east&campus_id=east&cursor=40`)
 await page.getByPlaceholder('快速检索').fill('portal')
 await expect(page).toHaveURL(new RegExp(`window=${window}`));await expect(page).toHaveURL(/app_protocol=http2/);await expect(page).not.toHaveURL(/cursor=/);await expect(page).toHaveURL(/q=portal/)
 await page.getByPlaceholder('快速检索').fill('');await expect(page).not.toHaveURL(/q=/)
 const event=page.locator('tbody a[href^="/events/"]').first();await expect(event).toBeVisible();await event.click()
 await expect(page.getByRole('heading',{name:'事件详情'})).toBeVisible();await page.getByRole('link',{name:'返回列表',exact:true}).click()
 await expect(page).toHaveURL(new RegExp(`window=${window}`));await expect(page).toHaveURL(/app_protocol=http2/);await expect(page).toHaveURL(/sensor_id=sensor-east/)
 await page.reload();await expect(page.locator('.ant-menu-item-selected')).toHaveText('事件检索')
})

test('legacy links preserve query and parent selection',async({page})=>{
 await page.goto('/ingest?tab=errors&errors_page=2&campus_id=east');await expect(page).toHaveURL(/settings\/sources\?/);await expect(page).toHaveURL(/diagnostic_tab=errors/);await expect(page).toHaveURL(/errors_page=2/)
 await page.goto('/settings/security?tab=exceptions&exceptions_page=2');await expect(page).toHaveURL(/policies\/exceptions\?/);await expect(page.locator('.ant-menu-item-selected')).toHaveText('校园例外')
 await page.goto('/settings/actions?tab=actions&actions_page=2');await expect(page).toHaveURL(/\/actions\?/);await expect(page.locator('.ant-menu-item-selected')).toHaveText('处置记录')
 await page.goto('/ips/10.255.0.59?return_to='+encodeURIComponent('/activity?section=technical&window=7d'));await expect(page.locator('.ant-menu-item-selected')).toHaveText('技术指纹')
 await page.goto('/ips/10.255.0.59?return_to='+encodeURIComponent('https://evil.test'));await expect(page.getByRole('link',{name:'返回来源列表'})).toHaveAttribute('href','/events');await expect(page.locator('.ant-menu-item-selected')).toHaveText('事件检索')
})

for(const role of ['viewer','reviewer','operator','admin'])test(`menu read and action boundaries for ${role}`,async({page})=>{
 await session(page,role)
 const requested:string[]=[];page.on('request',request=>requested.push(request.url()))
 await page.goto('/settings/security')
 if(role==='admin'){await expect(page.getByRole('button',{name:'新建用户',exact:true})).toBeVisible()}
 else{await expect(page.getByText('没有访问权限')).toBeVisible();expect(requested.some(url=>url.includes('/api/v1/users'))).toBe(false)}
 await page.goto('/policies/exceptions');await expect(page.getByRole('heading',{name:'校园例外',exact:true})).toBeVisible();const add=page.getByRole('button',{name:'新增例外'});if(role==='admin')await expect(add).toBeEnabled();else await expect(add).toBeDisabled()
 expect(requested.filter(url=>url.includes('/api/v1/users')).length).toBe(role==='admin'?1:0)
})

test('split pages isolate unrelated failed requests',async({page})=>{
 await session(page,'admin',['/api/v1/users','/api/v1/actions/connectors'])
 const requested:string[]=[];page.on('request',request=>requested.push(request.url()))
 await page.goto('/actions?tab=actions');await expect(page.getByRole('heading',{name:'处置记录'})).toBeVisible();await expect(page.getByText('最近动作')).toBeVisible();expect(requested.some(url=>url.includes('/api/v1/actions/connectors'))).toBe(false)
 await page.goto('/policies/exceptions');await expect(page.getByText('vpn.henu.edu.cn')).toBeVisible();expect(requested.some(url=>url.includes('/api/v1/users'))).toBe(false)
})

const routes=[['/overview','高校网络风险运营工作台'],['/shared-access?tab=observations','共享发现'],['/shared-access?tab=reviews','账号复核'],['/cases','风险案件'],['/actions?tab=executions','处置记录'],['/actions?tab=actions','处置记录'],['/devices','终端画像'],['/discovery','网络设备发现'],['/activity?section=applications','应用访问'],['/activity?section=access&window=7d','访问分析'],['/activity?section=technical','技术指纹'],['/events','DPI 标准事件检索'],['/policies','防代理策略'],['/policies/exceptions','校园例外'],['/settings/rules','规则与特征库'],['/settings/sources','采集诊断与节点性能'],['/settings/sources?tab=sources','发现采集配置'],['/settings/sources?tab=scan','发现采集配置'],['/settings/sources?tab=tasks','发现采集配置'],['/settings/actions','认证与处置接入'],['/settings/organization','校区与网络区域'],['/settings/security','用户权限'],['/audit','系统操作与策略审计日志']]
for(const [width,height]of [[390,844],[1280,800],[1440,900]])test(`all menu layout and style probes ${width}`,async({page},info)=>{
 test.setTimeout(150000);await page.setViewportSize({width,height});const dir=info.outputPath('menus');await mkdir(dir,{recursive:true});const probes=[]
 for(const [url,title]of routes){await page.goto(url);await expect(page.getByRole('heading',{name:title,exact:true}).first()).toBeVisible();await page.waitForTimeout(150)
 const probe=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth+2,internal:[...document.querySelectorAll('.page-header,.app-table-bar,.ant-btn')].filter(e=>e.getBoundingClientRect().width&&e.getBoundingClientRect().right>innerWidth+2).map(e=>e.textContent),controls:[...document.querySelectorAll('.ant-btn,.ant-tag,.ant-badge')].filter(e=>getComputedStyle(e).whiteSpace!=='nowrap'||getComputedStyle(e).flexShrink!=='0').map(e=>e.textContent),clipped:[...document.querySelectorAll('.ant-table-cell-fix-right .ant-btn')].filter(e=>{const cell=e.closest('td');return cell&&e.getBoundingClientRect().width>0&&e.getBoundingClientRect().right>cell.getBoundingClientRect().right+2}).map(e=>e.textContent),selected:[...document.querySelectorAll('.ant-menu-item-selected')].map(e=>({color:getComputedStyle(e).color,background:getComputedStyle(e).backgroundColor})),forbidden:/未识别|未获取|待关联|未关联|未观测|未知/.test(document.querySelector('.app-content')?.textContent||'')}))
 probes.push({url,...probe});expect(probe.overflow,url).toBe(false);expect(probe.internal,url).toEqual([]);expect(probe.clipped,url).toEqual([]);expect(probe.controls,url).toEqual([]);expect(probe.forbidden,url).toBe(false);for(const selected of probe.selected)expect(contrast(selected.color,selected.background),url).toBeGreaterThanOrEqual(4.5)
 await page.screenshot({path:path.join(dir,`${probes.length}.png`),fullPage:true,animations:'disabled'})
 }
 await writeFile(info.outputPath('dom.json'),JSON.stringify(probes,null,2))
})

for(const [width,height]of [[390,844],[1280,800],[1440,900]])test(`business details ${width}`,async({page},info)=>{
 await page.setViewportSize({width,height})
 for(const list of ['/audit','/settings/sources?tab=diagnostics&diagnostic_tab=diagnostics']){
  await page.goto(list)
  const link=page.locator('.app-content a[href*="/audit/"],.app-content a[href*="/settings/sources/diagnostics/"]').filter({visible:true}).first()
  await expect(link).toBeVisible()
  await link.click()
  await expect(page.getByText('技术详情',{exact:true})).toBeVisible()
  expect(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+2)).toBe(false)
  await page.screenshot({path:info.outputPath(`${list.split('?')[0].replaceAll('/','-')}-detail.png`),fullPage:true,animations:'disabled'})
 }
})

test('retired evaluation routes are absent from navigation',async({page},info)=>{
 for(const [width,height] of [[390,844],[1280,800],[1440,900]]){
  await page.setViewportSize({width,height})
  await page.goto('/overview')
  await expect(page.getByRole('heading',{name:'高校网络风险运营工作台'})).toBeVisible()
  await expect(page.getByRole('menuitem',{name:'影子评估'})).toHaveCount(0)
  await expect(page.getByRole('menuitem',{name:'样本复核'})).toHaveCount(0)
  const probe=await page.evaluate(()=>({
   overflow:document.documentElement.scrollWidth>innerWidth+2,
   selected:[...document.querySelectorAll('.ant-menu-item-selected')].map(el=>({color:getComputedStyle(el).color,background:getComputedStyle(el).backgroundColor})),
   staleLinks:[...document.querySelectorAll('a[href]')].filter(el=>/\/(shadow-runs|review-samples)(\/|$)/.test(el.getAttribute('href')||'')).length,
   activityWidth:document.querySelector('.overview-activity-summary')?.getBoundingClientRect().width||0,
  }))
  expect(probe.overflow).toBe(false)
  expect(probe.staleLinks).toBe(0)
  expect(probe.activityWidth).toBeGreaterThan(0)
  for(const selected of probe.selected)expect(contrast(selected.color,selected.background)).toBeGreaterThanOrEqual(4.5)
  await page.screenshot({path:info.outputPath(`overview-${width}.png`),fullPage:true,animations:'disabled'})
 }
 for(const path of ['/shadow-runs','/review-samples']){
  await page.goto(path)
  await expect(page.getByRole('heading',{name:'影子评估'})).toHaveCount(0)
  await expect(page.getByRole('heading',{name:'样本复核'})).toHaveCount(0)
 }
})

function contrast(color:string,background:string){
 const luminance=(rgb:string)=>{const components=(rgb.match(/[\d.]+/g)||[]).slice(0,3).map(Number).map(value=>{const s=value/255;return s<=.04045?s/12.92:((s+.055)/1.055)**2.4});return components[0]*.2126+components[1]*.7152+components[2]*.0722};const a=luminance(color),b=luminance(background);return (Math.max(a,b)+.05)/(Math.min(a,b)+.05)
}

test('flow investigation preserves window and avoids disabled rule reload',async({page})=>{
 const requested:string[]=[];page.on('request',request=>requested.push(request.url()))
 await page.goto('/overview?window=30d&campus_id=east');await page.getByRole('button',{name:'DPI Flow 样本'}).filter({visible:true}).first().click();await expect(page.getByText('Flow 查询窗口：30d。风险与复核依据为当前风险快照。')).toBeVisible()
 await expect.poll(()=>requested.some(url=>url.includes('/dpi/ips/')&&url.includes('window=30d')&&url.includes('campus_id=east'))).toBe(true)
 await expect(page.getByRole('button',{name:'一键加入影子审计'})).toHaveCount(0);expect(requested.some(url=>url.includes('/rules/reload'))).toBe(false)
})
