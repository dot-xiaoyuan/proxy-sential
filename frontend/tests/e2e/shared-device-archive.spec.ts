import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

for(const [width,height] of [[390,844],[1280,800],[1440,900]]) test(`holiday equipment archive ${width}`,async({page})=>{
 await page.setViewportSize({width,height})
 await page.addInitScript(()=>{
  const original=window.fetch
  const checked='2026-10-05T15:30:00Z'
  const identity={profile_id:'router-22',sensor_id:'office',endpoint_id:'mac:20:3a:eb:e9:de:10',mac:'20:3a:eb:e9:de:10',ip:'192.168.0.22',brand:'ZTE',model:'SR7410-20',role:'router',identity_state:'historical',identity_current:false,identity_at:'2026-09-30T09:00:00Z',identity_expires_at:'2026-10-01T09:00:00Z',identity_evidence_id:'proof-'+'a'.repeat(100),identity_assessment_id:'router-22',identity_basis:'DHCP 明确型号提供身份依据',address_state:'verified',address_last_activity_at:'2026-10-05T15:29:00Z',last_shared_at:'2026-09-30T09:00:00Z',last_shared_observation_id:'old-share-22',current_shared:false,address_only:false,auth_bindings:[{session_id:'auth-22',account_id:'20260022',assigned_ips:['222.204.10.22','2001:db8::22'],mac:'20:3a:eb:e9:de:10',source:'ncu-srun4k',match_basis:'exact_mac',ambiguous:false}]}
  const vendor={...identity,profile_id:'vendor-63',endpoint_id:'mac:20:3a:eb:e9:de:63',mac:'20:3a:eb:e9:de:63',ip:'192.168.0.63',brand:'TP-Link',model:'',role:'',identity_state:'reference',identity_basis:'TP-Link 云证书关联，仅作为厂商线索',last_shared_at:undefined,last_shared_observation_id:undefined,auth_bindings:[]}
  const second={...identity,profile_id:'router-page-2',ip:'192.168.0.99',brand:'Ruijie',model:'RG-EG',auth_bindings:[]}
  const legacy={observation_id:'old-share-82',sensor_id:'office',ip:'192.168.0.82',endpoint_id:'mac:42:59:38:7a:fc:b3',status:'confirmed',confidence:100,signal_groups:['tcp_stack','tls_stack','ua_os'],reasons:['旧规则协议差异判断'],conflicts:[],coverage_state:'verified',rule_version:'shared-behavior/v8',current:false,first_seen:'2026-09-30T09:30:00Z',last_seen:'2026-09-30T09:39:29Z',window_start:'2026-09-30T09:30:00Z',window_end:'2026-09-30T09:40:00Z',router:{},score_components:[],feature_samples:{},event_ids:['legacy-proof'],known_devices:[]}
  const strong={...legacy,observation_id:'old-share-22',ip:'192.168.0.22',strong_anchor:'ieee1905_association',device_lower_bound:8,signal_groups:['ieee1905_association'],confidence:90,rule_version:'shared-behavior/v10'}
  window.fetch=async(...args)=>{
   const url=String(args[0]);let value:unknown
   if(url.includes('/shared-access/devices?')) {if(url.includes('cursor=20')) await new Promise(resolve=>setTimeout(resolve,500));value={items:url.includes('cursor=20')?[second]:[identity,vendor],page:{total:21,limit:20},checked_at:checked}}
   else if(url.includes('/shared-access/observations/')) value={...legacy,history:[{status:'confirmed',confidence:100,signal_groups:['tcp_stack'],coverage_state:'verified',rule_version:'shared-behavior/v8',observed_at:legacy.last_seen,created_at:legacy.last_seen}]}
   else if(url.includes('/shared-access/observations?')) value={items:url.includes('view=history')?(url.includes('history_basis=clues')?[legacy]:[strong]):[],page:{total:url.includes('view=history')?1:0,limit:20}}
   else return original(...args)
   return new Response(JSON.stringify(value),{status:200,headers:{'Content-Type':'application/json'}})
  }
 })
 await page.goto('/shared-access')
 await expect(page.getByRole('tab',{name:'设备档案',exact:true})).toHaveAttribute('aria-selected','true')
 const deviceList=width<=1599?page.locator('.shared-profile-mobile-list'):page.locator('.shared-profile-desktop-list')
 await expect(deviceList.getByText('ZTE SR7410-20',{exact:true})).toBeVisible()
 await expect(deviceList.getByText('历史身份依据',{exact:true})).toBeVisible()
 await expect(deviceList.getByText('20260022',{exact:true})).toBeVisible()
 await expect(deviceList.getByText('MAC 精确匹配',{exact:true})).toBeVisible()
 const vendor=deviceList.locator('.shared-profile-reference')
  await expect(vendor).toContainText('辅助识别线索')
 await expect(vendor).not.toContainText('路由器画像')
 if(width>=1280){
  const adaptiveRow=await vendor.evaluate(element=>{const row=element.getBoundingClientRect();const blocks=[...element.querySelectorAll('.shared-profile-mobile-block')].filter(child=>child.getBoundingClientRect().width>0);const last=blocks.at(-1)?.getBoundingClientRect();return {blockCount:blocks.length,rightGap:last?Math.round(row.right-last.right):-1}})
  expect(adaptiveRow.blockCount).toBe(3);expect(adaptiveRow.rightGap).toBeLessThanOrEqual(2)
 }
 await expect(page.getByText('已确认当前共享',{exact:true})).toHaveCount(0)
 await expect(page.locator('.shared-profile-card')).toHaveCount(0)
 const dir=path.resolve('test-results/shared-device-archive');await mkdir(dir,{recursive:true})
 const audit=async(name:string)=>{
  const probe=await page.evaluate(()=>{const pagination=document.querySelector('.shared-profile-panel>.app-server-pagination')?.getBoundingClientRect();const overlapsPagination=pagination?[...document.querySelectorAll('.shared-profile-mobile-row')].filter(element=>{const row=element.getBoundingClientRect();return row.width>0&&row.top<pagination.bottom&&row.bottom>pagination.top}).length:0;return {overflow:document.documentElement.scrollWidth>innerWidth+2,visibleHorizontalScrollers:[...document.querySelectorAll('.shared-profile-panel *')].filter(element=>{const node=element as HTMLElement;const style=getComputedStyle(node);return node.getBoundingClientRect().width>0&&node.scrollWidth>node.clientWidth+2&&['auto','scroll'].includes(style.overflowX)}).map(element=>element.className),overlapsPagination,missingLabels:[...document.querySelectorAll('main')].map(e=>e.textContent).filter(t=>/未识别|未获取|未关联|未观测|未知/.test(t||'')),controls:[...document.querySelectorAll('.ant-btn,.ant-tag')].filter(e=>getComputedStyle(e).whiteSpace!=='nowrap'||getComputedStyle(e).flexShrink!=='0').map(e=>e.textContent),emphasis:[...document.querySelectorAll('.shared-profile-device strong')].filter(e=>e.getBoundingClientRect().width>0).map(e=>({text:e.textContent,size:getComputedStyle(e).fontSize,weight:getComputedStyle(e).fontWeight,color:getComputedStyle(e).color})),cards:document.querySelectorAll('.shared-profile-card').length,listRows:[...document.querySelectorAll('.shared-profile-desktop-list tbody tr,.shared-profile-mobile-row')].filter(e=>e.getBoundingClientRect().width>0).length}})
  expect(probe.overflow).toBe(false);expect(probe.visibleHorizontalScrollers).toEqual([]);expect(probe.overlapsPagination).toBe(0);expect(probe.controls).toEqual([]);expect(probe.missingLabels).toEqual([])
  await writeFile(path.join(dir,`${name}-dom-${width}.json`),JSON.stringify(probe,null,2));await page.screenshot({path:path.join(dir,`${name}-${width}.png`),fullPage:true,animations:'disabled'})
 }
 await audit('devices')
 await page.locator('.app-server-pagination .ant-pagination-next').click()
 await expect(page.getByText('正在加载第 2 页',{exact:true})).toBeVisible()
 await expect(deviceList.getByText('ZTE SR7410-20',{exact:true})).toHaveCount(0)
 await expect(page.locator('.app-server-pagination')).toHaveClass(/ant-pagination-disabled/)
 const loadingProbe=await page.evaluate(()=>({
  oldPageRows:[...document.querySelectorAll('.shared-profile-desktop-list tbody tr,.shared-profile-mobile-row')].filter(element=>element.getBoundingClientRect().width>0).length,
  paginationDisabled:document.querySelector('.app-server-pagination')?.classList.contains('ant-pagination-disabled')||false,
  loadingText:document.querySelector('.shared-profile-page-loading')?.textContent||'',
 }))
 expect(loadingProbe.oldPageRows).toBe(0);expect(loadingProbe.paginationDisabled).toBe(true);expect(loadingProbe.loadingText).toContain('正在加载第 2 页')
 await writeFile(path.join(dir,`devices-loading-dom-${width}.json`),JSON.stringify(loadingProbe,null,2))
 await page.screenshot({path:path.join(dir,`devices-loading-${width}.png`),fullPage:true,animations:'disabled'})
 await expect(deviceList.getByText('Ruijie RG-EG',{exact:true})).toBeVisible()
 await page.getByRole('tab',{name:'当前共享',exact:true}).click()
 await expect(page.getByText('当前没有可确认的共享记录',{exact:true})).toBeVisible()
 await page.getByRole('tab',{name:'历史观察',exact:true}).click()
 await expect(page.getByText('192.168.0.22',{exact:true})).toBeVisible()
 await expect(page.getByText('192.168.0.82',{exact:true})).toHaveCount(0)
 await expect(page.getByText('历史多终端证据，需核对当前状态',{exact:true})).toBeVisible()
 await audit('history-default')
 await page.getByRole('combobox',{name:'历史证据范围'}).click()
 await page.getByTitle('旧规则线索复核',{exact:true}).click()
 await expect(page).toHaveURL(/history_basis=clues/)
 await expect(page.getByText('192.168.0.82',{exact:true})).toBeVisible()
 await expect(page.getByText('历史协议线索，需复核',{exact:true})).toBeVisible()
 const behaviorList=width<=560?page.locator('.shared-behavior-mobile-list'):page.locator('.shared-behavior-desktop-list')
 await expect(behaviorList.locator('.ant-tag-green')).toHaveCount(0)
 await audit('history')
 await behaviorList.getByRole('button',{name:'查看计分与原始证据引用'}).click()
 await behaviorList.getByRole('link',{name:'查看完整识别记录',exact:true}).click()
 await expect(page.getByRole('heading',{name:'历史共享观察：192.168.0.82'})).toBeVisible()
 await expect(page.locator('.ant-tag-green')).toHaveCount(0)
 await audit('historical-detail')
})
