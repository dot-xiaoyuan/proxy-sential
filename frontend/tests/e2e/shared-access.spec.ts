import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

for (const [width, height] of [[390,844],[1280,800],[1440,900]]) test(`shared review workflow ${width}`,async({page})=>{
 await page.setViewportSize({width,height})
 await page.addInitScript(()=>{
  const original=window.fetch
  const result={state:'basis_present',reasons:['requires_review'],signal_groups:['UA','TTL','TLS'],quantity_known:false,device_lower_bound:0,confidence:0.7,from:'2026-09-18T06:00:00Z',to:'2026-09-18T06:00:20Z'}
  let conclusion:object|undefined
  window.fetch=async(...args)=>{
   const url=String(args[0]);if(!url.includes('/shared-access/'))return original(...args)
   const review={review_id:'review-office-test',account_id:'yuantong',campus_id:'office-test',access_domain:'office-lan',session_generation:'generation-'+'a'.repeat(90),episode:1,latest_version:2,latest_result:result,coverage_state:'unknown',last_conclusion:conclusion}
   const behavior={observation_id:'shared-behavior-test',sensor_id:'idle-test',campus_id:'ncu',access_domain:'campus-mirror',ip:'172.21.20.171',endpoint_id:'endpoint-test',status:'confirmed',confidence:95,signal_groups:['ua_os','ttl_path','tcp_stack'],reasons:['至少两类独立共享行为信号反复共现','满足高置信度共享网关确认条件'],conflicts:[],coverage_state:'verified',rule_version:'shared-behavior/v11',current:true,strong_anchor:'coexisting_device_models',device_lower_bound:2,first_seen:'2026-09-28T10:00:00Z',last_seen:'2026-09-28T10:09:30Z',window_start:'2026-09-28T10:00:00Z',window_end:'2026-09-28T10:10:00Z',expires_at:'2026-10-28T10:10:00Z',router:{},score_components:[{signal:'ua_os',score:30,explanation:'同一出口反复共现多个操作系统 User-Agent'},{signal:'ttl_path',score:35,explanation:'同一出口反复共现多个归一化 TTL 路径'},{signal:'tcp_stack',score:30,explanation:'同一出口反复共现多个 TCP SYN 协议栈指纹'}],feature_samples:{ua_os:{Android:{count:3,buckets:[1,2]},Windows:{count:3,buckets:[1,2]}},ttl_path:{'initial=64,hops=0,observed=64':{count:3,buckets:[1,2]},'initial=128,hops=0,observed=128':{count:3,buckets:[1,2]}},tcp_stack:{'mss=1380,ws=9,sack=true,ts=true,df=true,opt=2-4-8-1-3':{count:3,buckets:[1,2]},'mss=1380,ws=6,sack=true,ts=true,df=true,opt=2-1-3-1-1-8-4-0':{count:3,buckets:[1,2]}}},event_ids:['device-'+'a'.repeat(90),'zeek-'+'b'.repeat(90)],known_device_count:2,known_device_basis:'explicit_hardware_model_lower_bound',known_device_window:'24h',known_devices:[{identity_id:'known-1',brand:'Honor',model:'MAA-AN00',os_family:'Android',device_type:'mobile',observations:8,first_seen:'2026-09-28T01:00:00Z',last_seen:'2026-09-28T10:09:00Z'},{identity_id:'known-2',brand:'Apple',model:'iPhone18,4',os_family:'iOS',device_type:'mobile',observations:2,first_seen:'2026-09-28T02:00:00Z',last_seen:'2026-09-28T10:08:00Z'}]}
   let value:unknown
   if(url.includes('/status'))value={checked_at:new Date().toISOString(),identity:[{connector_id:'office',scope:{campus_id:'office-test',access_domain:'office-lan'},state:'unavailable',blocker:'inventory_completeness_unproven',fresh:false,observed_at:'2026-09-18T06:00:20Z',record_count:1}],collection:{state:'unknown',blocker:'capture_coverage_not_verified'},materialization:{state:'unknown',blocker:'materialization_freshness_not_verified'},policy:{state:'blocked',blocker:'shared_review_gate_not_verified'},controller:{state:'blocked',blocker:'manual_action_not_verified'}}
   else if(url.includes('/observations?'))value={items:[behavior],page:{limit:20,next_cursor:null,total:1}}
   else if(url.includes('/observations/'))value={...behavior,history:[{status:'confirmed',confidence:95,signal_groups:behavior.signal_groups,coverage_state:'verified',rule_version:'shared-behavior/v3',observed_at:behavior.last_seen,created_at:behavior.last_seen}]}
   else if(url.includes('/evidence'))value={items:[{version:2,created_at:'2026-09-18T06:00:20Z',evidence:{result,window:{feature_samples:{ua_os:{Android:{count:3,buckets:[1,2]},Windows:{count:3,buckets:[1,2]}}},records:[{event_id:'e'.repeat(120),source:'synthetic-replay'}]}}}],next_cursor:''}
   else if(url.includes('/executions'))value={items:[],next_cursor:''}
   else if(url.includes('/conclusion')) {const req=JSON.parse(String(args[1]?.body));conclusion={...req,evidence_version:2,operator_id:'mock-operator',created_at:new Date().toISOString()};value={enforcement_ready:false}}
   else if(url.includes('/reviews?'))value={items:[review],next_cursor:''}
   else value=review
   return new Response(JSON.stringify(value),{status:200,headers:{'Content-Type':'application/json'}})
  }
 })
 await page.goto('/shared-access?tab=observations')
 await page.getByText('链路状态与处置准入说明').click()
 await expect(page.getByText('清单完整性尚未证明')).toBeVisible()
 await expect(page.getByText('172.21.20.171')).toBeVisible()
 await expect(page.getByText('当前窗口设备下界：2 台')).toBeVisible()
 await page.getByText('链路状态与处置准入说明').click()
 const listDir=path.resolve('test-results/shared-access');await mkdir(listDir,{recursive:true})
 const listProbe=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth+2,controls:[...document.querySelectorAll('.ant-btn,.ant-tag')].filter(e=>getComputedStyle(e).whiteSpace!=='nowrap'||getComputedStyle(e).flexShrink!=='0').map(e=>e.textContent)}))
 expect(listProbe.overflow).toBe(false);expect(listProbe.controls).toEqual([])
 await writeFile(path.join(listDir,`list-dom-${width}.json`),JSON.stringify(listProbe,null,2));await page.screenshot({path:path.join(listDir,`list-${width}.png`),fullPage:true,animations:'disabled'})
 const behaviorList=width<=560?page.locator('.shared-behavior-mobile-list'):page.locator('.shared-behavior-desktop-list')
 await behaviorList.getByRole('button',{name:'查看计分与原始证据引用'}).click()
 await behaviorList.getByRole('link',{name:'查看完整识别记录'}).click()
 await expect(page.getByRole('heading',{name:'共享网关识别记录：172.21.20.171'})).toBeVisible()
 await expect(page.getByText('当前窗口设备下界：2 台')).toBeVisible()
 await page.getByText('近 24 小时型号参考（不计入当前共享判定）').click()
 await expect(page.getByText('Honor MAA-AN00')).toBeVisible()
 const behaviorProbe=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth+2,controls:[...document.querySelectorAll('.ant-btn,.ant-tag')].filter(e=>getComputedStyle(e).whiteSpace!=='nowrap'||getComputedStyle(e).flexShrink!=='0').map(e=>e.textContent),inlineStyles:document.querySelectorAll('[style]').length}))
 expect(behaviorProbe.overflow).toBe(false);expect(behaviorProbe.controls).toEqual([])
 const dir=path.resolve('test-results/shared-access');await mkdir(dir,{recursive:true});await writeFile(path.join(dir,`behavior-dom-${width}.json`),JSON.stringify(behaviorProbe,null,2));await page.screenshot({path:path.join(dir,`behavior-${width}.png`),fullPage:true,animations:'disabled'})
 await page.goto('/shared-access?tab=reviews')
 await page.getByRole('link',{name:'yuantong',exact:true}).click()
 await expect(page.getByText('依据版本 2',{exact:true})).toBeVisible()
 await expect(page.getByText('暂无执行记录；复核结论不会自动下线')).toBeVisible()
 await page.getByText('原始证据引用（有界摘要）').click()
 const probe=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth+2,controls:[...document.querySelectorAll('.ant-btn,.ant-tag')].filter(e=>getComputedStyle(e).whiteSpace!=='nowrap'||getComputedStyle(e).flexShrink!=='0').map(e=>e.textContent)}))
 expect(probe.overflow).toBe(false);expect(probe.controls).toEqual([])
 await writeFile(path.join(dir,`dom-${width}.json`),JSON.stringify(probe,null,2));await page.screenshot({path:path.join(dir,`${width}.png`),fullPage:true,animations:'disabled'})
 await page.getByRole('button',{name:'记录人工结论'}).click()
 const dialog=page.getByRole('dialog');await dialog.getByLabel('复核结论').click();await page.getByText('证据不足',{exact:true}).last().click();await dialog.getByLabel('复核理由').fill('隔离回放，采集覆盖尚未验证');
 const modalProbe=await dialog.evaluate(el=>({footerBottom:el.querySelector('.ant-modal-footer')!.getBoundingClientRect().bottom,controls:[...el.querySelectorAll('.ant-btn')].filter(e=>getComputedStyle(e).whiteSpace!=='nowrap'||getComputedStyle(e).flexShrink!=='0').map(e=>e.textContent)}));expect(modalProbe.footerBottom).toBeLessThanOrEqual(height);expect(modalProbe.controls).toEqual([]);await writeFile(path.join(dir,`modal-dom-${width}.json`),JSON.stringify(modalProbe,null,2));await page.screenshot({path:path.join(dir,`${width}-conclusion.png`),animations:'disabled'});
 await dialog.getByRole('button',{name:'保存结论'}).click()
 await expect(dialog).toHaveCount(0);await expect(page.getByText('隔离回放，采集覆盖尚未验证')).toBeVisible()
})
