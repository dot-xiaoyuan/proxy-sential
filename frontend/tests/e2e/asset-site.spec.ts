import {expect, test} from '@playwright/test'
import {mockSession} from '../../src/mocks/fixtures'
import {writeFile} from 'node:fs/promises'
import {reviewColumns} from '../../src/pages/truthReview'

for (const [width,height] of [[390,844],[1280,800],[1440,900]]) {
  for (const profile of ['passive_assets','shared']) {
    test(profile+' navigation and report '+width, async ({page}, info) => {
      const errors:string[]=[]
      page.on('pageerror',e=>errors.push(e.message))
      page.on('console',e=>{if(e.type()==='error')errors.push(e.text())})
      page.on('response',r=>{if(r.status()>=400)errors.push(String(r.status())+' '+r.url())})
      await page.setViewportSize({width,height})
      await page.addInitScript(session=>{
        const original=window.fetch
        window.fetch=async (...args)=>{
          const url=args[0] instanceof Request ? args[0].url : String(args[0])
          if(new URL(url,location.href).pathname==='/api/v1/session')return Response.json(session)
          return original(...args)
        }
      },profile==='shared'?mockSession:{...mockSession,site_profile:'passive_assets'})
      await page.goto('/overview')
      if(profile==='passive_assets'){
        await expect(page).toHaveURL(/\/devices\/coverage/)
        await expect(page.getByRole('heading',{name:'资产总览报表',level:1})).toBeVisible()
        await expect(page.getByRole('region',{name:'设备发现覆盖报表'})).toBeVisible()
      } else await expect(page.getByRole('heading',{name:'运营工作台',level:1})).toBeVisible()
      if(width===390)await page.getByRole('button',{name:'打开导航'}).click()
      const menus=page.getByRole('menu').filter({visible:true})
      await expect(menus.getByText('运营工作台',{exact:true})).toHaveCount(profile==='shared'?1:0)
      await expect(menus.getByText('设备中心',{exact:true})).toBeVisible()
      if(profile==='passive_assets'){
        await expect(menus.getByText('资产总览报表',{exact:true})).toHaveCount(1)
        await expect(menus.getByText('全局数据报表',{exact:true})).toHaveCount(0)
      }
      await page.screenshot({path:info.outputPath('navigation.png'),animations:'disabled'})
      if(profile==='passive_assets'){
        await page.goto('/devices/coverage?section=review')
        await expect(page.getByRole('heading',{name:'人工核实结果'})).toBeVisible()
        const csv=[reviewColumns.join(','),'sample-1,系统抽样,打印机,M1,已确认,打印机,M1,实物,是,2026-11-25,测试','sample-2,独立台账,,,,打印机,M1,台账,否,2026-11-25,测试'].join('\n')
        await page.getByLabel('核实表 CSV').setInputFiles({name:'sample.csv',mimeType:'text/csv',buffer:Buffer.from(csv)})
        await expect(page.getByText('品类准确率',{exact:true})).toBeVisible()
        await expect(page.getByText('0 / 1（0.0%）').first()).toBeVisible()
        await page.screenshot({path:info.outputPath('review.png'),animations:'disabled'})
        for (const days of [7,30]) {
          await page.goto('/devices/coverage?window='+days*24+'h')
          const heading=page.getByRole('heading',{name:'近 '+days+' 天硬件身份变化'})
          await expect(heading).toBeVisible()
          await heading.scrollIntoViewIfNeeded()
          await page.screenshot({path:info.outputPath('trend-'+days+'.png'),animations:'disabled'})
        }
      }
      const probe=await page.evaluate(()=>({
        viewport:innerWidth,
        overflow:document.documentElement.scrollWidth>innerWidth+2,
        badControls:[...document.querySelectorAll('.ant-btn,.ant-tag')].filter(e=>e.getClientRects().length && (getComputedStyle(e).whiteSpace!=='nowrap'||getComputedStyle(e).flexShrink!=='0')).length,
      }))
      await writeFile(info.outputPath('layout.json'),JSON.stringify({probe,errors},null,2))
      expect(probe.overflow).toBe(false)
      expect(probe.badControls).toBe(0)
      expect(errors).toEqual([])
    })
  }
}
