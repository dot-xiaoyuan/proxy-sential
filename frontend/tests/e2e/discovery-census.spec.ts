import { expect, test } from '@playwright/test'

test('mirror census stays readable and scoped at three viewports', async ({page}) => {
  const consoleErrors:string[]=[],networkErrors:string[]=[]
  page.on('console',message=>{if(message.type()==='error')consoleErrors.push(message.text())})
  page.on('response',response=>{if(response.status()>=400)networkErrors.push(`${response.status()} ${response.url()}`)})
  for(const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]){
    await page.setViewportSize(viewport)
    await page.goto('/discovery')
    const panel=page.getByRole('region',{name:'镜像可见标识统计'})
    await expect(panel).toBeVisible()
    await expect(panel.locator('.census-card').first()).toContainText('2')
    await expect(panel.getByText('传感器 sensor-test',{exact:false})).toBeVisible()
    await page.screenshot({path:`test-results/discovery-census-${viewport.width}x${viewport.height}.png`,fullPage:true})
    const probe=await page.evaluate(()=>{
      const panel=document.querySelector('.census-panel')!
      const cards=[...panel.querySelectorAll('.census-card')]
      const badButtons=[...panel.querySelectorAll('.ant-btn')].filter(button=>{const style=getComputedStyle(button);return style.whiteSpace!=='nowrap'||style.flexShrink!=='0'}).length
      const selected=panel.querySelector('.census-card.is-active')!
      const rgb=(value:string)=>[...value.matchAll(/[\d.]+/g)].slice(0,3).map(match=>Number(match[0]))
      const luminance=(value:string)=>rgb(value).reduce((sum,channel,index)=>{const scaled=channel/255;return sum+[.2126,.7152,.0722][index]*(scaled<=.04045?scaled/12.92:((scaled+.055)/1.055)**2.4)},0)
      const foreground=luminance(getComputedStyle(selected).color),background=luminance(getComputedStyle(selected).backgroundColor)
      const contrast=(Math.max(foreground,background)+.05)/(Math.min(foreground,background)+.05)
      return {documentOverflow:document.documentElement.scrollWidth>innerWidth+2,panelOverflow:panel.scrollWidth>panel.clientWidth+2,badButtons,cardCount:cards.length,cardOverflow:cards.filter(card=>card.scrollWidth>card.clientWidth+2).length,selectedContrast:contrast}
    })
    expect(probe.documentOverflow).toBe(false)
    expect(probe.panelOverflow).toBe(false)
    expect(probe.badButtons).toBe(0)
    expect(probe.cardCount).toBe(4)
    expect(probe.cardOverflow).toBe(0)
    expect(probe.selectedContrast).toBeGreaterThanOrEqual(4.5)
    await panel.getByLabel('导入对方 CSV').setInputFiles({name:'对照.csv',mimeType:'text/csv',buffer:Buffer.from('scope,ip,mac,type\nsensor-test|主校区|教学网|20|,192.0.2.10,00:11:22:33:44:55,打印机\n')})
    await panel.getByRole('button',{name:'开始本地比对'}).click()
    await expect(panel.getByText('双方共有 1')).toBeVisible()
    await panel.locator('.census-compare').scrollIntoViewIfNeeded()
    await page.screenshot({path:`test-results/discovery-census-compare-${viewport.width}x${viewport.height}.png`})
    const comparisonOverflow=await panel.locator('.census-compare').evaluate(element=>element.scrollWidth>element.clientWidth+2)
    expect(comparisonOverflow).toBe(false)
  }
  expect(consoleErrors).toEqual([])
  expect(networkErrors).toEqual([])
})
