import { expect, test } from '@playwright/test'

test('confirmed type overview stays readable at the required viewports', async ({page}) => {
  const consoleErrors:string[]=[],networkErrors:string[]=[]
  page.on('console',entry=>{if(entry.type()==='error')consoleErrors.push(entry.text())})
  page.on('response',response=>{if(response.status()>=400)networkErrors.push(`${response.status()} ${response.url()}`)})
  for(const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]){
    await page.setViewportSize(viewport)
    await page.goto('/discovery')
    const overview=page.getByLabel('发现设备总览')
    await expect(overview).toContainText('已识别类型（合计')
    const probe=await overview.evaluate(element=>({
      labels:[...element.querySelectorAll('.discovery-overview-type')].map(button=>(button.textContent??'').replace(/\s+\d+$/, '').trim()),
      overflow:element.scrollWidth>element.clientWidth+2,
      badButtons:[...element.querySelectorAll('.ant-btn')].filter(button=>{const style=getComputedStyle(button);return style.whiteSpace!=='nowrap'||style.flexShrink!=='0'}).length,
    }))
    expect(probe.labels.length).toBeGreaterThan(0)
    expect(new Set(probe.labels).size).toBe(probe.labels.length)
    expect(probe.overflow).toBe(false)
    expect(probe.badButtons).toBe(0)
    await page.screenshot({path:`test-results/discovery-hotfix-${viewport.width}x${viewport.height}.png`,fullPage:true})
    await overview.locator('.discovery-overview-type').first().click()
    await expect(page).toHaveURL(/discovery_state=identified/)
  }
  expect(consoleErrors).toEqual([])
  expect(networkErrors).toEqual([])
})
