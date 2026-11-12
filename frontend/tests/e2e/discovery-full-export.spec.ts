import { expect, test } from '@playwright/test'

test('full filtered export is clear and usable at all required viewports', async ({page}) => {
  const consoleErrors:string[]=[],networkErrors:string[]=[]
  page.on('console',entry=>{if(entry.type()==='error')consoleErrors.push(entry.text())})
  page.on('response',response=>{if(response.status()>=400)networkErrors.push(`${response.status()} ${response.url()}`)})
  for(const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]){
    await page.setViewportSize(viewport)
    await page.goto('/discovery')
    const button=page.getByRole('button',{name:'导出全部筛选结果'})
    await expect(button).toBeVisible()
    const probe=await button.evaluate(element=>{
      const style=getComputedStyle(element)
      const bounds=element.getBoundingClientRect()
      return {whiteSpace:style.whiteSpace,flexShrink:style.flexShrink,insideViewport:bounds.left>=0&&bounds.right<=innerWidth+1,overflow:document.documentElement.scrollWidth>innerWidth+2}
    })
    expect(probe).toEqual({whiteSpace:'nowrap',flexShrink:'0',insideViewport:true,overflow:false})
    await page.screenshot({path:`test-results/discovery-full-export-${viewport.width}x${viewport.height}.png`,fullPage:true})
  }
  expect(consoleErrors).toEqual([])
  expect(networkErrors).toEqual([])
})
