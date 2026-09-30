import {test,expect} from '@playwright/test'

for(const window of ['7d','30d'])test(`application chart drill-down retains ${window} and site conditions`,async({page})=>{
 await page.setViewportSize({width:1440,height:900})
 await page.goto(`/activity?section=access&window=${window}&sensor_id=campus-sensor&campus_id=east`)
 const chart=page.locator('.report-chart-card').filter({hasText:'应用协议分布'}).locator('.report-chart')
 await expect(chart.locator('canvas')).toBeVisible()
 const bounds=await chart.boundingBox();expect(bounds).not.toBeNull()
 // The first slice spans the right side of the donut in the replay fixture.
 await chart.click({position:{x:bounds!.width*.5+Math.min(bounds!.width,bounds!.height)*.29,y:bounds!.height*.43}})
 await expect(page).toHaveURL(/\/events\?/)
 const query=new URL(page.url()).searchParams
 expect(query.get('window')).toBe(window);expect(query.get('app_protocol')).toBe('http2');expect(query.get('sensor_id')).toBe('campus-sensor');expect(query.get('campus_id')).toBe('east')
})
