import {expect, test} from '@playwright/test'
import {writeFile} from 'node:fs/promises'

test('persistent hardware, activity, and sources remain distinct at three viewports', async ({page},testInfo)=>{
  const errors:string[]=[]
  page.on('pageerror',error=>errors.push(error.message))
  page.on('console',message=>{if(message.type()==='error')errors.push(message.text())})
  page.on('response',response=>{if(response.status()>=400)errors.push(`${response.status()} ${response.url()}`)})
  await page.goto('/discovery')
  await expect(page.locator('.passive-ledger-table')).toBeVisible()
  await page.evaluate(async()=>{const path='/src/mocks/hardwareReplay.ts';const fixture=await import(path);fixture.installHardwareReplay()})
  await page.getByRole('button',{name:'刷新数据'}).click()
  const ledger = page.locator('.passive-ledger-table')
  const printer = ledger.locator('tr[data-row-key]').filter({ has: page.getByRole('button', {name:'00:11:22:33:44:55', exact:true}) })
  await expect(printer.locator('.discovery-identity-name')).toHaveText('回放多功能打印机')
  await expect(ledger.getByRole('button', {name:'回放多功能打印机', exact:true})).toHaveCount(0)
  await expect(ledger.getByRole('button', {name:'00:11:22:33:44:66', exact:true})).toBeVisible()
  await expect(page.getByText('最近活动线索已过期',{exact:true})).toBeVisible()
  await expect(page.getByLabel('发现设备总览')).toContainText('已确认 2')
  const observation = ledger.getByRole('row').filter({hasText:'192.0.2.40'})
  await expect(observation.getByRole('button', {name:'地址线索', exact:true})).toBeVisible()
  await expect(observation.getByRole('button', {name:'192.0.2.40', exact:true})).toHaveCount(0)
  await page.getByRole('button',{name:'统计与类型线索'}).click()
  await expect(page.getByLabel('画像类型线索').getByRole('button', {name:/手机/})).toBeVisible()
  await page.getByRole('button',{name:'收起统计'}).click()
  await expect(page.locator('.passive-ledger-table').getByText('疑似手机',{exact:true})).toBeVisible()
  await expect(page.locator('.center-list-surface.is-updating')).toHaveCount(0)
  for(const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]){
    await page.setViewportSize(viewport)
    await page.locator('.passive-ledger-table').scrollIntoViewIfNeeded()
    await page.screenshot({path:`test-results/discovery-hardware-${viewport.width}x${viewport.height}.png`,fullPage:true,animations:'disabled'})
    const probe=await page.evaluate(()=>({
      overflow:document.documentElement.scrollWidth>innerWidth+2,
      badButtons:[...document.querySelectorAll('.ant-btn')].filter(button=>{const style=getComputedStyle(button);return style.whiteSpace!=='nowrap'||style.flexShrink!=='0'}).length,
      cardOverflow:[...document.querySelectorAll('.census-card,.census-type')].some(card=>card.scrollWidth>card.clientWidth+2),
    }))
    expect(probe).toEqual({overflow:false,badButtons:0,cardOverflow:false})
    // The mobile table is taller than the viewport: scrolling its wrapper can
    // leave the first row above the clipped app-content scroller. Visibility
    // alone permits offscreen elements and does not wait for responsive paint.
    const deviceButton=page.locator('.passive-ledger-table').getByRole('button',{name:'00:11:22:33:44:55',exact:true})
    await deviceButton.scrollIntoViewIfNeeded()
    await expect(deviceButton).toBeInViewport({ratio:1})
    await expect.poll(()=>deviceButton.evaluate(async button=>{
      const position=()=>{
        const rect=button.getBoundingClientRect()
        return JSON.stringify([rect.x,rect.y,rect.width,rect.height,document.querySelector('.app-content')?.scrollTop])
      }
      // ResizeObserver/AntD sticky columns settle before the next paint. Wait
      // for two real frames, then require stable geometry rather than sleeping.
      await new Promise<void>(resolve=>requestAnimationFrame(()=>resolve()))
      const first=position()
      await new Promise<void>(resolve=>requestAnimationFrame(()=>resolve()))
      return first===position()
    })).toBe(true)
    const paintProbe=await deviceButton.evaluate(button=>{
      const ancestors=[]
      for(let node:Element|null=button;node;node=node.parentElement){const s=getComputedStyle(node);const r=node.getBoundingClientRect();ancestors.push({node:node.tagName,classes:node.className,rect:{x:r.x,y:r.y,width:r.width,height:r.height},opacity:s.opacity,visibility:s.visibility,display:s.display,transform:s.transform,overflow:s.overflow,scrollTop:node.scrollTop,scrollLeft:node.scrollLeft,scrollHeight:node.scrollHeight,clientHeight:node.clientHeight})}
      const rect=button.getBoundingClientRect()
      const hit=document.elementFromPoint(rect.x+rect.width/2,rect.y+rect.height/2)
      return {viewport:{width:innerWidth,height:innerHeight},ancestors,unobscured:!!hit&&(button===hit||button.contains(hit)),animations:document.getAnimations().map(a=>({playState:a.playState,currentTime:a.currentTime,effect:a.effect instanceof KeyframeEffect?String((a.effect.target as Element)?.className):''}))}
    })
    expect(paintProbe.unobscured).toBe(true)
    expect(paintProbe.ancestors.every(node=>Number(node.opacity)===1&&node.visibility==='visible'&&node.display!=='none')).toBe(true)
    const screenshot=await page.screenshot({path:`test-results/discovery-hardware-list-${viewport.width}x${viewport.height}.png`,animations:'disabled'})
    // Assert the delivered PNG actually painted the row's label. This catches a
    // blank compositor frame even when DOM visibility and hit testing pass.
    const paintedPixels=await page.evaluate(async({data,rect})=>{
      const image=new Image()
      image.src=`data:image/png;base64,${data}`
      await image.decode()
      const canvas=document.createElement('canvas')
      canvas.width=image.width;canvas.height=image.height
      const context=canvas.getContext('2d')!
      context.drawImage(image,0,0)
      const scale=image.width/innerWidth
      const pixels=context.getImageData(Math.floor(rect.x*scale),Math.floor(rect.y*scale),Math.ceil(rect.width*scale),Math.ceil(rect.height*scale)).data
      let ink=0
      for(let i=0;i<pixels.length;i+=4){if(pixels[i]<220||pixels[i+1]<220||pixels[i+2]<220)ink++}
      return ink
    },{data:screenshot.toString('base64'),rect:paintProbe.ancestors[0].rect})
    const probePath=`test-results/discovery-hardware-list-${viewport.width}x${viewport.height}.dom.json`
    await writeFile(probePath,JSON.stringify({...paintProbe,viewportAudit:probe,paintedPixels},null,2))
    await testInfo.attach(`paint-before-list-${viewport.width}`,{path:probePath,contentType:'application/json'})
    expect(paintedPixels,'the list screenshot must contain the visible device label').toBeGreaterThan(30)
    await deviceButton.click()
    const dialog=page.getByRole('dialog')
    await expect(dialog.getByText('类型依据时间',{exact:true})).toBeVisible()
    await expect(dialog.getByText('source-event:hardware-printer',{exact:true})).toBeVisible()
    await expect(dialog.getByText('Canon MF260 Series',{exact:true})).toBeVisible()
    await expect.poll(()=>dialog.evaluate(element=>{const style=getComputedStyle(element);return style.opacity==='1'&&style.transform==='none'})).toBe(true)
    await page.screenshot({path:`test-results/discovery-hardware-detail-${viewport.width}x${viewport.height}.png`,animations:'disabled'})
    expect(await dialog.evaluate(element=>element.scrollWidth>element.clientWidth+2)).toBe(false)
    await dialog.getByRole('button',{name:'Close',exact:true}).click()
    await expect(dialog).not.toBeVisible()
  }
  expect(errors).toEqual([])
})

test('computer clues fill the detail panel at mobile and desktop widths', async ({page}, testInfo) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  page.on('console', entry => { if (entry.type() === 'error') errors.push(entry.text()) })
  page.on('requestfailed', request => { if (request.failure()?.errorText !== 'net::ERR_ABORTED') errors.push(request.url()) })
  page.on('response', response => { if (response.status() >= 400) errors.push(String(response.status()) + ' ' + response.url()) })
  await page.goto('/discovery')
  await expect(page.locator('.passive-ledger-table')).toBeVisible()
  await page.evaluate(async () => { const path = '/src/mocks/hardwareReplay.ts'; (await import(path)).installHardwareReplay() })
  await page.getByRole('button', {name:'刷新数据'}).click()
  for (const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]) {
    await page.setViewportSize(viewport)
    await page.getByRole('button', {name:'00:11:22:33:44:78'}).click()
    const dialog = page.getByRole('dialog')
    const summary = dialog.getByRole('region', {name:'设备类型'})
    await expect(summary.getByText('疑似个人电脑')).toBeVisible()
    await expect(summary.getByText('硬件类型待确认')).toBeVisible()
    await expect(summary.getByText(/台式机和笔记本/)).toBeVisible()
    await expect(summary.getByText(/Mac 浏览器/)).toBeVisible()
    await expect.poll(() => dialog.evaluate(el => {
      const style = getComputedStyle(el)
      return style.transform === 'none' && style.opacity === '1' &&
        !el.className.match(/zoom-(enter|appear|leave)/) && el.getAnimations({subtree:true}).every(a => a.playState !== 'running')
    })).toBe(true)
    const probe = await dialog.evaluate(el => {
      const body = el.querySelector<HTMLElement>('.ant-modal-body')!
      const summary = body.querySelector<HTMLElement>('.discovery-type-summary')!
      const facts = body.querySelector<HTMLElement>('.discovery-detail-facts')!
      return {
        documentFits: document.documentElement.scrollWidth <= innerWidth + 1,
        bodyFits: body.scrollWidth <= body.clientWidth + 1,
        summaryFits: Math.abs(summary.offsetWidth - facts.offsetWidth) < 3,
        columns: getComputedStyle(facts).gridTemplateColumns.split(' ').length,
        buttonsFit: Array.from(el.querySelectorAll('button')).every(b => b.scrollWidth <= b.clientWidth + 2),
      }
    })
    expect(probe).toEqual({documentFits:true,bodyFits:true,summaryFits:true,columns:viewport.width<560?1:2,buttonsFit:true})
    const bounds = await summary.boundingBox()
    expect(bounds).toBeTruthy()
    const shot = await page.screenshot({path:testInfo.outputPath(`computer-${viewport.width}.png`)})
    const painted = await page.evaluate(async ({data,x,y}) => {
      const img = new Image()
      img.src = 'data:image/png;base64,' + data
      await img.decode()
      const surface = document.createElement('canvas').getContext('2d')!
      surface.drawImage(img, x, y, 1, 1, 0, 0, 1, 1)
      return [...surface.getImageData(0,0,1,1).data].slice(0,3).every(channel => channel > 235)
    }, {data:shot.toString('base64'),x:Math.floor(bounds!.x+8),y:Math.floor(bounds!.y+8)})
    expect(painted, 'the screenshot must show the light surface behind the type summary').toBe(true)
    await dialog.getByRole('button', {name:'Close'}).click()
    await expect(dialog).not.toBeVisible()
  }
  expect(errors).toEqual([])
})
