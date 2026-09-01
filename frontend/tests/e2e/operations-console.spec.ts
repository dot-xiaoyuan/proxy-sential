import { expect, test } from '@playwright/test'

test('redirects the legacy risk list to cases and opens a case', async ({ page }) => {
  await page.goto('/risks')
  await expect(page).toHaveURL(/\/cases$/)
  await expect(page.getByRole('heading', { name: '风险处置' })).toBeVisible()
  const firstCase = page.locator('tbody a[href^="/cases/"]').first()
  await firstCase.click()
  await expect(page.getByText('证据快照')).toBeVisible()
})

test('submits a review label on IP detail', async ({ page }) => {
  await page.goto('/ips/10.255.0.59')
  await expect(page.getByRole('heading', { name: '访问画像' })).toBeVisible()
  await expect(page.getByText('portal.example.test').first()).toBeVisible()
  await expect(page.getByText('api.example.test').first()).toBeVisible()
  await expect(page.getByText('Mozilla/5.0 (Windows NT 10.0; Win64; x64)').first()).toBeVisible()
  await page.getByLabel('复核结论').click()
  await page.getByTitle('确认代理').click()
  await page.getByLabel('复核原因').fill('证据链完整，确认共享上网')
  await page.getByRole('button', { name: '提交标注' }).click()
  await expect(page.getByText('标注已写入审计队列')).toBeVisible()
})

test('shows shadow run summaries', async ({ page }) => {
  await page.goto('/shadow-runs')
  await expect(page.getByText('20260724-131645')).toBeVisible()
  await expect(page.getByText('截断')).toBeVisible()
  await expect(page.getByRole('columnheader', { name: '标准化' })).toBeVisible()
  await expect(page.getByRole('columnheader', { name: 'Zeek' })).toBeVisible()
  await expect(page.getByText('unavailable')).toBeVisible()
  await expect(page.getByText('no_dhcp_events')).toBeVisible()
})

test('shows compact endpoint inventory and opens endpoint detail', async ({ page }) => {
  await page.goto('/devices')
  await expect(page.getByRole('heading', { name: '终端画像' })).toBeVisible()
  await expect(page.getByRole('columnheader', { name: '设备识别' })).toBeVisible()
  const firstEndpoint = page.locator('tbody a[href^="/devices/"]').first()
  await expect(firstEndpoint).toBeVisible()
  await firstEndpoint.click()
  await expect(page.locator('h3').first()).toBeVisible()
})

test('validates and imports an offline device fingerprint bundle', async ({ page }) => {
  await page.goto('/settings/rules')
  await page.locator('input[type="file"]').setInputFiles({ name:'device-fingerprint-bundle.tar.gz',mimeType:'application/gzip',buffer:Buffer.from('mock bundle') })
  await expect(page.getByText(/校验通过：offline-20260831-mock/)).toBeVisible()
  await page.getByRole('button',{name:'确认导入'}).click()
  await expect(page.getByText(/特征库已导入 offline-20260831-mock/)).toBeVisible()
})

test('redirects the legacy review queue into the unified case workflow', async ({ page }) => {
  await page.goto('/review')
  await expect(page).toHaveURL(/\/cases$/)
  const caseLink = page.locator('tbody a[href^="/cases/"]').first()
  await expect(caseLink).toBeVisible()
  await caseLink.click()
  await expect(page.getByText('证据快照')).toBeVisible()
})

test('shows ingest diagnostics and normalized event samples', async ({ page }) => {
  await page.goto('/ingest')
  await expect(page.getByRole('heading', { name: '采集诊断' })).toBeVisible()
  await expect(page.getByText('suricata', { exact: true })).toBeVisible()
  await expect(page.getByText('ens1f1', { exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: /按类型统计标准事件/ })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Zeek 设备指纹采集' })).toBeVisible()
  await expect(page.getByText('2048 -> 4096')).toBeVisible()
  await expect(page.getByText('collector run completed with skipped or malformed input records').first()).toBeVisible()
  await expect(page.getByText('event-http-59-a')).toBeVisible()
})

test('shows observed activity posture and opens active risk IP detail', async ({ page }) => {
  await page.goto('/activity')
  await expect(page.getByRole('heading', { name: 'DPI 观测与访问态势' })).toBeVisible()
  await expect(page.getByText('基于标准事件元数据呈现 L7 协议流向')).toBeVisible()
  await expect(page.getByText('api.example.test').first()).toBeVisible()
  await page.getByRole('tab', { name: '客户端指纹' }).click()
  await expect(page.getByText('Mozilla/5.0 (Windows NT 10.0; Win64; x64)').first()).toBeVisible()
  await expect(page.getByText('10.255.0.59').first()).toBeVisible()
  await page.getByRole('link', { name: '10.255.0.59' }).click()
  await expect(page.getByRole('heading', { name: '10.255.0.59' })).toBeVisible()
})

test('shows local users and versioned campus exceptions', async ({ page }) => {
  await page.goto('/settings/security')
  await expect(page.getByRole('heading', { name: '权限与校园例外' })).toBeVisible()
  await expect(page.getByText('系统管理员').first()).toBeVisible()
  await expect(page.getByText('vpn.henu.edu.cn')).toBeVisible()
  await expect(page.getByRole('button', { name: '新建用户' })).toBeVisible()
  await expect(page.getByRole('button', { name: '新增例外' })).toBeVisible()
})

test('maintains campus organization mappings and exposes university filters', async ({ page }) => {
  await page.goto('/settings/organization')
  await expect(page.getByRole('heading', { name: '校区与网络区域' })).toBeVisible()
  await page.getByRole('button', { name: '新增校区' }).click()
  await page.getByLabel('校区 ID').fill('west')
  await page.getByLabel('校区编码').fill('WEST')
  await page.getByLabel('校区名称').fill('西校区')
  await page.getByRole('button', { name: '确 定' }).click()
  await expect(page.getByText('组织与网络位置映射已保存')).toBeVisible()

  await page.goto('/devices')
  await expect(page.getByText('全部校区', { exact: true })).toBeVisible()
  await expect(page.getByPlaceholder('院系')).toBeVisible()
  await expect(page.getByPlaceholder('NAS IP')).toBeVisible()
})
