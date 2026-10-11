import { test, expect, type Page } from '@playwright/test'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'

/**
 * 全页面遍历测试：router.tsx 中登记的每一个页面路由 + tab/section 变体 + 遗留重定向，
 * 在 390x844 / 1280x800 / 1440x900 三视口下逐页采集渲染、控制台、网络、布局与文案规范证据，
 * 结果写入机器可读 JSON 与逐页截图，供 docs/page-test-report-*.md 汇总。
 */

type Kind = 'page' | 'redirect'

type Entry = {
	url: string
	pattern: string
	label: string
	kind: Kind
	heading?: string
	redirectTo?: RegExp
}

const viewports = [
	{ width: 390, height: 844 },
	{ width: 1280, height: 800 },
	{ width: 1440, height: 900 },
]

const diagnosticId = 'diag-20260724-131645'
const caseId = 'proxy-review-openvpn'

// A 组：静态页面主路由（21 条，覆盖 router.tsx 全部静态页面）
const staticPages: Entry[] = [
	{ url: '/overview', pattern: '/overview', label: '运营工作台', kind: 'page', heading: '高校网络风险运营工作台' },
	{ url: '/shared-access', pattern: '/shared-access', label: '共享上网发现', kind: 'page' },
	{ url: '/cases', pattern: '/cases', label: '风险案件', kind: 'page', heading: '风险案件' },
	{ url: '/actions', pattern: '/actions', label: '处置记录', kind: 'page' },
	{ url: '/devices', pattern: '/devices', label: '终端画像', kind: 'page', heading: '终端画像' },
	{ url: '/discovery', pattern: '/discovery', label: '网络设备发现', kind: 'page', heading: '网络设备发现' },
	{ url: '/activity', pattern: '/activity', label: '访问分析入口', kind: 'page' },
	{ url: '/events', pattern: '/events', label: '标准事件检索', kind: 'page', heading: 'DPI 标准事件检索' },
	{ url: '/policies', pattern: '/policies', label: '防代理策略', kind: 'page', heading: '防代理策略' },
	{ url: '/policies/whitelist', pattern: '/policies/whitelist', label: '白名单', kind: 'page' },
	{ url: '/policies/blacklist', pattern: '/policies/blacklist', label: '黑名单', kind: 'page' },
	{ url: '/policies/destination-targets', pattern: '/policies/destination-targets', label: '目标地址策略', kind: 'page' },
	{ url: '/policies/exceptions', pattern: '/policies/exceptions', label: '校园例外', kind: 'page', heading: '校园例外' },
	{ url: '/settings/rules', pattern: '/settings/rules', label: '规则与特征库', kind: 'page', heading: '规则与特征库' },
	{ url: '/settings/sources', pattern: '/settings/sources', label: '采集诊断与节点性能', kind: 'page', heading: '采集诊断与节点性能' },
	{ url: '/settings/actions', pattern: '/settings/actions', label: '认证与处置接入', kind: 'page', heading: '认证与处置接入' },
	{ url: '/settings/organization', pattern: '/settings/organization', label: '校区与网络区域', kind: 'page', heading: '校区与网络区域' },
	{ url: '/settings/security', pattern: '/settings/security', label: '用户权限', kind: 'page', heading: '用户权限' },
	{ url: '/settings/notifications', pattern: '/settings/notifications', label: '通知投递', kind: 'page' },
	{ url: '/settings/behavior-reports', pattern: '/settings/behavior-reports', label: '行为报表', kind: 'page' },
	{ url: '/audit', pattern: '/audit', label: '审计日志', kind: 'page', heading: '系统操作与策略审计日志' },
]

// B 组：tab / section 变体（12 条）
const variants: Entry[] = [
	{ url: '/shared-access?tab=devices', pattern: '/shared-access', label: '共享发现', kind: 'page' },
	{ url: '/shared-access?tab=observations', pattern: '/shared-access', label: '共享发现', kind: 'page', heading: '共享发现' },
	{ url: '/shared-access?tab=reviews', pattern: '/shared-access', label: '账号复核', kind: 'page', heading: '账号复核' },
	{ url: '/activity?section=applications', pattern: '/activity', label: '应用访问', kind: 'page', heading: '应用访问' },
	{ url: '/activity?section=access', pattern: '/activity', label: '访问分析', kind: 'page', heading: '访问分析' },
	{ url: '/activity?section=technical', pattern: '/activity', label: '技术指纹', kind: 'page', heading: '技术指纹' },
	{ url: '/actions?tab=executions', pattern: '/actions', label: '处置记录', kind: 'page', heading: '处置记录' },
	{ url: '/actions?tab=actions', pattern: '/actions', label: '处置记录', kind: 'page', heading: '处置记录' },
	{ url: '/settings/sources?tab=sources', pattern: '/settings/sources', label: '发现采集配置', kind: 'page', heading: '发现采集配置' },
	{ url: '/settings/sources?tab=scan', pattern: '/settings/sources', label: '发现采集配置', kind: 'page', heading: '发现采集配置' },
	{ url: '/settings/sources?tab=tasks', pattern: '/settings/sources', label: '发现采集配置', kind: 'page', heading: '发现采集配置' },
	{ url: '/settings/sources?tab=diagnostics', pattern: '/settings/sources', label: '采集诊断与节点性能', kind: 'page', heading: '采集诊断与节点性能' },
]

// C 组：动态详情页（11 条，参数取自已核实 mock fixture）
const details: Entry[] = [
	{ url: '/discovery/routers/router-huawei-ar-001', pattern: '/discovery/routers/:assessmentId', label: '路由器观测详情', kind: 'page' },
	{ url: '/devices/endpoint-mi14-ops', pattern: '/devices/:endpointId', label: '终端详情', kind: 'page' },
	{ url: '/events/event-tls-59-b', pattern: '/events/:eventId', label: '事件详情', kind: 'page' },
	{ url: `/ingest/diagnostics/${diagnosticId}`, pattern: '/ingest/diagnostics/:diagnosticId', label: '采集诊断详情', kind: 'page' },
	{ url: '/ips/10.255.0.59', pattern: '/ips/:ip', label: 'IP 详情', kind: 'page' },
	{ url: `/review/${caseId}`, pattern: '/review/:caseId', label: '复核详情', kind: 'page' },
	{ url: `/cases/${caseId}`, pattern: '/cases/:caseId', label: '案件详情', kind: 'page' },
	{ url: '/audit/audit-001', pattern: '/audit/:auditId', label: '审计详情', kind: 'page' },
	{ url: '/shared-access/observations/shared-behavior-test', pattern: '/shared-access/observations/:observationId', label: '共享行为详情', kind: 'page' },
	{ url: '/shared-access/reviews/review-office-test', pattern: '/shared-access/reviews/:id', label: '共享复核详情', kind: 'page' },
	{ url: `/settings/sources/diagnostics/${diagnosticId}`, pattern: '/settings/sources/diagnostics/:diagnosticId', label: '采集诊断详情', kind: 'page' },
]

// D 组：遗留重定向（3 条）
const redirects: Entry[] = [
	{ url: '/ingest', pattern: '/ingest', label: '遗留采集入口', kind: 'redirect', redirectTo: /\/settings\/sources\?.*tab=diagnostics/ },
	{ url: '/risks', pattern: '/risks', label: '遗留风险入口', kind: 'redirect', redirectTo: /\/cases/ },
	{ url: '/review', pattern: '/review', label: '遗留复核入口', kind: 'redirect', redirectTo: /\/cases/ },
]

const manifest: Entry[] = [...staticPages, ...variants, ...details, ...redirects]

type Finding = { route: string; viewport: string; kind: string; detail: string }

type PageRecord = {
	url: string
	label: string
	kind: Kind
	viewport: string
	ok: boolean
	headingTexts: string[]
	findings: Finding[]
	pageErrors: string[]
	consoleErrors: string[]
	mockErrors: { url: string; status: number }[]
	unmockedRequests: { url: string; status: number }[]
	requestFailures: string[]
	abortedRequests: string[]
	wideContainers: string[]
	observations: string[]
	contentDelayMs: number
	screenshot?: string
	error?: string
}

function slugify(url: string) {
	return url.replace(/^\//, '').replace(/[^a-zA-Z0-9]+/g, '-').replace(/^-|-$/g, '') || 'root'
}

function toRelative(rootDir: string, target: string) {
	return path.relative(rootDir, target)
}

async function probe(page: Page, specHeading?: string) {
	return page.evaluate((expectedHeading) => {
		const content = document.querySelector('.app-content')
		const text = content?.textContent ?? ''
		const visible = (el: Element) => {
			const box = el.getBoundingClientRect()
			if (box.width <= 0 || box.height <= 0) return false
			// 未激活的 Tabs 面板仍有布局尺寸，需按 visibility/opacity 排除
			const check = (el as Element & { checkVisibility?: (options: Record<string, boolean>) => boolean }).checkVisibility
			if (typeof check === 'function' && !check.call(el, { visibilityProperty: true, opacityProperty: true })) return false
			return true
		}
		const headings = [...document.querySelectorAll('.app-content h1, .app-content h2, .app-content h3, .app-content .ant-page-header-heading-title')]
			.filter(visible)
			.map((el) => (el.textContent ?? '').trim())
			.filter(Boolean)

		const scrollable = (el: Element) => {
			const style = getComputedStyle(el)
			return (
				style.overflowX === 'auto' ||
				style.overflowX === 'scroll' ||
				el.querySelector('[style*="overflow-x: auto"]') !== null ||
				el.querySelector('.ant-tabs-nav-wrap') !== null ||
				el.querySelector('.ant-table-content') !== null
			)
		}

		const internalOverflow: string[] = []
		const internalSelectors = ['.page', '.surface', '.details-grid', '.sample-list', '.evidence-item', '.page-header', '.app-table-bar', '.card', '.ant-card-body']
		for (const selector of internalSelectors) {
			document.querySelectorAll(selector).forEach((el, index) => {
				if (!visible(el) || scrollable(el)) return
				if (el.scrollWidth > el.clientWidth + 2) internalOverflow.push(`${selector}[${index}] ${el.scrollWidth}>${el.clientWidth}`)
			})
		}

		// 严格项：按钮/标签/Badge/操作项 必须 nowrap + flex-shrink:0（AGENTS 规范）
		const strictSelectors = '.ant-btn, .ant-tag, .ant-badge, .mock-badge, .action-item, .app-table-bar .ant-btn'
		const controlsNotNowrap = [...document.querySelectorAll(strictSelectors)]
			.filter(visible)
			.filter((el) => {
				const style = getComputedStyle(el)
				return style.whiteSpace !== 'nowrap' || style.flexShrink !== '0'
			})
			.map((el) => `${el.tagName.toLowerCase()}.${(el.className || '').toString().split(' ')[0]}「${(el.textContent ?? '').trim().slice(0, 16)}」`)

		// 文本弹性项：截断单元格只需具备明确的换行/截断策略，不求 flex-shrink:0（否则 ellipsis 会失效）
		const cellSelectors = '.nowrap-cell, .ellipsis-cell, .list-cell-nowrap'
		const cellsWithoutStrategy = [...document.querySelectorAll(cellSelectors)]
			.filter(visible)
			.filter((el) => {
				const style = getComputedStyle(el)
				return (
					style.whiteSpace !== 'nowrap' &&
					style.textOverflow !== 'ellipsis' &&
					style.overflowWrap !== 'anywhere' &&
					style.overflowWrap !== 'break-word' &&
					style.wordBreak !== 'break-all'
				)
			})
			.map((el) => `${el.tagName.toLowerCase()}.${(el.className || '').toString().split(' ')[0]}「${(el.textContent ?? '').trim().slice(0, 16)}」`)

		const actionOverflow = [...document.querySelectorAll('.page-header, .app-table-bar, .ant-btn')]
			.filter(visible)
			.filter((el) => el.getBoundingClientRect().right > window.innerWidth + 2)
			.map((el) => {
				const box = el.getBoundingClientRect()
				const scroller = el.closest('.ant-table-content')
				const scrollX = scroller ? getComputedStyle(scroller).overflowX : 'none'
				return `${el.tagName.toLowerCase()}.${(el.className || '').toString().split(' ')[0]}「${(el.textContent ?? '').trim().slice(0, 10)}」right=${Math.round(box.right)} viewport=${window.innerWidth} 容器overflowX=${scrollX}`
			})

		const clippedFixedCellButtons = [...document.querySelectorAll('.ant-table-cell-fix-right .ant-btn')]
			.filter(visible)
			.filter((el) => {
				const cell = el.closest('td')
				return Boolean(cell) && el.getBoundingClientRect().right > (cell as HTMLElement).getBoundingClientRect().right + 2
			})
			.map((el) => (el.textContent ?? '').trim())

		const forbiddenMatches = text.match(/未识别|未获取|待关联|未关联|未观测|未知/g) ?? []

		const dashPlaceholders = [...document.querySelectorAll('.app-content *')]
			.filter((el) => el.children.length === 0)
			.map((el) => (el.textContent ?? '').trim())
			.filter((value) => value === '—' || value === '–').length

		const clippedIds: string[] = []
		const idPattern = /(\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}|[0-9a-fA-F]{32,}/
		for (const el of document.querySelectorAll('.app-content *')) {
			if (clippedIds.length >= 5) break
			if (el.children.length > 0) continue
			const own = (el.textContent ?? '').trim()
			if (!own || own.length > 200 || !idPattern.test(own)) continue
			if (!visible(el) || scrollable(el) || el.scrollWidth <= el.clientWidth + 2) continue
			const style = getComputedStyle(el)
			const handled =
				style.overflowWrap === 'anywhere' ||
				style.overflowWrap === 'break-word' ||
				style.wordBreak === 'break-all' ||
				style.textOverflow === 'ellipsis' ||
				style.whiteSpace === 'nowrap'
			if (!handled) clippedIds.push(`${el.tagName.toLowerCase()}.${(el.className || '').toString().split(' ')[0]}「${own.slice(0, 40)}」`)
		}

		// 横向内容超出容器时的诊断信息：是否提供了滚动能力、超出多少、是否有子元素真的越过容器右边界
		// 注意：可滚动且提供了固定列时属于 antd 既有允许模式，只有“不可滚动”或固定列缺失才可能是缺陷
		const wideContainers: string[] = []
		for (const el of document.querySelectorAll('.ant-table-content, .ant-table-wrapper, .details-grid, .sample-list, .surface')) {
			if (!visible(el) || el.scrollWidth <= el.clientWidth + 2) continue
			const style = getComputedStyle(el)
			const hasScrollX = style.overflowX === 'auto' || style.overflowX === 'scroll'
			const bottomRight = el.getBoundingClientRect().right
			const pastRight = [...el.querySelectorAll('*')].filter((child) => visible(child) && child.getBoundingClientRect().right > bottomRight + 2).length
			// antd 5 用 -fix-right/-fix-left，antd 6 改为 -fix-end/-fix-start
			const fixedColumns = el.querySelectorAll('.ant-table-cell-fix-right, .ant-table-cell-fix-left, .ant-table-cell-fix-end, .ant-table-cell-fix-start').length
			wideContainers.push(
				`${el.tagName.toLowerCase()}.${(el.className || '').toString().split(' ')[0]} ${el.scrollWidth}>${el.clientWidth} overflowX=${style.overflowX}${hasScrollX ? '（可滚动）' : '（不可滚动）'} 越过右边界子元素=${pastRight} 固定列=${fixedColumns}`,
			)
		}

		const selectedMenu = [...document.querySelectorAll('.ant-menu-item-selected')]
			.filter(visible)
			.map((el) => ({ label: (el.textContent ?? '').trim(), color: getComputedStyle(el).color, background: getComputedStyle(el).backgroundColor }))

		// 视口专属区块不得串台：>560px 不应出现 mobile-only，<=560px 不应出现 desktop-only
		const isMobileViewport = window.innerWidth <= 560
		const crossViewportBlocks = [...document.querySelectorAll('.mobile-only, .desktop-only')]
			.filter((el) => visible(el))
			.filter((el) => (isMobileViewport ? el.classList.contains('desktop-only') : el.classList.contains('mobile-only')))
			.map((el) => `${el.classList.contains('mobile-only') ? 'mobile-only' : 'desktop-only'} ${el.tagName.toLowerCase()}.${(el.className || '').toString().split(' ')[0]}`)

		return {
			docOverflow: document.documentElement.scrollWidth > window.innerWidth + 2,
			crossViewportBlocks,
			internalOverflow,
			controlsNotNowrap,
			cellsWithoutStrategy,
			actionOverflow,
			clippedFixedCellButtons,
			forbiddenMatches,
			dashPlaceholders,
			clippedIds,
			wideContainers,
			selectedMenu,
			headings,
			headingMissed: expectedHeading ? !headings.some((value) => value === expectedHeading) : false,
			permissionDenied: text.includes('没有访问权限'),
			viteOverlay: document.querySelector('vite-error-overlay') !== null,
			contentLength: text.trim().length,
		}
	}, specHeading)
}

function contrast(color: string, background: string) {
	const luminance = (rgb: string) => {
		const components = (rgb.match(/[\d.]+/g) ?? []).slice(0, 3).map(Number).map((value) => {
			const channel = value / 255
			return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4
		})
		return components[0] * 0.2126 + components[1] * 0.7152 + components[2] * 0.0722
	}
	const a = luminance(color)
	const b = luminance(background)
	return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05)
}

for (const viewport of viewports) {
	const tag = `${viewport.width}x${viewport.height}`

	test(`全页面遍历 ${tag}`, async ({ page }, testInfo) => {
		test.setTimeout(300_000)
		await page.setViewportSize(viewport)
		const rootDir = path.resolve(testInfo.config.rootDir, '..', '..')
		const shotsDir = testInfo.outputPath('shots')
		await mkdir(shotsDir, { recursive: true })

		const pageErrors: string[] = []
		const consoleErrors: string[] = []
		const requestFailures: string[] = []
		const httpErrors: { url: string; status: number; mock: boolean }[] = []
		page.on('pageerror', (error) => pageErrors.push(error.message))
		page.on('console', (message) => {
			if (message.type() === 'error') consoleErrors.push(message.text())
		})
		page.on('requestfailed', (request) => requestFailures.push(`${request.method()} ${request.url()} ${request.failure()?.errorText ?? ''}`))
		page.on('response', (response) => {
			if (response.status() < 400) return
			if (!response.url().includes('/api/')) return
			httpErrors.push({ url: `${response.request().method()} ${response.url()}`, status: response.status(), mock: response.fromServiceWorker() })
		})

		const records: PageRecord[] = []
		const softFailures: string[] = []

		for (const entry of manifest) {
			pageErrors.length = 0
			consoleErrors.length = 0
			requestFailures.length = 0
			httpErrors.length = 0

			const findings: Finding[] = []
			const record: PageRecord = {
				url: entry.url,
				label: entry.label,
				kind: entry.kind,
				viewport: tag,
				ok: true,
				headingTexts: [],
				findings,
				pageErrors: [],
				consoleErrors: [],
				mockErrors: [],
				unmockedRequests: [],
				requestFailures: [],
				abortedRequests: [],
				wideContainers: [],
				observations: [],
				contentDelayMs: -1,
			}

			const push = (kind: string, detail: string) => findings.push({ route: entry.url, viewport: tag, kind, detail })

			try {
				const response = await page.goto(entry.url, { waitUntil: 'domcontentloaded' })
				if (response && response.status() >= 400) push('document-http', `文档状态 ${response.status()}`)
				if (entry.kind === 'redirect' && entry.redirectTo) {
					try {
						await page.waitForURL(entry.redirectTo, { timeout: 8_000 })
					} catch {
						push('redirect', `未重定向到 ${entry.redirectTo}，当前 ${page.url()}`)
					}
				}
				await page.locator('.app-content').waitFor({ state: 'visible', timeout: 15_000 })
				// 等待内容真正出现（此前固定 500ms 会误判慢页面为空白页），并记录首屏内容耗时
				const waitStart = Date.now()
				try {
					await expect
						.poll(async () => ((await page.locator('.app-content').innerText()) || '').trim().length, { timeout: 5_000, intervals: [100, 200, 500] })
						.toBeGreaterThan(0)
				} catch {
					// 5s 内仍无内容，交由下方探针记为缺陷
				}
				record.contentDelayMs = Date.now() - waitStart
				await page.waitForTimeout(200)

				const result = await probe(page, entry.heading)
				record.headingTexts = result.headings
				record.wideContainers = result.wideContainers

				if (result.viteOverlay) push('render', '出现 Vite 错误覆盖层')
				if (result.contentLength === 0) push('render', '.app-content 内容为空')
				if (result.headings.length === 0) push('render', '页面无可见标题')
				if (result.headingMissed) push('content', `标题与预期「${entry.heading}」不一致，实际 ${result.headings.join(' / ')}`)
				if (result.permissionDenied) push('permission', '出现「没有访问权限」，当前 mock 会话权限不足')
				for (const item of result.crossViewportBlocks) push('viewport-visibility', `视口专属区块串台 ${item}`)
				if (result.docOverflow) push('layout-document', '文档横向溢出')
				for (const item of result.internalOverflow) push('layout-internal', `容器内部溢出 ${item}`)
				for (const item of result.controlsNotNowrap) push('style-nowrap', `按钮/标签未保持 nowrap+flex-shrink:0 ${item}`)
				for (const item of result.cellsWithoutStrategy) push('style-cell', `截断单元格缺少换行/截断策略 ${item}`)
				for (const item of result.actionOverflow) push('layout-actions', `操作项右溢出 ${item}`)
				for (const item of result.clippedFixedCellButtons) push('layout-clipped', `固定列按钮被裁 「${item}」`)
				for (const item of result.wideContainers) {
					// 不可滚动 = 内容被硬裁切，属于违规；可滚动 = 宽表格的既有允许模式，仅记入观察项
					if (item.includes('不可滚动')) push('layout-clip', `内容超出容器且无滚动能力 ${item}`)
					else record.observations.push(`宽表格内容超出容器，需横向滚动 ${item}`)
				}
				if (result.forbiddenMatches.length) push('copy-placeholder', `禁用缺省文案 ${[...new Set(result.forbiddenMatches)].join('/')}`)
				if (result.dashPlaceholders > 0) push('copy-placeholder', `横杠占位 ${result.dashPlaceholders} 处`)
				for (const item of result.clippedIds) push('layout-id', `长标识符无换行/截断策略 ${item}`)
				for (const selected of result.selectedMenu) {
					if (!selected.color || !selected.background) continue
					const ratio = contrast(selected.color, selected.background)
					if (ratio < 4.5) push('contrast', `选中菜单「${selected.label}」对比度 ${ratio.toFixed(2)} < 4.5`)
				}
				const shot = path.join(shotsDir, `${slugify(entry.url)}-${viewport.width}.png`)
				await page.screenshot({ path: shot, fullPage: true, animations: 'disabled' })
				record.screenshot = toRelative(rootDir, shot)
			} catch (error) {
				record.error = error instanceof Error ? error.message.split('\n')[0] : String(error)
				push('probe-failed', record.error)
			}

			// 网络/控制台证据在每轮结束时快照，避免被下一轮的清空操作影响
			record.pageErrors = [...pageErrors]
			record.consoleErrors = [...consoleErrors]
			record.requestFailures = [...requestFailures]
			record.mockErrors = httpErrors.filter((item) => item.mock).map((item) => ({ url: item.url, status: item.status }))
			record.unmockedRequests = httpErrors.filter((item) => !item.mock).map((item) => ({ url: item.url, status: item.status }))
			for (const error of record.pageErrors) push('js-error', error.split('\n')[0])
			for (const item of record.mockErrors) push('api-error', `mock 接口 ${item.status} ${item.url}`)
			// 导航导致的请求取消（ERR_ABORTED）属于页面切换的正常行为，仅作信息记录，不计为缺陷
			for (const item of record.requestFailures) {
				if (item.includes('ERR_ABORTED')) record.abortedRequests.push(item)
				else push('request-failed', item)
			}

			record.ok = findings.length === 0
			records.push(record)
			for (const finding of findings) softFailures.push(`[${finding.kind}] ${finding.route} @${tag} ${finding.detail}`)
			console.log(`[all-pages] ${record.ok ? 'PASS' : `ISSUE(${findings.length})`} ${entry.url} @${tag}`)
		}

		const report = {
			generatedAt: new Date().toISOString(),
			viewport: tag,
			total: records.length,
			ok: records.filter((record) => record.ok).length,
			records,
		}
		await writeFile(testInfo.outputPath('all-pages.json'), JSON.stringify(report, null, 2))
		console.log(`[all-pages] ${tag} 汇总：${report.ok}/${report.total} 通过，问题 ${softFailures.length} 项`)
		expect.soft(softFailures, `${tag} 共发现 ${softFailures.length} 项问题`).toEqual([])
	})
}

test('路由清单与 router.tsx 完全对齐', async ({}, testInfo) => {
	const routerPath = path.resolve(testInfo.config.rootDir, '..', '..', 'src/app/router.tsx')
	const source = await readFile(routerPath, 'utf8')
	const declared = [...source.matchAll(/path:\s*'([^']+)'/g)]
		.map((match) => match[1])
		.map((value) => (value.startsWith('/') ? value : `/${value}`))
		.filter((value) => value !== '/')
	const declaredSet = new Set(declared)
	const coveredSet = new Set(manifest.map((entry) => entry.pattern))

	const missing = [...declaredSet].filter((route) => !coveredSet.has(route))
	const extra = [...coveredSet].filter((route) => !declaredSet.has(route))
	expect(missing, 'router.tsx 中未纳入遍历的路由').toEqual([])
	expect(extra, '遍历清单中不存在于 router.tsx 的路由').toEqual([])
	expect(declaredSet.size, 'router.tsx 路由总数').toBe(35)
	expect(manifest.length, '遍历条目总数').toBe(47)
})
