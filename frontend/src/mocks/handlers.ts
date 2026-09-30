import { sharedAccessHandlers } from './sharedAccess'
import { discoveryHandlers } from './discovery'
import { macOSDevice, macOSProfile, manufacturerReferenceDevices } from './deviceRecognition'
import { proxyProof } from './proxyProtocol'
import { domainOnlyDevice, domainOnlyProfile } from './brandInference'
import { policyHandlers } from './policies'
import { applicationHandlers } from './applications'
import { routerObservationHandlers } from './routerObservations'
import { delay, http, HttpResponse } from 'msw'

import type { CreateLabelRequest, RiskCase, CaseHistoryRow } from '../shared/api/types'
import {
  activityByIp,
  getActivityOverviewByWindow,
  auditLogs,
  deviceInventoriesByIp,
  eventsByIp,
  evidenceByIp,
  ingestDiagnostics,
  ingestEventTypes,
  ingestStatus,
  mockDpiProtocolFlows,
  mockDpiTrendPoints,
  mockFingerprintConflicts,
  mockFlowSamples,
  mockSession,
  overview,
  proxyReviewResponse,
  riskSnapshots,
  shadowRuns,
  shadowEvaluation,
  shadowReviewSamples,
} from './fixtures'

function normalizeIp(value: string) {
  return decodeURIComponent(value)
}

const mockCases: RiskCase[] = proxyReviewResponse.items.map((item, index) => ({
  case_id: item.case_id,
  subject_type: 'ip',
  subject_id: item.ip,
  ip: item.ip,
  account_id: item.account_id,
  endpoint_id: item.endpoint_id,
  campus_id: index === 0 ? 'main' : 'north',
  status: index === 0 ? 'investigating' as const : 'new' as const,
  priority: item.risk_score >= 90 ? 'high' as const : 'medium' as const,
  risk_score: item.risk_score,
  risk_confidence: Math.min(0.99, Math.max(0.5, item.risk_score / 100)),
  assessment_level: item.risk_score >= 90 ? 'high' : 'suspicious',
  due_at: new Date(Date.now() + (index - 1) * 3_600_000).toISOString(),
  first_seen: item.first_seen,
  last_seen: item.last_seen,
  created_at: item.first_seen,
  updated_at: item.last_seen,
  comments: [],
  timeline: [{ event_id: `timeline-${index}`, actor_id: 'system', type: 'case.created', created_at: item.first_seen }],
  evidence_snapshot: item,
}))

const mockOrganization = {
  campuses: [{ campus_id: 'main', code: 'MAIN', name: '主校区', enabled: true }, { campus_id: 'north', code: 'NORTH', name: '北校区', enabled: true }],
  buildings: [{ building_id: 'lib', campus_id: 'main', code: 'LIB', name: '图书馆', enabled: true }],
  network_zones: [{ network_zone_id: 'student-wifi', campus_id: 'main', name: '学生无线网', cidrs: ['10.20.0.0/16'], ssids: ['Campus-WiFi'], vlans: ['120'], enabled: true }],
  access_points: [{ access_point_id: 'ap-lib-01', campus_id: 'main', building_id: 'lib', network_zone_id: 'student-wifi', kind: 'ap', name: '图书馆一层 AP', management_ip: '10.1.1.10', enabled: true }],
}

const mockConnectors = [{ connector_id: 'portal-gateway', name: 'Portal 北向网关', endpoint_url: 'https://portal.example.edu/api/actions', action_mapping: { disconnect: 'kick' }, mode: 'shadow' as const, enabled: true, shadow_ready: false, shadow_candidate_count: 12, shadow_reviewed_count: 10, shadow_accuracy: .9, updated_at: new Date().toISOString() }]
const mockActions: Array<Record<string, unknown>> = []
const mockUsers = [{user_id:'admin-1',username:'admin',display_name:'系统管理员',role:'admin',disabled:false},{user_id:'reviewer-1',username:'reviewer',display_name:'风险复核员',role:'reviewer',disabled:false}]
const mockCampusExceptions = [{exception_id:'exception-webvpn',scope_type:'domain',scope_value:'vpn.henu.edu.cn',reason:'学校 WebVPN',ruleset_version:'campus-exceptions-v1',valid_from:new Date().toISOString(),enabled:true,created_by:'admin-1',created_at:new Date().toISOString()}]

export const handlers = [
 ...sharedAccessHandlers,
 ...discoveryHandlers,
 ...routerObservationHandlers,
 http.get("/api/v1/events/proxy-fixture",()=>HttpResponse.json({event_id:"proxy-fixture",type:"proxy_transaction",source:"zeek",timestamp:proxyProof.response_at,proxy_protocol:proxyProof})),
  ...applicationHandlers,
  ...policyHandlers,
  http.get('/api/v1/session', async () => {
    await delay(120)
    return HttpResponse.json(mockSession)
  }),
  http.post('/api/v1/auth/login', () => HttpResponse.json(mockSession)),
  http.post('/api/v1/auth/logout', () => new HttpResponse(null, { status: 204 })),
  http.get('/api/v1/users', () => HttpResponse.json({items:mockUsers,page:{limit:20,next_cursor:null,total:mockUsers.length}})),
  http.post('/api/v1/users', async ({request}) => {const payload=await request.json() as Record<string,unknown>;const item={user_id:`user-${Date.now()}`,username:String(payload.username),display_name:String(payload.display_name),role:String(payload.role),disabled:false};mockUsers.push(item);return HttpResponse.json(item,{status:201})}),
  http.post('/api/v1/users/:userId/:operation', ({params}) => {const item=mockUsers.find(entry=>entry.user_id===params.userId);if(!item)return new HttpResponse(null,{status:404});if(params.operation==='disable')item.disabled=true;if(params.operation==='enable')item.disabled=false;return HttpResponse.json(item)}),
  http.get('/api/v1/campus-exceptions', () => HttpResponse.json({items:mockCampusExceptions,page:{limit:20,next_cursor:null,total:mockCampusExceptions.length}})),
  http.post('/api/v1/campus-exceptions', async ({request}) => {const payload=await request.json() as Record<string,unknown>;const item={...payload,exception_id:`exception-${Date.now()}`,enabled:true,created_by:'admin-1',created_at:new Date().toISOString()};mockCampusExceptions.push(item as typeof mockCampusExceptions[number]);return HttpResponse.json(item,{status:201})}),
  http.post('/api/v1/campus-exceptions/:exceptionId/disable', ({params}) => {const item=mockCampusExceptions.find(entry=>entry.exception_id===params.exceptionId);if(!item)return new HttpResponse(null,{status:404});item.enabled=false;return HttpResponse.json(item)}),
  http.get('/api/v1/cases', ({ request }) => {
    const url = new URL(request.url)
    const result = mockPage(mockCases.filter((item) => !url.searchParams.get('status') || item.status === url.searchParams.get('status')), url)
    return HttpResponse.json(result)
  }),
  http.get('/api/v1/cases/:caseId/history/:kind', ({params,request}) => {
    const item=mockCases.find(entry=>entry.case_id===params.caseId)
    if(!item)return new HttpResponse(null,{status:404})
    const evidence=item.evidence_snapshot
    const rows:CaseHistoryRow[]=params.kind==='evidence'?(evidence?Array.from({length:45},(_,index)=>({snapshot_id:`${item.case_id}-snapshot-${45-index}`,evidence,ruleset_version:'review-v1',created_at:item.created_at})):[]):params.kind==='comments'?(item.comments??[]):(item.timeline??[]).slice().reverse()
    return HttpResponse.json(mockPage(rows,new URL(request.url)))
  }),
  http.get('/api/v1/cases/:caseId', ({ params }) => {
    const item = mockCases.find((entry) => entry.case_id === params.caseId)
    return item ? HttpResponse.json(item) : new HttpResponse(null, { status: 404 })
  }),
  http.post('/api/v1/cases/batch', async ({ request }) => {
    const payload = await request.json() as {case_ids:string[];operation:'assign'|'close';assignee_id?:string}
    const items = mockCases.filter((item) => payload.case_ids.includes(item.case_id))
    for (const item of items) {
      if (payload.operation === 'assign') Object.assign(item, { assignee_id: payload.assignee_id, status: 'assigned' })
      else Object.assign(item, { status: 'closed' })
    }
    return HttpResponse.json({items,updated:items.length})
  }),
  http.post('/api/v1/cases/:caseId/:operation', async ({ params, request }) => {
    const item = mockCases.find((entry) => entry.case_id === params.caseId)
    if (!item) return new HttpResponse(null, { status: 404 })
    const payload = await request.json() as Record<string, string>
    if (params.operation === 'assign') Object.assign(item, { assignee_id: payload.assignee_id, status: 'assigned' })
    if (params.operation === 'status') Object.assign(item, { status: payload.status })
    if (params.operation === 'priority') Object.assign(item, { priority: payload.priority })
    if (params.operation === 'disposition') Object.assign(item, { disposition: payload.disposition, status: 'resolved' })
    if (params.operation === 'comments') (item.comments ??= []).push({ comment_id: `comment-${Date.now()}`, author_id: mockSession.user.id, body: payload.body, created_at: new Date().toISOString() })
    return HttpResponse.json(item)
  }),
  http.get('/api/v1/organization', ({request}) => { const url=new URL(request.url);const kind=url.searchParams.get('kind') as keyof typeof mockOrganization|null;if(!kind)return HttpResponse.json(mockOrganization);const items=(mockOrganization[kind]??[]) as Array<Record<string,unknown>>;const result=mockPage(items,url);return HttpResponse.json(result) }),
  http.post('/api/v1/organization/:kind', async ({ params, request }) => {
    const payload = await request.json() as Record<string, unknown>
    const collection = params.kind === 'campuses' ? mockOrganization.campuses : params.kind === 'buildings' ? mockOrganization.buildings : params.kind === 'network-zones' ? mockOrganization.network_zones : params.kind === 'access-points' ? mockOrganization.access_points : undefined
    if (!collection) return new HttpResponse(null, { status: 404 })
    collection.push(payload as never)
    return HttpResponse.json(payload, { status: 201 })
  }),
  http.get('/api/v1/actions/connectors', () => HttpResponse.json({ items: mockConnectors, global_stop: false })),
  http.post('/api/v1/actions/connectors', async ({request}) => {const payload=await request.json() as typeof mockConnectors[number] & {secret?:string};const existing=mockConnectors.findIndex(item=>item.connector_id===payload.connector_id);const item={...payload,shadow_ready:existing>=0?mockConnectors[existing].shadow_ready:false,updated_at:new Date().toISOString()};delete item.secret;if(existing>=0)mockConnectors[existing]=item;else mockConnectors.push(item);return HttpResponse.json(item)}),
  http.post('/api/v1/actions/connectors/:connectorId/test', ({params}) => HttpResponse.json({connector_id:params.connectorId,reachable:true,checked_at:new Date().toISOString()})),
  http.get('/api/v1/actions', ({ request }) => { const result = mockPage(mockActions, new URL(request.url)); return HttpResponse.json(result) }),
  http.get('/api/v1/actions/:actionId/native-observations', ({ request }) => {
    const older = new URL(request.url).searchParams.has('before')
    return HttpResponse.json({items:[{id:older?'9007199254740992':'9007199254740993',step_failed:!older,recorded_at:'2026-09-15T09:00:00Z',result:{delivery:older?'acknowledged':'uncertain',observation:older?'online':'absent',reserved_at:'2026-09-15T08:59:00Z'}}],...(older?{}:{next_before:'9007199254740993'})})
  }),
  http.post('/api/v1/actions/execute', async ({ request }) => {
    const payload = await request.json() as Record<string, string>
    const action = { ...payload, action_id: `action-${Date.now()}`, idempotency_key: 'mock', subject_id: payload.ip, mode: 'shadow', status: 'shadow', blockers: [], created_at: new Date().toISOString(), updated_at: new Date().toISOString() }
    mockActions.unshift(action)
    return HttpResponse.json(action, { status: 202 })
  }),
  http.post('/api/v1/actions/:actionId/revoke', ({ params }) => HttpResponse.json({ action_id: params.actionId, status: 'revoked', updated_at: new Date().toISOString() })),
  http.post('/api/v1/actions/emergency-stop', () => HttpResponse.json({ global_stop: true })),
  http.get('/api/v1/overview', async () => {
    await delay(160)
    return HttpResponse.json({...overview,statistics_as_of:new Date().toISOString()})
  }),
  http.get('/api/v1/activity/overview', ({ request }) => {
    const url = new URL(request.url)
    const windowValue = url.searchParams.get('window') ?? '1h'
    return HttpResponse.json({...getActivityOverviewByWindow(windowValue),statistics_as_of:new Date().toISOString()})
  }),
  http.get('/api/v1/activity/reports', ({request}) => {
    const dimension=new URL(request.url).searchParams.get('dimension')??'domain'
    const overview=getActivityOverviewByWindow('1h')
    const source=dimension==='domain'?overview.top_domains:dimension==='http_host'?overview.top_http_hosts:dimension==='tls_sni'?overview.top_tls_sni:dimension==='user_agent'?overview.top_user_agents:dimension==='dst_port'?overview.top_dst_ports:dimension==='dst_ip'?overview.top_dst_ips:dimension==='src_ip'?overview.top_source_ips:dimension==='ecosystem'?[{value:'Apple',count:120,last_seen:new Date().toISOString()},{value:'Huawei',count:72,last_seen:new Date().toISOString()}]:dimension==='application'?[{value:'http2',count:220,last_seen:new Date().toISOString()},{value:'dns',count:160,last_seen:new Date().toISOString()},{value:'未知',count:40,last_seen:new Date().toISOString()}]:overview.protocol_counts
    const total=source.reduce((sum,item)=>sum+item.count,0);const unknown=source.find(item=>item.value==='未知')?.count??0
    return HttpResponse.json({dimension,total,classified_count:total-unknown,unknown_count:unknown,items:source.map(item=>({key:item.value,label:item.value,count:item.count,share:total?item.count/total:0,last_seen:item.last_seen}))})
  }),
  http.get('/api/v1/proxy-reviews', ({ request }) => {
    const url = new URL(request.url)
    const window = url.searchParams.get('window') === '24h' ? '24h' : '7d'
    const page = mockPage(proxyReviewResponse.items, url)
    return HttpResponse.json({ ...proxyReviewResponse, window, items: page.items, page: page.page })
  }),
  http.get('/api/v1/proxy-reviews/:caseId', ({ params }) => {
    const item = proxyReviewResponse.items.find((entry) => entry.case_id === params.caseId)
    return item ? HttpResponse.json(item) : new HttpResponse(null, { status: 404 })
  }),
  http.get('/api/v1/dpi/overview', ({ request }) => {
    const url = new URL(request.url)
    const windowValue = url.searchParams.get('window') ?? '1h'
    const activity = getActivityOverviewByWindow(windowValue)
    return HttpResponse.json({
      sensor_id: activity.sensor_id,
      window: activity.window,
      event_count: activity.event_count,
      active_ip_count: activity.active_ip_count,
      protocol_flow_count: mockDpiProtocolFlows.length,
      fingerprint_conflict_count: mockFingerprintConflicts.length,
      flow_sample_count: Object.values(mockFlowSamples).flat().length,
      first_seen: activity.first_seen,
      last_seen: activity.last_seen,
    })
  }),
  http.get('/api/v1/dpi/trends', () => HttpResponse.json({ points: mockDpiTrendPoints })),
  http.get('/api/v1/dpi/protocol-flows', () => HttpResponse.json({ items: mockDpiProtocolFlows })),
  http.get('/api/v1/dpi/fingerprint-conflicts', () => HttpResponse.json({ items: mockFingerprintConflicts })),
  http.get('/api/v1/dpi/flows', ({ request }) => {
    const url = new URL(request.url)
    return HttpResponse.json(filterMockFlows(url))
  }),
  http.get('/api/v1/dpi/flows/:flowId', ({ params }) => {
    const flowId = normalizeIp(String(params.flowId))
    const flow = Object.values(mockFlowSamples).flat().find((item) => item.flow_id === flowId || item.event_id === flowId)
    return flow
      ? HttpResponse.json({
          flow,
          event: Object.values(eventsByIp).flat().find((item) => item.event_id === flow.event_id) ?? eventsByIp['10.255.0.59'][0],
          risk: riskSnapshots.find((item) => item.ip === flow.src_ip) ?? riskSnapshots[3],
          evidence: evidenceByIp[flow.src_ip ?? ''] ?? [],
        })
      : HttpResponse.json({ code: 'not_found', message: 'dpi flow not found' }, { status: 404 })
  }),
  http.get('/api/v1/dpi/ips/:ip/flows', ({ params, request }) => {
    const url = new URL(request.url)
    url.searchParams.set('src_ip', normalizeIp(String(params.ip)))
    return HttpResponse.json(filterMockFlows(url))
  }),
  http.get('/api/v1/risks', ({ request }) => {
    const url = new URL(request.url)
    const level = url.searchParams.get('level')
    const q = url.searchParams.get('q')?.toLowerCase()
    const limit = Number(url.searchParams.get('limit') ?? 50)
    const filtered = riskSnapshots
      .filter((item) => !level || item.level === level)
      .filter((item) => !q || item.ip.toLowerCase().includes(q) || item.summary.toLowerCase().includes(q))
      .slice(0, limit)

    return HttpResponse.json({
      items: filtered,
      page: { limit, next_cursor: null, total: filtered.length },
    })
  }),
  http.get('/api/v1/ips/:ip/risk', ({ params }) => {
    const ip = normalizeIp(String(params.ip))
    const snapshot = riskSnapshots.find((item) => item.ip === ip)
    return snapshot ? HttpResponse.json(snapshot) : HttpResponse.json(riskSnapshots[3])
  }),
  http.get('/api/v1/ips/:ip/evidence', ({ params }) => {
    const ip = normalizeIp(String(params.ip))
    return HttpResponse.json({ evidence: evidenceByIp[ip] ?? [] })
  }),
  http.get('/api/v1/ips/:ip/activity', ({ params }) => {
    const ip = normalizeIp(String(params.ip))
    return HttpResponse.json(
      activityByIp[ip] ?? {
        ip,
        window: 'latest-run',
        event_count: 0,
        event_type_counts: [],
        protocol_counts: [],
        top_domains: [],
        top_http_hosts: [],
        top_tls_sni: [],
        top_user_agents: [],
        top_tls_fingerprints: [],
        top_dst_ports: [],
        top_dst_ips: [],
        recent_accesses: [],
      },
    )
  }),
  http.get('/api/v1/ips/:ip/devices', ({ params }) => {
    const ip = normalizeIp(String(params.ip))
    return HttpResponse.json(
      deviceInventoriesByIp[ip] ?? {
        ip,
        window: '1h',
        suspected_device_count: 0,
        confidence: 0,
        status: 'insufficient_signal',
        summary: '当前标准事件中没有足够设备识别信号，无法判断该 IP 背后设备数量或品牌',
        devices: [],
        signals: [],
        conflicts: [],
      },
    )
  }),
  http.get('/api/v1/devices', ({ request }) => {
    const url = new URL(request.url)
    const q = url.searchParams.get('q')?.toLowerCase()
    const ip = url.searchParams.get('ip')
    const brand = url.searchParams.get('brand')?.toLowerCase()
    const osFamily = url.searchParams.get('os_family')?.toLowerCase()
	const ecosystem=url.searchParams.get('ecosystem')?.toLowerCase()
    const limit = Number(url.searchParams.get('limit') ?? 50)
    const cursor = Number(url.searchParams.get('cursor') ?? 0)
    const endpointItems = Object.values(deviceInventoriesByIp).flatMap((inventory) =>
      inventory.devices.map((device) => ({
        endpoint_id: device.endpoint_id || device.device_id,
        primary_mac: device.signals.find((signal) => signal.kind === 'mac')?.normalized_value,
        entity_role: device.entity_role || 'endpoint',
        registration_status: device.endpoint_id ? 'registered' : 'unregistered',
        owner_account: device.account_id || '',
        owner_name: device.account_id ? '样本用户' : '',
        owner_department: device.account_id ? '网络中心' : '',
        asset_tag: device.endpoint_id ? `ASSET-${device.device_id.slice(-4)}` : '',
        ownership_class: device.endpoint_id ? 'school_asset' : 'unknown',
        merge_status: 'active',
        current_account: device.account_id || '',
        current_ip: inventory.ip,
        current_access_id: device.access_id || '',
        accounts: device.account_id ? [device.account_id] : [],
        ips: [inventory.ip],
        access_ids: device.access_id ? [device.access_id] : [],
        brand: device.brand || '',
        vendor: device.vendor || '',
        model: device.model || '',
        vendor_confidence: device.vendor && device.vendor !== 'unknown' ? device.confidence : 0,
        brand_confidence: device.brand && device.brand !== 'unknown' ? device.confidence : 0,
        model_confidence: device.model && device.model !== 'unknown' ? device.confidence : 0,
        device_type_confidence: 0,
        os_family: device.os_family || '',
        os_family_confidence: device.confidence,
        recognition_confidence: device.confidence,
        randomized_mac: false,
        recognition_conflict: false,
		ecosystem_hint:device.model?'Microsoft Windows':'',
		ecosystem_confidence:device.model?0.6:0,
		ecosystem_conflict:false,
		ecosystem_evidence_count:device.model?4:0,
        first_seen: device.first_seen || inventory.first_seen,
        last_seen: device.last_seen || inventory.last_seen,
        identity_confidence: device.confidence,
        summary: `${device.brand && device.brand !== 'unknown' ? device.brand + ' ' : ''}${device.model && device.model !== 'unknown' ? device.model + ' ' : ''}终端 ${device.endpoint_id || device.device_id}，观察到 1 个 IP`,
      })),
    )
    const now=Date.now(),view=url.searchParams.get('view'),window=url.searchParams.get('window')||'24h'
    const cutoff=now-({'10m':600000,'1h':3600000,'24h':86400000}[window]||86400000)
    const allItems = [...endpointItems, domainOnlyDevice, macOSDevice, ...manufacturerReferenceDevices].filter(item=>view!=='recent'||(Date.parse(item.last_seen||'')>=cutoff&&Date.parse(item.last_seen||'')<=now))
    const brandValue = (item: typeof allItems[number]) => {
      const inference = 'brand_inference' in item ? item.brand_inference : undefined
      if (inference?.status === 'inferred' && ((item.brand_confidence ?? 0) < .8 || item.recognition_conflict)) return inference.brand || 'unknown'
      if (!item.recognition_conflict && (item.brand_confidence ?? 0) >= .8 && item.brand && item.brand.toLowerCase() !== 'unknown') return item.brand
      if (inference?.status === 'inferred') return inference.brand || 'unknown'
      const reference = 'brand_reference' in item ? item.brand_reference : undefined
      if (!item.recognition_conflict && reference && inference?.status !== 'conflict') return reference.brand
      if (!item.recognition_conflict && item.brand && item.brand.toLowerCase() !== 'unknown') return item.brand
      return 'unknown'
    }
    const osValue = (item: typeof allItems[number]) => !item.recognition_conflict && item.os_family ? item.os_family : 'unknown'
    const facets = { brands: [...new Set(allItems.map(brandValue))].sort(), os_families: [...new Set(allItems.map(osValue))].sort() }
    const filtered = allItems
      .filter(item => !brand || brandValue(item).toLowerCase() === brand)
      .filter(item => !osFamily || osValue(item).toLowerCase() === osFamily)
      .filter((item) => !ip || item.current_ip === ip)
      .filter((item) => !q || (/^\d+\.\d+\.\d+\.\d+$/.test(q) ? item.ips.includes(q) : JSON.stringify(item).toLowerCase().includes(q)))
	  .filter((item)=>!ecosystem||(item.ecosystem_hint || '').toLowerCase()===ecosystem)
    const pageItems = filtered.slice(cursor, cursor + limit).map(item=>({...item,...(q&&/^\d+\.\d+\.\d+\.\d+$/.test(q)?{ip_match:{ip:q,source:'ip_observation',matched_at:item.last_seen,is_recent_ip:item.current_ip===q}}:{})}))
    const nextCursor = cursor + pageItems.length < filtered.length ? String(cursor + pageItems.length) : null

    return HttpResponse.json({
      items: pageItems,
      facets,
      page: { limit, next_cursor: nextCursor, total: filtered.length },
    })
  }),
  http.get('/api/v1/device-recognition/summary', () => HttpResponse.json({
    total_endpoints: 121,
    brand_inference_conflicts: 0, brand_inference_enabled: true, domain_window: '7d',
    coverage: { brand_inferred: { known: 1, rate: 1 / 121 }, vendor: { known: 52, rate: 52 / 121 }, brand: { known: 1, rate: 1 / 121 }, model: { known: 1, rate: 1 / 121 }, device_type: { known: 15, rate: 15 / 121 }, os_family: { known: 15, rate: 15 / 121 }, ecosystem: { known: 0, rate: 0 } },
    event_count: 3_795_418,
    attributed_event_count: 0,
    event_attribution_rate: 0,
    ecosystem_matched: 27_124,
    ecosystem_attributed: 0,
    ecosystem_unattributed: 27_124,
    ecosystem_conflicts: 0,
    domain_rule_version: 'offline-20260831-mock',
    backfill_status: 'completed',
    backfill_processed: 10_039_092,
    as_of: new Date().toISOString(),
    window: '24h',
  })),
  http.get('/api/v1/endpoints/:endpointId/name-evidence', () => HttpResponse.json({items: [{value:'office-mac41.local',source:'dhcp_hostname',kind:'hostname',event_id:'fixture-name-event',sensor_id:'fixture',observed_at:new Date().toISOString(),valid_until:new Date(Date.now()+86400000).toISOString(),attribution:'dhcp_mac'}],total:1})),
  http.post('/api/v1/endpoints/:endpointId/name-note', async ({request}) => {
    const {value}=await request.json() as {value:string}
    macOSProfile.device_name=value?{value,source:'manual',manual:true,status:'current',multiple_names:false}:macOSDevice.device_name
    return HttpResponse.json({updated:true})
  }),
  http.get('/api/v1/endpoints/:endpointId/identity', ({ params }) => {
    const endpointId = decodeURIComponent(String(params.endpointId))
    const referenceDevice = manufacturerReferenceDevices.find(item => item.endpoint_id === endpointId)
    if (referenceDevice) return HttpResponse.json({ ...macOSProfile, endpoint_id: endpointId, endpoint: { ...macOSProfile.endpoint, endpoint_id: endpointId, primary_mac: referenceDevice.primary_mac, attributes: { oui_vendor: referenceDevice.vendor } }, recognition: referenceDevice })
    if (endpointId === macOSDevice.endpoint_id) return HttpResponse.json(macOSProfile)
    if (endpointId === domainOnlyDevice.endpoint_id) return HttpResponse.json(domainOnlyProfile)
    for (const inventory of Object.values(deviceInventoriesByIp)) {
      const device = inventory.devices.find((item) => item.endpoint_id === endpointId || item.device_id === endpointId)
      if (!device) {
        continue
      }
      const accountId = device.account_id || '2026000123'
      return HttpResponse.json({
        endpoint_id: endpointId,
        summary: `终端 ${endpointId} 关联 1 个账号、1 个 IP 和 1 个接入位置`,
        endpoint: {
          endpoint_id: endpointId,
          primary_mac: device.signals.find((signal) => signal.kind === 'mac')?.normalized_value,
          entity_role: 'endpoint',
          first_seen: device.first_seen || inventory.first_seen,
          last_seen: device.last_seen || inventory.last_seen,
          identity_confidence: device.confidence,
          attributes: {},
          registration_status: device.endpoint_id ? 'registered' : 'unregistered',
          owner_account: accountId,
          owner_name: '样本用户',
          owner_department: '网络中心',
          asset_tag: `ASSET-${device.device_id.slice(-4)}`,
          ownership_class: 'school_asset',
          registration_note: 'Mock endpoint 登记样本',
          merge_status: 'active',
        },
        accounts: [accountId],
        sessions: [
          {
            session_id: `session-${device.device_id}`,
            account_id: accountId,
            endpoint_id: endpointId,
            ip: inventory.ip,
            mac: device.signals.find((signal) => signal.kind === 'mac')?.normalized_value,
            access_id: device.access_id || 'Dorm-A-AP01',
            source: 'mock',
            started_at: device.first_seen || inventory.first_seen,
            ended_at: device.last_seen || inventory.last_seen,
            identity_confidence: device.confidence,
          },
        ],
        ip_history: [
          {
            event_id: `ip-${device.device_id}`,
            endpoint_id: endpointId,
            account_id: accountId,
            entity_role: 'endpoint',
            ip: inventory.ip,
            mac: device.signals.find((signal) => signal.kind === 'mac')?.normalized_value,
            source: 'mock',
            first_seen: inventory.first_seen,
            last_seen: inventory.last_seen,
            identity_confidence: device.confidence,
            event_ids_sample: [`event-device-${device.device_id}`],
          },
        ],
        access_history: [
          {
            event_id: `access-${device.device_id}`,
            endpoint_id: endpointId,
            account_id: accountId,
            entity_role: 'endpoint',
            access_id: device.access_id || 'Dorm-A-AP01',
            access_type: 'wireless',
            ap: device.access_id || 'Dorm-A-AP01',
            source: 'mock',
            first_seen: inventory.first_seen,
            last_seen: inventory.last_seen,
            identity_confidence: device.confidence,
            event_ids_sample: [`event-access-${device.device_id}`],
          },
        ],
		ecosystem_evidence: device.model?[{endpoint_id:endpointId,domain:'settings-win.data.microsoft.com',ecosystem:'Microsoft Windows',event_source:'tls',attribution_method:'active_auth_session',auth_session_id:`session-${device.device_id}`,rule_source:'NextDNS',rule_version:'offline-mock-v2',category:'telemetry',confidence:0.55,first_seen:inventory.first_seen,last_seen:inventory.last_seen,count:4,event_ids_sample:[`event-domain-${device.device_id}`]}]:[],
        first_seen: device.first_seen || inventory.first_seen,
        last_seen: device.last_seen || inventory.last_seen,
      })
    }
    return HttpResponse.json({
      endpoint_id: endpointId,
      summary: `终端 ${endpointId} 暂无完整身份历史`,
      endpoint: {
        endpoint_id: endpointId,
        entity_role: 'endpoint',
        first_seen: new Date().toISOString(),
        last_seen: new Date().toISOString(),
        identity_confidence: 0,
        attributes: {},
        registration_status: 'unregistered',
        merge_status: 'active',
      },
      accounts: [],
      sessions: [],
      ip_history: [],
      access_history: [],
      first_seen: new Date().toISOString(),
      last_seen: new Date().toISOString(),
    })
  }),
  http.get('/api/v1/device-signals', () =>
    HttpResponse.json({ items: Object.values(deviceInventoriesByIp).flatMap((item) => item.signals) }),
  ),
  http.get('/api/v1/device-fingerprint-conflicts', () =>
    HttpResponse.json({ items: Object.values(deviceInventoriesByIp).flatMap((item) => item.conflicts) }),
  ),
  http.get('/api/v1/ips/:ip/events', ({ params }) => {
    const ip = normalizeIp(String(params.ip))
    return HttpResponse.json({ events: eventsByIp[ip] ?? [] })
  }),
  http.get('/api/v1/events', ({ request }) => {
    const url = new URL(request.url)
    const q = url.searchParams.get('q')?.toLowerCase()
    const eventType = url.searchParams.get('type')
    const domain = url.searchParams.get('domain')?.toLowerCase()
    const srcIp = url.searchParams.get('src_ip')
    const dstIp = url.searchParams.get('dst_ip')
    const userAgent = url.searchParams.get('user_agent')?.toLowerCase()
    const fingerprint = url.searchParams.get('fingerprint')?.toLowerCase()
    const proto = url.searchParams.get('proto')?.toLowerCase()
    const port = url.searchParams.get('port')
    const limit = Number(url.searchParams.get('limit') ?? 50)
    const cursor = Number(url.searchParams.get('cursor') ?? 0)
    const allEvents = Object.values(eventsByIp).flat()
    const filtered = allEvents
      .filter((event) => !eventType || event.type === eventType)
      .filter((event) => !q || event.event_id.toLowerCase().includes(q) || JSON.stringify(event.subject).toLowerCase().includes(q))
      .filter((event) => !domain || JSON.stringify(event.payload).toLowerCase().includes(domain))
      .filter((event) => !srcIp || event.flow?.src_ip === srcIp || event.subject?.ip === srcIp)
      .filter((event) => !dstIp || event.flow?.dst_ip === dstIp)
      .filter((event) => !userAgent || String(event.payload?.user_agent ?? '').toLowerCase().includes(userAgent))
      .filter((event) => !fingerprint || String(`${event.payload?.ja3 ?? ''} ${event.payload?.ja4 ?? ''}`).toLowerCase().includes(fingerprint))
      .filter((event) => !proto || String(event.flow?.proto ?? '').toLowerCase() === proto)
      .filter((event) => !port || String(event.flow?.dst_port ?? '') === port)
    const pageItems = filtered.slice(cursor, cursor + limit)
    const nextCursor = cursor + pageItems.length < filtered.length ? String(cursor + pageItems.length) : null
    return HttpResponse.json({ events: pageItems, page: { limit, next_cursor: nextCursor, total: filtered.length } })
  }),
  http.get('/api/v1/events/:eventId', ({ params }) => {
    const item = Object.values(eventsByIp).flat().find((entry) => entry.event_id === params.eventId)
    return item ? HttpResponse.json(item) : new HttpResponse(null, { status: 404 })
  }),
  http.get('/api/v1/ingest/status', () => HttpResponse.json(ingestStatus)),
  http.get('/api/v1/ingest/runs', () => HttpResponse.json({ runs: shadowRuns })),
  http.get('/api/v1/ingest/diagnostics', ({ request }) => { const result = mockPage(ingestDiagnostics, new URL(request.url)); return HttpResponse.json({ diagnostics: result.items, page: result.page }) }),
  http.get('/api/v1/ingest/diagnostics/:diagnosticId', ({ params }) => { const item = ingestDiagnostics.find((entry) => entry.diagnostic_id === params.diagnosticId); return item ? HttpResponse.json(item) : new HttpResponse(null, { status: 404 }) }),
  http.get('/api/v1/ingest/event-types', () => HttpResponse.json({ event_types: ingestEventTypes })),
  http.get('/api/v1/ingest/errors', ({ request }) => { const result = mockPage(ingestDiagnostics.filter((item) => item.severity !== 'info'), new URL(request.url)); return HttpResponse.json({ diagnostics: result.items, page: result.page }) }),
  http.post('/api/v1/labels', async ({ request }) => {
    const payload = (await request.json()) as CreateLabelRequest
    const created = {
      ...payload,
      label_id: `label-${Date.now()}`,
      created_by: mockSession.user.id,
      created_at: new Date().toISOString(),
    }
    if(payload.target_type==='risk_snapshot'){
      const sample=shadowReviewSamples.samples.find(sample=>sample.sample_id===payload.target_id);
      if(sample){sample.review_status=payload.label;sample.review_reason=payload.reason;sample.reviewed_by=created.created_by;sample.reviewed_at=created.created_at;}
    }
    auditLogs.unshift({
      audit_id: `audit-${Date.now()}`,
      actor: mockSession.user.id,
      action: 'labels.create',
      target: `${payload.target_type}:${payload.target_id}`,
      outcome: payload.label,
      created_at: created.created_at,
    })
    return HttpResponse.json(created, { status: 201 })
  }),
  http.get('/api/v1/shadow/runs', ({ request }) => { const result = mockPage(shadowRuns, new URL(request.url)); return HttpResponse.json({ runs: result.items, page: result.page }) }),
  http.get('/api/v1/shadow/runs/:runId', ({ params }) => { const item = shadowRuns.find((entry) => entry.run_id === params.runId); return item ? HttpResponse.json(item) : new HttpResponse(null, { status: 404 }) }),
  http.get('/api/v1/shadow/evaluation', () => HttpResponse.json(shadowEvaluation)),
  http.get('/api/v1/shadow/review-samples', ({ request }) => {
    const date = new URL(request.url).searchParams.get('date')
    return HttpResponse.json({ ...shadowReviewSamples, date: date ?? shadowReviewSamples.date })
  }),
  http.get('/api/v1/audit-logs', ({ request }) => { const result = mockPage(auditLogs, new URL(request.url)); return HttpResponse.json({ logs: result.items, page: result.page }) }),
  http.get('/api/v1/audit-logs/:auditId', ({ params }) => { const item = auditLogs.find((entry) => entry.audit_id === params.auditId); return item ? HttpResponse.json(item) : new HttpResponse(null, { status: 404 }) }),
  http.get('/api/v1/device-fingerprint-library', () => HttpResponse.json({ domain_available:true,brand_eligible_rule_count:3,domain_sources:[{name:'Apple enterprise networks',version:'reviewed-2026-09-08',rule_count:3,brand_eligible_rule_count:3},{name:'HaGeZi',version:'mock-pinned',rule_count:100,brand_eligible_rule_count:0}],version:'offline-20260831-mock',status:'ready',source:'offline-bundle',checksum:'mock',offline_mode:true,rule_count:860,oui_count:42000,dhcp_rule_count:310,domain_rule_count:128,domain_ecosystem_count:8,domain_source_version:'abcdef123456',domain_backfill_status:'completed',domain_backfill_processed:3200,licenses:['Apache-2.0','ODbL-1.0','DbCL-1.0','MIT (NextDNS)'],backfill_status:'completed',backfill_processed:110 })),
  http.post('/api/v1/device-fingerprint-library/update', () => HttpResponse.json({ code:'offline_update_required',message:'import a verified bundle' },{status:409})),
  http.post('/api/v1/device-fingerprint-library/validate', () => HttpResponse.json({schema_version:'device-fingerprint-bundle/v1',version:'offline-20260831-mock',created_at:new Date().toISOString(),sources:[{name:'IEEE MA-L/MA-M/MA-S',version:'2026-08-31',url:'https://standards-oui.ieee.org/',license:'IEEE public registry'},{name:'uap-core',version:'mocksha',url:'https://github.com/ua-parser/uap-core',license:'Apache-2.0'},{name:'Fingerbank public snapshot',version:'6.8.2-20140609',url:'https://github.com/karottc/fingerbank',license:'ODbL-1.0/DbCL-1.0'}],files:{}})),
  http.post('/api/v1/device-fingerprint-library/import', () => HttpResponse.json({version:'offline-20260831-mock',status:'ready',source:'offline-bundle',checksum:'mock',offline_mode:true,rule_count:860,oui_count:42000,dhcp_rule_count:310,licenses:['Apache-2.0','ODbL-1.0','DbCL-1.0'],backfill_status:'pending',backfill_processed:0})),
  http.get('/api/v1/rules/status', () => HttpResponse.json({reload_supported:false,reload_status:'disabled'})),
  http.get('/api/v1/shadow/review-samples/:sampleId', ({params}) => { const sample=shadowReviewSamples.samples.find(s=>s.sample_id===params.sampleId); if(!sample)return new HttpResponse(null,{status:404}); const evidence=(evidenceByIp[sample.ip]??[]).filter(e=>sample.evidence_ids.includes(e.evidence_id)); return HttpResponse.json({sample,snapshot:{ip:sample.ip,level:sample.level,score:sample.score,confidence:sample.confidence,window:"24h",updated_at:sample.snapshot_time,evidence_ids:sample.evidence_ids,summary:"历史回放快照"},evidence,missing_evidence_ids:sample.evidence_ids.filter(id=>!evidence.some(e=>e.evidence_id===id))}); }),
  http.post('/api/v1/rules/reload', () =>
    HttpResponse.json(
      { status: 'disabled', mode: 'shadow', requested_at: new Date().toISOString() },
      { status: 202 },
    ),
  ),
]

function mockPage<T>(items: T[], url: URL) {
  const limit = Number(url.searchParams.get('limit') ?? 20)
  const cursor = Number(url.searchParams.get('cursor') ?? 0)
  const pageItems = items.slice(cursor, cursor + limit)
  return { items: pageItems, page: { limit, next_cursor: cursor + pageItems.length < items.length ? String(cursor + pageItems.length) : null, total: items.length } }
}

function filterMockFlows(url: URL) {
  const q = url.searchParams.get('q')?.toLowerCase()
  const domain = url.searchParams.get('domain')?.toLowerCase()
  const srcIp = url.searchParams.get('src_ip')
  const dstIp = url.searchParams.get('dst_ip')
  const userAgent = url.searchParams.get('user_agent')?.toLowerCase()
  const fingerprint = url.searchParams.get('fingerprint')?.toLowerCase()
  const proto = url.searchParams.get('proto')?.toLowerCase()
  const port = url.searchParams.get('port')
  const limit = Number(url.searchParams.get('limit') ?? 50)
  const cursor = Number(url.searchParams.get('cursor') ?? 0)
  const filtered = Object.values(mockFlowSamples)
    .flat()
    .filter((flow) => !q || JSON.stringify(flow).toLowerCase().includes(q))
    .filter((flow) => !domain || String(flow.domain ?? flow.tls_sni ?? '').toLowerCase().includes(domain))
    .filter((flow) => !srcIp || flow.src_ip === srcIp)
    .filter((flow) => !dstIp || flow.dst_ip === dstIp)
    .filter((flow) => !userAgent || String(flow.user_agent ?? '').toLowerCase().includes(userAgent))
    .filter((flow) => !fingerprint || String(`${flow.ja3 ?? ''} ${flow.ja4 ?? ''}`).toLowerCase().includes(fingerprint))
    .filter((flow) => !proto || String(flow.protocol ?? '').toLowerCase() === proto)
    .filter((flow) => !port || String(flow.dst_port ?? '') === port)
  const items = filtered.slice(cursor, cursor + limit)
  const nextCursor = cursor + items.length < filtered.length ? String(cursor + items.length) : null
  return { items, page: { limit, next_cursor: nextCursor, total: filtered.length } }
}
