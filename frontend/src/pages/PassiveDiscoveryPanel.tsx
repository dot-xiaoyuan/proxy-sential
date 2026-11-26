import {
  AppErrorAlert,
  AppServerPagination, useCursorPagePosition, usePaginationMetadata,
  AppTable,
  StatusDot
} from '../shared/ui'
import { Notice as Alert } from '../shared/ui/Notice'
import {
  useEffect,
  useState
} from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Button,
  Checkbox,
  Collapse,
  Drawer,
  Dropdown,
  Input,
  Modal,
  Select,
  Space,
  Tag,
  Typography,
  message,
} from 'antd'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { DownloadOutlined, DownOutlined, FilterOutlined, LoadingOutlined, ReloadOutlined, SearchOutlined } from '@ant-design/icons'
import { ApiError, request } from '../shared/api/client'
import type { components } from '../shared/api/generated'
import type { InventoryDetail } from '../shared/api/types'
import { DiscoveryDeviceIcon } from '../entities/device/DiscoveryDeviceIcon'
import { resolveDeviceBrand } from '../entities/device/brandMatcher'
import { isLocallyAdministeredMAC } from '../entities/device/mac'
import { DiscoveryEvidenceSummary } from './DiscoveryEvidenceSummary'
import { DiscoveryBehaviorEvidence } from './DiscoveryBehaviorEvidence'
import { DiscoveryObservationRange } from './DiscoveryObservationRange'
import { DiscoveryDistribution } from './DiscoveryDistribution'
import { DiscoveryProductClues } from './DiscoveryProductClues'
import { discoveryCSV, fetchDiscoveryExport } from './discoveryExport'
import { qualityReportCSV } from './discoveryQualityReport'
import { loadDiscoveryViews, removeDiscoveryView, saveDiscoveryView } from './discoveryViews'
import { deviceTypeLabel } from '../entities/device/DeviceInventoryCells'
import { observedTimeLabel, observedTimeTitle } from '../shared/ui/observedTime'
import { flowBelongsToDevice, serviceBelongsToDevice, signalAddressMatchesDevice } from './discoveryServiceAttribution'
import { discoveryClassificationExplanation, discoveryNameClue } from './discoveryClassificationClues'
import { activityStates, confirmedDeviceType, deviceTypeEvidenceState, hardwareStates, typeEvidenceLabels, type HardwareView } from './discoveryHardware'

type DeviceRecognition = { os_family?: string; os_family_confidence?: number; device_type?: string; brand?: string; model?: string; confidence?: number; rule_version?: string; source?: string; evidence?: string[]; brand_inference_status?: string; brand_inference_brand?: string; brand_inference_confidence?: number }
type Device = components['schemas']['DiscoveryDevice'] & HardwareView & { recognition?: DeviceRecognition }
type Page = components['schemas']['DiscoveryDevicePage']
type Coverage = components['schemas']['DiscoveryCoverage']
type Statistics = components['schemas']['DiscoveryStatistics']
type Catalogue = components['schemas']['DiscoveryTypeCatalogue']
type History = components['schemas']['DiscoveryHistoryPage']
type ServiceClue = components['schemas']['DiscoveryServiceClue']
type ObservedPort = components['schemas']['DiscoveryObservedPort']
type PassiveSignals = components['schemas']['DiscoveryPassiveSignals']
type PassiveSignal = components['schemas']['DiscoveryPassiveSignal']
const dhcpEvidenceLabels: Record<string, string> = {
  hostname: 'DHCP 主机名',
  dhcp_vendor_class: 'DHCP 厂商类',
  dhcp_requested_options: 'DHCP 请求选项',
  dhcp_client_id_hwtype: 'DHCP 客户端标识类型',
  dhcp_option93_present: 'DHCP 选项 93',
}
function dhcpFieldEvidenceFor(signal?: PassiveSignal) {
  const values: Record<string, string> = {
    hostname: signal?.dhcp_hostname ?? '',
    dhcp_vendor_class: signal?.dhcp_vendor_class ?? '',
    dhcp_requested_options: signal?.dhcp_options ?? '',
    dhcp_client_id_hwtype: signal?.dhcp_client_id_hwtype ?? '',
    dhcp_option93_present: signal?.dhcp_option93_present ? '已观测' : '',
  }
  return Object.entries(signal?.dhcp_field_evidence ?? {})
    .filter(([field, ref]) => values[field] && (ref.event_id || ref.raw_sha256))
    .map(([field, ref]) => ({ field, label: dhcpEvidenceLabels[field] ?? field, value: values[field], ref }))
}
type HandshakeClue = components['schemas']['DiscoveryHandshakeClue']
const protocols: Record<string, string> = { dhcp: 'DHCP', dhcp_client: 'DHCP 客户端特征', dhcpv6: 'DHCPv6', sip: 'SIP', sadp: 'SADP', capwap: 'CAPWAP', dahua_discovery: '大华发现', ssh_banner: 'SSH', dns_sd: 'DNS-SD', ssdp: 'SSDP', ws_discovery: 'WS-Discovery', arp: 'ARP', ndp: 'NDP', ieee1905: 'IEEE 1905', ieee1905_client: 'IEEE 1905', ieee1905_client_association: 'IEEE 1905', lldp: 'LLDP', cdp: 'CDP', snmp: 'SNMP', ipp: 'IPP', onvif: 'ONVIF', nbns: 'NBNS', llmnr: 'LLMNR', bacnet: 'BACnet/IP', modbus: 'Modbus', coap: 'CoAP', mqtt: 'MQTT', http: 'HTTP', tls: 'TLS', rtsp: 'RTSP', fdb: '交换机 MAC 表', neighbor: '邻居表', active: '探测响应' }
const capabilities: Record<string, string> = { printing: '打印', scanning: '扫描', casting: '投屏', network_video: '网络视频', media_rendering: '媒体播放', voice: '语音通话' }
function discoveryAddressClue(item: Device) {
  return item.hardware_type_status && !item.mac && !item.endpoint_id
    ? item.current_addresses?.[0] || item.primary_ip || item.last_observed_ip || ''
    : ''
}

function hardwareStatusLabel(item: Device): string {
  const evidence = deviceTypeEvidenceState(item)
  if (hasVirtualizationClue(item)) return '画像线索'
  if (evidence !== 'identified' && item.cross_verification?.status === 'cross_verified' && item.cross_verification.device_type) {
    return '多源交叉确认'
  }
  if (evidence === 'ip_product_only') return item.product_clues?.some(clue => clue.product_status === 'conflict')
    ? 'IP 自报产品有冲突' : 'IP 自报 · 归属待核实'
  return typeEvidenceLabels[evidence] ?? ''
}

function ipProductTypeLabel(item: Device, types: Record<string, string>) {
  if (item.hardware_type_status !== 'candidate' || !item.product_clues?.length) return ''
  if (item.product_clues.some(clue => clue.product_status === 'conflict')) return ''
  const hints = new Set(item.product_clues.map(clue => clue.type).filter(Boolean))
  const type = hints.size === 1 ? [...hints][0] : undefined
  return type ? types[type] ?? deviceTypeLabel(type) : ''
}

const states: Record<string, string> = { identified: '证据有效', expired: '证据已过期', conflict: '类型证据冲突', candidate: '发现线索' }
const reviewReasons: Record<string, string> = { new_priority: '近 7 天新出现重点品类', type_change: '待核实类型变化线索', conflict: '类型证据冲突', address_only: '长期只有地址线索' }
const categories: Record<string, string> = { mobile: '手机', tablet: '平板', desktop: '电脑类设备', printer: '打印设备', camera: '摄像设备', access_control: '门禁设备', network: '网络设备', media: '媒体设备', voice: '语音设备', identity_only: '仅身份线索' }
function qualityItem(label: string, value: { known: number; rate: number } | undefined, total: number) {
  if (!value) return null
  return <span className="recognition-quality-item" key={label}><Typography.Text type="secondary">{label}</Typography.Text><Typography.Text strong>{Math.round(value.rate * 100)}%</Typography.Text><Typography.Text type="secondary">{value.known}/{total}</Typography.Text></span>
}

function dumbTerminal(item: Device) {
  if (['access_point', 'router', 'switch', 'wireless_controller', 'wireless_host', 'gateway', 'firewall'].includes(confirmedDeviceType(item) || item.candidate_device_type || '')) return ''
  const caps = item.capabilities ?? []
  if (caps.includes('printing') || caps.includes('scanning')) return '打印/扫描'
  if (caps.includes('casting') || caps.includes('media_rendering')) return '媒体播放/投屏'
  if (caps.includes('network_video')) return '视频监控'
  if (caps.includes('voice')) return '语音话机'
  return ''
}

// One discovery key can legitimately split into separate evidence/identity groups.
// Keep the API id for history and use a scoped evidence key only for reconciliation.
function discoveryTableRowKey(item: Device) {
  return JSON.stringify([item.id, item.sensor_id, item.site, item.domain, item.vlan, item.endpoint_id, item.mac, item.observations.map(o => o.id).sort()])
}

function typeLabel(item: Device, types: Record<string, string>) {
  if (item.hardware_type_status) {
    if (item.hardware_type_status === 'conflict') return hardwareStates.conflict
    const hardware = confirmedDeviceType(item)
    if (hardware) return types[hardware] ?? deviceTypeLabel(hardware)
    if (item.cross_verification?.status === 'cross_verified' && item.cross_verification.device_type) {
      return types[item.cross_verification.device_type] ?? deviceTypeLabel(item.cross_verification.device_type)
    }
    return profileCandidateLabel(item, types)
  }
  if (item.classification_status === 'conflict') return '类型证据冲突'
  if (item.classification_status === 'expired') return item.last_device_type ? `${types[item.last_device_type] ?? deviceTypeLabel(item.last_device_type)} · 历史类型` : ''
  if (item.classification_status === 'candidate' && item.last_product_type) return `${types[item.last_product_type] ?? deviceTypeLabel(item.last_product_type)} · 历史型号自报`
  const observed = item.device_type
  if (observed) {
    const label = types[observed] ?? deviceTypeLabel(observed)
    return item.classification_status === 'candidate' ? `${label} · 类型线索` : label
  }
  const recognized = item.recognition?.device_type
  if (recognized && ((item.recognition?.confidence ?? 0) >= .8)) return types[recognized] ?? deviceTypeLabel(recognized)
  return ''
}

function profileCandidateLabel(item: Device, types: Record<string, string>) {
  const type = item.candidate_device_type
  if (hasVirtualizationClue(item)) return '虚拟化线索'
  return item.hardware_type_status === 'candidate' && type ? (types[type] ?? deviceTypeLabel(type)) : ''
}

function hasVirtualizationClue(item: Device) {
  return item.hardware_type_status === 'candidate' && item.candidate_device_type === 'virtual_machine'
}

const virtualizationHelp = '网卡厂商或终端指纹提示可能来自虚拟机或虚拟网卡，仅凭这条线索无法确认设备类型。'

function recognitionTypeLabel(item: Device, types: Record<string, string>) {
  if (item.hardware_type_status) return ''
  const type = item.recognition?.device_type
  if (!type) return ''
  const label = types[type] ?? deviceTypeLabel(type)
  const confidence = item.recognition?.confidence ?? 0
  return confidence > 0 && confidence < .8 ? `${label} · 类型线索（${Math.round(confidence * 100)}%）` : label
}

function recognitionOSLabel(item: Device) {
  const os = item.recognition?.os_family
  if (!os) return ''
  const confidence = item.recognition?.os_family_confidence ?? item.recognition?.confidence ?? 0
  return confidence > 0 && confidence < .8 ? `${os} · 系统线索（${Math.round(confidence * 100)}%）` : os
}

function dhcpHintLabel(hint: string) {
  const lower = hint.toLowerCase()
  if (lower.includes('android')) return 'Android 设备'
  if (lower.includes('windows')) return 'Windows 设备'
  if (lower.includes('apple') || lower.includes('ios') || lower.includes('mac')) return 'Apple 设备'
  if (lower.includes('linux')) return 'Linux 设备'
  return hint
}

function DebouncedInput({ label, placeholder, value, onChange }: { label: string; placeholder: string; value: string; onChange: (value: string) => void }) {
  const [draft, setDraft] = useState(value)
  useEffect(() => setDraft(value), [value])
  useEffect(() => {
    const timer = globalThis.setTimeout(() => { if (draft !== value) onChange(draft) }, 300)
    return () => globalThis.clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft, value])
  return <Input aria-label={label} placeholder={placeholder} allowClear value={draft} onChange={event => setDraft(event.target.value)} />
}

function barBucket(value: number, max: number) {
  if (value <= 0 || max <= 0) return 0
  return Math.min(10, Math.max(1, Math.ceil(value / max * 10)))
}

function trendBucket(value: number, max: number) {
  if (value <= 0) return 0
  if (max <= 0) return 1
  return Math.min(5, Math.max(1, Math.ceil(value / max * 5)))
}

function secondaryTypeClue(item: Device, types: Record<string, string>, signal?: PassiveSignal) {
  if (dumbTerminal(item)) return `服务能力线索 · ${dumbTerminal(item)}`
  if (signal?.device_hint) return `${dhcpHintLabel(signal.device_hint)} · DHCP ${signal.dhcp_historical ? '历史线索' : '线索'}`
  if (item.recognition?.brand_inference_status === 'inferred' && item.recognition?.brand_inference_brand) return `${item.recognition.brand_inference_brand} · 品牌推断线索`
  const recognized = item.hardware_type_status ? '' : item.recognition?.device_type
  if (recognized && (item.recognition?.confidence ?? 0) < .8) return `${types[recognized] ?? deviceTypeLabel(recognized)} · 低置信度线索`
  if (item.classification_status === 'candidate' && item.device_type && !item.last_product_type) return `${types[item.device_type] ?? deviceTypeLabel(item.device_type)} · 类型线索`
  return ''
}

const discoveryFilterKeys = ['category', 'type', 'protocol', 'state', 'domain', 'vlan', 'window', 'capability', 'random_mac', 'os', 'review_reason', 'last_seen_from', 'last_seen_to', 'first_seen_within', 'subnet', 'identity_scope'] as const
const discoveryPresets = [
  { id: 'active-dumb', name: '近 15 分钟活跃哑终端', params: 'discovery_window=15m&discovery_capability=dumb' },
  { id: 'new-confirmed', name: '高置信度新设备 · 近 7 天', params: 'discovery_window=168h&discovery_state=identified&discovery_first_seen_within=168h' },
  { id: 'conflicts', name: '类型冲突待核实', params: 'discovery_state=conflict' },
]

const dumbTerminalGroups: Array<{ key: string; label: string; types: string[] }> = [
  { key: 'print', label: '打印/扫描', types: ['printer', 'scanner'] },
  { key: 'video', label: '视频监控', types: ['camera', 'recorder'] },
  { key: 'access', label: '门禁考勤', types: ['access_control', 'attendance'] },
  { key: 'media', label: '媒体显示', types: ['media_player', 'media_device', 'display', 'tv'] },
  { key: 'voice', label: '语音话机', types: ['voip_phone', 'voice_gateway'] },
  { key: 'facility', label: '动环楼宇', types: ['ups', 'pdu', 'environment_monitor', 'building_controller', 'building_device', 'sensor', 'iot_gateway'] },
]
function DiscoveryDetailHeader({ item, types, profileModel, openProfile }: { item: Device; types: Record<string, string>; profileModel?: string; openProfile: () => void }) {
  const address = discoveryAddressClue(item)
  const identifier = item.mac || address || item.endpoint_id || item.primary_ip || item.id
  const name = item.name?.trim()
  const title = name || identifier
  const confirmed = confirmedDeviceType(item)
  const profile = profileCandidateLabel(item, types)
  const product = ipProductTypeLabel(item, types)
  const status = item.hardware_type_status || item.classification_status
  const hasProfileType = deviceTypeEvidenceState(item) === 'profile_typed'
  const evidence = deviceTypeEvidenceState(item)
  const statusLabel = item.hardware_type_status
    ? hardwareStatusLabel(item)
    : ({ conflict: '类型证据冲突', expired: '历史证据已过期' } as Record<string, string>)[status ?? '']
  const type = confirmed ? types[confirmed] ?? deviceTypeLabel(confirmed)
    : profile || product || (!item.hardware_type_status && status !== 'conflict' ? typeLabel(item, types) : '')
  let explanation = discoveryClassificationExplanation(item)
  if (profile) {
    explanation = item.candidate_device_type === 'desktop'
      ? '电脑画像可见于台式机和笔记本。'
      : hasVirtualizationClue(item) ? virtualizationHelp : ''
  } else if (evidence === 'ip_product_only' && !item.product_clues?.some(clue => clue.product_status === 'conflict')) {
    explanation = ''
  }
  return <>
    <header className="discovery-detail-identity">
      <DiscoveryDeviceIcon type={confirmed} capabilities={item.capabilities} />
      <div className="discovery-detail-title">
        <strong>{title}</strong>
        {name && identifier && name.toLowerCase() !== identifier.toLowerCase() && <span>{identifier}</span>}
      </div>
      {item.endpoint_id && <Button type="link" size="small" className="discovery-detail-profile-link" onClick={openProfile}>查看终端画像</Button>}
    </header>
    <section className="discovery-type-summary" aria-label="设备类型">
      <Typography.Title level={5}>设备类型</Typography.Title>
      <div className="discovery-type-summary-line">
        {type && <strong>{type}</strong>}
        {statusLabel && <Tag color={confirmed ? 'success' : status === 'conflict' ? 'warning' : undefined}>{statusLabel}</Tag>}
      </div>
      {explanation && <p>{explanation}</p>}
      {profile && profileModel && <p>关联终端画像中的型号 · {profileModel}</p>}
      {hasProfileType && item.candidate_device_type === 'desktop' && item.recognition?.evidence?.filter(note => note.startsWith('Client UA: ')).map(note =>
        <p key={note}>同 MAC 画像中的浏览器线索 · {note.slice('Client UA: '.length)}</p>)}
    </section>
  </>
}

const detailFactGroups: Array<{ title: string; labels: string[] }> = [
  { title: '厂商与型号', labels: ['制造商', '型号', '型号状态', '型号冲突项'] },
  { title: '网络与时效', labels: ['活动状态', 'MAC', 'MAC 管理方式', '当前地址', '最后观测地址', '网络域', 'VLAN', '采集传感器', '窗口内首次观测', '最近观测', '证据数'] },
  { title: '系统与 DHCP', labels: ['识别操作系统', '操作系统线索', '操作系统依据', '系统置信度', 'DHCP 线索时效', 'DHCP 观测时间', '最近 DHCP 证据事件', 'DHCP 主机名', 'DHCP 厂商类', 'DHCP 请求选项', 'DHCP 客户端标识类型', 'DHCP 选项 93', 'TTL', 'TTL 观测时间', 'TTL 证据引用'] },
  { title: '识别规则', labels: ['类型依据时间', '互斥类型', '分类补充线索', '名称线索', '名称线索依据', '类型置信度', '识别设备类型', '识别规则', '识别依据', '硬件规则版本', '品牌推断'] },
]
function renderDetailFacts(entries: Array<[string, unknown]>) {
  const present = entries.filter(([, value]) => value).map(([label, value]) => [label, String(value)] as const)
  const grouped = new Set(detailFactGroups.flatMap(group => group.labels))
  const sections = detailFactGroups.map(group => ({ title: group.title, items: present.filter(([label]) => group.labels.includes(label)) })).filter(section => section.items.length)
  const rest = present.filter(([label]) => !grouped.has(label))
  const list = (items: ReadonlyArray<readonly [string, string]>) => <dl className="discovery-detail-facts">{items.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
  return <>
    <div className="discovery-detail-groups">{sections.map(section => <section className="discovery-detail-section" key={section.title}><Typography.Title level={5}>{section.title}</Typography.Title>{list(section.items)}</section>)}</div>
    {rest.length > 0 && <details className="discovery-detail-diagnostics"><summary>诊断详情（{rest.length} 项）</summary>{list(rest)}</details>}
  </>
}

export function PassiveDiscoveryPanel({ view }: { view: 'iot' | 'records' }) {
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const search = params.get('discovery_search') || ''
  const scopedView = view === 'records' && params.get('discovery_identity_scope') === 'scoped_devices'
  const addressView = view === 'records' && params.get('discovery_identity_scope') === 'address_clues'
  const dumbFilter = params.get('discovery_capability') === 'dumb'
  const [draft, setDraft] = useState(search)
  const [moreOpen, setMoreOpen] = useState(false)
  const [views, setViews] = useState(() => loadDiscoveryViews(globalThis.localStorage))
  const [activeViewId, setActiveViewId] = useState('')
  const [saveViewOpen, setSaveViewOpen] = useState(false)
  const [viewName, setViewName] = useState('')
  const [manageViewsOpen, setManageViewsOpen] = useState(false)
  const deleteSavedView = (id: string) => {
    setViews(removeDiscoveryView(globalThis.localStorage, id))
    if (activeViewId === id) setActiveViewId('')
  }
  const saveCurrentView = () => {
    const next = new URLSearchParams()
    for (const [key, value] of params) if (key.startsWith('discovery_')) next.set(key, value)
    const updated = saveDiscoveryView(globalThis.localStorage, viewName, next.toString())
    setViews(updated)
    setSaveViewOpen(false)
    setViewName('')
    message.success('视图已保存')
  }
  const [overviewOpen, setOverviewOpen] = useState(false)
  const [qualityOpen, setQualityOpen] = useState(false)
  const [trendDays, setTrendDays] = useState(7)
  const [autoRefresh, setAutoRefresh] = useState(() => {
    try { return globalThis.localStorage.getItem('proxy-sentinel.discovery.auto-refresh') === 'true' } catch { return false }
  })
  const toggleAutoRefresh = (value: boolean) => {
    setAutoRefresh(value)
    try { globalThis.localStorage.setItem('proxy-sentinel.discovery.auto-refresh', String(value)) } catch { }
  }
  const quality = useQuery({ queryKey: ['device-recognition-summary'], queryFn: ({ signal }) => request<components['schemas']['DeviceRecognitionSummary']>('/device-recognition/summary', { signal }), enabled: qualityOpen || params.get('discovery_capability') === 'dumb', staleTime: 60_000 })
  const trends = useQuery({ queryKey: ['discovery-trends', trendDays], queryFn: ({ signal }) => request<components['schemas']['DiscoveryTrends']>(`/discovery/trends?days=${trendDays}`, { signal }), enabled: qualityOpen, staleTime: 60_000 })
  const [pageSize, setPageSize] = useState(20)
  const filterKey = [view, search, pageSize, ...discoveryFilterKeys.map(k => params.get(`discovery_${k}`) || '')].join('|')
  const [paging, setPaging] = useState({ key: filterKey, page: 0 })
  useEffect(() => setPaging(current => current.key === filterKey ? current : { key: filterKey, page: 0 }), [filterKey])
  const page = paging.key === filterKey ? paging.page : 0
  const [selected, setSelected] = useState<Device>()
  const [historyPage, setHistoryPage] = useState(1), [historyPageSize, setHistoryPageSize] = useState(20)
  useEffect(() => setDraft(search), [search])
  useEffect(() => { const timer = globalThis.setTimeout(() => { const next = draft.trim(); if (next !== search) change('search', next) }, 300); return () => globalThis.clearTimeout(timer) }, [draft])
  const change = (key: string, value: string) => {
    setParams(current => { const next = new URLSearchParams(current); if (value) next.set(`discovery_${key}`, value); else next.delete(`discovery_${key}`); if (key === 'type') next.delete('discovery_category'); if (key === 'review_reason' && value) next.delete('discovery_state'); return next }, { replace: true })
  }
  const shortcut = (type: string, capability = '', state?: string) => setParams(current => { const next = new URLSearchParams(current); for (const key of ['type', 'category', 'capability', 'identity_scope']) next.delete(`discovery_${key}`); if (type) next.set('discovery_type', type); if (capability) next.set('discovery_capability', capability); if (state !== undefined) { if (state) next.set('discovery_state', state); else next.delete('discovery_state') } return next }, { replace: true })
  const showMACScopes = (item: Device) => {
    const mac = item.mac
    if (!mac) return
    setSelected(undefined)
    setDraft(mac)
    setParams(current => {
      const next = new URLSearchParams(current)
      for (const key of discoveryFilterKeys) if (key !== 'window') next.delete(`discovery_${key}`)
      next.set('discovery_search', mac)
      next.set('discovery_identity_scope', 'scoped_devices')
      if (item.domain) next.set('discovery_domain', item.domain)
      return next
    })
  }
  const showAddressClues = () => setParams(current => {
    const next = new URLSearchParams(current)
    for (const key of ['type', 'category', 'capability', 'state', 'review_reason', 'os', 'random_mac', 'first_seen_within', 'subnet']) {
      next.delete(`discovery_${key}`)
    }
    next.set('discovery_identity_scope', 'address_clues')
    return next
  }, { replace: true })
  const applyView = (view: { id: string; params: string }) => {
    setParams(current => {
      const next = new URLSearchParams(current)
      for (const key of [...next.keys()]) if (key.startsWith('discovery_') && key !== 'discovery_view') next.delete(key)
      for (const [key, value] of new URLSearchParams(view.params)) next.set(key, value)
      return next
    }, { replace: true })
    setActiveViewId(view.id)
  }
  const setWindow = (value: string) => setParams(current => {
    const next = new URLSearchParams(current)
    next.delete('discovery_last_seen_from')
    next.delete('discovery_last_seen_to')
    if (value) next.set('discovery_window', value)
    else next.delete('discovery_window')
    return next
  }, { replace: true })
  const toggleState = (value: string) => change('state', params.get('discovery_state') === value ? '' : value)
  const query = new URLSearchParams({ mode: 'passive', limit: String(pageSize) })
  if (view === 'iot') query.set('view', 'iot')
  if (search) query.set('search', search)
  for (const key of discoveryFilterKeys) { const value = params.get(`discovery_${key}`); if (key !== 'identity_scope' && value) query.set(key, value) }
  if (scopedView) query.set('identity_scope', 'scoped_devices')
  else if (addressView) query.set('identity_scope', 'address_clues')
  else if (view === 'records' && !dumbFilter) query.set('identity_scope', 'devices')
  const position = useCursorPagePosition({ path: '/discovery/devices/position', query, page: page + 1, pageSize })
  if (position.cursor) query.set('cursor', position.cursor)
  const devices = useQuery({ queryKey: ['discovery-center', query.toString()], queryFn: ({ signal }) => request<Page>(`/discovery/devices?${query}`, { signal }), enabled: position.ready, refetchInterval: autoRefresh ? 60_000 : false, refetchOnWindowFocus: autoRefresh })
  const catalogue = useQuery({ queryKey: ['discovery-types'], queryFn: ({ signal }) => request<Catalogue>('/discovery/types', { signal }) })
  const coverage = useQuery({ queryKey: ['discovery-coverage'], queryFn: ({ signal }) => request<Coverage>('/discovery/coverage', { signal }) })
  const statistics = useQuery({ queryKey: ['discovery-statistics'], queryFn: ({ signal }) => request<Statistics>('/discovery/statistics', { signal }), enabled: coverage.data?.enabled === true })
  const metadataQuery = new URLSearchParams(query); metadataQuery.delete('cursor'); metadataQuery.delete('limit')
  if (addressView) metadataQuery.set('overview', 'false')
  const discoveryMetadata = useQuery({ queryKey: ['discovery-metadata', metadataQuery.toString()], queryFn: ({ signal }) => request<components['schemas']['DiscoveryDeviceMetadata']>(`/discovery/devices/metadata?${metadataQuery}`, { signal }), refetchInterval: autoRefresh ? 60_000 : false, refetchOnWindowFocus: autoRefresh })
  const vlanFacetQuery = new URLSearchParams(metadataQuery); vlanFacetQuery.delete('vlan'); vlanFacetQuery.set('overview', 'false')
  const vlanFacets = useQuery({ queryKey: ['discovery-vlan-facets', vlanFacetQuery.toString()], queryFn: ({ signal }) => request<components['schemas']['DiscoveryDeviceMetadata']>(`/discovery/devices/metadata?${vlanFacetQuery}`, { signal }), enabled: moreOpen, staleTime: 60_000 })
  const availableTypeQuery = new URLSearchParams(metadataQuery)
  availableTypeQuery.delete('type'); availableTypeQuery.set('overview', 'false')
  const typeFacets = useQuery({
    queryKey: ['discovery-type-facets', availableTypeQuery.toString()],
    queryFn: ({ signal }) => request<components['schemas']['DiscoveryDeviceMetadata']>(`/discovery/devices/metadata?${availableTypeQuery}`, { signal }),
    enabled: query.has('type'), staleTime: 60_000,
  })
  const hardwareV2 = discoveryMetadata.data?.classification_version === 'passive-hardware/v2'
  const confirmedTypesLabel = hardwareV2 ? typeEvidenceLabels.identified : '已识别类型'
  const groupedDevices = discoveryMetadata.data?.count_unit === 'cross_vlan_discovery_identity'
  const countUnit = groupedDevices ? '个发现身份' : scopedView ? '条范围记录' : addressView ? '条地址线索' : hardwareV2 ? '条发现记录' : '个设备'
  const discoveryTotal = discoveryMetadata.data?.total
  const metadata = discoveryMetadata.data
  const hasTypeBreakdown = hardwareV2 && metadata?.profile_typed !== undefined && metadata.ip_product_only !== undefined && metadata.no_type_clue !== undefined
  const candidateCards = [
    { state: 'profile_typed', label: typeEvidenceLabels.profile_typed, count: metadata?.profile_typed },
    { state: 'ip_product_only', label: typeEvidenceLabels.ip_product_only, count: metadata?.ip_product_only },
    { state: 'no_type_clue', label: typeEvidenceLabels.no_type_clue, count: metadata?.no_type_clue },
  ]
  const viewStates = hardwareV2 ? { ...typeEvidenceLabels, candidate: '全部发现线索', expired: typeEvidenceLabels.revoked } : states
  const waitingForMetadata = discoveryMetadata.error instanceof ApiError && discoveryMetadata.error.status === 503 &&
    discoveryMetadata.error.message.includes('discovery_report_preparing')
  const metadataFailure = discoveryMetadata.isError && !waitingForMetadata
  const metadataValue = (value?: number) => value ?? (metadataFailure ? '统计读取失败' : '统计中')
  // keepPreviousData 会保留上一次结果，只看 isPending 会让搜索看起来没有反应。
  // 输入尚未落到 URL、列表或统计仍在请求时都算“更新中”，给用户持续反馈。
  const pendingSearch = draft.trim() !== search
  const listUpdating = devices.isFetching || position.isLocating
  const searching = pendingSearch || listUpdating || discoveryMetadata.isFetching
  const historyEnabled = Boolean(selected) && coverage.data?.enabled === true
  const historyMetadata = usePaginationMetadata('/discovery/history/metadata', { device_id: selected?.id }, historyEnabled)
  const historyScope = new URLSearchParams({ device_id: selected?.id ?? '' })
  if (historyMetadata.data?.snapshot) historyScope.set('snapshot', historyMetadata.data.snapshot)
  const historyPosition = useCursorPagePosition({ path: '/discovery/history/position', query: historyScope, page: historyPage, pageSize: historyPageSize, enabled: historyEnabled && Boolean(historyMetadata.data) })
  const historyQuery = new URLSearchParams(historyScope); historyQuery.set('limit', String(historyPageSize)); if (historyPosition.cursor) historyQuery.set('cursor', historyPosition.cursor)
  const history = useQuery({ queryKey: ['discovery-history', historyQuery.toString()], queryFn: ({ signal }) => request<History>(`/discovery/history?${historyQuery}`, { signal }), enabled: historyPosition.ready })
  const detailIP = selected?.current_addresses?.[0] ?? (selected?.current_addresses ? undefined : selected?.primary_ip)
  const detailFlowTarget = selected?.sensor_id && detailIP ? `${selected.sensor_id}|${detailIP}` : ''
  const portReadEnabled = detailFlowTarget !== '' && coverage.data?.enabled === true
  const handshakeClues = useQuery({ queryKey: ['discovery-handshake-clues', selected?.id, selected?.sensor_id, selected?.site, selected?.domain, detailIP], queryFn: ({ signal }) => request<{ items: HandshakeClue[] }>(`/discovery/handshake-clues?${new URLSearchParams({ sensor_id: selected!.sensor_id || '', campus_id: selected!.site || '', access_domain: selected!.domain || '', ip: detailIP! })}`, { signal }), enabled: !!selected?.sensor_id && !!selected?.site && !!selected?.domain && !!detailIP && coverage.data?.enabled === true, staleTime: 30_000 })
  const fingerprintDetail = useQuery({ queryKey: ['discovery-fingerprints', selected?.endpoint_id], queryFn: ({ signal }) => request<InventoryDetail>(`/device-inventory/${encodeURIComponent(selected!.endpoint_id!)}`, { signal }), enabled: !!selected?.endpoint_id, staleTime: 60_000 })
  const detailRecognition = fingerprintDetail.data?.profile.recognition
  const virtualizationVendor = detailRecognition?.dimension_evidence?.some(evidence => evidence.layer === 'hypervisor_oui')
    ? detailRecognition.vendor : undefined
  const types = Object.fromEntries((catalogue.data?.items ?? []).map(t => [t.id, t.label]))
  types.desktop = '个人电脑'
  if (hardwareV2) types.virtual_machine = '虚拟化'
  const items: Device[] = devices.data?.items ?? []
  const judgedPageCount = items.filter(item => confirmedDeviceType(item) || deviceTypeEvidenceState(item) === 'profile_typed').length
  const allServiceTargets = [...new Set(items.flatMap(item => item.sensor_id && item.mac ? (item.current_addresses ?? (item.primary_ip ? [item.primary_ip] : [])).map(ip => `${item.sensor_id}|${item.mac!.toLowerCase()}|${ip}`) : []))].sort()
  const serviceKey = allServiceTargets.slice(0, 50).join(',')
  const serviceClues = useQuery({ queryKey: ['discovery-service-clues', serviceKey], queryFn: ({ signal }) => request<{ items: Record<string, ServiceClue[]> }>(`/discovery/service-clues?targets=${encodeURIComponent(serviceKey)}`, { signal }), enabled: serviceKey !== '' && coverage.data?.enabled === true, staleTime: 60_000 })
  const signalKey = [...new Set(items.flatMap(item => [item.current_addresses?.[0], item.primary_ip, item.last_observed_ip].filter(Boolean) as string[]))].sort().join(',')
  const signalMACs = [...new Set(items.map(item => item.mac?.toLowerCase()).filter(Boolean))].sort().join(',')
  const signalSensors = [...new Set(items.map(item => item.sensor_id).filter(Boolean))].sort().join(',')
  const observedPorts = useQuery({ queryKey: ['discovery-observed-ports', detailFlowTarget], queryFn: ({ signal }) => request<{ items: Record<string, ObservedPort[]> }>(`/discovery/observed-ports?targets=${encodeURIComponent(detailFlowTarget)}`, { signal }), enabled: portReadEnabled, staleTime: 60_000 })
  const passiveSignals = useQuery({ queryKey: ['discovery-passive-signals', signalKey, signalMACs, signalSensors], queryFn: ({ signal }) => request<PassiveSignals>(`/discovery/passive-signals?ips=${encodeURIComponent(signalKey)}&macs=${encodeURIComponent(signalMACs)}&sensors=${encodeURIComponent(signalSensors)}`, { signal }), enabled: (signalKey !== '' || signalMACs !== '') && coverage.data?.enabled === true, staleTime: 60_000 })
  const signalFor = (item: Device) => { const ips = new Set(item.current_addresses ?? [item.primary_ip].filter(Boolean)); const mac = (item.mac || '').toLowerCase(); const candidates = (passiveSignals.data?.items ?? []).filter(signal => { const vlan = signal.dhcp_vlan || signal.ttl_vlan; return !!item.sensor_id && signal.sensor_id === item.sensor_id && !signal.client_clues?.length && (!item.vlan || !vlan || item.vlan === vlan) && signalAddressMatchesDevice(item, signal) && ((mac && signal.mac?.toLowerCase() === mac) || (signal.ip && ips.has(signal.ip) && (!mac || !signal.mac))) }); return candidates.find(signal => mac && signal.mac?.toLowerCase() === mac && (signal.dhcp_vlan || signal.ttl_vlan) === item.vlan) ?? (candidates.length === 1 ? candidates[0] : undefined) }
  const clientFor = (item: Device) => { const current = new Set(item.current_addresses ?? []); return (passiveSignals.data?.items ?? []).find(signal => !!item.sensor_id && signal.sensor_id === item.sensor_id && !!signal.ip && current.has(signal.ip) && !!signal.client_clues?.length) }
  const osFor = (item: Device) => { const signal = signalFor(item); const client = clientFor(item); const base = signal?.os_family || item.recognition?.os_family; const ipFamily = item.mac ? '' : client?.os_family; const conflict = signal?.os_conflict || (!item.mac && client?.os_conflict) || (base && ipFamily && base !== ipFamily); const detail = [signal?.os_evidence, item.recognition?.os_family ? `识别：${item.recognition.rule_version || '规则'}${item.recognition.os_family_confidence ? `（${Math.round(item.recognition.os_family_confidence * 100)}%）` : ''}` : '', !item.mac && client?.os_evidence ? `${client.os_evidence}；仅按 IP 关联，需核对地址归属` : ''].filter(Boolean).join('；'); if (conflict) return { label: '线索冲突', detail, ipOnly: false }; return { label: base || ipFamily || signal?.os_hint || '', detail: detail || (signal?.ttl ? `TTL ${signal.ttl}` : ''), ipOnly: !base && !!ipFamily } }
  const hardwareFresh = devices.data?.hardware_freshness
  const fresh = devices.data?.freshness
  const recentPageCount = (devices.data?.items ?? []).filter(item => Date.now() - new Date(item.last_seen).getTime() <= 15 * 60 * 1000).length
  const identity = (item: Device) => {
    const addressClue = discoveryAddressClue(item)
    const mac = item.mac?.toLowerCase()
    const isL3Managed = !mac && item.identity_kind === 'l3_managed_entity'
    const title = mac || (isL3Managed ? '三层受管网元' : addressClue ? '地址线索' : item.endpoint_id)
    const name = item.name?.trim()
    const sameMAC = mac && name?.replace(/[.:-]/g, '').toLowerCase() === mac.replace(/:/g, '')
    const secondary = name && name !== addressClue && !sameMAC ? name : ''
    const nameClue = discoveryNameClue(secondary)
    const iconType = item.hardware_type_status
      ? confirmedDeviceType(item)
      : ['conflict', 'expired'].includes(item.classification_status ?? '')
        ? ''
        : item.device_type || ((item.recognition?.confidence ?? 0) >= .8 ? item.recognition?.device_type : '')
    return <div className="terminal-identity discovery-identity-cell">
      <DiscoveryDeviceIcon type={iconType} capabilities={item.capabilities} />
      <div>
        {title && <Button type="link" className={mac ? 'terminal-device-link discovery-identity-mac' : 'terminal-device-link'}
          title={title} onClick={() => show(item)}>{title}</Button>}
        {secondary && <Typography.Text type="secondary" className="terminal-kind-caption discovery-identity-name"
          title={secondary}>{secondary}</Typography.Text>}
        {nameClue && <Typography.Text type="secondary" className="terminal-kind-caption" title={nameClue.detail}>{nameClue.label}</Typography.Text>}
        {mac && isLocallyAdministeredMAC(mac) && <span className="terminal-kind-caption">本地管理</span>}
        {isL3Managed ? <span className="terminal-kind-caption">跨三层自报 · 无源 MAC</span> : addressClue && item.product_clues?.length ? <span className="terminal-kind-caption">产品线索 · 归属待核实</span> : null}
      </div>
    </div>
  }
  const kind = (item: Device) => {
    const label = typeLabel(item, types)
    const productHint = label ? '' : ipProductTypeLabel(item, types)
    if (productHint) {
      return <Typography.Text type="secondary" title="IP 自报产品类型，设备归属待核实">{productHint}</Typography.Text>
    }
    if (!label) return null
    const title = hasVirtualizationClue(item)
      ? virtualizationHelp
      : item.type_evidence_at ? `类型依据于 ${observedTimeTitle(item.type_evidence_at)}`
        : item.last_product_at && item.classification_status === 'candidate'
          ? `型号自报于 ${observedTimeTitle(item.last_product_at)}，当前类型证据已过期`
          : undefined
    return <Typography.Text strong={Boolean(confirmedDeviceType(item))} title={title}>{label}</Typography.Text>
  }
  const vendor = (item: Device) => {
    const isL3Managed = !item.mac && item.identity_kind === 'l3_managed_entity'
    const productClues = discoveryAddressClue(item) ? item.product_clues ?? [] : []
    const observedManufacturers = isL3Managed && !productClues.some(clue => clue.product_status === 'conflict')
      ? [...new Set(productClues.map(clue => clue.manufacturer).filter(Boolean))]
      : []
    const observedManufacturer = observedManufacturers.length === 1 ? observedManufacturers[0] : ''
    const manufacturer = item.manufacturer || ((item.recognition?.confidence ?? 0) >= .8 ? item.recognition?.brand : '') || observedManufacturer
    const brand = resolveDeviceBrand({ brand: manufacturer })
    const brandLabel = brand.key === 'unknown' ? brand.name : brand.nameEn
    const observedModels = productClues.some(clue => clue.product_status === 'conflict')
      ? []
      : [...new Set(productClues.map(clue => clue.model).filter(Boolean))]
    const observedModel = observedModels.length === 1 ? observedModels[0] : undefined
    const model = item.hardware_type_status ? item.hardware_model || observedModel : item.model_name
    const os = osFor(item)
    const signal = signalFor(item)
    const osEvidence = signal?.dhcp_historical && signal.os_family ? '历史线索' : os.ipOnly ? 'IP 线索' : '线索'
    if (!(brandLabel || model || os.label)) return null
    return <div className="terminal-vendor">
      {brandLabel && <Typography.Text className="terminal-vendor-value" title={manufacturer}>{brandLabel}</Typography.Text>}
      {model && <Typography.Text className="terminal-vendor-value" type="secondary" title={observedModel ? `自报型号 ${model}，归属待核实` : model}>{model}</Typography.Text>}
      {os.label && <Typography.Text className="terminal-vendor-value" type="secondary" title={os.detail || os.label}>{os.label} · {osEvidence}</Typography.Text>}
    </div>
  }
  const location = (item: Device) => <Space orientation="vertical" size={0}>{item.vlan_scope_count && <Button type="link" size="small" className="discovery-scope-link" onClick={() => showMACScopes(item)}>{item.vlan_scope_count} 个采集范围</Button>}<Typography.Text>{item.vlan ? `VLAN ${item.vlan}` : item.domain}</Typography.Text><Typography.Text type="secondary">{item.vlan ? [item.domain, item.sensor_id].filter(Boolean).join(' · ') : item.sensor_id}</Typography.Text></Space>
  const servicesFor = (item: Device) => { const list = serviceClues.data?.items?.[`${item.sensor_id}|${(item.mac || '').toLowerCase()}`] ?? []; const seen = new Set<string>(); return list.filter(clue => { if (!serviceBelongsToDevice(item, clue)) return false; const key = `${clue.service_type}:${clue.port}`; if (seen.has(key)) return false; seen.add(key); return true }) }
  const portsFor = (item: Device) => { const seen = new Set<string>(); return (portReadEnabled ? observedPorts.data?.items?.[detailFlowTarget] ?? [] : []).filter(clue => { if (!flowBelongsToDevice(item, clue)) return false; const key = `${clue.proto}:${clue.dst_port}`; if (seen.has(key)) return false; seen.add(key); return true }).slice(0, 8) }
  const portLabel = (clue: ObservedPort) => clue.connection_outcome === 'syn_ack_observed' ? `见 TCP SYN-ACK ${clue.dst_port}` : `尝试连接 ${clue.proto.toUpperCase()} ${clue.dst_port}`
  const clues = (item: Device) => {
    const capItems = (item.capabilities ?? []).filter(c => capabilities[c])
    const protoItems = item.protocols ?? []
    if (!capItems.length && !protoItems.length) return null
    return <div className="discovery-clue-tags">{capItems.map(c => <Tag key={c} className="discovery-clue-tag">{capabilities[c]}</Tag>)}{protoItems.map(p => <Tag key={p} className="discovery-clue-tag">{protocols[p] ?? p}</Tag>)}</div>
  }
  const statusDotTone = (item: Device): 'ok' | 'info' | 'warn' | 'neutral' => {
    if (item.hardware_type_status) {
      const evidence = deviceTypeEvidenceState(item)
      if (evidence === 'identified') return 'ok'
      if (item.cross_verification?.status === 'cross_verified' && item.cross_verification.device_type) return 'info'
      if (evidence === 'profile_typed') return 'info'
      if (item.hardware_type_status === 'conflict' || evidence === 'revoked' || item.product_clues?.some(c => c.product_status === 'conflict')) return 'warn'
      return 'neutral'
    }
    if (item.classification_status === 'conflict' || item.classification_status === 'expired') return 'warn'
    if (item.classification_status === 'identified' || (item.current && typeLabel(item, types))) return 'ok'
    return 'neutral'
  }
  const state = (item: Device) => {
    const primaryLabel = item.hardware_type_status
      ? hardwareStatusLabel(item)
      : item.classification_status === 'candidate' && !typeLabel(item, types)
        ? ((item.protocols ?? []).every(p => p === 'arp' || p === 'ndp') && item.protocols?.length ? (item.protocols.includes('arp') ? 'ARP 地址候选' : 'NDP 地址线索') : '缺少类型证据')
        : states[item.classification_status ?? ''] ?? (item.current ? '证据有效' : '证据已过期')
    return <div className="discovery-status-details">
      {primaryLabel && <StatusDot tone={statusDotTone(item)}>{primaryLabel}</StatusDot>}
      {item.hardware_type_status && item.cross_verification?.status === 'cross_verified' && item.cross_verification.explanation && !confirmedDeviceType(item) && <Typography.Text type="secondary" title={item.cross_verification.explanation}>{item.cross_verification.explanation}</Typography.Text>}
      {item.hardware_type_status && item.activity_status && <Typography.Text type="secondary">{activityStates[item.activity_status]}</Typography.Text>}
      {item.hardware_type_status && item.type_evidence_at && <Typography.Text type="secondary" title={observedTimeTitle(item.type_evidence_at)}>类型依据 {observedTimeLabel(item.type_evidence_at)}</Typography.Text>}
      {item.hardware_type_status && item.hardware_model_status === 'conflict' && <Typography.Text type="warning">型号证据冲突</Typography.Text>}
      {item.review_reason && <Typography.Text type="secondary" title={item.review_observed_at ? observedTimeTitle(item.review_observed_at) : undefined}>{reviewReasons[item.review_reason] ?? item.review_reason}{item.review_observed_at ? ` · ${observedTimeLabel(item.review_observed_at)}` : ''}</Typography.Text>}
    </div>
  }
  const refreshDiscovery = () => { const first = new URLSearchParams(query); first.delete('cursor'); setPaging({ key: filterKey, page: 0 }); void position.invalidate(); void discoveryMetadata.refetch(); void coverage.refetch(); void statistics.refetch(); void queryClient.invalidateQueries({ queryKey: ['discovery-center'], refetchType: 'none' }); void queryClient.refetchQueries({ queryKey: ['discovery-center', first.toString()], exact: true }) }
  const refreshWorkspace = () => refreshDiscovery()
  const selectedPosition = selected ? items.findIndex(item => item.id === selected.id) : -1
  const [exporting, setExporting] = useState(false)
  const [exportProgress, setExportProgress] = useState({ count: 0, total: 0 })
  const exportDevices = async () => {
    setExporting(true)
    setExportProgress({ count: 0, total: 0 })
    try {
      const { items: devices, snapshotAt, scope, total } = await fetchDiscoveryExport<Device>(query, (count, total) => setExportProgress({ count, total }), discoveryTableRowKey)
      const blob = new Blob(['\ufeff' + discoveryCSV(devices, types, { scope, snapshotAt, total })], { type: 'text/csv;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `discovery-${new Date().toISOString().slice(0, 10)}.csv`
      anchor.click()
      URL.revokeObjectURL(url)
      message.success(`已导出当前筛选的全部 ${devices.length} ${countUnit}${snapshotAt ? ` · 快照 ${observedTimeTitle(snapshotAt)}` : ''}`)
    } catch (error) {
      message.error(`导出失败：${error instanceof Error ? error.message : String(error)}`)
    } finally {
      setExporting(false)
      setExportProgress({ count: 0, total: 0 })
    }
  }
  const exportQualityReport = () => {
    if (!quality.data) return
    const blob = new Blob(['\ufeff' + qualityReportCSV(quality.data, trends.data, types)], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `discovery-quality-${new Date().toISOString().slice(0, 10)}.csv`
    anchor.click()
    URL.revokeObjectURL(url)
  }
  const show = (item: Device) => { setHistoryPage(1); setSelected(item) }
  const deviceColumns = [
    { title: '设备标识', key: 'identity', width: 240, render: (_: unknown, item: Device) => identity(item) },
    { title: '设备类型', key: 'type', width: 128, render: (_: unknown, item: Device) => kind(item) },
    {
      title: '地址 / 网络', key: 'address', width: 172, render: (_: unknown, item: Device) => {
        const addressClue = discoveryAddressClue(item)
        const currentIP = item.current_addresses?.[0] || (item.current_addresses ? '' : item.primary_ip)
        const lastIP = !addressClue && !currentIP ? item.last_observed_ip : ''
        const address = addressClue || currentIP || lastIP
        return <div className="terminal-address">
          {address && <span className="mono wrap-text">{address}</span>}
          {addressClue
            ? <Typography.Text type="secondary">观测地址</Typography.Text>
            : lastIP && <Typography.Text type="secondary" title={observedTimeTitle(item.last_observed_ip_at)}>最后观测 IP{item.last_observed_ip_at && ` · ${observedTimeLabel(item.last_observed_ip_at)}`}</Typography.Text>}
          {location(item)}
        </div>
      }
    },
    { title: '厂商 / 系统', key: 'vendor', width: 156, render: (_: unknown, item: Device) => vendor(item) },
    { title: '识别依据', key: 'clues', width: 225, render: (_: unknown, item: Device) => <div className="discovery-ledger-stack"><div className="discovery-desktop-clues">{clues(item)}{secondaryTypeClue(item, types, signalFor(item)) && <Typography.Text type="secondary">{secondaryTypeClue(item, types, signalFor(item))}</Typography.Text>}</div>{state(item)}</div> },
    { title: '最近观测', key: 'seen', width: 104, render: (_: unknown, item: Device) => <span className="tabular-num" title={observedTimeTitle(item.last_seen)}>{observedTimeLabel(item.last_seen)}</span> },
    { title: '操作', key: 'action', width: 88, fixed: 'right' as const, align: 'right' as const, render: (_: unknown, item: Device) => <div className="terminal-row-actions"><Button type="link" size="small" onClick={() => show(item)}>查看详情</Button></div> },
  ]
  const addressColumns = [
    {
      title: '观测地址', key: 'identity', width: 210, render: (_: unknown, item: Device) =>
        <Button type="link" className="terminal-device-link mono" onClick={() => show(item)}>{discoveryAddressClue(item)}</Button>
    },
    { title: '采集范围', key: 'address', width: 200, render: (_: unknown, item: Device) => location(item) },
    { title: '发现协议', key: 'clues', width: 180, render: (_: unknown, item: Device) => <div className="discovery-clue-tags">{(item.protocols ?? []).map(p => <Tag key={p} className="discovery-clue-tag">{protocols[p] ?? p}</Tag>)}</div> },
    ...deviceColumns.slice(-2),
  ]

  const dashboard = discoveryMetadata.data?.overview
  const confirmedTypes = discoveryMetadata.data?.types ?? []
  const brandFacets = new Map<string, number>()
  for (const row of dashboard?.brands ?? []) {
    brandFacets.set(row.brand, (brandFacets.get(row.brand) ?? 0) + row.count)
  }
  const typeMax = Math.max(1, ...confirmedTypes.map(item => item.count))
  const typeFacet = query.has('type') ? typeFacets.data : discoveryMetadata.data
  const facetCounts = (rows: typeof confirmedTypes = []) => new Map(rows.map(item => [item.device_type, item.count]))
  const confirmedFacets = facetCounts(typeFacet?.types)
  const profileFacets = facetCounts(typeFacet?.candidate_types)
  const productFacets = facetCounts(typeFacet?.ip_product_types)
  const selectedTypes = (params.get('discovery_type') ?? '').split(',').filter(Boolean)
  const scopeLabel = params.get('discovery_last_seen_from')
    ? `${observedTimeTitle(params.get('discovery_last_seen_from')!)} 至 ${observedTimeTitle(params.get('discovery_last_seen_to') ?? '')}`
    : ({ '15m': '近 15 分钟', '168h': '近 7 天', '720h': '近 30 天', all: '近 30 天' } as Record<string, string>)[params.get('discovery_window') ?? ''] ?? '近 24 小时'
  const typeOptions = Object.entries({
    printer: '打印机', camera: '摄像机', access_point: '无线接入点', router: '路由器',
    switch: '交换机', desktop: '个人电脑', mobile: '手机', voip_phone: 'VoIP 话机',
    ...Object.fromEntries(selectedTypes.map(value => [value, deviceTypeLabel(value)])),
    ...types,
  }).map(([value, label]) => ({ value, label }))
  const stateOptions = [
    { value: '', label: '全部证据状态' },
    { value: 'identified,candidate,conflict', label: '当前有效（不含过期）' },
    ...Object.entries(viewStates).filter(([value]) => !hardwareV2 || !['candidate', 'expired'].includes(value) || params.get('discovery_state') === value).map(([value, label]) => ({ value, label })),
  ]
  const filterLabels: Record<string, string> = {
    category: '分类', type: '类型', protocol: '协议', state: '证据', domain: '网络域', vlan: 'VLAN',
    window: '观测时间', capability: '视角', random_mac: 'MAC', os: '系统', review_reason: '核实原因',
    last_seen_from: '观测时间', first_seen_within: '首次观测', subnet: '网段', identity_scope: '视角',
  }
  const displayFilterValue = (key: string, value: string) => {
    switch (key) {
      case 'type': return value.split(',').map(type => types[type] ?? deviceTypeLabel(type)).join('、')
      case 'protocol': return value.split(',').map(protocol => protocols[protocol] ?? protocol).join('、')
      case 'state': return stateOptions.find(option => option.value === value)?.label ?? value
      case 'category': return categories[value] ?? value
      case 'review_reason': return reviewReasons[value] ?? value
      case 'window':
      case 'last_seen_from': return scopeLabel
      case 'capability': return value === 'dumb' ? '哑终端线索' : value
      case 'identity_scope': return value === 'scoped_devices' ? '按采集范围查看' : '地址线索'
      case 'random_mac': return '本地管理'
      case 'first_seen_within': return '近 7 天'
      default: return value
    }
  }
  const activeFilters = discoveryFilterKeys.filter(key => key !== 'last_seen_to' && params.get(`discovery_${key}`))
    .map(key => ({ key, value: displayFilterValue(key, params.get(`discovery_${key}`)!) }))
  const hasFilters = activeFilters.length > 0 || Boolean(draft)
  const clearFilters = () => {
    setDraft('')
    applyView({ id: '', params: '' })
  }
  const availableViews = [...discoveryPresets.filter(item => hardwareV2 || item.id !== 'new-confirmed'), ...views]
  const chosenView = availableViews.find(item => item.id === activeViewId)
  const activeView = chosenView && [...new URLSearchParams(chosenView.params)].every(([key, value]) => params.get(key) === value) ? chosenView : undefined
  const viewMenu = [
    { key: 'default', label: '全部发现' },
    ...(view === 'records' && (hardwareV2 || addressView) ? [{ key: 'address_clues', label: '地址线索' }] : []),
    { key: 'dumb', label: '哑终端线索' },
    ...availableViews.map(item => ({ key: `view:${item.id}`, label: item.name })),
    { type: 'divider' as const },
    { key: 'save', label: '保存视图' },
    ...(views.length ? [{ key: 'manage', label: '管理视图' }] : []),
  ]

  const filterDrawer = <Drawer rootClassName="discovery-filter-drawer" title="筛选发现记录"
    closable={{ 'aria-label': '关闭筛选' }} open={moreOpen} onClose={() => setMoreOpen(false)} size={440}
    footer={<div className="discovery-filter-footer"><Button disabled={!hasFilters} onClick={clearFilters}>重置筛选</Button><Button type="primary" onClick={() => setMoreOpen(false)}>查看结果</Button></div>}>
    <section className="discovery-filter-group">
      <Typography.Title level={5}>观测与证据</Typography.Title>
      <div className="discovery-filter-grid">
        {!addressView && <><label>证据状态<Select aria-label="证据状态" value={params.get('discovery_state') || ''} options={stateOptions} onChange={value => change('state', value)} /></label>
          <label>待核实原因<Select aria-label="待核实原因" value={params.get('discovery_review_reason') || ''}
            options={[{ value: '', label: '全部核实原因' }, ...Object.entries(reviewReasons).map(([value, label]) => ({ value, label }))]} onChange={value => change('review_reason', value)} /></label></>}
        <label>发现协议<Select aria-label="发现协议" mode="multiple" allowClear placeholder="全部协议"
          value={(params.get('discovery_protocol') || '').split(',').filter(Boolean)}
          options={Object.entries(protocols).map(([value, label]) => ({ value, label }))}
          onChange={values => change('protocol', values.join(','))} /></label>
        <label>最近观测范围<Select aria-label="最近观测范围" value={params.has('discovery_last_seen_from') ? 'custom' : params.get('discovery_window') === 'all' ? '720h' : params.get('discovery_window') || ''}
          options={[{ value: '', label: '近 24 小时' }, { value: '15m', label: '近 15 分钟' }, { value: '168h', label: '近 7 天' }, { value: '720h', label: '近 30 天' }, ...(params.has('discovery_last_seen_from') ? [{ value: 'custom', label: '自定义时间' }] : [])]}
          onChange={value => { if (value !== 'custom') setWindow(value) }} /></label>
      </div>
      <DiscoveryObservationRange key={`${params.get('discovery_last_seen_from')}|${params.get('discovery_last_seen_to')}`}
        from={params.get('discovery_last_seen_from') ?? ''} to={params.get('discovery_last_seen_to') ?? ''}
        apply={(from, to) => setParams(current => {
          const next = new URLSearchParams(current)
          next.set('discovery_last_seen_from', from)
          next.set('discovery_last_seen_to', to)
          next.delete('discovery_window')
          return next
        }, { replace: true })} />
    </section>
    <section className="discovery-filter-group">
      <Typography.Title level={5}>{addressView ? '采集范围' : '网络与设备'}</Typography.Title>
      <div className="discovery-filter-grid">
        <label>VLAN<Select aria-label="VLAN" mode="tags" allowClear placeholder="选择或输入 VLAN"
          value={(params.get('discovery_vlan') || '').split(',').filter(Boolean)}
          options={(vlanFacets.data?.vlans ?? []).map(item => ({ value: item.vlan, label: `VLAN ${item.vlan} · ${item.count}` }))}
          onChange={values => change('vlan', values.map(value => String(value).trim()).filter(Boolean).join(','))} /></label>
        {!addressView && <label>网段<Select aria-label="网段" allowClear placeholder="全部网段" value={params.get('discovery_subnet') || undefined}
          options={[...new Set([...(dashboard?.subnets ?? []).map(item => item.subnet), ...(params.has('discovery_subnet') ? [params.get('discovery_subnet')!] : [])])].map(value => ({ value, label: value }))}
          onChange={value => change('subnet', value ?? '')} /></label>}
        <label>网络域<DebouncedInput label="网络域" placeholder="多个网络域用逗号分隔" value={params.get('discovery_domain') || ''} onChange={value => change('domain', value)} /></label>
        {!addressView && <><label>操作系统<DebouncedInput label="操作系统" placeholder="全部系统" value={params.get('discovery_os') || ''} onChange={value => change('os', value)} /></label>
          <label>设备分类<Select aria-label="设备分类" value={params.get('discovery_category') || ''}
            options={[{ value: '', label: '全部设备分类' }, ...Object.entries(categories).map(([value, label]) => ({ value, label }))]}
            onChange={value => setParams(current => { const next = new URLSearchParams(current); next.delete('discovery_type'); if (value) next.set('discovery_category', value); else next.delete('discovery_category'); return next }, { replace: true })} /></label></>}
        {brandFacets.size > 0 && <label>已确认厂商<Select aria-label="已确认厂商" allowClear placeholder="将厂商填入搜索"
          value={brandFacets.has(search) ? search : undefined}
          options={[...brandFacets].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([value, count]) => ({ value, label: `${value} · ${count}` }))}
          onChange={value => change('search', value ?? '')} /></label>}
      </div>
      {!addressView && <Checkbox checked={params.get('discovery_random_mac') === 'true'} onChange={event => change('random_mac', event.target.checked ? 'true' : '')}>本地管理 MAC</Checkbox>}
    </section>
  </Drawer>
  const statCard = (state: string, label: string, value?: number) => {
    const total = discoveryMetadata.data?.total
    const active = params.get('discovery_state') === state
    const rate = value !== undefined && total ? Math.round(value / total * 100) : undefined
    return <Button key={state} type="text" className={`discovery-stat-card${active ? ' is-active' : ''}`} aria-pressed={active} onClick={() => toggleState(state)}><span className="discovery-stat-label">{label}</span>{' '}<strong>{metadataValue(value)}</strong>{rate !== undefined && <span className="discovery-stat-rate">占 {rate}%</span>}</Button>
  }
  const dumbOverview = () => {
    const confirmed = new Map((discoveryMetadata.data?.types ?? []).map(item => [item.device_type, item.count]))
    const clues = new Map((discoveryMetadata.data?.candidate_types ?? []).map(item => [item.device_type, item.count]))
    const sumOf = (source: Map<string, number>, list: string[]) => list.reduce((total, type) => total + (source.get(type) ?? 0), 0)
    const memberTypes = new Set(dumbTerminalGroups.flatMap(group => group.types))
    const scopedBrands = (dashboard?.brands ?? []).filter(row => memberTypes.has(row.device_type))
    const brandTotals = [...(quality.data?.top_type_brands ?? []).filter(item => memberTypes.has(item.device_type)).reduce((map, item) => map.set(item.brand, (map.get(item.brand) ?? 0) + item.count), new Map<string, number>())].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 8)
    return <section className="discovery-dumb-overview" aria-label="哑终端总览">
      <div className="discovery-dumb-cards">
        {dumbTerminalGroups.map(group => {
          const active = (params.get('discovery_type') || '') === group.types.join(',')
          const clueCount = sumOf(clues, group.types)
          return <Button key={group.key} type="text" className={`discovery-stat-card${active ? ' is-active' : ''}`} aria-pressed={active} onClick={() => shortcut(active ? '' : group.types.join(','), 'dumb')}><span className="discovery-stat-label">{group.label}</span>{' '}<strong>{sumOf(confirmed, group.types)}</strong>{clueCount > 0 && <span className="discovery-stat-rate">另有线索 {clueCount}</span>}</Button>
        })}
        {hasTypeBreakdown
          ? candidateCards.map(card => statCard(card.state, card.label, card.count))
          : statCard('candidate', '发现线索', metadata?.candidate)}
      </div>
      {scopedBrands.length > 0 && <div className="discovery-dumb-brands"><Typography.Text type="secondary">当前筛选已确认品牌</Typography.Text>
        {scopedBrands.map(row => <Button key={`${row.brand}:${row.device_type}`} size="small" onClick={() => change('search', row.brand)}>
          {row.brand} · {types[row.device_type] ?? deviceTypeLabel(row.device_type)} · {row.count}
        </Button>)}
      </div>}
      {discoveryMetadata.data && dashboard && <DiscoveryDistribution data={discoveryMetadata.data} vlanOnly onSelect={change} />}
      {!dashboard && brandTotals.length > 0 && <div className="discovery-dumb-brands"><Typography.Text type="secondary">哑终端厂商（全局识别画像）</Typography.Text>{brandTotals.map(([brand, count]) => <Button key={brand} type="text" size="small" className="recognition-quality-link" onClick={() => change('search', brand)}>{brand} {count}</Button>)}</div>}
    </section>
  }
  return <section className="passive-discovery-panel terminal-workspace">
    {waitingForMetadata && <div role="status">正在生成统计报表。</div>}
    {metadataFailure && <AppErrorAlert title="读取发现数量失败" message={discoveryMetadata.error?.message} action={<Button onClick={() => void discoveryMetadata.refetch()}>重试统计</Button>} />}
    {position.isError && <AppErrorAlert title="页码定位失败" message={position.error.message} action={<Button onClick={() => void position.refetch()}>重试定位</Button>} />}
    {devices.isError && <AppErrorAlert title="读取发现设备失败" message={devices.data ? '当前展示上次成功读取的结果；请重试。' : devices.error.message} action={<Button onClick={() => void devices.refetch()}>重试列表</Button>} />}
    {(!devices.isError || devices.data) && <section aria-busy={searching} className={searching ? 'surface center-list-surface is-updating' : 'surface center-list-surface'}>
      <section className="discovery-overview" aria-label="发现设备总览">
        <div className="discovery-overview-line">
          <strong>{discoveryTotal === undefined ? (metadataFailure ? '统计读取失败' : '统计中') : `共 ${discoveryTotal} ${countUnit}`}</strong>
          {!addressView && metadata && <Typography.Text type="secondary">
            {hasTypeBreakdown
              ? `已有类型判断 ${(metadata.identified + (metadata.profile_typed ?? 0)).toLocaleString('zh-CN')} · 缺少类型线索 ${metadata.no_type_clue?.toLocaleString('zh-CN')}`
              : `已确认 ${metadata.identified} · 发现线索 ${metadata.candidate}`}
          </Typography.Text>}
          <Typography.Text className="discovery-overview-caption" type="secondary" title={groupedDevices ? '同一采集域中，地址一致且无类型冲突的全局 MAC 跨 VLAN 汇总' : hardwareV2 ? '按采集范围和发现分组计数' : undefined}>
            {scopeLabel}{discoveryMetadata.data?.as_of ? ` · 统计于 ${observedTimeTitle(discoveryMetadata.data.as_of)}` : ''}{discoveryMetadata.data?.publication && ` · 报表发布于 ${observedTimeTitle(discoveryMetadata.data.publication.published_at)}`}{discoveryMetadata.data?.publication?.delayed ? ' · 发布延迟' : ''}{discoveryMetadata.isFetching ? ' · 统计更新中' : ''}
          </Typography.Text>
          {fresh?.status === 'ready' && <Typography.Text type="secondary" className="discovery-freshness">{fresh.lag_seconds < 60 ? '数据实时' : `数据延迟 ${Math.round(fresh.lag_seconds / 60)} 分钟`}</Typography.Text>}
          {!addressView && <Button type="link" size="small" className="discovery-overview-toggle" aria-expanded={overviewOpen} aria-controls="discovery-overview-breakdown" onClick={() => setOverviewOpen(open => !open)}>
            {overviewOpen ? '收起统计' : '统计与类型线索'}
          </Button>}
        </div>
        <div id="discovery-overview-breakdown" className="discovery-overview-breakdown" hidden={!overviewOpen || addressView}>
          <div className="discovery-stat-cards">
            {dashboard && <>
              <Button className="discovery-stat-card" onClick={() => setWindow('15m')}><span className="discovery-stat-label">近 15 分钟活跃</span><strong>{dashboard.active}</strong>
                <span className="discovery-stat-rate">{dashboard.previous_active === undefined ? '昨日覆盖不足' : `较昨日 ${dashboard.active >= dashboard.previous_active ? '+' : ''}${dashboard.active - dashboard.previous_active}`}</span>
              </Button>
              <Button className="discovery-stat-card" aria-pressed={dumbFilter} onClick={() => shortcut('', dumbFilter ? '' : 'dumb')}><span className="discovery-stat-label">哑终端</span><strong>{dashboard.dumb_terminals}</strong></Button>
              <Button className="discovery-stat-card" aria-pressed={params.has('discovery_first_seen_within')} onClick={() => change('first_seen_within', params.has('discovery_first_seen_within') ? '' : '168h')}>
                <span className="discovery-stat-label">近 7 天新增</span><strong>{dashboard.new_seven_days}</strong>
                <span className="discovery-trend-bars" aria-label="七日新增趋势">{dashboard.new_by_day.map(day => <span key={day.date} className={`discovery-trend-bar is-${trendBucket(day.count, Math.max(1, ...dashboard.new_by_day.map(point => point.count)))}`} title={`${day.date} · ${day.count}`} />)}</span>
              </Button>
            </>}
            {statCard('identified', confirmedTypesLabel, discoveryMetadata.data?.identified)}
            {hasTypeBreakdown ? candidateCards.map(card => statCard(card.state, card.label, card.count)) : statCard('candidate', '发现线索', metadata?.candidate)}
            {statCard('conflict', '类型冲突', discoveryMetadata.data?.conflict)}
            {statCard(hardwareV2 ? 'revoked' : 'expired', hardwareV2 ? typeEvidenceLabels.revoked : '证据过期', hardwareV2 ? (metadata?.revoked ?? metadata?.expired) : metadata?.expired)}
          </div>
          <div className="discovery-type-chart">
            <Typography.Text type="secondary" className="discovery-type-chart-head">{confirmedTypesLabel}{discoveryMetadata.data ? `（合计 ${confirmedTypes.reduce((sum, item) => sum + item.count, 0)}）` : ''}</Typography.Text>
            {confirmedTypes.length ? [...confirmedTypes].sort((a, b) => b.count - a.count || a.device_type.localeCompare(b.device_type)).map(item => <Button key={item.device_type} type="text" size="small" className="discovery-type-row" onClick={() => shortcut(item.device_type, dumbFilter ? 'dumb' : '', 'identified')}><span className="discovery-type-row-body">{types[item.device_type] ?? deviceTypeLabel(item.device_type)} <span className="discovery-type-track" aria-hidden="true">
              <span className={`discovery-type-fill is-${barBucket(item.count, typeMax)}`} /></span><strong className="discovery-type-count">{item.count}</strong></span></Button>) : <Typography.Text type="secondary">{discoveryMetadata.data ? `当前筛选下暂无${confirmedTypesLabel}` : metadataFailure ? '统计读取失败' : '统计中'}</Typography.Text>}
          </div>
          {!!discoveryMetadata.data?.candidate_types?.length && <div className="discovery-overview-types discovery-overview-candidates" aria-label="画像识别类型">
            <Typography.Text type="secondary">画像识别</Typography.Text>
            {[...discoveryMetadata.data.candidate_types].sort((a, b) => b.count - a.count || a.device_type.localeCompare(b.device_type)).map(item =>
              <Button key={item.device_type} type="text" size="small" className="discovery-overview-type" onClick={() => shortcut(item.device_type, dumbFilter ? 'dumb' : '', hasTypeBreakdown ? 'profile_typed' : 'candidate')}>{types[item.device_type] ?? deviceTypeLabel(item.device_type)} <strong>{item.count}</strong></Button>
            )}
          </div>}
          {!!discoveryMetadata.data?.ip_product_types?.length && <div className="discovery-overview-types discovery-overview-candidates" aria-label="IP 产品类型线索">
            <Typography.Text type="secondary">IP 产品自报 · 设备归属待核实</Typography.Text>
            {[...discoveryMetadata.data.ip_product_types].sort((a, b) => b.count - a.count || a.device_type.localeCompare(b.device_type)).map(item =>
              <Button key={item.device_type} type="text" size="small" className="discovery-overview-type" onClick={() => shortcut(item.device_type, dumbFilter ? 'dumb' : '', hasTypeBreakdown ? 'ip_product_only' : 'candidate')}>{types[item.device_type] ?? deviceTypeLabel(item.device_type)} <strong>{item.count}</strong></Button>
            )}
          </div>}
        </div>
      </section>
      <div className="list-surface-head discovery-list-head">
        <div className="discovery-query-bar" role="group" aria-label="发现设备筛选工具栏">
          <Input allowClear className="discovery-query-search" aria-label="搜索 IP、MAC、名称或型号"
            placeholder="搜索 IP、MAC、名称或型号" prefix={<SearchOutlined aria-hidden="true" />}
            suffix={searching ? <span role="status" aria-label={draft.trim() || search ? '正在搜索' : '正在加载'}><LoadingOutlined spin /></span> : undefined}
            value={draft} onChange={event => setDraft(event.target.value)} onPressEnter={() => change('search', draft.trim())} />
          <div className="discovery-query-controls">
            {!addressView && <Select className="discovery-type-picker" aria-label="设备类型" mode="multiple" allowClear
              placeholder="设备类型" showSearch optionFilterProp="label" maxTagCount={0}
              maxTagPlaceholder={() => `类型 · ${selectedTypes.length}`} popupMatchSelectWidth={286}
              classNames={{ popup: { root: 'discovery-type-popup' } }} virtual={false}
              value={selectedTypes} options={typeOptions}
              optionRender={option => {
                const type = String(option.value)
                const counts = [
                  [hardwareV2 ? '已确认' : '已识别', confirmedFacets.get(type)],
                  ['画像识别', profileFacets.get(type)], ['IP 产品自报', productFacets.get(type)],
                ] as const
                return <span className="discovery-type-option"><span>{option.label}</span>
                  <span className="discovery-type-option-counts">{counts.map(([label, count]) =>
                    count !== undefined && <span key={label}>{label} {count.toLocaleString('zh-CN')}</span>)}</span>
                </span>
              }}
              onChange={values => change('type', values.join(','))} />}
            <Button className={activeFilters.length ? 'discovery-filter-active' : undefined} icon={<FilterOutlined aria-hidden="true" />}
              aria-haspopup="dialog" onClick={() => setMoreOpen(true)}>筛选{activeFilters.length ? ` · ${activeFilters.length}` : ''}</Button>
            <Dropdown trigger={['click']} menu={{
              items: viewMenu, selectable: true,
              selectedKeys: activeView ? [`view:${activeView.id}`] : addressView ? ['address_clues'] : dumbFilter ? ['dumb'] : hasFilters ? [] : ['default'],
              onClick: ({ key }) => {
                if (key === 'default') clearFilters()
                else if (key === 'address_clues') showAddressClues()
                else if (key === 'dumb') shortcut('', 'dumb', '')
                else if (key === 'save') setSaveViewOpen(true)
                else if (key === 'manage') setManageViewsOpen(true)
                else { const saved = availableViews.find(item => `view:${item.id}` === key); if (saved) applyView(saved) }
              }
            }}>
              <Button aria-label="视图">视图 <DownOutlined aria-hidden="true" /></Button>
            </Dropdown>
            <Dropdown trigger={['click']} menu={{
              items: [
                { key: 'export', label: '导出全部筛选结果', icon: <DownloadOutlined aria-hidden="true" />, disabled: exporting },
                { key: 'auto', label: autoRefresh ? '关闭自动刷新' : '开启自动刷新' },
              ], onClick: ({ key }) => key === 'export' ? void exportDevices() : toggleAutoRefresh(!autoRefresh)
            }}>
              <Button aria-label="操作" loading={exporting}>操作 <DownOutlined aria-hidden="true" /></Button>
            </Dropdown>
            <Button icon={<ReloadOutlined aria-hidden="true" />} onClick={refreshWorkspace}>刷新数据</Button>
          </div>
          {exporting && <Typography.Text type="secondary" className="discovery-export-progress" role="status">已导出 {exportProgress.count}/{exportProgress.total || '…'}</Typography.Text>}
        </div>
        {activeFilters.length > 0 && <div className="discovery-applied-filters" aria-label="已应用筛选">
          {activeFilters.map(({ key, value }) => <Tag key={key} className="discovery-filter-chip"
            closable={{ 'aria-label': `移除${filterLabels[key]}筛选` }} onClose={() => key === 'last_seen_from' || key === 'window' ? setWindow('') : change(key, '')}>
            <span title={value}>{filterLabels[key]} · {value}</span>
          </Tag>)}
          <Button type="link" size="small" onClick={clearFilters}>清除筛选</Button>
        </div>}
        {filterDrawer}
        {dumbFilter && dumbOverview()}
      </div>
      {hardwareFresh?.status === 'failed' && <div className="discovery-hardware-progress" aria-label="硬件分类处理进度"><Typography.Text type="warning">硬件分类处理异常：{hardwareFresh.error || '处理状态读取失败'}</Typography.Text></div>}
      <AppTable className="passive-ledger-table" rowKey={discoveryTableRowKey} columns={addressView ? addressColumns : deviceColumns} dataSource={items} tableLayout="fixed" loading={{ spinning: listUpdating, delay: 150 }} scroll={{ x: addressView ? 782 : 1113 }} locale={{ emptyText: listUpdating ? '正在加载发现记录…' : devices.isError ? '发现记录读取失败' : addressView ? '当前筛选下暂无地址线索' : search && !dumbFilter && view === 'records' ? <div className="discovery-empty-guidance"><span>当前筛选下暂无符合条件的设备</span><div className="discovery-empty-actions">{params.get('discovery_window') !== '168h' && params.get('discovery_window') !== '720h' && params.get('discovery_window') !== 'all' && <Button type="link" size="small" onClick={() => setWindow('168h')}>切换至近 7 天</Button>}{params.get('discovery_window') !== '720h' && params.get('discovery_window') !== 'all' && <Button type="link" size="small" onClick={() => setWindow('720h')}>切换至近 30 天</Button>}{hardwareV2 && <Button type="link" size="small" onClick={showAddressClues}>搜索地址线索</Button>}<Button type="link" size="small" onClick={() => navigate(`/devices?tab=terminal&view=recent&window=24h&q=${encodeURIComponent(search)}`)}>在终端列表搜索</Button></div></div> : '当前筛选下暂无符合条件的设备' }} />
      <div className="discovery-result-footer">
        <div className="terminal-page-summary" aria-label="发现设备摘要">
          <span>当前页 <strong>{items.length}</strong> {countUnit}</span>
          {!addressView && <span>本页已有类型判断 <strong>{judgedPageCount}</strong></span>}
          <span>本页近15分钟观测 <strong>{recentPageCount}</strong></span>
        </div>
        <AppServerPagination disabled={devices.isFetching || position.isLocating} page={page + 1} pageSize={pageSize} total={discoveryMetadata.data?.total} onChange={(nextPage, nextSize) => {
          if (nextSize !== pageSize) { setPageSize(nextSize); setPaging({ key: filterKey, page: 0 }); return }
          setPaging({ key: filterKey, page: nextPage - 1 })
        }} totalText={discoveryMetadata.data ? `共 ${discoveryMetadata.data.total} ${countUnit}` : (discoveryMetadata.isError ? '数量读取失败' : '正在统计数量')} />
      </div>
    </section>}
    <details className="terminal-diagnostics" open={qualityOpen}><summary onClick={event => { event.preventDefault(); setQualityOpen(value => !value) }}>采集与识别状态</summary>    <section className="surface center-list-toolbar">
      {hardwareFresh && hardwareFresh.status !== 'failed' && <div className="discovery-hardware-progress" aria-label="硬件分类处理进度"><Typography.Text type="secondary">硬件分类{hardwareFresh.coverage === 'live_input_only' ? '仅含启用后输入' : hardwareFresh.backfill_complete ? '保留观测回填完成' : '保留观测回填中'}{hardwareFresh.available_from ? ` · 可用起点 ${observedTimeTitle(hardwareFresh.available_from)}` : ''} · 待处理 {hardwareFresh.pending_identities ?? 0} · 处理失败 {hardwareFresh.failed_identities ?? 0}{hardwareFresh.oldest_pending_at ? ` · 最早积压 ${observedTimeTitle(hardwareFresh.oldest_pending_at)}` : ''}{hardwareFresh.missing_source_refs ? ` · 缺少原文引用 ${hardwareFresh.missing_source_refs}` : ''}{hardwareFresh.changed_after_backfill_start ? ` · 回填窗口被新观测替换 ${hardwareFresh.changed_after_backfill_start}` : ''}</Typography.Text></div>}
      {fresh?.source === 'passive-discovery-batch-v3' && <div className="discovery-batch-progress" aria-label="存储处理进度">
        {fresh.ingested_at && <Typography.Text type="secondary">采集入库 {observedTimeTitle(fresh.ingested_at)}</Typography.Text>}
        {fresh.processed_at && <Typography.Text type="secondary">设备发现 {observedTimeTitle(fresh.processed_at)}</Typography.Text>}
        {fresh.pending_batches !== undefined && <Typography.Text type="secondary">待发现批次 {fresh.pending_batches}</Typography.Text>}
        {fresh.archive_verified_at && <Typography.Text type="secondary">证据归档 {observedTimeTitle(fresh.archive_verified_at)}</Typography.Text>}
        {fresh.archive_pending_batches !== undefined && <Typography.Text type="secondary">待归档批次 {fresh.archive_pending_batches}</Typography.Text>}
        {fresh.archive_oldest_pending_at && <Typography.Text type="secondary">最早待归档 {observedTimeTitle(fresh.archive_oldest_pending_at)}</Typography.Text>}
      </div>}
      {qualityOpen && <div className="recognition-quality-strip" aria-label="识别质量">
        <Typography.Text type="secondary" className="recognition-quality-scope">全局识别画像 · 不随列表筛选变化</Typography.Text>
        {quality.isError && <AppErrorAlert title="识别质量读取失败" message={quality.error.message} />}
        {quality.data && <>
          {qualityItem('类型覆盖', quality.data.coverage.device_type, quality.data.total_endpoints)}
          {qualityItem('品牌覆盖', quality.data.coverage.brand, quality.data.total_endpoints)}
          {qualityItem('型号覆盖', quality.data.coverage.model, quality.data.total_endpoints)}
          {qualityItem('系统覆盖', quality.data.coverage.os_family, quality.data.total_endpoints)}
          <span className="recognition-quality-item"><Typography.Text type="secondary">链路层归属</Typography.Text><Typography.Text strong>{Math.round((quality.data.mac_attribution_rate ?? 0) * 100)}%</Typography.Text></span>
          {quality.data.top_brands?.length ? <span className="recognition-quality-brands"><Typography.Text type="secondary">厂商 Top</Typography.Text>{quality.data.top_brands.map(item => <Button key={item.brand} type="text" size="small" className="recognition-quality-link" onClick={() => change('search', item.brand)}>{item.brand} {item.count}</Button>)}</span> : null}
          {quality.data.top_type_brands?.length ? <span className="recognition-quality-brands"><Typography.Text type="secondary">类型厂商</Typography.Text>{quality.data.top_type_brands.map(item => <Button key={`${item.device_type}:${item.brand}`} type="text" size="small" className="recognition-quality-link" onClick={() => setParams(current => { const next = new URLSearchParams(current); next.set('discovery_search', item.brand); next.set('discovery_type', item.device_type); next.delete('discovery_category'); return next }, { replace: true })}>{types[item.device_type] ?? deviceTypeLabel(item.device_type)} · {item.brand} {item.count}</Button>)}</span> : null}
          {quality.data.top_os?.length ? <span className="recognition-quality-brands"><Typography.Text type="secondary">系统 Top</Typography.Text>{quality.data.top_os.map(item => <Button key={item.os} type="text" size="small" className="recognition-quality-link" onClick={() => change('os', item.os)}>{item.os} {item.count}</Button>)}</span> : null}
          {quality.data.top_models?.length ? <span className="recognition-quality-brands"><Typography.Text type="secondary">型号 Top</Typography.Text>{quality.data.top_models.map(item => <Button key={`${item.brand}:${item.model}`} type="text" size="small" className="recognition-quality-link" onClick={() => setParams(current => { const next = new URLSearchParams(current); next.set('discovery_search', item.model); next.delete('discovery_type'); next.delete('discovery_category'); return next }, { replace: true })}>{item.brand ? `${item.brand} · ` : ''}{item.model} {item.count}</Button>)}</span> : null}
          {quality.data.untyped_reasons?.length ? <span className="recognition-quality-brands"><Typography.Text type="secondary">待核实原因</Typography.Text>{quality.data.untyped_reasons.map(item => <Tag key={item.reason}>{item.reason} {item.count}</Tag>)}</span> : null}
          <div className="recognition-quality-actions"><Button size="small" icon={<DownloadOutlined aria-hidden="true" />} onClick={exportQualityReport} disabled={!quality.data}>导出质量报告</Button></div>
          {trends.data?.days?.length ? <span className="discovery-trend" aria-label={`近 ${trendDays} 天新增设备`}><Typography.Text type="secondary">近 {trendDays} 天新增</Typography.Text><span className={`discovery-trend-bars${trendDays > 7 ? ' is-wide' : ''}`}>{trends.data.days.map(day => <span key={day.date} className={`discovery-trend-bar is-${trendBucket(day.new, Math.max(...trends.data.days.map(item => item.new), 1))}`} title={`${day.date} 新增 ${day.new}，明确类型 ${day.typed}`} />)}</span><Typography.Text type="secondary">{trends.data.days.reduce((sum, day) => sum + day.new, 0)} 台 · 今天 {trends.data.days[trends.data.days.length - 1]?.new ?? 0}</Typography.Text><Select size="small" aria-label="趋势范围" value={String(trendDays)} options={[{ value: '7', label: '近 7 天' }, { value: '30', label: '近 30 天' }]} onChange={value => setTrendDays(Number(value))} /></span> : null}
          {trends.data?.top_types?.length ? <span className="recognition-quality-brands"><Typography.Text type="secondary">新增类型</Typography.Text>{trends.data.top_types.map(item => <Button key={item.device_type} type="text" size="small" className="recognition-quality-link" onClick={() => shortcut(item.device_type)}>{types[item.device_type] ?? deviceTypeLabel(item.device_type)} {item.count}</Button>)}</span> : null}
        </>}
        {quality.isLoading && <Typography.Text type="secondary">识别质量读取中</Typography.Text>}
      </div>}
      {catalogue.isError && <AppErrorAlert title="读取设备类型失败" message={catalogue.error.message} />}
      {fresh && fresh.status !== 'ready' && <Alert type={fresh.status === 'failed' ? 'error' : 'warning'} showIcon title={fresh.status === 'failed' ? '设备数据处理失败' : fresh.status === 'delayed' ? '设备数据更新延迟' : '设备数据处理中'} description={fresh.oldest_pending_at ? `最早待处理时间：${observedTimeTitle(fresh.oldest_pending_at)}` : undefined} />}
      {coverage.data?.capture_scope?.status === 'expiring' && <Alert type="warning" showIcon title="镜像采集范围即将到期" description={coverage.data.capture_scope.valid_until ? `有效期至 ${observedTimeTitle(coverage.data.capture_scope.valid_until)}，请提前更新采集范围。` : undefined} />}
      {coverage.data?.capture_scope?.status === 'expired' && <Alert type="error" showIcon title="镜像采集范围已到期" description={coverage.data.capture_scope.valid_until ? `有效期截止于 ${observedTimeTitle(coverage.data.capture_scope.valid_until)}。` : undefined} />}
      {coverage.data?.capture_scope?.status === 'invalid' && <Alert type="error" showIcon title="镜像采集范围配置无法读取" />}
      {coverage.data?.quarantine?.status === 'blocked' && <Alert type="error" showIcon title="发现数据段已隔离，处理存在缺口" description={`待核对段数至少 ${coverage.data.quarantine.count_at_least}；原始段已保留，需核对采集范围后恢复。`} />}
      {coverage.data?.quarantine?.status === 'unavailable' && <Alert type="warning" showIcon title="发现隔离状态暂不可用" />}
      {passiveSignals.data?.durable_status === 'unavailable' && <Alert type="warning" showIcon title="较早的 DHCP 线索暂不可用" description="当前仅展示近期镜像日志中的被动线索。" />}
      {passiveSignals.data?.client_status === 'unavailable' && <Alert type="warning" showIcon title="HTTP 与 TLS 被动线索暂不可用" />}
      {passiveSignals.isError && <AppErrorAlert title="读取被动识别线索失败" message={passiveSignals.error.message} />}
      {serviceClues.isError && <AppErrorAlert title="读取服务公告线索失败" message={serviceClues.error.message} action={<Button size="small" loading={serviceClues.isFetching} onClick={() => void serviceClues.refetch()}>重试</Button>} />}
      {allServiceTargets.length > 50 && <Alert type="warning" showIcon title="本页当前地址超过 50 个，仅展示已查询地址的服务公告线索" />}
      {statistics.isError && <AppErrorAlert title="读取设备统计失败" message={statistics.error.message} />}
      {statistics.data && !hardwareV2 && <div className="discovery-statistics" aria-label="设备类型统计">{statistics.data.items.filter(item => item.count > 0 && item.state !== 'candidate').map(item => <span className="discovery-statistics-item" title={`统计更新于 ${observedTimeTitle(item.updated_at)}`} key={`${item.device_type}:${item.state}`}>{types[item.device_type] ?? item.device_type} · {states[item.state] ?? ''} {item.count}</span>)}{statistics.data.pending_updates > 0 && <Typography.Text type="secondary">统计处理中 {statistics.data.pending_updates}</Typography.Text>}</div>}
      <Collapse ghost items={[{ key: 'coverage', label: '采集覆盖与处理状态', children: coverage.isError ? <AppErrorAlert title="读取采集状态失败" /> : coverage.data?.enabled === false ? <Typography.Text>当前运行旧版发现路径</Typography.Text> : <div className="iot-coverage-grid">{coverage.data?.items.map(p => <article className="iot-coverage-item" key={`${p.sensor_id}:${p.protocol}`}><strong>{protocols[p.protocol] ?? p.protocol}</strong><Typography.Text type="secondary">{p.sensor_id}</Typography.Text><span>{p.message_source_epoch ? '逐消息源已登记' : p.handshake_source_epoch ? '握手侧车已登记 · 详情弱线索' : p.error ? '采集异常' : !p.enabled ? '未启用' : p.received === 0 ? '暂未捕获协议流量' : '已捕获协议流量'}</span><span>{p.message_source_epoch ? '旧链路累计 ' : p.handshake_source_epoch ? '发现链路累计 ' : ''}捕获 {p.received} · 解析 {p.parsed} · 处理 {p.admitted}</span></article>)}</div> }]} />
    </section>
    </details>
    <Modal title="管理视图" open={manageViewsOpen} footer={null} onCancel={() => setManageViewsOpen(false)}>{views.length ? views.map(view => <div key={view.id} className="discovery-view-manage-row"><Typography.Text>{view.name}</Typography.Text><Button type="link" size="small" danger onClick={() => deleteSavedView(view.id)}>删除</Button></div>) : <Typography.Text type="secondary">还没有保存的视图</Typography.Text>}</Modal>
    <Modal title="保存视图" open={saveViewOpen} okText="保存" cancelText="取消" onOk={saveCurrentView} onCancel={() => { setSaveViewOpen(false); setViewName('') }}><Input aria-label="视图名称" placeholder="例如：网络设备 · 近 7 天" value={viewName} onChange={e => setViewName(e.target.value)} /><Typography.Paragraph type="secondary">保存当前筛选条件，仅存储在本机浏览器。</Typography.Paragraph></Modal>
    <Modal className="discovery-evidence-modal" width={760} centered title="设备详情" open={!!selected} footer={selected ? <div className="discovery-detail-nav"><Typography.Text type="secondary">{selectedPosition + 1} / {items.length}</Typography.Text><Button disabled={selectedPosition <= 0} onClick={() => setSelected(items[selectedPosition - 1])}>上一台</Button><Button disabled={selectedPosition < 0 || selectedPosition >= items.length - 1} onClick={() => setSelected(items[selectedPosition + 1])}>下一台</Button></div> : null} onCancel={() => setSelected(undefined)}>{selected && <><DiscoveryDetailHeader item={selected} types={types}
      profileModel={detailRecognition?.device_type === selected.candidate_device_type && !detailRecognition?.recognition_conflict ? detailRecognition?.model : undefined}
      openProfile={() => {
        setSelected(undefined)
        if (selected.endpoint_id) navigate(`/devices/${encodeURIComponent(selected.endpoint_id)}`)
      }} />
      {selected.vlan_scope_count && <p>此身份出现在 {selected.vlan_scope_count} 个采集范围。下方证据来自当前展示的范围。<Button size="small" type="link" onClick={() => showMACScopes(selected)}>按范围查看此 MAC</Button></p>}{discoveryAddressClue(selected) && <Typography.Paragraph type="secondary">这是一条按采集范围记录的地址线索，尚无可绑定的 MAC 或设备身份。不同 VLAN 可以重复使用同一地址。</Typography.Paragraph>}{hasVirtualizationClue(selected) && <Typography.Paragraph type="secondary">{virtualizationHelp}{virtualizationVendor && ` 当前 MAC 前缀匹配网卡厂商 ${virtualizationVendor}。`}</Typography.Paragraph>}{renderDetailFacts([[`类型依据时间`, selected.type_evidence_at ? observedTimeTitle(selected.type_evidence_at) : ''], [`活动状态`, activityStates[selected.activity_status ?? '']], [`硬件规则版本`, selected.type_rule_version], [`型号状态`, selected.hardware_model_status === 'conflict' ? '型号证据冲突' : ''], [`互斥类型`, (selected.hardware_conflicting_types ?? []).map(type => types[type] ?? deviceTypeLabel(type)).join('、')], [`型号冲突项`, (selected.hardware_conflicting_models ?? []).join('、')], [`名称线索`, discoveryNameClue(selected.name)?.label], [`名称线索依据`, discoveryNameClue(selected.name)?.detail], [`分类补充线索`, secondaryTypeClue(selected, types, signalFor(selected))], [`操作系统线索`, osFor(selected).label ? `${osFor(selected).label} · ${signalFor(selected)?.dhcp_historical && signalFor(selected)?.os_family ? '历史线索' : '线索'}` : ''], [`操作系统依据`, osFor(selected).detail], [`DHCP 线索时效`, signalFor(selected)?.dhcp_historical ? '历史 REQUEST 线索；同源当前租约仍有效，需结合观测时间核对' : ''], [`DHCP 观测时间`, signalFor(selected)?.dhcp_observed_at ? observedTimeTitle(signalFor(selected)!.dhcp_observed_at!) : ''], [`最近 DHCP 证据事件`, signalFor(selected)?.dhcp_evidence_id], [`TTL 证据引用`, signalFor(selected)?.ttl_evidence?.event_id || ((signalFor(selected)?.ttl_evidence?.raw_sha256) ? `原文 SHA256 ${signalFor(selected)?.ttl_evidence?.raw_sha256}` : '')], [`TTL 观测时间`, signalFor(selected)?.ttl_observed_at ? observedTimeTitle(signalFor(selected)!.ttl_observed_at!) : ''], [`TTL`, signalFor(selected)?.ttl ? String(signalFor(selected)?.ttl) : ''], [`DHCP 主机名`, signalFor(selected)?.dhcp_hostname], [`DHCP 厂商类`, signalFor(selected)?.dhcp_vendor_class], [`DHCP 请求选项`, signalFor(selected)?.dhcp_options], [`DHCP 客户端标识类型`, signalFor(selected)?.dhcp_client_id_hwtype], [`DHCP 选项 93`, signalFor(selected)?.dhcp_option93_present ? '已观测' : ''], [`识别操作系统`, recognitionOSLabel(selected)], [`识别设备类型`, recognitionTypeLabel(selected, types)], [`类型置信度`, selected.recognition?.confidence ? `${Math.round(selected.recognition.confidence * 100)}%` : ''], [`系统置信度`, selected.recognition?.os_family && selected.recognition?.os_family_confidence ? `${Math.round(selected.recognition.os_family_confidence * 100)}%` : ''], [`识别规则`, selected.recognition?.rule_version], [`识别依据`, (selected.recognition?.evidence ?? []).join('；')], [`品牌推断`, selected.recognition?.brand_inference_status === 'inferred' && selected.recognition?.brand_inference_brand ? `${selected.recognition.brand_inference_brand} · 设备服务线索推断${selected.recognition.brand_inference_confidence ? `（${Math.round(selected.recognition.brand_inference_confidence * 100)}%）` : ''}` : ''], [`制造商`, selected.manufacturer], [`型号`, selected.hardware_type_status ? selected.hardware_model : selected.model_name], [`MAC`, selected.mac], [`MAC 管理方式`, selected.mac ? (isLocallyAdministeredMAC(selected.mac) ? '本地管理（不能据此判定随机）' : '全局管理') : ''], [`当前地址`, discoveryAddressClue(selected) ? '' : (selected.current_addresses ?? []).join('、') || (!selected.current_addresses ? selected.primary_ip : '')], [`最后观测地址`, [selected.last_observed_ip, observedTimeTitle(selected.last_observed_ip_at)].filter(Boolean).join(' · ')], [`网络域`, selected.domain], [`VLAN`, selected.vlan], [`采集传感器`, selected.sensor_id], [`窗口内首次观测`, selected.first_seen ? observedTimeTitle(selected.first_seen) : ''], [`最近观测`, observedTimeTitle(selected.last_seen)], [`证据数`, selected.evidence_count ? String(selected.evidence_count) : '']])}{dhcpFieldEvidenceFor(signalFor(selected)).length > 0 && <section className="discovery-client-clues"><Typography.Text type="secondary">DHCP 字段证据（各字段保留对应原始报文引用）</Typography.Text>{dhcpFieldEvidenceFor(signalFor(selected)).map(entry => <article key={entry.field}><strong>{entry.label}</strong><span>{entry.value}</span><Typography.Text type="secondary">{[entry.ref.event_id ? `事件 ${entry.ref.event_id}` : entry.ref.raw_sha256 ? `原文 SHA256 ${entry.ref.raw_sha256}` : '', entry.ref.historical ? '历史线索' : '', observedTimeTitle(entry.ref.observed_at)].filter(Boolean).join(' · ')}</Typography.Text></article>)}</section>}{selected?.endpoint_id && fingerprintDetail.data?.profile?.recognition?.source_matches?.length ? <section className="discovery-client-clues"><Typography.Text type="secondary">指纹库命中（端点识别）</Typography.Text>{fingerprintDetail.data.profile.recognition.source_matches.slice(0, 6).map(m => <article key={`${m.source_id}:${m.rule_id}`}><strong>{m.name}</strong><span>{m.strength === 'auxiliary' ? '辅助线索' : '自报证据'} · {m.source_id}</span><Typography.Text type="secondary">{[m.fields.join('、'), Object.values(m.observed ?? {}).join('；')].filter(Boolean).join(' · ')}</Typography.Text></article>)}</section> : null}{clientFor(selected)?.client_clues?.length && <section className="discovery-client-clues"><Typography.Text type="secondary">HTTP / TLS 客户端弱线索（仅按当前 IP 关联，地址共享或复用时需核对）</Typography.Text>{clientFor(selected)?.client_clues?.map((clue, index) => <article key={`${clue.kind}:${clue.evidence_id}:${index}`}><strong>{clue.kind === 'user_agent' ? 'HTTP User-Agent' : clue.kind.toUpperCase()}</strong><span>{clue.value}</span><Typography.Text type="secondary">{[clue.evidence_id, observedTimeTitle(clue.observed_at)].filter(Boolean).join(' · ')}</Typography.Text></article>)}</section>}<Typography.Paragraph>{selected.classification?.reason}</Typography.Paragraph>{selected.type_sources?.length ? <section className="discovery-hardware-evidence" aria-label="硬件类型证据"><Typography.Title level={5}>硬件类型证据</Typography.Title><Typography.Paragraph type="secondary">类型保留已确认的硬件事实；服务公告和地址绑定的有效期单独判断。</Typography.Paragraph>{selected.type_sources.map(source => <article key={`${source.source}:${source.rule_id}:${source.evidence_id}`}><strong>{protocols[source.source] ?? source.source}</strong><span>{source.rule_id} · {source.rule_version}</span><span>{source.evidence_id}</span><time>{observedTimeTitle(source.observed_at)}</time></article>)}</section> : null}<DiscoveryProductClues clues={selected.product_clues} /><DiscoveryEvidenceSummary observations={selected.observations} />
      {(selected.behavior_keys ?? []).map(key => <DiscoveryBehaviorEvidence key={key} evidenceKey={key} />)}
      {handshakeClues.isError && <AppErrorAlert title="读取握手弱线索失败" />}
      {!!handshakeClues.data?.items.length && <section className="discovery-client-clues"><Typography.Text type="secondary">镜像握手弱线索（当前 IP {detailIP}，地址共享或复用时需核对）</Typography.Text>{handshakeClues.data.items.map((clue, index) => <article key={`${clue.kind}:${clue.evidence_id}:${index}`}><strong>{clue.kind === 'user_agent' ? 'HTTP User-Agent' : clue.kind === 'ja4' ? 'TLS JA4' : 'TLS JA3'}</strong><span>{clue.value}</span><Typography.Text type="secondary">{[clue.dst_port ? `握手目标 TCP/${clue.dst_port}` : '', clue.evidence_id, observedTimeTitle(clue.observed_at)].filter(Boolean).join(' · ')}</Typography.Text></article>)}</section>}
      {servicesFor(selected).length > 0 && <section className="discovery-client-clues"><Typography.Text type="secondary">服务公告证据事件</Typography.Text>{servicesFor(selected).map(clue => <article key={`${clue.service_type}:${clue.port}`}><strong>{clue.service_type} · {clue.port}</strong><Typography.Text type="secondary">{clue.evidence_id} · {observedTimeTitle(clue.last_seen)}</Typography.Text></article>)}</section>}
      {portReadEnabled && observedPorts.isPending && <Typography.Text type="secondary">正在读取当前 IP 近 2 小时目标端口线索</Typography.Text>}
      {portReadEnabled && observedPorts.isError && <AppErrorAlert title="读取目标端口线索失败" message={observedPorts.error.message} />}
      {portReadEnabled && observedPorts.data && portsFor(selected).length === 0 && <Typography.Text type="secondary">当前 IP 近 2 小时的镜像端口聚合中无匹配记录</Typography.Text>}
      {portsFor(selected).length > 0 && <section className="discovery-client-clues"><Typography.Text type="secondary">近 2 小时目标端口线索（按当前 IP 关联；SYN-ACK 仅说明镜像见到反向响应，不证明连接完成或设备本机端口开放）</Typography.Text>{portsFor(selected).map(clue => <article key={`${clue.proto}:${clue.dst_port}`}><strong>{portLabel(clue)}</strong><Typography.Text type="secondary">{clue.evidence_id} · {observedTimeTitle(clue.last_seen)}</Typography.Text></article>)}</section>}
      {history.isError && <AppErrorAlert title="读取设备历史失败" />}
      {historyEnabled && <section className="discovery-history" aria-label="变化历史"><Typography.Title level={5}>证据时间线</Typography.Title>
        {(history.isError || historyMetadata.isError || historyPosition.isError) ? <AppErrorAlert title="读取设备历史失败" message={history.error?.message || historyMetadata.error?.message || historyPosition.error?.message} /> : historyMetadata.isPending || historyPosition.isLocating || history.isFetching ? <Typography.Text type="secondary">正在读取历史记录</Typography.Text> : historyPosition.ready && (history.data?.items ?? []).map(row => <article className="discovery-card" key={row.id}><strong>{protocols[row.evidence?.origin] ?? row.evidence?.origin}</strong><span>{row.evidence?.explanation}</span><Typography.Text type="secondary">观测于 {observedTimeTitle(row.observed_at)}</Typography.Text></article>)}
        <AppServerPagination disabled={history.isFetching || historyPosition.isLocating} page={historyPage} pageSize={historyPageSize} total={historyMetadata.data?.total} totalText={historyMetadata.isError ? '数量读取失败' : undefined} onChange={(next, size) => { setHistoryPage(next); setHistoryPageSize(size) }} />
      </section>}
    </>}</Modal>
  </section>
}
