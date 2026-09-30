import { safeReturnTo } from '../app/navigation'
import { useQuery } from '@tanstack/react-query'
import { Alert, Descriptions, Progress, Space, Tag, Timeline, Typography } from 'antd'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { api } from '../shared/api/client'
import type { RouterEvidence } from '../shared/api/types'
import { AppErrorAlert, AppLoadingState } from '../shared/ui'

const statuses: Record<string, string> = { candidate: '候选', likely: '较可信', confirmed: '已确认' }
const roles: Record<string, string> = { router: '路由器', ap: '接入点', switch: '交换机', firewall: '防火墙', endpoint: '普通终端', unknown: '' }
const sourceLabels: Record<string, string> = { oui: 'MAC 厂商', dhcp: 'DHCP', software: '软件识别', lldp: 'LLDP', cdp: 'CDP', ssdp: 'SSDP', first_hop_redundancy: 'VRRP / HSRP', shared_gateway_behavior: '共享网关行为', http_management: 'HTTP 管理面', tls_management: 'TLS 管理面', weak_stack: '弱栈特征' }
const conflictLabels: Record<string, string> = { ordinary_endpoint: '普通终端特征冲突', infrastructure_ap: '接入点排除', infrastructure_switch: '交换机排除', infrastructure_firewall: '防火墙排除', infrastructure_role: '基础设施角色', ambiguous_association: '关联不唯一', brand_reference_only: '仅品牌参考', strong_evidence_required: '缺少强证据' }

export function RouterObservationDetailsPage() {
 const [params]=useSearchParams();
  const { assessmentId = '' } = useParams()
  const query = useQuery({ queryKey: ['router-observation', assessmentId], queryFn: () => api.routerObservation(assessmentId), enabled: Boolean(assessmentId) })
  if (query.isLoading) return <main className="page router-detail-page"><AppLoadingState rows={8} /></main>
  if (query.isError || !query.data) return <main className="page router-detail-page"><AppErrorAlert title="路由观察加载失败" message={query.error?.message || '记录不存在'} /></main>
  const item = query.data
  const evidence = [...(item.evidence || [])].sort((a, b) => Date.parse(b.last_seen) - Date.parse(a.last_seen))
  const history = meaningfulHistory(item.history)
  return <main className="page router-detail-page">
    <header className="router-detail-header"><div><Link to={safeReturnTo(params.get('return_to'),'/discovery?tab=routers')}>返回网络设备发现</Link><Typography.Title level={3}>{[item.brand, item.model || item.series, roles[item.role]].filter(Boolean).join(' · ')}</Typography.Title><Typography.Text className="router-detail-id">{item.assessment_id}</Typography.Text></div><Space wrap><Tag className={`router-status router-status-${item.status}`}>{statuses[item.status]}</Tag><strong>{item.confidence} 分</strong></Space></header>
    {item.brand_reference_only && <Alert type="info" showIcon title="仅为品牌参考，不足以确认路由器" description="当前观察只有厂商或 OUI 线索，没有满足型号、角色强证据和独立来源要求。" />}
    {item.infrastructure && <Alert type="warning" showIcon title="基础设施设备不进入路由器确认" description="保留真实角色与证据用于核查，但该标记会阻止 confirmed_router。" />}
    {!!item.conflicts.length && <Alert type="error" showIcon title="存在冲突证据" description={item.conflicts.map(value => conflictLabels[value] || value).join('；')} />}
    <section className="surface router-detail-summary"><Descriptions column={{ xs: 1, sm: 2, lg: 3 }} size="small" items={[
      { key: 'brand', label: '品牌', children: item.brand || '' }, { key: 'series', label: '系列', children: item.series || '' }, { key: 'model', label: '型号', children: item.model || '' },
      { key: 'role', label: '角色', children: roles[item.role] || '' }, { key: 'ip', label: 'IP', children: item.ip || '' }, { key: 'mac', label: 'MAC', children: item.mac || '' },
      { key: 'vlan', label: 'VLAN', children: item.vlans?.join(', ') || '' }, { key: 'association', label: '关联质量', children: item.association_quality }, { key: 'sources', label: '独立来源', children: `${item.independent_sources} · ${item.sources.join(', ')}` },
      { key: 'first', label: '首次发现', children: formatTime(item.first_seen) }, { key: 'last', label: '最近发现', children: formatTime(item.last_seen) }, { key: 'rules', label: '规则版本', children: item.rule_version },
    ]} /></section>
    <section className="surface router-detail-section"><Typography.Title level={4}>分数构成</Typography.Title><Progress percent={item.confidence} status={item.status === 'confirmed' ? 'success' : 'normal'} /><div className="router-score-grid">{item.score_components.map(component => <article key={`${component.source_family}-${component.evidence_id}`}><strong>{sourceLabels[component.source_family] || component.source_family} · {component.score > 0 ? '+' : ''}{component.score}</strong><span>{component.explanation}</span></article>)}</div></section>
    <section className="surface router-detail-section"><div className="router-detail-section-heading"><Typography.Title level={4}>当前有效证据</Typography.Title><Typography.Text type="secondary">{evidence.length} 条，已隐藏过期和旧规则记录</Typography.Text></div><Timeline items={evidence.map(entry => ({ color: entry.conflict || entry.exclusion ? 'red' : entry.strength === 'strong' ? 'green' : 'blue', content: <EvidenceItem item={entry} /> }))} /></section>
    <section className="surface router-detail-section"><div className="router-detail-section-heading"><Typography.Title level={4}>有效状态变化</Typography.Title><Typography.Text type="secondary">相同状态和分数的重复计算已折叠</Typography.Text></div><Timeline items={history.map(entry => ({ content: <div className="router-history-item"><strong>{statuses[entry.status]} · {entry.confidence} 分</strong><span>{formatTime(entry.changed_at)} · 规则 {entry.rule_version}</span>{entry.conflicts.length > 0 && <span>{entry.conflicts.map(value => conflictLabels[value] || value).join('；')}</span>}</div> }))} /></section>
  </main>
}

function EvidenceItem({ item }: { item: RouterEvidence }) {
  return <article className="router-evidence-item"><div className="router-evidence-heading"><strong>{sourceLabels[item.source_family] || item.source_family}</strong><Space wrap><Tag>{item.strength}</Tag><Tag>{item.score > 0 ? '+' : ''}{item.score}</Tag>{item.exclusion && <Tag color="error">排除规则</Tag>}{item.ambiguous && <Tag color="warning">关联不唯一</Tag>}</Space></div>{item.raw_value && <div className="router-evidence-value">{item.raw_value}</div>}<Typography.Text>{item.explanation}</Typography.Text><Typography.Text type="secondary">来源 {item.source} · {formatTime(item.first_seen)} 至 {formatTime(item.last_seen)}</Typography.Text><Typography.Text type="secondary">关联方式 {item.association_quality}{item.association_reason ? ` · ${item.association_reason}` : ''}</Typography.Text>{item.event_ids.length > 0 && <details className="router-evidence-events"><summary>关联 {item.event_ids.length} 个原始事件</summary><div>{item.event_ids.join('、')}</div></details>}</article>
}

function meaningfulHistory<T extends { status: string; confidence: number; conflicts: string[] }>(items: T[]) {
  return items.filter((item, index) => {
    if (index === 0) return true
    const previous = items[index - 1]
    return item.status !== previous.status || item.confidence !== previous.confidence || [...item.conflicts].sort().join('|') !== [...previous.conflicts].sort().join('|')
  })
}

function formatTime(value?: string) {
  return value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : ''
}
