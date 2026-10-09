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
conflictLabels.shared_gateway_window_retired = '支持窗口已失效'
const associationLabels: Record<string,string> = { mac: 'MAC 关联', dhcp_lease: 'DHCP 租约关联', shared_gateway_window: '共享窗口推测' }

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
    <header className="router-detail-header"><div><Link to={safeReturnTo(params.get('return_to'),'/discovery?tab=routers')}>返回网络设备发现</Link><Typography.Title level={3}>{item.current ? [item.brand, item.model || item.series, roles[item.role]].filter(Boolean).join(' · ') || '路由观察' : '历史路由观察'}</Typography.Title><Typography.Text className="router-detail-id">{item.assessment_id}</Typography.Text></div>{item.current ? <Space wrap><Tag className={`router-status router-status-${item.status}`}>{statuses[item.status]}</Tag><strong>{item.confidence} 分</strong></Space> : <Tag>已失效</Tag>}</header>
    {!item.current && <Alert type="info" showIcon title="该观察已失效" description="以下身份信息和判定仅供历史复核，不用于当前设备或共享确认。" />}
    {item.brand_reference_only && <Alert type="info" showIcon title="仅为品牌参考，不足以确认路由器" description="当前观察只有厂商或 OUI 线索，没有满足型号、角色强证据和独立来源要求。" />}
    {item.infrastructure && <Alert type="warning" showIcon title="基础设施设备不进入路由器确认" description="保留真实角色与证据用于核查，但该标记会阻止 confirmed_router。" />}
    {!!item.conflicts.length && <Alert type="error" showIcon title="存在冲突证据" description={item.conflicts.map(value => conflictLabels[value] || value).join('；')} />}
    <section className="surface router-detail-summary"><Descriptions column={{ xs: 1, sm: 2, lg: 3 }} size="small" items={[
      { key: 'brand', label: '品牌', children: item.brand || '' }, { key: 'series', label: '系列', children: item.series || '' }, { key: 'model', label: '型号', children: item.model || '' },
      { key: 'role', label: item.current ? '角色' : '历史角色', children: roles[item.role] || '' }, { key: 'ip', label: 'IP', children: item.ip || '' }, { key: 'mac', label: 'MAC', children: item.mac || '' },
      { key: 'vlan', label: 'VLAN', children: item.vlans?.join(', ') || '' }, { key: 'association', label: '关联质量', children: associationLabels[item.association_quality] || item.association_quality }, { key: 'sources', label: item.current ? '独立来源' : '历史来源', children: item.sources.length ? `${item.independent_sources} · ${item.sources.map(source=>sourceLabels[source]||source).join('、')}` : '' },
      { key: 'first', label: '首次发现', children: formatTime(item.first_seen) }, { key: 'last', label: '最近发现', children: formatTime(item.last_seen) }, { key: 'rules', label: '规则版本', children: item.rule_version },
      { key: 'expires', label: item.current ? '判定有效至' : '失效时间', children: formatTime(item.expires_at) },
    ]} /></section>
    {!!item.auth_bindings?.length && <section className="surface router-detail-section"><div className="router-detail-section-heading"><Typography.Title level={4}>认证身份</Typography.Title><Typography.Text type="secondary">仅展示 MAC 或终端标识精确匹配，认证信息不参与路由置信度计算</Typography.Text></div>{item.auth_bindings.some(binding=>binding.ambiguous)&&<Alert type="warning" showIcon title="存在多个当前认证会话" description="以下记录均为精确命中，但不能作为唯一归属展示。" />}<div className="router-auth-binding-list">{item.auth_bindings.map(binding=><article className={binding.ambiguous?'router-auth-binding router-auth-binding-ambiguous':'router-auth-binding'} key={`${binding.source}-${binding.session_id}`}><div><strong>{binding.account_id}</strong>{binding.ambiguous&&<Tag color="warning">归属有歧义</Tag>}</div><Descriptions column={{xs:1,sm:2,lg:3}} size="small" items={[{key:'ips',label:'认证分配 IP',children:binding.assigned_ips.join('、')},{key:'mac',label:'认证 MAC',children:binding.mac||''},{key:'basis',label:'匹配依据',children:binding.match_basis==='exact_endpoint'?'终端标识精确匹配':'MAC 精确匹配'},{key:'vlan',label:'VLAN',children:binding.vlan||''},{key:'nas',label:'NAS',children:binding.nas_ip||''},{key:'access',label:'接入标识',children:binding.access_id||''},{key:'started',label:'会话开始',children:formatTime(binding.started_at)},{key:'confirmed',label:'最近校准',children:formatTime(binding.last_confirmed_at)},{key:'source',label:'来源',children:binding.source}]} /></article>)}</div></section>}
    {item.current ? <section className="surface router-detail-section"><Typography.Title level={4}>分数构成</Typography.Title><Progress percent={item.confidence} status={item.status === 'confirmed' ? 'success' : 'normal'} /><ScoreComponents components={item.score_components} /></section> : <section className="surface router-detail-section"><details className="router-historical-score"><summary>查看历史分数（{item.confidence} 分）</summary><Typography.Paragraph type="secondary">历史判定：{statuses[item.status]}。分数不代表当前风险或设备确认。</Typography.Paragraph><ScoreComponents components={item.score_components}/></details></section>}
    <section className="surface router-detail-section"><div className="router-detail-section-heading"><Typography.Title level={4}>当前有效证据</Typography.Title><Typography.Text type="secondary">{evidence.length} 条，已隐藏过期和旧规则记录</Typography.Text></div><Timeline items={evidence.map(entry => ({ color: entry.conflict || entry.exclusion ? 'red' : entry.strength === 'strong' ? 'green' : 'blue', content: <EvidenceItem item={entry} /> }))} /></section>
    <section className="surface router-detail-section"><div className="router-detail-section-heading"><Typography.Title level={4}>判定历史</Typography.Title><Typography.Text type="secondary">相同状态和分数的重复计算已折叠</Typography.Text></div><Timeline items={history.map(entry => ({ content: <div className="router-history-item"><strong>{statuses[entry.status]} · {entry.confidence} 分</strong><span>{formatTime(entry.changed_at)} · 规则 {entry.rule_version}</span>{entry.conflicts.length > 0 && <span>{entry.conflicts.map(value => conflictLabels[value] || value).join('；')}</span>}</div> }))} /></section>
  </main>
}

function ScoreComponents({components}:{components: {source_family:string;evidence_id:string;score:number;explanation:string}[]}) {
 return <div className="router-score-grid">{components.map(component=><article key={`${component.source_family}-${component.evidence_id}`}><strong>{sourceLabels[component.source_family]||component.source_family} · {component.score>0?'+':''}{component.score}</strong><span>{component.explanation}</span>{component.evidence_id&&<span className="router-score-evidence-id">证据 {component.evidence_id}</span>}</article>)}</div>
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
