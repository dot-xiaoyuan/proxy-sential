import { useState } from 'react'
import { DeviceAddress } from '../entities/device/DeviceAddress'
import { DeviceHistoryPanel } from './DeviceHistoryPanel'
import { NetworkProfileDetails } from './NetworkDeviceContext'
import { safeReturnTo } from '../app/navigation'
import { useQuery } from '@tanstack/react-query'
import { Alert, Descriptions, Progress, Space, Tabs, Tag, Typography } from 'antd'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { api } from '../shared/api/client'
import { AppErrorAlert, AppLoadingState } from '../shared/ui'
import { routerAssociationLabels, routerConflictLabels, routerRoleLabels, routerSourceLabels, routerStatusLabels } from './routerLabels'

const conflictLabels = routerConflictLabels

export function RouterObservationDetailsPage() {
 const [params]=useSearchParams();
 const [tab,setTab]=useState("overview");
  const { assessmentId = '' } = useParams()
  const query = useQuery({ queryKey: ['router-observation', assessmentId], queryFn: () => api.routerObservation(assessmentId), enabled: Boolean(assessmentId) })
  if (query.isLoading) return <main className="page router-detail-page"><AppLoadingState rows={8} /></main>
  if (query.isError || !query.data) return <main className="page router-detail-page"><AppErrorAlert title="路由观察加载失败" message={query.error?.message || '记录不存在'} /></main>
  const item = query.data
  const summaryItems = [
    { key: 'brand', label: item.brand_reference_only ? '厂商线索' : '品牌', children: item.brand || '' }, { key: 'series', label: '系列', children: item.series || '' }, { key: 'model', label: '型号', children: item.model || '' },
    { key: 'role', label: item.current ? '角色' : '历史角色', children: routerRoleLabels[item.role] || '' }, { key: 'ip', label: 'IP', children: item.ip || '' }, { key: 'mac', label: 'MAC', children: item.mac || '' },
    { key: 'vlan', label: 'VLAN', children: item.vlans?.join(', ') || '' }, { key: 'association', label: '关联质量', children: routerAssociationLabels[item.association_quality] || '' }, { key: 'sources', label: item.current ? '独立来源' : '历史来源', children: item.sources.length ? `${item.independent_sources} · ${item.sources.map(source=>routerSourceLabels[source]||source).join('、')}` : '' },
    { key: 'first', label: '首次发现', children: formatTime(item.first_seen) }, { key: 'last', label: '最近发现', children: formatTime(item.last_seen) }, { key: 'rules', label: '规则版本', children: item.rule_version },
    { key: 'expires', label: item.current ? '判定有效至' : '失效时间', children: formatTime(item.expires_at) },
  ].filter(entry => entry.children !== '')
  return <main className="page router-detail-page">
    <header className="router-detail-header"><div><Link to={safeReturnTo(params.get('return_to'),'/devices?tab=network')}>返回设备中心</Link><Typography.Title level={3}>网络设备详情</Typography.Title><DeviceAddress ip={item.current?item.primary_ip??item.ip:undefined} addresses={item.current_addresses} historicalIP={!item.current?item.ip:undefined} mac={item.mac}/><Typography.Text className="router-detail-id">{item.assessment_id}</Typography.Text></div>{item.current ? <Space wrap><Tag className={`router-status router-status-${item.status}`}>{routerStatusLabels[item.status]}</Tag>{item.status === 'candidate' ? <span className="router-score-muted">{item.confidence} 分</span> : <strong>{item.confidence} 分</strong>}</Space> : <Tag>已失效</Tag>}</header>
    {!item.current && <Alert type="info" showIcon title="该观察已失效" description="以下身份信息和判定仅供历史复核，不用于当前设备或共享确认。" />}
    {item.brand_reference_only && <Alert type="info" showIcon title="仅为品牌参考，不足以确认路由器" description="当前观察只有厂商或 OUI 线索，没有满足型号、角色强证据和独立来源要求。" />}
    {item.infrastructure && <Alert type="warning" showIcon title="基础设施设备不进入路由器确认" description="保留真实角色与证据用于核查，但该标记会阻止 confirmed_router。" />}
    {!!item.conflicts.length && <Alert type="error" showIcon title="存在冲突证据" description={item.conflicts.map(value => conflictLabels[value] || value).join('；')} />}
    <Tabs activeKey={tab} onChange={setTab} items={[{key:'overview',label:'概况'},{key:'history',label:'变化历史'},{key:'evidence',label:'发现证据'}]}/>
    {tab==='overview'&&<><NetworkProfileDetails id={assessmentId}/>
    <section className="surface router-detail-summary"><Descriptions column={{ xs: 1, sm: 2, lg: 3 }} size="small" items={summaryItems} /></section>
    {!!item.auth_bindings?.length && <section className="surface router-detail-section"><div className="router-detail-section-heading"><Typography.Title level={4}>认证身份</Typography.Title><Typography.Text type="secondary">仅展示 MAC 或终端标识精确匹配，认证信息不参与路由置信度计算</Typography.Text></div>{item.auth_bindings.some(binding=>binding.ambiguous)&&<Alert type="warning" showIcon title="存在多个当前认证会话" description="以下记录均为精确命中，但不能作为唯一归属展示。" />}<div className="router-auth-binding-list">{item.auth_bindings.map(binding=><article className={binding.ambiguous?'router-auth-binding router-auth-binding-ambiguous':'router-auth-binding'} key={`${binding.source}-${binding.session_id}`}><div><strong>{binding.account_id}</strong>{binding.ambiguous&&<Tag color="warning">归属有歧义</Tag>}</div><Descriptions column={{xs:1,sm:2,lg:3}} size="small" items={[{key:'ips',label:'认证分配 IP',children:binding.assigned_ips.join('、')},{key:'mac',label:'认证 MAC',children:binding.mac||''},{key:'basis',label:'匹配依据',children:binding.match_basis==='exact_endpoint'?'终端标识精确匹配':'MAC 精确匹配'},{key:'vlan',label:'VLAN',children:binding.vlan||''},{key:'nas',label:'NAS',children:binding.nas_ip||''},{key:'access',label:'接入标识',children:binding.access_id||''},{key:'started',label:'会话开始',children:formatTime(binding.started_at)},{key:'confirmed',label:'最近校准',children:formatTime(binding.last_confirmed_at)},{key:'source',label:'来源',children:binding.source}].filter(entry => entry.children !== '')} /></article>)}</div></section>}
    {item.current ? <section className="surface router-detail-section"><Typography.Title level={4}>分数构成</Typography.Title><Progress percent={item.confidence} status={item.status === 'confirmed' ? 'success' : 'normal'} /><ScoreComponents components={item.score_components} /></section> : <section className="surface router-detail-section"><details className="router-historical-score"><summary>查看历史分数（{item.confidence} 分）</summary><Typography.Paragraph type="secondary">历史判定：{routerStatusLabels[item.status]}。分数不代表当前风险或设备确认。</Typography.Paragraph><ScoreComponents components={item.score_components}/></details></section>}
    </>}
    {tab==='evidence'&&<>
    <DeviceHistoryPanel kind="router_evidence" id={assessmentId}/>
    </>}
    {tab==='history'&&<><DeviceHistoryPanel kind="router" id={assessmentId}/><NetworkProfileDetails id={assessmentId} history/></>}

  </main>
}

function ScoreComponents({components}:{components: {source_family:string;evidence_id:string;score:number;explanation:string}[]}) {
 return <div className="router-score-grid">{components.map(component=><article key={`${component.source_family}-${component.evidence_id}`}><strong>{routerSourceLabels[component.source_family]||component.source_family} · {component.score>0?'+':''}{component.score}</strong><span>{component.explanation}</span>{component.evidence_id&&<span className="router-score-evidence-id">证据 {component.evidence_id}</span>}</article>)}</div>
}

function formatTime(value?: string) {
  return value && !value.startsWith('0001-') ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : ''
}
