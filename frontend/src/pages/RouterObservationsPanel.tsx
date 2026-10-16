import { observedTimeLabel, observedTimeTitle } from '../shared/ui/observedTime'
import { DeviceAddress } from '../entities/device/DeviceAddress'
import { detailPath } from '../app/navigation'
import { useServerPagination } from '../shared/ui'
import { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Checkbox, Form, Input, InputNumber, Select, Switch, Table, Tag, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Link,useLocation,useSearchParams } from 'react-router-dom'
import { InfoCircleOutlined, ReloadOutlined, SearchOutlined } from '@ant-design/icons'
import { api } from '../shared/api/client'
import type { RouterAssessment, RouterObservationQuery } from '../shared/api/types'
import { AppErrorAlert, AppLoadingState, AppServerPagination } from '../shared/ui'
import { BrandLogo } from '../entities/device/BrandLogo'
import { routerLibraryLabels } from '../entities/device/libraryLabels'
import { routerConflictLabels, routerRoleLabels, routerSourceLabels, routerStatusLabels } from './routerLabels'

const statusLabels = routerStatusLabels
const roleLabels = routerRoleLabels
const sourceLabels = routerSourceLabels
const filterRoles = ['router', 'ap', 'switch', 'firewall', 'endpoint']
const brandOptions = ['Huawei', 'H3C', 'Cisco', 'TP-Link', 'Ruijie', 'MikroTik', 'Juniper', 'ZTE', 'Xiaomi', 'Tenda', 'NETGEAR', 'ASUS', 'Ubiquiti', 'OpenWrt', 'VyOS']

function iso(value?: string) {
  if (!value) return undefined
  const date = new Date(value)
  return Number.isFinite(date.getTime()) ? date.toISOString() : undefined
}

export function routerObservationQueryFromParams(params: URLSearchParams): RouterObservationQuery {
  return { role: 'network', include_candidates: false, ...Object.fromEntries([...params.entries()].filter(([key]) => key.startsWith('router_')).map(([key, value]) => [key.slice(7), ['confidence_min', 'confidence_max'].includes(key.slice(7)) ? Number(value) : ['router_infrastructure','router_include_candidates','router_has_auth_binding'].includes(key) ? value === 'true' : value])) } as RouterObservationQuery
}

export function RouterObservationsPanel() {
  const [form] = Form.useForm()
  const location=useLocation();const [params,setParams]=useSearchParams();const pagination=useServerPagination('routers_');const page=pagination.page;const setPage=(value:number)=>pagination.update(value,pagination.pageSize)
  const query=routerObservationQueryFromParams(params)
  query.limit=pagination.pageSize
  useEffect(()=>{form.setFieldsValue(query)},[params,form])
  const requestQuery = { ...query, cursor: String((page - 1) * (query.limit || 20)) }
  const observations = useQuery({ queryKey: ['router-observations', requestQuery], queryFn: () => api.routerObservations(requestQuery) })
  useEffect(() => { if (observations.data && observations.data.items.length === 0 && page > 1) setPage(1) }, [observations.data, page])
  const submit = (values: Record<string, string | number | boolean | undefined>) => {
    const query={ ...values, include_candidates: values.status === 'candidate' || Boolean(values.include_candidates), first_seen_from: iso(values.first_seen_from as string), first_seen_to: iso(values.first_seen_to as string), last_seen_from: iso(values.last_seen_from as string), last_seen_to: iso(values.last_seen_to as string) }
    setParams(current=>{const next=new URLSearchParams(current);for(const key of [...next.keys()])if(key.startsWith('router_')||key==='routers_page')next.delete(key);for(const [key,value]of Object.entries(query))if(value!==undefined&&value!=='')next.set(`router_${key}`,String(value));return next})
  }
  const items = observations.data?.items || []
  const columns: ColumnsType<RouterAssessment> = [
    // Recognition leads the row: brand, role, model and the scored evidence that produced them.
    { title:'识别结果',key:'recognition',width:290,render:(_,item)=><RouterRecognition item={item}/> },
    { title:'地址',key:'identity',width:230,render:(_,item)=><DeviceIdentity item={item}/> },
    { title:'关联账号',key:'auth',render:(_,item)=><AuthIdentity item={item}/> },
    { title:'最近观测',dataIndex:'last_seen',width:118,render:(value?:string)=><ObservedTime value={value}/> },
    { title:'操作',key:'action',width:84,render:(_,item)=><Link to={detailPath(`/devices/network/${encodeURIComponent(item.assessment_id)}`,location.pathname+location.search)}>查看详情</Link> },
  ]
  const total = observations.data?.page?.total ?? 0
  return <div className="router-observations-panel">
    {/* Filters and the list identity share one card so the table is not pushed down. */}
    <Form form={form} className="surface router-filter-form center-list-toolbar" layout="vertical" onFinish={submit}>
      <div className="center-list-toolbar-row">
        <div className="center-list-search router-filter-primary"><Form.Item name="keyword"><Input allowClear prefix={<SearchOutlined />} placeholder="搜索品牌、型号、IP 或 MAC" /></Form.Item><Form.Item className="router-auth-filter" name="has_auth_binding" valuePropName="checked"><Checkbox>只看有认证身份</Checkbox></Form.Item><div className="router-filter-actions"><Button type="primary" htmlType="submit">查询</Button><Button onClick={() => { form.resetFields(); submit({}) }}>重置</Button><Button icon={<ReloadOutlined />} loading={observations.isFetching} onClick={() => void observations.refetch()}>刷新</Button></div></div>
      </div>
      <div className="router-filter-footer">
      <details className="router-advanced-filters"><summary>更多筛选条件</summary><div className="router-filter-grid">
        <Form.Item name="brand" label="品牌"><Select allowClear showSearch options={brandOptions.map(value => ({ value, label: value }))} /></Form.Item>
        <Form.Item name="role" label="角色"><Select allowClear options={filterRoles.map(value => ({ value, label: roleLabels[value] }))} /></Form.Item>
        <Form.Item name="status" label="状态"><Select allowClear options={Object.entries(statusLabels).map(([value, label]) => ({ value, label }))} /></Form.Item>
        <Form.Item name="ip" label="IP"><Input allowClear /></Form.Item>
        <Form.Item name="mac" label="MAC"><Input allowClear /></Form.Item>
        <Form.Item name="vlan" label="VLAN"><Input allowClear /></Form.Item>
        <Form.Item name="model" label="型号／系列"><Input allowClear /></Form.Item>
        <Form.Item name="source" label="证据来源"><Select allowClear options={Object.entries(sourceLabels).map(([value, label]) => ({ value, label }))} /></Form.Item>
        <Form.Item name="confidence_min" label="最低分"><InputNumber min={0} max={100} /></Form.Item>
        <Form.Item name="confidence_max" label="最高分"><InputNumber min={0} max={100} /></Form.Item>
        <Form.Item name="first_seen_from" label="首次发现起"><Input type="datetime-local" /></Form.Item>
        <Form.Item name="first_seen_to" label="首次发现止"><Input type="datetime-local" /></Form.Item>
        <Form.Item name="last_seen_from" label="最近发现起"><Input type="datetime-local" /></Form.Item>
        <Form.Item name="last_seen_to" label="最近发现止"><Input type="datetime-local" /></Form.Item>
        <Form.Item name="infrastructure" label="仅基础设施" valuePropName="checked"><Switch /></Form.Item>
        <Form.Item name="include_candidates" label="包含候选记录" valuePropName="checked"><Switch /></Form.Item>
      </div></details>
      <div className="center-list-meta"><Typography.Text type="secondary">{total} 台设备</Typography.Text><Tooltip title="按路由身份聚合；品牌、型号与角色来自多源证据评分，MAC 合并要求采集范围和 VLAN 一致。"><InfoCircleOutlined aria-label="网络设备说明" /></Tooltip></div>
      </div>
    </Form>
    <section className="surface center-list-surface">{observations.isLoading ? <AppLoadingState rows={6} /> : observations.isError ? <AppErrorAlert title="路由观察加载失败" message={observations.error.message} /> : <>
      <div className="router-desktop-list"><Table rowKey="assessment_id" size="small" columns={columns} dataSource={items} pagination={false} tableLayout="fixed" locale={{ emptyText: '没有匹配的路由设备' }} /></div>
      <div className="router-mobile-list">{items.map(item=><article className="router-observation-card" key={item.assessment_id}><RouterRecognition item={item}/><DeviceIdentity item={item}/><AuthIdentity item={item}/><div className="router-card-footer"><ObservedTime value={item.last_seen}/><Link to={detailPath(`/devices/network/${encodeURIComponent(item.assessment_id)}`,location.pathname+location.search)}>查看详情</Link></div></article>)}</div>
      <AppServerPagination page={page} pageSize={pagination.pageSize} total={total} onChange={pagination.update}/>
    </>}</section>
  </div>
}

function AuthIdentity({ item }: { item: RouterAssessment }) {
  const bindings = item.auth_bindings || []
  if (!bindings.length) return null
  const certain = bindings.filter(binding => !binding.ambiguous)
  if (!certain.length) return <div className="router-auth-identity router-auth-identity-ambiguous"><Tag color="warning">多会话精确命中</Tag><span>{bindings.length} 个当前认证会话</span></div>
  const binding = certain[0]
  return <div className="router-auth-identity"><strong>{binding.account_id}</strong><span>{binding.match_basis === 'exact_endpoint' ? '终端标识精确匹配' : 'MAC 精确匹配'}</span></div>
}

/**
 * Routing gear is identified from scored multi-source evidence, so the list shows the
 * conclusion (brand / role / model) together with the score and the sources behind it,
 * instead of two unlabelled stacked strings.
 */
function RouterRecognition({ item }: { item: RouterAssessment }) {
 const brand = item.brand_reference_only ? '' : (item.brand || '')
 // series and model often repeat the brand or each other; show each fact once.
 const model = (() => {
  const series = (item.series || '').trim()
  const modelValue = (item.model || '').trim()
  const parts: string[] = []
  if (series && !(modelValue && modelValue.toLowerCase().includes(series.toLowerCase()))) parts.push(series)
  if (modelValue) parts.push(brand && modelValue.toLowerCase().startsWith(brand.toLowerCase()) ? modelValue.slice(brand.length).trim() : modelValue)
  return parts.join(' · ')
 })()
 const sources = item.sources || []
 const components = item.score_components || []
 const basis = components.length > 0
  ? <div className="router-basis"><b>识别依据 · 规则 {item.rule_version || ''}</b>{components.map(component => <div key={component.evidence_id}>{routerSourceLabels[component.source_family] || component.source_family} {component.score > 0 ? `+${component.score}` : component.score} · {component.explanation}</div>)}</div>
  : undefined
 return <div className="router-recognition">
  <div className="router-recognition-head">
   {brand && <BrandLogo brandKey={brand} />}
   {brand && <strong className="router-brand">{brand}</strong>}
   <Tag className={`router-role router-role-${item.role}`}>{roleLabels[item.role] || item.role}</Tag>
  </div>
  {model && <span className="router-model" title={model}>{model}</span>}
  <div className="router-recognition-evidence">
   <Tooltip title={basis}><span className={`router-score router-score-${item.status}`}>{statusLabels[item.status]} · {item.confidence} 分</span></Tooltip>
   {sources.slice(0, 3).map(source => <Tag key={source} className="router-source">{routerSourceLabels[source] || source}</Tag>)}
   {sources.length > 3 && <Tooltip title={sources.map(source => routerSourceLabels[source] || source).join('、')}><Tag className="router-source">+{sources.length - 3}</Tag></Tooltip>}
   {(item.libraries || []).map(library => <Tag key={library} className="router-library">{routerLibraryLabels[library] || library}</Tag>)}
   {item.ambiguous && <Tag color="warning">关联不唯一</Tag>}
   {item.conflicts.length > 0 && <Tooltip title={item.conflicts.map(conflict => routerConflictLabels[conflict] || conflict).join('、')}><Tag color="error">证据冲突</Tag></Tooltip>}
  </div>
 </div>
}
function DeviceIdentity({item,historical=false,name}:{item:RouterAssessment;historical?:boolean;name?:string}){
 return <DeviceAddress ip={historical?undefined:item.ip} historicalIP={historical?item.ip:undefined} mac={item.mac} name={name}/>
}

// Every device list renders 最近观测 the same way; the exact time stays in the title.
function ObservedTime({ value }: { value?: string }) {
  return <span className="device-observed-time" title={observedTimeTitle(value)}>{observedTimeLabel(value)}</span>
}
