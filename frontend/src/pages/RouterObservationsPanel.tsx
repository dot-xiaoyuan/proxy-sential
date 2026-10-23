import {
  observedTimeLabel,
  observedTimeTitle } from '../shared/ui/observedTime'
import { DeviceAddress } from '../entities/device/DeviceAddress'
import { detailPath } from '../app/navigation'
import { AppTable,
  useServerPagination } from '../shared/ui'
import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button,
  Checkbox,
  Form,
  Input,
  InputNumber,
  Segmented,
  Select,
  Switch,
  Tag,
  Tooltip,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Link,useLocation,useSearchParams } from 'react-router-dom'
import { InfoCircleOutlined } from '@ant-design/icons'
import { api } from '../shared/api/client'
import type { RouterAssessment, RouterObservationQuery } from '../shared/api/types'
import { AppErrorAlert, AppListHeader, AppLoadingState, AppServerPagination, AppTableBar, useMediaQuery } from '../shared/ui'
import { BrandLogo } from '../entities/device/BrandLogo'
import { routerLibraryLabels } from '../entities/device/libraryLabels'
import { routerConflictLabels, routerRoleLabels, routerSourceLabels, routerStatusLabels } from './routerLabels'
import { routerVerdictExplanation } from './routerVerdictExplanation'

const statusLabels = routerStatusLabels
const roleLabels = routerRoleLabels
const sourceLabels = routerSourceLabels
const brandOptions = ['Huawei', 'H3C', 'Cisco', 'TP-Link', 'Ruijie', 'MikroTik', 'Juniper', 'ZTE', 'Xiaomi', 'Tenda', 'NETGEAR', 'ASUS', 'Ubiquiti', 'OpenWrt', 'VyOS']

function iso(value?: string) {
  if (!value) return undefined
  const date = new Date(value)
  return Number.isFinite(date.getTime()) ? date.toISOString() : undefined
}

export function routerObservationQueryFromParams(params: URLSearchParams): RouterObservationQuery {
  const view = params.get('routers_view') === 'ap' ? 'ap' : 'router'
  const query = { role: view, include_candidates: false, ...Object.fromEntries([...params.entries()].filter(([key]) => key.startsWith('router_')).map(([key, value]) => [key.slice(7), ['confidence_min', 'confidence_max'].includes(key.slice(7)) ? Number(value) : ['router_infrastructure','router_include_candidates','router_has_auth_binding'].includes(key) ? value === 'true' : value])) } as RouterObservationQuery
  query.role = view
  return query
}

export function RouterObservationsPanel() {
  const [form] = Form.useForm()
  const location=useLocation();const [params,setParams]=useSearchParams();const pagination=useServerPagination('routers_');const page=pagination.page;const setPage=(value:number)=>pagination.update(value,pagination.pageSize)
  const query=routerObservationQueryFromParams(params)
  const view = params.get('routers_view') === 'ap' ? 'ap' : 'router'
  const desktopAuth = useMediaQuery('(min-width: 1100px)')
  const mobileAuth = useMediaQuery('(max-width: 559px)')
  const showAuth = desktopAuth || mobileAuth
  const switchView = (value: string | number) => { const nextView = String(value); if (nextView === view) return; setParams(current => { const next = new URLSearchParams(current); next.set('routers_view', nextView); next.delete('routers_page'); return next }) }
  const [searchDraft,setSearchDraft]=useState(String(params.get('router_keyword')||''))
  const [moreOpen,setMoreOpen]=useState(false)
  useEffect(()=>{setSearchDraft(String(params.get('router_keyword')||''))},[params])
  query.limit=pagination.pageSize
  useEffect(()=>{form.setFieldsValue(query)},[params,form])
  const requestQuery = { ...query, cursor: String((page - 1) * (query.limit || 20)) }
  const observations = useQuery({ queryKey: ['router-observations', requestQuery], queryFn: () => api.routerObservations(requestQuery) })
  useEffect(() => { if (observations.data && observations.data.items.length === 0 && page > 1) setPage(1) }, [observations.data, page])
  const hasAuthBinding = Form.useWatch('has_auth_binding', form)
  const search = (value: string) => submit({ ...form.getFieldsValue(), keyword: value.trim() })
  useEffect(()=>{const timer=globalThis.setTimeout(()=>{const next=searchDraft.trim();if(next!==String(params.get('router_keyword')||''))search(next)},300);return()=>globalThis.clearTimeout(timer)},[searchDraft])
  const submit = (values: Record<string, string | number | boolean | undefined>) => {
    const query={ ...values, include_candidates: values.status === 'candidate' || Boolean(values.include_candidates), first_seen_from: iso(values.first_seen_from as string), first_seen_to: iso(values.first_seen_to as string), last_seen_from: iso(values.last_seen_from as string), last_seen_to: iso(values.last_seen_to as string) }
    setParams(current=>{const next=new URLSearchParams(current);for(const key of [...next.keys()])if(key.startsWith('router_')||key==='routers_page')next.delete(key);for(const [key,value]of Object.entries(query))if(value!==undefined&&value!=='')next.set(`router_${key}`,String(value));return next})
  }
  const items = observations.data?.items || []
  const columns: ColumnsType<RouterAssessment> = [
    { title:'识别结果',key:'recognition',width:185,render:(_,item)=><RouterRecognition item={item}/> },
    { title:'地址',key:'identity',width:165,render:(_,item)=><DeviceIdentity item={item}/> },
    { title:'判定依据',key:'evidence',width:195,render:(_,item)=><RouterEvidence item={item}/> },
    ...(showAuth ? [{ title:'关联账号',key:'auth',width:145,render:(_: unknown,item:RouterAssessment)=><AuthIdentity item={item}/> }] : []),
    { title:'最近观测',dataIndex:'last_seen',width:100,render:(value?:string)=><ObservedTime value={value}/> },
    { title:'操作',key:'action',width:75,render:(_,item)=><Link to={detailPath(`/devices/network/${encodeURIComponent(item.assessment_id)}`,location.pathname+location.search)}>查看详情</Link> },
  ]
  const total = observations.data?.page?.total ?? 0
  return <div className="router-observations-panel">
    <div className="router-view-switch">
      <Segmented aria-label="网络设备类型" value={view} onChange={switchView} options={[{label:'路由器',value:'router'},{label:'接入点',value:'ap'}]} />
    </div>
    {/* Filters and the list identity share one card so the table is not pushed down. */}
    <Form form={form} className="router-filter-form" layout="vertical" onFinish={submit}>
      <AppTableBar
        searchPlaceholder="搜索品牌、型号、IP 或 MAC"
        searchValue={searchDraft}
        onSearchChange={setSearchDraft}
        onSearch={value=>search(value)}
        filters={<>
          <Checkbox checked={Boolean(hasAuthBinding)} onChange={event => submit({ ...form.getFieldsValue(), keyword: searchDraft.trim(), has_auth_binding: event.target.checked })}>只看有认证身份</Checkbox>
          <Button size="small" type="text" onClick={()=>setMoreOpen(value=>!value)}>{moreOpen?'收起筛选':'更多筛选'}</Button>
          <Button size="small" type="text" onClick={() => { form.resetFields(); setSearchDraft(''); submit({}) }}>重置</Button>
        </>}
        panel={moreOpen?<div className="app-filter-panel router-filter-panel">
          <div className="router-filter-grid">
<Form.Item name="brand" label="品牌"><Select allowClear showSearch options={brandOptions.map(value => ({ value, label: value }))} /></Form.Item>
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
        </div>
          <div className="router-filter-actions"><Button type="primary" onClick={() => submit({ ...form.getFieldsValue(), keyword: searchDraft.trim() })}>应用筛选</Button></div>
        </div>:undefined}
      />
    </Form>
    <section className="surface center-list-surface">
      <AppListHeader
        title={view === 'ap' ? '接入点观察' : '路由器观察'}
        count={`${total} 台${view === 'ap' ? '接入点' : '设备'}`}
        actions={<Tooltip title={view === 'ap' ? '本页识别接入点。接入点记录不参与路由器确认；分类基于 DHCP、LLDP、管理面等证据，仍可能受弱信号影响。' : '本页识别路由器，不代表下游共享已确认。分数表示证据匹配强度；路由器确认还要求明确路由角色、独立来源、强证据和可靠设备关联，基础设施及排除证据会阻断确认。'}><InfoCircleOutlined aria-label="网络设备说明" /></Tooltip>}
      />
      {observations.isLoading ? <AppLoadingState rows={6} /> : observations.isError ? <AppErrorAlert title="路由观察读取失败" message={observations.error.message} /> : <>
        <AppTable rowKey="assessment_id" columns={columns} dataSource={items} pagination={false} tableLayout="fixed" scroll={{ x: showAuth ? 865 : 720 }} locale={{ emptyText: view === 'ap' ? '暂无匹配的接入点' : '暂无匹配的路由器' }} />
        <AppServerPagination page={page} pageSize={pagination.pageSize} total={total} onChange={pagination.update}/>
    </>}</section>
  </div>
}

function AuthIdentity({ item }: { item: RouterAssessment }) {
  const bindings = item.auth_bindings || []
  if (!bindings.length) return <div className="router-auth-identity"><span className="account-placeholder">无认证账号</span></div>
  const certain = bindings.filter(binding => !binding.ambiguous)
  if (!certain.length) return <div className="router-auth-identity router-auth-identity-ambiguous"><Tag color="warning">多会话精确命中</Tag><span>{bindings.length} 个当前认证会话</span></div>
  const binding = certain[0]
  return <div className="router-auth-identity"><strong>{binding.account_id}</strong><span>{binding.match_basis === 'exact_endpoint' ? '终端标识精确匹配' : 'MAC 精确匹配'}</span></div>
}

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
 return <div className="router-recognition">
  <div className="router-recognition-head">
   {brand && <BrandLogo brandKey={brand} />}
   <Tag className={`router-role router-role-${item.role}`}>{roleLabels[item.role] || item.role}</Tag>
  </div>
  {model && <span className="router-model" title={model}>{model}</span>}
 </div>
}
function RouterEvidence({ item }: { item: RouterAssessment }) {
 const sources = item.sources || []
 const components = item.score_components || []
 const basis = components.length > 0
  ? <div className="router-basis"><b>识别依据 · 规则 {item.rule_version || ''}</b>{components.map(component => <div key={component.evidence_id}>{routerSourceLabels[component.source_family] || component.source_family} {component.score > 0 ? `+${component.score}` : component.score} · {component.explanation}</div>)}</div>
  : undefined
 return <div className="router-recognition-evidence">
   <Tooltip title={basis}><span className={`router-score router-score-${item.status}`}>{statusLabels[item.status]} · 匹配 {item.confidence} 分</span></Tooltip>
   {sources.slice(0, 3).map(source => <Tag key={source} className="router-source">{routerSourceLabels[source] || source}</Tag>)}
   {sources.length > 3 && <Tooltip title={sources.map(source => routerSourceLabels[source] || source).join('、')}><Tag className="router-source">+{sources.length - 3}</Tag></Tooltip>}
   {(item.libraries || []).map(library => <Tag key={library} className="router-library">{routerLibraryLabels[library] || library}</Tag>)}
   {item.ambiguous && <Tag color="warning">关联不唯一</Tag>}
   {item.conflicts.length > 0 && <Tooltip title={item.conflicts.map(conflict => routerConflictLabels[conflict] || conflict).join('、')}><Tag color={item.conflicts.every(conflict=>['infrastructure_role','ambiguous_association'].includes(conflict))?'warning':'error'}>{item.conflicts.every(conflict=>['infrastructure_role','ambiguous_association'].includes(conflict))?'确认受限':'证据冲突'}</Tag></Tooltip>}
   {item.status !== 'confirmed' && <span className="router-verdict-reason">未确认：{routerVerdictExplanation(item)}</span>}
 </div>
}
function DeviceIdentity({item,historical=false,name}:{item:RouterAssessment;historical?:boolean;name?:string}){
 return <DeviceAddress ip={historical?undefined:item.ip} historicalIP={historical?item.ip:undefined} mac={item.mac} name={name}/>
}

// Every device list renders 最近观测 the same way; the exact time stays in the title.
function ObservedTime({ value }: { value?: string }) {
  return <span className="device-observed-time" title={observedTimeTitle(value)}>{observedTimeLabel(value)}</span>
}
