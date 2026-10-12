import { DeviceAddress } from '../entities/device/DeviceAddress'
import { useNetworkContexts, NetworkSharing } from './NetworkDeviceContext'
import { detailPath } from '../app/navigation'
import { useServerPagination } from '../shared/ui'
import { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Checkbox, Form, Input, InputNumber, Select, Space, Switch, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Link,useLocation,useSearchParams } from 'react-router-dom'
import { ReloadOutlined, SearchOutlined } from '@ant-design/icons'
import { api } from '../shared/api/client'
import type { RouterAssessment, RouterObservationQuery } from '../shared/api/types'
import { AppErrorAlert, AppLoadingState } from '../shared/ui'
import { routerRoleLabels, routerSourceLabels, routerStatusLabels } from './routerLabels'

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

export function RouterObservationsPanel({addressState='current'}:{addressState?:'current'|'link'|'history'}) {
  const [form] = Form.useForm()
  const location=useLocation();const [params,setParams]=useSearchParams();const pagination=useServerPagination('routers_');const page=pagination.page;const setPage=(value:number)=>pagination.update(value,pagination.pageSize)
  const query=routerObservationQueryFromParams(params)
  query.limit=20
  useEffect(()=>{form.setFieldsValue(query)},[params,form])
  const requestQuery = { ...query, address_state:addressState, cursor: String((page - 1) * (query.limit || 20)) }
  const observations = useQuery({ queryKey: ['router-observations', requestQuery], queryFn: () => api.routerObservations(requestQuery) })
  useEffect(() => { if (observations.data && observations.data.items.length === 0 && page > 1) setPage(1) }, [observations.data, page])
  const submit = (values: Record<string, string | number | boolean | undefined>) => {
    const query={ ...values, include_candidates: values.status === 'candidate' || Boolean(values.include_candidates), first_seen_from: iso(values.first_seen_from as string), first_seen_to: iso(values.first_seen_to as string), last_seen_from: iso(values.last_seen_from as string), last_seen_to: iso(values.last_seen_to as string) }
    setParams(current=>{const next=new URLSearchParams(current);for(const key of [...next.keys()])if(key.startsWith('router_')||key==='routers_page')next.delete(key);for(const [key,value]of Object.entries(query))if(value!==undefined&&value!=='')next.set(`router_${key}`,String(value));return next})
  }
  const items = observations.data?.items || []
  const contexts=useNetworkContexts(items.map(item=>item.assessment_id))
  const columns: ColumnsType<RouterAssessment> = [
    { title:'IP / 名称 / MAC',key:'identity',width:270,render:(_,item)=><DeviceIdentity item={item} name={contexts.data?.[item.assessment_id]?.length===1?contexts.data[item.assessment_id][0].display_name:undefined} historical={addressState==='history'}/> },
    { title:'类型 / 品牌',key:'type',render:(_,item)=><div className="center-two-lines"><span>{roleLabels[item.role]}</span><span>{item.brand_reference_only?'':item.brand}</span></div> },
    { title:'关联账号',key:'auth',render:(_,item)=><AuthIdentity item={item}/> },
    { title:'路由 / 共享状态',key:'status',render:(_,item)=><><Verdict item={item}/><NetworkSharing profiles={contexts.data?.[item.assessment_id]}/></> },
    { title:'最近观测',dataIndex:'last_seen',width:155,render:formatTime },
    { title:'操作',key:'action',width:90,render:(_,item)=><Link to={detailPath(`/devices/network/${encodeURIComponent(item.assessment_id)}`,location.pathname+location.search)}>查看详情</Link> },
  ]
  const total = observations.data?.page?.total ?? 0
  return <div className="router-observations-panel">
    <Form form={form} className="router-filter-form" layout="vertical" onFinish={submit}>
      <div className="router-filter-primary"><Form.Item name="keyword"><Input allowClear prefix={<SearchOutlined />} placeholder="搜索品牌、型号、IP 或 MAC" /></Form.Item><Form.Item className="router-auth-filter" name="has_auth_binding" valuePropName="checked"><Checkbox>只看有认证身份</Checkbox></Form.Item><div className="router-filter-actions"><Button type="primary" htmlType="submit">查询</Button><Button onClick={() => { form.resetFields(); submit({}) }}>重置</Button><Button icon={<ReloadOutlined />} loading={observations.isFetching} onClick={() => void observations.refetch()}>刷新</Button></div></div>
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
    </Form>
    <div className="router-list-heading"><Typography.Title level={4}>网络设备</Typography.Title><Typography.Text type="secondary">{total} 台设备 · 依据路由身份聚合</Typography.Text></div>
    {observations.isLoading ? <AppLoadingState rows={6} /> : observations.isError ? <AppErrorAlert title="路由观察加载失败" message={observations.error.message} /> : <>
      <div className="router-desktop-list"><Table rowKey="assessment_id" size="small" columns={columns} dataSource={items} pagination={{ current: page, pageSize: query.limit || 20, total, showSizeChanger: false, onChange: setPage }} tableLayout="fixed" locale={{ emptyText: '没有匹配的路由设备' }} /></div>
      <div className="router-mobile-list">{items.map(item=><article className="router-observation-card" key={item.assessment_id}><DeviceIdentity item={item} name={contexts.data?.[item.assessment_id]?.length===1?contexts.data[item.assessment_id][0].display_name:undefined} historical={addressState==='history'}/><span>{[roleLabels[item.role],item.brand_reference_only?'':item.brand].filter(Boolean).join(' · ')}</span><AuthIdentity item={item}/><Verdict item={item}/><NetworkSharing profiles={contexts.data?.[item.assessment_id]}/><div className="router-card-footer"><span>{formatTime(item.last_seen)}</span><Link to={detailPath(`/devices/network/${encodeURIComponent(item.assessment_id)}`,location.pathname+location.search)}>查看详情</Link></div></article>)}<Space wrap><Button disabled={page===1} onClick={()=>setPage(page-1)}>上一页</Button><span>{page} / {Math.max(1,Math.ceil(total/20))}</span><Button disabled={page*20>=total} onClick={()=>setPage(page+1)}>下一页</Button></Space></div>

    </>}
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

function Verdict({ item }: { item: RouterAssessment }) {
 return <div className="center-verdict"><Tag className={`router-status router-status-${item.status}`}>{statusLabels[item.status]}</Tag><span>{item.confidence} 分</span>{item.ambiguous&&<Tag color="warning">关联不唯一</Tag>}{item.conflicts.length>0&&<Tag color="error">证据冲突</Tag>}</div>
}
function DeviceIdentity({item,historical=false,name}:{item:RouterAssessment;historical?:boolean;name?:string}){
 return <DeviceAddress ip={historical?undefined:item.primary_ip??item.ip} historicalIP={historical?item.ip:undefined} mac={item.mac} name={name} addresses={item.current_addresses}/>
}

function formatTime(value?: string) {
  return value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : ''
}
