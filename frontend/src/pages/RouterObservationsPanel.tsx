import { detailPath } from '../app/navigation'
import { useServerPagination } from '../shared/ui'
import { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Form, Input, InputNumber, Progress, Select, Space, Switch, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Link,useLocation,useSearchParams } from 'react-router-dom'
import { ApartmentOutlined, ReloadOutlined, SearchOutlined } from '@ant-design/icons'
import { api } from '../shared/api/client'
import type { RouterAssessment, RouterObservationQuery } from '../shared/api/types'
import { AppErrorAlert, AppLoadingState } from '../shared/ui'

const statusLabels: Record<string, string> = { candidate: '候选', likely: '较可信', confirmed: '已确认' }
const roleLabels: Record<string, string> = { router: '路由器', ap: '接入点', switch: '交换机', firewall: '防火墙', endpoint: '普通终端', unknown: '' }
const sourceLabels: Record<string, string> = { oui: 'MAC 厂商', dhcp: 'DHCP', software: '软件识别', lldp: 'LLDP', cdp: 'CDP', ssdp: 'SSDP', first_hop_redundancy: 'VRRP / HSRP', shared_gateway_behavior: '共享网关行为', http_management: 'HTTP 管理面', tls_management: 'TLS 管理面', weak_stack: '弱栈特征' }
const brandOptions = ['Huawei', 'H3C', 'Cisco', 'TP-Link', 'Ruijie', 'MikroTik', 'Juniper', 'ZTE', 'Xiaomi', 'Tenda', 'NETGEAR', 'ASUS', 'Ubiquiti', 'OpenWrt', 'VyOS']
const conflictLabels: Record<string, string> = { ordinary_endpoint: '普通终端特征冲突', infrastructure_ap: '接入点排除', infrastructure_switch: '交换机排除', infrastructure_firewall: '防火墙排除', infrastructure_role: '基础设施角色', ambiguous_association: '关联不唯一', brand_reference_only: '仅品牌参考', strong_evidence_required: '缺少强证据' }

function iso(value?: string) {
  if (!value) return undefined
  const date = new Date(value)
  return Number.isFinite(date.getTime()) ? date.toISOString() : undefined
}

export function RouterObservationsPanel() {
  const [form] = Form.useForm()
  const location=useLocation();const [params,setParams]=useSearchParams();const pagination=useServerPagination('routers_');const page=pagination.page;const setPage=(value:number)=>pagination.update(value,pagination.pageSize)
  const query=Object.fromEntries([...params.entries()].filter(([key])=>key.startsWith('router_')).map(([key,value])=>[key.slice(7),['confidence_min','confidence_max'].includes(key.slice(7))?Number(value):key==='router_infrastructure'?value==='true':value])) as RouterObservationQuery
  query.limit=20
  useEffect(()=>{form.setFieldsValue(query)},[params,form])
  const requestQuery = { ...query, cursor: String((page - 1) * (query.limit || 20)) }
  const observations = useQuery({ queryKey: ['router-observations', requestQuery], queryFn: () => api.routerObservations(requestQuery) })
  useEffect(() => { if (observations.data && observations.data.items.length === 0 && page > 1) setPage(1) }, [observations.data, page])
  const submit = (values: Record<string, string | number | boolean | undefined>) => {
    const query={ ...values, first_seen_from: iso(values.first_seen_from as string), first_seen_to: iso(values.first_seen_to as string), last_seen_from: iso(values.last_seen_from as string), last_seen_to: iso(values.last_seen_to as string) }
    setParams(current=>{const next=new URLSearchParams(current);for(const key of [...next.keys()])if(key.startsWith('router_')||key==='routers_page')next.delete(key);for(const [key,value]of Object.entries(query))if(value!==undefined&&value!=='')next.set(`router_${key}`,String(value));return next})
  }
  const columns: ColumnsType<RouterAssessment> = [
    { title: '设备', key: 'identity', width: 270, render: (_, item) => <DeviceIdentity item={item} /> },
    { title: '网络身份', key: 'address', width: 220, render: (_, item) => <div className="router-address"><strong>{item.ip || ''}</strong><span className="router-monospace">{item.mac || ''}</span>{item.vlans?.length ? <span>VLAN {item.vlans.join(', ')}</span> : null}</div> },
    { title: '识别判定', key: 'status', width: 185, render: (_, item) => <div className="router-verdict"><div><Tag className={`router-status router-status-${item.status}`}>{statusLabels[item.status]}</Tag><strong>{item.confidence} 分</strong></div><Progress percent={item.confidence} showInfo={false} size="small" status={item.status === 'confirmed' ? 'success' : 'normal'} /><span>{item.independent_sources} 类独立证据</span></div> },
    { title: '关键依据', key: 'sources', width: 250, render: (_, item) => <EvidenceTags sources={item.sources} /> },
    { title: '校验情况', key: 'constraints', width: 190, render: (_, item) => <ConstraintTags item={item} /> },
    { title: '最近发现', dataIndex: 'last_seen', width: 170, render: value => formatTime(value) },
    { title: '操作', key: 'action', width: 90, fixed: 'right', render: (_, item) => <Link to={detailPath(`/discovery/routers/${encodeURIComponent(item.assessment_id)}`,location.pathname+location.search)}>查看详情</Link> },
  ]
  const items = observations.data?.items || []
  const total = observations.data?.page.total || 0
  return <div className="router-observations-panel">
    <Form form={form} className="router-filter-form" layout="vertical" onFinish={submit}>
      <div className="router-filter-primary"><Form.Item name="keyword"><Input allowClear prefix={<SearchOutlined />} placeholder="搜索品牌、型号、IP 或 MAC" /></Form.Item><div className="router-filter-actions"><Button type="primary" htmlType="submit">查询</Button><Button onClick={() => { form.resetFields(); submit({}) }}>重置</Button><Button icon={<ReloadOutlined />} loading={observations.isFetching} onClick={() => void observations.refetch()}>刷新</Button></div></div>
      <details className="router-advanced-filters"><summary>更多筛选条件</summary><div className="router-filter-grid">
        <Form.Item name="brand" label="品牌"><Select allowClear showSearch options={brandOptions.map(value => ({ value, label: value }))} /></Form.Item>
        <Form.Item name="role" label="角色"><Select allowClear options={Object.entries(roleLabels).filter(([, label]) => label).map(([value, label]) => ({ value, label }))} /></Form.Item>
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
      </div></details>
    </Form>
    <div className="router-list-heading"><Typography.Title level={4}>路由设备识别</Typography.Title><Typography.Text type="secondary">{total} 台当前设备 · 已自动合并重复观察 · 仅用于影子验证</Typography.Text></div>
    {observations.isLoading ? <AppLoadingState rows={6} /> : observations.isError ? <AppErrorAlert title="路由观察加载失败" message={observations.error.message} /> : <>
      <div className="router-desktop-list"><Table rowKey="assessment_id" size="small" columns={columns} dataSource={items} pagination={{ current: page, pageSize: query.limit || 20, total, showSizeChanger: false, onChange: setPage }} scroll={{ x: 1320 }} locale={{ emptyText: '没有匹配的路由设备' }} /></div>
      <div className="router-mobile-list">{items.map(item => <article className="router-observation-card" key={item.assessment_id}><div className="router-card-heading"><DeviceIdentity item={item} /><Tag className={`router-status router-status-${item.status}`}>{statusLabels[item.status]} · {item.confidence} 分</Tag></div><div className="router-address"><strong>{item.ip || ''}</strong><span className="router-monospace">{item.mac || ''}</span>{item.vlans?.length ? <span>VLAN {item.vlans.join(', ')}</span> : null}</div><Progress percent={item.confidence} showInfo={false} size="small" status={item.status === 'confirmed' ? 'success' : 'normal'} /><EvidenceTags sources={item.sources} /><ConstraintTags item={item} /><div className="router-card-footer"><span>最近发现 {formatTime(item.last_seen)}</span><Link to={detailPath(`/discovery/routers/${encodeURIComponent(item.assessment_id)}`,location.pathname+location.search)}>查看详情</Link></div></article>)}</div>
    </>}
  </div>
}

function DeviceIdentity({ item }: { item: RouterAssessment }) {
  const title = [item.brand, item.model || item.series].filter(Boolean).join(' ') || (item.role === 'router' ? '待确认的路由设备' : roleLabels[item.role] || '待识别设备')
  return <div className="router-device-cell"><span className="router-device-icon"><ApartmentOutlined /></span><div className="router-identity"><strong>{title}</strong><span>{roleLabels[item.role] || '角色待确认'}</span>{item.brand_reference_only && <Typography.Text type="secondary">当前仅有厂商线索</Typography.Text>}{(item.merged_records || 1) > 1 && <Typography.Text className="router-merged-hint">已合并 {item.merged_records} 条重复观察</Typography.Text>}</div></div>
}

function EvidenceTags({ sources }: { sources: string[] }) {
  if (!sources.length) return <Typography.Text type="secondary">暂无有效依据</Typography.Text>
  const visible = sources.slice(0, 3)
  return <Space wrap size={[4, 4]}>{visible.map(source => <Tag key={source}>{sourceLabels[source] || source}</Tag>)}{sources.length > visible.length && <Tag>+{sources.length - visible.length}</Tag>}</Space>
}

function ConstraintTags({ item }: { item: RouterAssessment }) {
  const hasConstraints = item.infrastructure || item.ambiguous || item.conflicts.length > 0
  if (!hasConstraints) return <Tag color="success">无明显冲突</Tag>
  return <Space wrap size={[4, 4]}>{item.infrastructure && <Tag>基础设施</Tag>}{item.ambiguous && <Tag color="warning">关联不唯一</Tag>}{item.conflicts.slice(0, 2).map(value => <Tag color="error" key={value}>{conflictLabels[value] || value}</Tag>)}{item.conflicts.length > 2 && <Tag color="error">+{item.conflicts.length - 2}</Tag>}</Space>
}

function formatTime(value?: string) {
  return value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : ''
}
