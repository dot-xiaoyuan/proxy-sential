import { useEffect, useState } from 'react'
import { Alert, Input, Select, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Link } from 'react-router-dom'

import { BrandLogo } from '../entities/device/BrandLogo'
import { useDeviceRecognitionSummary, useDevices } from '../shared/api/queries'
import type { EndpointDeviceInventory } from '../shared/api/types'
import { AppErrorAlert, AppLoadingState, AppPageHeader, AppServerPagination, UniversityDimensionFilters, useServerPagination, type QuickWindow, type UniversityDimensions } from '../shared/ui'

export function DevicesPage() {
  const [quickWindow, setQuickWindow] = useState<QuickWindow>('24h')
	const pagination = useServerPagination()
  const [searchInput, setSearchInput] = useState('')
  const [query, setQuery] = useState('')
  const [dimensions, setDimensions] = useState<UniversityDimensions>({})
	const [ecosystem,setEcosystem]=useState<string>()
	const recognitionSummary = useDeviceRecognitionSummary()
  useEffect(() => { const timer = globalThis.setTimeout(() => { setQuery(searchInput.trim()); pagination.reset() }, 300); return () => globalThis.clearTimeout(timer) }, [searchInput])
  const devices = useDevices({ window: quickWindow, q: query, ecosystem, ...dimensions, limit: pagination.pageSize, cursor: pagination.cursor })

  const columns: ColumnsType<EndpointDeviceInventory> = [
    { title:'终端 / MAC', key:'endpoint', width:250, render:(_,row) => <div className="list-primary-cell"><Link className="list-cell-nowrap mono" title={row.endpoint_id} to={`/devices/${encodeURIComponent(row.endpoint_id)}`}>{row.endpoint_id}</Link><Typography.Text className="list-cell-nowrap mono" title={row.primary_mac} type="secondary">{row.primary_mac || '-'}</Typography.Text></div> },
    { title:'设备识别', key:'recognition', width:220, render:(_,row) => { const safe=!row.recognition_conflict;const brand=safe&&(row.brand_confidence??0)>=0.8?row.brand:'';const vendor=safe&&(row.vendor_confidence??0)>=0.8?row.vendor:'';const summary=safe?[(row.model_confidence??0)>=0.8?row.model:'',(row.device_type_confidence??0)>=0.8?row.device_type:'',(row.os_family_confidence??0)>=0.8?row.os_family:''].filter(Boolean).join(' · '):'';return <div className="list-primary-cell">{brand ? <BrandLogo device={{...row,brand}} /> : <Typography.Text strong>{vendor||'未知'}</Typography.Text>}<Typography.Text className="list-cell-nowrap" title={summary || '识别证据不足或存在冲突'} type="secondary">{summary || '未知设备'}</Typography.Text></div> } },
	{ title:'生态线索',key:'ecosystem',width:150,render:(_,row)=><div className="list-primary-cell"><Typography.Text className="list-cell-nowrap" title={row.ecosystem_hint||'访问线索不足'}>{row.ecosystem_conflict?'线索冲突':row.ecosystem_hint||'未知'}</Typography.Text><Typography.Text type="secondary">{row.ecosystem_evidence_count?`${Math.round((row.ecosystem_confidence??0)*100)}% · ${row.ecosystem_evidence_count} 次`:'-'}</Typography.Text></div> },
    { title:'登记', dataIndex:'registration_status', width:100, render:(value:EndpointDeviceInventory['registration_status']) => <Tag color={registrationStatusColor(value)}>{registrationStatusText(value)}</Tag> },
    { title:'账号 / 责任人', key:'owner', width:190, render:(_,row) => <Typography.Text className="list-cell-nowrap" title={[row.current_account,row.owner_name || row.owner_account].filter(Boolean).join(' / ')}>{[row.current_account,row.owner_name || row.owner_account].filter(Boolean).join(' / ') || '-'}</Typography.Text> },
    { title:'当前 IP', dataIndex:'current_ip', width:150, render:(value?:string) => <Typography.Text className="list-cell-nowrap mono" copyable={Boolean(value)} title={value}>{value || '-'}</Typography.Text> },
    { title:'接入位置', dataIndex:'current_access_id', width:170, render:(value?:string) => <Typography.Text className="list-cell-nowrap" title={value}>{value || '-'}</Typography.Text> },
    { title:'可信度', key:'confidence', width:100, render:(_,row) => `${Math.round((row.recognition_confidence || row.identity_confidence) * 100)}%` },
    { title:'最近出现', dataIndex:'last_seen', width:180, render:(value?:string) => value ? new Date(value).toLocaleString() : '-' },
  ]

  return <main className="page">
    <AppPageHeader title="终端画像" subtitle="按终端显示身份、网络位置与保守设备识别摘要，点击终端查看完整证据。" quickWindow={quickWindow} onQuickWindowChange={(value) => { setQuickWindow(value); pagination.reset() }} loading={devices.isFetching} onRefresh={() => void devices.refetch()} extra={<div className="list-toolbar"><Input.Search allowClear placeholder="搜索终端、MAC、品牌、生态、账号或 IP" value={searchInput} onChange={(event) => setSearchInput(event.target.value)} /><Select allowClear className="ecosystem-filter" placeholder="生态线索" value={ecosystem} options={['Apple','Huawei','Samsung','Xiaomi','Microsoft Windows','Amazon Alexa','Roku','Sonos'].map(value=>({label:value,value}))} onChange={(value)=>{setEcosystem(value);pagination.reset()}} /></div>} />
    <section className="surface filter-surface"><UniversityDimensionFilters value={dimensions} onChange={(next) => { setDimensions(next); pagination.reset() }} /></section>
    {recognitionSummary.data && <section className="surface recognition-summary-surface">
		<div className="recognition-coverage-strip">
			<RecognitionCoverage label="厂商" value={recognitionSummary.data.coverage.vendor} total={recognitionSummary.data.total_endpoints} />
			<RecognitionCoverage label="品牌" value={recognitionSummary.data.coverage.brand} total={recognitionSummary.data.total_endpoints} />
			<RecognitionCoverage label="型号" value={recognitionSummary.data.coverage.model} total={recognitionSummary.data.total_endpoints} />
			<RecognitionCoverage label="类型" value={recognitionSummary.data.coverage.device_type} total={recognitionSummary.data.total_endpoints} />
			<RecognitionCoverage label="操作系统" value={recognitionSummary.data.coverage.os_family} total={recognitionSummary.data.total_endpoints} />
			<RecognitionCoverage label="生态线索" value={recognitionSummary.data.coverage.ecosystem} total={recognitionSummary.data.total_endpoints} />
		</div>
		<div className="recognition-summary-meta">生态匹配 {recognitionSummary.data.ecosystem_matched} · 已归属 {recognitionSummary.data.ecosystem_attributed} · 未归属 {recognitionSummary.data.ecosystem_unattributed} · 规则 {recognitionSummary.data.domain_rule_version || '-'}</div>
		{recognitionSummary.data.event_count > 0 && recognitionSummary.data.event_attribution_rate < 0.2 && <Alert showIcon type="warning" title={`最近 24 小时终端归属率 ${Math.round(recognitionSummary.data.event_attribution_rate * 100)}%，生态命中暂无法完整写入终端画像`} description={<Link to="/ingest">检查身份接入与标准事件 endpoint_id</Link>} />}
	</section>}
    <section className="surface">{devices.isLoading ? <AppLoadingState rows={8} /> : devices.isError ? <AppErrorAlert title="设备列表加载失败" message={devices.error.message} /> : <><Table className="compact-list-table" columns={columns} dataSource={devices.data?.items ?? []} locale={{emptyText:'没有匹配的终端'}} pagination={false} rowKey="endpoint_id" scroll={{x:1510}} size="small" /><AppServerPagination page={pagination.page} pageSize={pagination.pageSize} total={devices.data?.page.total ?? 0} onChange={pagination.update} /></>}</section>
  </main>
}

function RecognitionCoverage({label,value,total}:{label:string;value?:{known:number;rate:number};total:number}) {
	return <div className="recognition-coverage-item"><Typography.Text type="secondary">{label}</Typography.Text><Typography.Text strong>{value?.known ?? 0}/{total} · {Math.round((value?.rate ?? 0)*100)}%</Typography.Text></div>
}

function registrationStatusText(status:EndpointDeviceInventory['registration_status']) { return status === 'registered' ? '已登记' : status === 'ignored' ? '已忽略' : status === 'retired' ? '已退役' : '未登记' }
function registrationStatusColor(status:EndpointDeviceInventory['registration_status']) { return status === 'registered' ? 'green' : status === 'retired' ? 'red' : status === 'ignored' ? 'default' : 'orange' }
