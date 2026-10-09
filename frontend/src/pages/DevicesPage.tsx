import { useEffect, useState, useCallback, useRef } from 'react'
import { Alert, Button, Checkbox, Input, Popover, Segmented, Select, Table, Tooltip, Typography } from 'antd'
import { resolveDeviceBrand } from '../entities/device/brandMatcher'
import type { ColumnsType } from 'antd/es/table'
import { Link, useSearchParams } from 'react-router-dom'
import { InfoCircleOutlined, ReloadOutlined, SettingOutlined } from '@ant-design/icons'

import { DeviceLedgerIdentity, DeviceLedgerRecognition, DeviceLedgerOS, deviceDetailsURL } from '../entities/device/DeviceInventoryCells'
import { useDeviceInventoryMetadata, useDeviceRecognitionSummary, useDevices } from '../shared/api/queries'
import type { DeviceInventoryListItem, DeviceQuery } from '../shared/api/types'
import { AppErrorAlert, AppLoadingState, AppServerPagination, UniversityDimensionFilters, useServerPagination, type ReportWindow, type UniversityDimensions } from '../shared/ui'

export function DevicesPage() {
  const [params, setParams] = useSearchParams()
  const pagination = useServerPagination()
  const view = params.get('view') === 'history' ? 'history' : 'recent'
  const quickWindow = (['10m','1h','24h','7d','30d'].includes(params.get('window') || '') ? params.get('window') : '24h') as ReportWindow
  const query = params.get('q') || ''
  const [searchInput, setSearchInput] = useState(query)
  const ecosystem = params.get('ecosystem') || undefined
  const brand = params.get('brand') || undefined
  const osFamily = params.get('os_family') || undefined
  const dimensionKeys = ['campus_id','department','person_type','ssid','vlan','ap','nas_ip'] as const
  const dimensions = Object.fromEntries(dimensionKeys.map(key=>[key,params.get(key)||undefined])) as UniversityDimensions
  const columnOptions=[{label:'类型 / 品牌',value:'recognition'},{label:'操作系统',value:'os'},{label:'关联账号 / 接入',value:'context'},{label:'最近观测',value:'observed'}]
  const [visibleColumns, setVisibleColumns] = useState<string[]>(()=>{try {const value=JSON.parse(localStorage.getItem('device-ledger-columns') || 'null');return Array.isArray(value)?value.filter(v=>['recognition','os','context','observed'].includes(v)):['recognition','os','context','observed']}catch{return ['recognition','os','context','observed']}})
  const [filtersOpen,setFiltersOpen]=useState(false)
  const [compact,setCompact]=useState(()=>window.matchMedia('(max-width: 991px)').matches)
  useEffect(()=>{
    const media=window.matchMedia('(max-width: 991px)')
    const change=(event:MediaQueryListEvent)=>setCompact(event.matches)
    setCompact(media.matches);media.addEventListener('change',change)
    return ()=>media.removeEventListener('change',change)
  },[])
  const [diagnosticsOpen, setDiagnosticsOpen] = useState(false)
  const change = useCallback((values: Record<string,string|undefined>)=>setParams(current=>{
    const next=new URLSearchParams(current)
    for(const [key,value] of Object.entries(values)){if(value)next.set(key,value);else next.delete(key)}
    next.set('page','1');next.delete('cursor');return next
  },{replace:true}),[setParams])
  useEffect(()=>{setSearchInput(query)},[query])
  useEffect(()=>{
    const next=searchInput.trim();if(next===query)return
    const timer=setTimeout(()=>change({q:next}),300);return ()=>clearTimeout(timer)
  },[searchInput,query,change])
  useEffect(()=>{if(!params.has('view')||!params.has('window'))setParams(current=>{const next=new URLSearchParams(current);if(!next.has('view'))next.set('view','recent');if(!next.has('window'))next.set('window','24h');return next},{replace:true})},[params,setParams])
  const recognitionSummary = useDeviceRecognitionSummary(diagnosticsOpen)
  const listQuery: DeviceQuery={ view, window: quickWindow, q: query, ecosystem, brand, os_family: osFamily, sensor_id:params.get('sensor_id')||undefined, ...dimensions, limit: pagination.pageSize, cursor: pagination.cursor }
  const devices = useDevices(listQuery)
  const metadata=useDeviceInventoryMetadata(listQuery,Boolean(devices.data)&&!devices.isPlaceholderData)
  const total=metadata.data?.total
  useEffect(()=>{if(total===undefined||metadata.isFetching||devices.isFetching||devices.isPlaceholderData||(devices.data?.items?.length??0)>0)return;const last=Math.max(1,Math.ceil(total/pagination.pageSize));if(pagination.page>last)pagination.update(last,pagination.pageSize)},[total,metadata.isFetching,devices.isFetching,devices.isPlaceholderData,devices.data,pagination])
  const entered=useRef(performance.getEntriesByName('device-inventory-enter').at(-1)?.startTime??performance.now())
  const measured=useRef(false)
  useEffect(()=>{
    if(!devices.data||measured.current)return
    const frame=requestAnimationFrame(()=>{performance.clearMeasures('device-inventory-visible');performance.measure('device-inventory-visible',{start:entered.current,end:performance.now()});performance.clearMarks('device-inventory-enter');measured.current=true})
    return ()=>cancelAnimationFrame(frame)
  },[devices.data])
  const [clock,setClock]=useState(Date.now())
  useEffect(()=>{const timer=setInterval(()=>setClock(Date.now()),30_000);return ()=>clearInterval(timer)},[])
  const returnTo='/devices?'+params.toString()
  const detailURL=(row:DeviceInventoryListItem)=>deviceDetailsURL(row)+'?return_to='+encodeURIComponent(returnTo)
  const items = devices.data?.items ?? []
  const matchSearch=items.some(row=>row.ip_match)

  const columns: ColumnsType<DeviceInventoryListItem> = [
    { title: '终端身份', key: 'identity', render: (_, row) => <DeviceLedgerIdentity device={row} href={detailURL(row)} showName={!devices.data?.device_names_disabled}/> },
    { title: '类型 / 品牌', key: 'recognition', render: (_,row)=><DeviceLedgerRecognition device={row}/> },
    { title: '操作系统', key: 'os', render: (_,row)=><DeviceLedgerOS device={row}/> },
    { title: '关联账号 / 接入', key: 'context', render: (_, row) => <OwnershipAccess device={row} /> },
    { title: '最近观测', key:'observed', dataIndex: 'last_seen', width: 110, render: (value?: string) => <ObservedTime value={value} /> },
  ]
  return <main className="page device-inventory-page">
    <header className="device-page-header"><Typography.Title level={3}>终端画像</Typography.Title><div className="device-header-actions"><Link to="/discovery">网络设备发现</Link><Segmented aria-label="终端范围" value={view} options={[{label:'近期观测',value:'recent'},{label:'全部历史',value:'history'}]} onChange={value=>change({view:String(value)})}/><Button icon={<ReloadOutlined/>} loading={devices.isFetching} onClick={()=>{void devices.refresh();void metadata.refresh()}}>刷新数据</Button></div></header>
    <section className="surface device-filter-bar device-filter-compact" aria-label="终端筛选">
      <div className="device-filter-primary"><Input.Search className="device-search" allowClear placeholder="搜索设备名称、MAC、IP 或账号" value={searchInput} onChange={event=>setSearchInput(event.target.value)} onSearch={value=>change({q:value.trim()})}/>{view==='recent'&&<Segmented aria-label="观测时间范围" value={quickWindow} options={[{label:'10 分钟',value:'10m'},{label:'1 小时',value:'1h'},{label:'24 小时',value:'24h'},{label:'7 天',value:'7d'},{label:'30 天',value:'30d'}]} onChange={value=>change({window:String(value)})}/>}</div>
      <details className="filter-disclosure device-filter-disclosure" onToggle={event=>setFiltersOpen(event.currentTarget.open)}><summary>更多筛选{[osFamily,brand,ecosystem,...Object.values(dimensions)].filter(Boolean).length ? `（已启用 ${[osFamily,brand,ecosystem,...Object.values(dimensions)].filter(Boolean).length} 项）` : ''}</summary>{filtersOpen&&<div className="filter-disclosure-content device-more-filters"><Select aria-label="操作系统筛选" allowClear showSearch optionFilterProp="label" placeholder="全部操作系统" value={osFamily} options={(metadata.data?.facets?.os_families??[]).map(value=>({value,label:value==='unknown'?'空值':value}))} onChange={value=>change({os_family:value})}/><Select aria-label="品牌筛选" allowClear showSearch optionFilterProp="label" placeholder="全部品牌" value={brand} options={(metadata.data?.facets?.brands??[]).map(value=>({value,label:brandFilterLabel(value)}))} onChange={value=>change({brand:value})}/><Select allowClear className="ecosystem-filter" placeholder="生态线索" value={ecosystem} options={['Apple','Huawei','Samsung','Xiaomi','Microsoft Windows','Amazon Alexa','Roku','Sonos','Vivo','OPPO/Realme'].map(value=>({label:value,value}))} onChange={value=>change({ecosystem:value})}/><UniversityDimensionFilters value={dimensions} onChange={next=>change(Object.fromEntries(dimensionKeys.map(key=>[key,next[key]])))}/></div>}</details>
    </section>
    <section className="surface device-inventory-surface">
      <div className="device-list-heading">
        <Typography.Title level={4}>终端台账</Typography.Title>
        {total!==undefined&&<Tooltip title={metadata.data?.as_of?`统计时间：${new Date(metadata.data.as_of).toLocaleString('zh-CN')}`:undefined}><Typography.Text type="secondary">{total} 个终端身份</Typography.Text></Tooltip>}
        <Tooltip title="近期观测不等于在线，终端身份数不等于物理设备数；账号和接入位置为观测关联。"><InfoCircleOutlined aria-label="列表说明"/></Tooltip>
        <Popover trigger="click" title="显示列" content={<Checkbox.Group value={visibleColumns} options={columnOptions} onChange={values=>{const next=values.map(String);setVisibleColumns(next);localStorage.setItem('device-ledger-columns',JSON.stringify(next))}}/>}><Button className="device-column-settings" icon={<SettingOutlined/>}>列设置</Button></Popover>
      </div>
      <div className="device-list-freshness">
        {devices.dataUpdatedAt>0&&<Typography.Text type="secondary">列表刷新 {new Date(devices.dataUpdatedAt).toLocaleTimeString('zh-CN',{hour12:false})}{clock-devices.dataUpdatedAt>30_000?' · 缓存已超过 30 秒，可手动刷新':''}</Typography.Text>}
        {devices.data?.as_of&&<Typography.Text type="secondary">画像更新时间 {shortTime(devices.data.as_of)}</Typography.Text>}
        {devices.data?.read_model_updating&&<Typography.Text className="device-read-model-state">画像摘要更新中</Typography.Text>}
        {metadata.isError&&<Typography.Text className="device-read-model-state">统计加载失败 <Button type="link" size="small" onClick={()=>void metadata.refresh()}>重试统计</Button></Typography.Text>}
      </div>
      {devices.isError&&devices.data&&<AppErrorAlert title="刷新失败，保留上次列表" message={devices.error.message}/>}
      {matchSearch&&<Typography.Paragraph className="device-list-note" type="secondary">精确 IP 匹配 · {view==='recent'?'所选时间内的观测与会话':'全部历史关联'}</Typography.Paragraph>}
      {devices.isLoading ? <AppLoadingState rows={8} /> : devices.isError && !devices.data ? <AppErrorAlert title="终端列表加载失败" message={devices.error.message} /> : <>
        {compact&&<div className="device-mobile-cards">{items.map(row => <article key={row.endpoint_id} className="device-mobile-card">
          <DeviceLedgerIdentity device={row} href={detailURL(row)} showName={!devices.data?.device_names_disabled}/>
          {visibleColumns.includes('recognition')&&<DeviceLedgerRecognition device={row}/>}
          {visibleColumns.includes('os')&&<DeviceLedgerOS device={row}/>}

          {visibleColumns.includes('context')&&(row.current_account||row.owner_name||row.owner_account||row.current_access_id)&&<OwnershipAccess device={row} />}
          <div className="device-mobile-footer">{visibleColumns.includes('observed')&&<ObservedTime value={row.last_seen}/>}<div className="device-row-actions"><Link to={detailURL(row)}>查看详情</Link></div></div>
        </article>)}</div>}
        {compact&&items.length === 0 && <Typography.Text className="device-mobile-empty" type="secondary">没有匹配的终端</Typography.Text>}
        {!compact&&<Table className="compact-list-table device-desktop-table" columns={columns.filter(column=>column.key==='identity'||visibleColumns.includes(String(column.key)))} dataSource={items} locale={{ emptyText: '没有匹配的终端' }} pagination={false} rowKey="endpoint_id" tableLayout="fixed" size="small" />}
        {total!==undefined?<AppServerPagination page={pagination.page} pageSize={pagination.pageSize} total={total} onChange={pagination.update}/>:<div className="device-pending-pagination" aria-label="统计等待分页"><Button disabled={pagination.page<=1||devices.isPlaceholderData} onClick={()=>pagination.update(pagination.page-1,pagination.pageSize)}>上一页</Button><Typography.Text>第 {pagination.page} 页</Typography.Text><Button disabled={!devices.data?.page.next_cursor||devices.isPlaceholderData} onClick={()=>pagination.update(pagination.page+1,pagination.pageSize)}>下一页</Button>{!metadata.isError&&<Typography.Text type="secondary">总数统计中</Typography.Text>}</div>}
      </>}
    </section>
    <details className="surface filter-disclosure device-diagnostics" onToggle={event=>setDiagnosticsOpen(event.currentTarget.open)}><summary>识别质量与接入诊断</summary>{diagnosticsOpen&&<div className="filter-disclosure-content recognition-summary-surface">
		{recognitionSummary.isLoading&&<AppLoadingState rows={3} />}
		{recognitionSummary.isError&&<AppErrorAlert title="识别诊断加载失败" message={recognitionSummary.error.message} />}
		{recognitionSummary.data&&<>
		<div className="recognition-coverage-strip">
			<RecognitionCoverage label="厂商" value={recognitionSummary.data.coverage.vendor} total={recognitionSummary.data.total_endpoints} />
			<RecognitionCoverage label="高置信度品牌" value={recognitionSummary.data.coverage.brand} total={recognitionSummary.data.total_endpoints} />
			<RecognitionCoverage label="推测品牌" value={recognitionSummary.data.coverage.brand_inferred} total={recognitionSummary.data.total_endpoints} />
			<RecognitionCoverage label="型号" value={recognitionSummary.data.coverage.model} total={recognitionSummary.data.total_endpoints} />
			<RecognitionCoverage label="类型" value={recognitionSummary.data.coverage.device_type} total={recognitionSummary.data.total_endpoints} />
			<RecognitionCoverage label="操作系统" value={recognitionSummary.data.coverage.os_family} total={recognitionSummary.data.total_endpoints} />
			<RecognitionCoverage label="生态线索" value={recognitionSummary.data.coverage.ecosystem} total={recognitionSummary.data.total_endpoints} />
		</div>
		<div className="recognition-summary-meta">近 7 天 · 品牌线索冲突 {recognitionSummary.data.brand_inference_conflicts ?? 0} · 生态匹配 {recognitionSummary.data.ecosystem_matched} · 已归属 {recognitionSummary.data.ecosystem_attributed} · 未归属 {recognitionSummary.data.ecosystem_unattributed} · 规则 {recognitionSummary.data.domain_rule_version || ''}</div>
		{recognitionSummary.data.event_count > 0 && recognitionSummary.data.event_attribution_rate < 0.2 && <Alert showIcon type="warning" title={`最近 24 小时终端归属率 ${Math.round(recognitionSummary.data.event_attribution_rate * 100)}%，生态命中暂无法完整写入终端画像`} description={<Link to="/ingest">检查身份接入与标准事件 endpoint_id</Link>} />}
		</>}
	</div>}</details>
  </main>
}

function OwnershipAccess({ device }: { device: DeviceInventoryListItem }) {
  return <div className="device-context-cell">
    {device.current_account&&<div><Typography.Text type="secondary">关联账号</Typography.Text><Typography.Text className="brand-evidence-wrap">{device.current_account}</Typography.Text></div>}
    {(device.owner_name||device.owner_account)&&<div><Typography.Text type="secondary">登记归属</Typography.Text><Typography.Text className="brand-evidence-wrap">{[device.owner_name,device.owner_account].filter(Boolean).join(' · ')}</Typography.Text></div>}
    {device.current_access_id&&<div><Typography.Text type="secondary">接入位置</Typography.Text><Typography.Text className="brand-evidence-wrap" title={device.current_access_id}>{device.current_access_id}</Typography.Text></div>}
  </div>
}

function ObservedTime({ value }: { value?: string }) {
  return <Typography.Text className="device-observed-time" title={value ? new Date(value).toLocaleString('zh-CN') : undefined}>{shortTime(value)}</Typography.Text>
}

function RecognitionCoverage({ label, value, total }: { label: string; value?: { known: number; rate: number }; total: number }) {
  return <div className="recognition-coverage-item"><Typography.Text type="secondary">{label}</Typography.Text><Typography.Text strong>{value?.known ?? 0}/{total} · {Math.round((value?.rate ?? 0) * 100)}%</Typography.Text></div>
}

function brandFilterLabel(value: string) {
  if (value === 'unknown') return '空值'
  const brand = resolveDeviceBrand({ brand: value })
  return brand.name === value ? value : `${brand.name}（${value}）`
}

function shortTime(value?:string) {
 if(!value)return '';const at=new Date(value),now=new Date();if(!Number.isFinite(at.getTime()))return ''
 const minutes=Math.floor((now.getTime()-at.getTime())/60000)
 if(minutes>=0&&minutes<1)return '刚刚';if(minutes>=1&&minutes<60)return `${minutes} 分钟前`
 const clock=at.toLocaleTimeString('zh-CN',{hour:'2-digit',minute:'2-digit',hour12:false})
 if(at.toDateString()===now.toDateString())return `今天 ${clock}`
 const yesterday=new Date(now);yesterday.setDate(now.getDate()-1);if(at.toDateString()===yesterday.toDateString())return `昨天 ${clock}`
 return at.toLocaleString('zh-CN',{year:at.getFullYear()!==now.getFullYear()?'numeric':undefined,month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false})
}
