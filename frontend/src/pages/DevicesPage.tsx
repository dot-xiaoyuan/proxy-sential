import { Notice as Alert } from '../shared/ui/Notice'
import { useEffect, useState, useCallback, useRef } from 'react'
import { Button, Checkbox, Popover, Segmented, Select, Tooltip, Typography, Tag } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { resolveDeviceBrand } from '../entities/device/brandMatcher'
import { Link, useSearchParams } from 'react-router-dom'
import { isIPAddress } from '../shared/ipAddress'
import { can } from '../shared/auth/permissions'
import { IpTrafficObservations } from '../widgets/IpTrafficObservations'
import { InfoCircleOutlined, SettingOutlined } from '@ant-design/icons'

import { DeviceMAC, DeviceLedgerRecognition, DeviceLedgerOS, deviceDetailsURL } from '../entities/device/DeviceInventoryCells'
import { useDeviceInventoryMetadata, useDeviceRecognitionSummary, useDevices, useSession } from '../shared/api/queries'
import type { DeviceInventoryListItem, DeviceQuery } from '../shared/api/types'
import { AppCursorPagination, AppErrorAlert, AppListHeader, AppLoadingState, AppServerPagination, AppTable, AppTableBar, formatDateTime, type ReportWindow, type UniversityDimensions, UniversityDimensionFilters, useMediaQuery, useServerPagination } from '../shared/ui'

export function DevicesPage({ embedded = false }: { embedded?: boolean }) {
  const [params, setParams] = useSearchParams()
  const session = useSession()
  const canReadTraffic = can(session.data, 'events:read')
  const pagination = useServerPagination()
  const showProfile = useMediaQuery('(min-width: 1440px)') || useMediaQuery('(max-width: 559px)')
  const showContext = useMediaQuery('(min-width: 1200px)') || useMediaQuery('(max-width: 559px)')
  const showMac = useMediaQuery('(min-width: 1000px)') || useMediaQuery('(max-width: 559px)')
  const cursorByPage = useRef<Record<number, string>>({ 1: '' })
  const view = params.get('view') === 'history' ? 'history' : 'recent'
  const quickWindow = (['10m','1h','24h','7d','30d'].includes(params.get('window') || '') ? params.get('window') : '24h') as ReportWindow
  const query = params.get('q') || ''
  const searchType=(params.get('search_type') || 'all') as NonNullable<DeviceQuery['search_type']>
  const [searchInput, setSearchInput] = useState(query)
  const ecosystem = params.get('ecosystem') || undefined
  const brand = params.get('brand') || undefined
  const osFamily = params.get('os_family') || undefined
  const dimensionKeys = ['campus_id','department','person_type','ssid','vlan','ap','nas_ip'] as const
  const dimensions = Object.fromEntries(dimensionKeys.map(key=>[key,params.get(key)||undefined])) as UniversityDimensions
  const columnOptions=[{label:'类型 / 品牌',value:'recognition'},{label:'操作系统',value:'os'},{label:'关联账号 / 接入',value:'context'},{label:'最近观测',value:'observed'}]
  const [visibleColumns, setVisibleColumns] = useState<string[]>(()=>{try {const value=JSON.parse(localStorage.getItem('device-ledger-columns') || 'null');return Array.isArray(value)?value.filter(v=>['recognition','os','context','observed'].includes(v)):['recognition','os','context','observed']}catch{return ['recognition','os','context','observed']}})
  const [filtersOpen,setFiltersOpen]=useState(false)
  const [diagnosticsOpen, setDiagnosticsOpen] = useState(false)
  const change = useCallback((values: Record<string,string|undefined>)=>setParams(current=>{
    const next=new URLSearchParams(current)
    for(const [key,value] of Object.entries(values)){if(value)next.set(key,value);else next.delete(key)}
    cursorByPage.current={1:''}
    next.set('page','1');next.delete('cursor');return next
  },{replace:true}),[setParams])
  useEffect(()=>{setSearchInput(query)},[query])
  useEffect(()=>{if(!params.has('view')||!params.has('window'))setParams(current=>{const next=new URLSearchParams(current);if(!next.has('view'))next.set('view','recent');if(!next.has('window'))next.set('window','24h');return next},{replace:true})},[params,setParams])
  const recognitionSummary = useDeviceRecognitionSummary(diagnosticsOpen)
  const listQuery: DeviceQuery={ search_type:searchType, view, window: quickWindow, q: query, ecosystem, brand, os_family: osFamily, sensor_id:params.get('sensor_id')||undefined, ...dimensions, limit: pagination.pageSize, cursor: cursorByPage.current[pagination.page] || undefined }
  const devices = useDevices(listQuery)
  const metadata=useDeviceInventoryMetadata(listQuery,Boolean(devices.data)&&!devices.isPlaceholderData)
  const total=metadata.data?.total
  useEffect(()=>{
    const next=devices.data?.page?.next_cursor
    if(next) cursorByPage.current[pagination.page+1]=next
  },[devices.data,pagination.page])
  const updatePagination=(nextPage:number,nextSize:number)=>{
    if(nextPage===1||nextSize!==pagination.pageSize)cursorByPage.current={1:''}
    pagination.update(nextPage,nextSize)
  }
  useEffect(()=>{if(total===undefined||metadata.isFetching||devices.isFetching||devices.isPlaceholderData||(devices.data?.items?.length??0)>0)return;const last=Math.max(1,Math.ceil(total/pagination.pageSize));if(pagination.page>last)pagination.update(last,pagination.pageSize)},[total,metadata.isFetching,devices.isFetching,devices.isPlaceholderData,devices.data,pagination])
  const entered=useRef(performance.getEntriesByName('device-inventory-enter').at(-1)?.startTime??performance.now())
  const measured=useRef(false)
  useEffect(()=>{
    if(!devices.data||measured.current)return
    const frame=requestAnimationFrame(()=>{performance.clearMeasures('device-inventory-visible');performance.measure('device-inventory-visible',{start:entered.current,end:performance.now()});performance.clearMarks('device-inventory-enter');measured.current=true})
    return ()=>cancelAnimationFrame(frame)
  },[devices.data])
  const returnTo='/devices?'+params.toString()
  const detailURL=(row:DeviceInventoryListItem)=>deviceDetailsURL(row)+'?return_to='+encodeURIComponent(returnTo)
  const items = devices.data?.items ?? []
  const matchSearch=items.some(row=>row.ip_match)

  const scopeControls = <>
    <Segmented aria-label="终端范围" value={view} options={[{label:'近期观测',value:'recent'},{label:'全部历史',value:'history'}]} onChange={value=>change({view:String(value)})}/>
  </>
  const searchPlaceholder = searchType==='account'?'输入完整账号（最新观测关联）':searchType==='ip'?'输入完整 IP（含历史精确匹配）':searchType==='mac'?'输入完整 MAC':searchType==='name'?'搜索终端名称':'搜索终端名称、MAC、IP 或账号'
  const searchTypeControl = <Select aria-label="搜索类型" value={searchType} options={[{value:'all',label:'综合'},{value:'account',label:'账号'},{value:'ip',label:'IP'},{value:'mac',label:'MAC'},{value:'name',label:'名称'}]} onChange={value=>change({search_type:value,q:searchInput.trim()})}/>
  const timeControl = view==='recent'?<Segmented aria-label="观测时间范围" value={quickWindow} options={[{label:'10 分钟',value:'10m'},{label:'1 小时',value:'1h'},{label:'24 小时',value:'24h'},{label:'7 天',value:'7d'},{label:'30 天',value:'30d'}]} onChange={value=>change({window:String(value)})}/>:undefined
  const osControl = <Select aria-label="操作系统筛选" allowClear showSearch optionFilterProp="label" placeholder="全部操作系统" value={osFamily} options={(metadata.data?.facets?.os_families??[]).map(value=>({value,label:value==='unknown'?'空值':value}))} onChange={value=>change({os_family:value})}/>
  const brandControl = <Select aria-label="品牌筛选" allowClear showSearch optionFilterProp="label" placeholder="全部品牌" value={brand} options={(metadata.data?.facets?.brands??[]).map(value=>({value,label:brandFilterLabel(value)}))} onChange={value=>change({brand:value})}/>
  const ecosystemControl = <Select allowClear className="ecosystem-filter" placeholder="生态线索" value={ecosystem} options={['Apple','Huawei','Samsung','Xiaomi','Microsoft Windows','Amazon Alexa','Roku','Sonos','Vivo','OPPO/Realme'].map(value=>({label:value,value}))} onChange={value=>change({ecosystem:value})}/>
  const dimensionControl = <UniversityDimensionFilters value={dimensions} onChange={next=>change(Object.fromEntries(dimensionKeys.map(key=>[key,next[key]])))}/>
  const moreFilterCount = [osFamily,brand,ecosystem,...Object.values(dimensions)].filter(Boolean).length
  const moreFilters = <div className="filter-disclosure-content device-more-filters">{osControl}{brandControl}{ecosystemControl}{dimensionControl}</div>
  const deviceName = (row: DeviceInventoryListItem) => devices.data?.device_names_disabled ? '' : row.device_name?.value || ''
  const deviceColumns: ColumnsType<DeviceInventoryListItem> = [
    { title: 'IPv4', key: 'ip', width: 145, render: (_, row) => { const ipv4 = ipv4Address(row.current_ip); return <div className="device-row-ip-value">{ipv4 && <><Link className="mono device-row-ip-link" to={detailURL(row)}>{ipv4}</Link><Typography.Text className="device-copy-control" copyable={{ text: ipv4 }} /></>}{row.ip_match && <span className="device-match-caption">{row.ip_match.is_recent_ip ? '最近 IP 命中' : '历史 IP 命中'}</span>}</div> } },
    { title: '终端名', key: 'name', width: 175, onCell: (row: DeviceInventoryListItem) => ({ className: deviceName(row) ? '' : 'mobile-empty-cell' }), render: (_, row) => { const name = deviceName(row); return name ? <><Link to={detailURL(row)} title={row.device_name?.status === 'historical' ? '历史观测名称' : name}>{name}</Link>{row.device_name?.status === 'historical' && <span className="device-name-caption">历史名称</span>}</> : null } },
    ...(showMac ? [{ title: 'MAC / IPv6', key: 'mac', width: 175, render: (_: unknown, row: DeviceInventoryListItem) => <>{row.primary_mac && <DeviceMAC device={row} href={detailURL(row)} />}{row.current_ip && !ipv4Address(row.current_ip) && <div className="device-row-ipv6"><span className="mono">{row.current_ip}</span></div>}</> }] : []),
    ...(showProfile && (visibleColumns.includes('recognition') || visibleColumns.includes('os')) ? [{ title: '类型与系统', key: 'profile', width: 205, render: (_: unknown, row: DeviceInventoryListItem) => <>{visibleColumns.includes('recognition') && <DeviceLedgerRecognition device={row} />}{visibleColumns.includes('os') && <DeviceLedgerOS device={row} />}</> }] : []),
    ...(showContext && visibleColumns.includes('context') ? [{ title: '账号与接入', key: 'access', width: 225, render: (_: unknown, row: DeviceInventoryListItem) => <OwnershipAccess device={row} /> }] : []),
    ...(visibleColumns.includes('observed') ? [{ title: '最近观测', key: 'observed', width: 105, render: (_: unknown, row: DeviceInventoryListItem) => <ObservedTime value={row.last_seen} /> }] : []),
    { title: '操作', key: 'action', width: 85, render: (_, row) => <Link to={detailURL(row)}>查看详情</Link> },
  ]
  const inlineBar = (
    <AppTableBar
      searchPlaceholder={searchPlaceholder}
      searchValue={searchInput}
      onSearchChange={setSearchInput}
      onSearch={()=>change({q:searchInput.trim()})}
      filters={<>
        {searchTypeControl}
        <Button size="small" onClick={()=>change({q:searchInput.trim()})}>查询</Button>
        <Button size="small" type="text" onClick={()=>setFiltersOpen(value=>!value)}>{filtersOpen?'收起筛选':'更多筛选'}{moreFilterCount?`（已启用 ${moreFilterCount} 项）`:''}</Button>
      </>}
      panel={filtersOpen?moreFilters:undefined}
      extra={timeControl}
    />
  )
  return <section className={embedded ? "device-inventory-page" : "page device-inventory-page"}>
    {!embedded&&<header className="device-page-header"><Typography.Title level={3}>终端列表</Typography.Title><div className="device-header-actions"><Link to="/devices?tab=network">网络设备</Link>{scopeControls}</div></header>}
    {inlineBar}
    {searchType==='account'&&<Typography.Text className="device-list-note" type="secondary">账号精确匹配最新观测候选，不代表在线或登记责任人；历史账号请进入详情溯源。</Typography.Text>}

    <section className="surface device-inventory-surface">
      <AppListHeader
        title="终端列表"
        count={total!==undefined?<Tooltip title={metadata.data?.as_of?`统计时间：${formatDateTime(metadata.data.as_of)}`:undefined}><span>{total} 个终端身份</span></Tooltip>:undefined}
        actions={<>
          {embedded&&scopeControls}
          <Tooltip title="近期观测不等于在线，终端身份数不等于物理终端数；账号和接入位置为观测关联。"><InfoCircleOutlined aria-label="列表说明"/></Tooltip>
          <Popover trigger="click" title="显示列" content={<Checkbox.Group value={visibleColumns} options={columnOptions} onChange={values=>{const next=values.map(String);setVisibleColumns(next);localStorage.setItem('device-ledger-columns',JSON.stringify(next))}}/>}><Button className="device-column-settings" icon={<SettingOutlined/>}>列设置</Button></Popover>
        </>}
      />
      <div className="device-list-freshness">
        {devices.dataUpdatedAt>0&&<Typography.Text type="secondary">列表刷新 {new Date(devices.dataUpdatedAt).toLocaleTimeString('zh-CN',{hour12:false})}</Typography.Text>}
        {devices.data?.as_of&&<Typography.Text type="secondary">画像更新时间 {shortTime(devices.data.as_of)}</Typography.Text>}
        {devices.data?.read_model_updating&&<Typography.Text className="device-read-model-state">画像摘要更新中</Typography.Text>}
        {metadata.isError&&<Typography.Text className="device-read-model-state">统计读取失败 <Button type="link" size="small" onClick={()=>void metadata.refresh()}>重试统计</Button></Typography.Text>}
      </div>
      {devices.isError&&devices.data&&<AppErrorAlert title="刷新失败，保留上次列表" message={devices.error.message}/>}
      {devices.data?.read_model_state&&!devices.data.read_model_state.complete&&<Alert type="info" showIcon title="历史关联正在回填" description="当前显示已生成的终端摘要；历史检索和关联统计尚不完整，更新延迟以处理状态为准。"/>}
      {devices.data?.read_model_state?.error&&<Alert type="warning" showIcon title="检索投影更新异常" description="保留上次已物化结果；关联变更可能尚未完成更新。"/>}
      {matchSearch&&<Typography.Paragraph className="device-list-note" type="secondary">精确 IP 匹配 · {view==='recent'?'所选时间内的观测与会话':'全部历史关联'}</Typography.Paragraph>}
      {isIPAddress(query) && pagination.page === 1 && !devices.isFetching && !devices.isError && items.length === 0 && <Alert type="info" showIcon title="当前检索条件下没有终端身份结果" description={canReadTraffic ? '下方按 IP 展示流量观测；握手 MAC 是终端候选线索，需结合身份与接入证据核实归属。' : '当前身份与地址索引中没有该 IP 的关联记录。'} />}
      {devices.isLoading ? <AppLoadingState rows={8} /> : devices.isError && !devices.data ? <AppErrorAlert title="终端列表读取失败" message={devices.error.message} /> : <>
        <AppTable rowKey="endpoint_id" columns={deviceColumns} dataSource={items} scroll={{ x: 145 + 175 + (showMac ? 175 : 0) + (showProfile ? 205 : 0) + (showContext ? 225 : 0) + 105 + 85 }} locale={{ emptyText: '没有匹配的终端' }} />
        {total!==undefined?<AppServerPagination cursorMode page={pagination.page} pageSize={pagination.pageSize} total={total} onChange={updatePagination}/>:<AppCursorPagination disabled={devices.isPlaceholderData} previous={pagination.page>1} next={Boolean(devices.data?.page.next_cursor)} label={`第 ${pagination.page} 页${metadata.isError?'':' · 总数统计中'}`} onPrevious={()=>updatePagination(pagination.page-1,pagination.pageSize)} onNext={()=>updatePagination(pagination.page+1,pagination.pageSize)} />}
      </>}
    </section>
    {isIPAddress(query) && pagination.page === 1 && !devices.isFetching && !devices.isError && items.length === 0 && canReadTraffic && <IpTrafficObservations key={query.trim()} ip={query.trim()} />}
    <details className="surface filter-disclosure device-diagnostics" onToggle={event=>setDiagnosticsOpen(event.currentTarget.open)}><summary>识别质量与接入诊断</summary>{diagnosticsOpen&&<div className="filter-disclosure-content recognition-summary-surface">
		{recognitionSummary.isLoading&&<AppLoadingState rows={3} />}
		{recognitionSummary.isError&&<AppErrorAlert title="识别诊断读取失败" message={recognitionSummary.error.message} />}
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
		{recognitionSummary.data.event_count > 0 && <>
			<div className="device-attribution-summary">
				<Typography.Text type="secondary">链路层归属（近 24 小时）</Typography.Text>
				<Typography.Text strong>{recognitionSummary.data.mac_attributed_event_count ?? 0} / {recognitionSummary.data.event_count} 事件带 MAC · {Math.round((recognitionSummary.data.mac_attribution_rate ?? 0) * 100)}%</Typography.Text>
			</div>
			{(recognitionSummary.data.observability?.length ?? 0) > 0 && <ul className="device-observability-list" aria-label="按来源可见性">
				{[...(recognitionSummary.data.observability ?? [])].sort((left,right)=>right.event_count-left.event_count).slice(0,12).map(item=><li key={item.source_event_type}>
					<Typography.Text className="device-observability-source">{item.source_event_type}</Typography.Text>
					<Typography.Text type="secondary">{item.event_count} 事件</Typography.Text>
					<Typography.Text strong={item.mac_attributed_count>0}>{item.mac_attributed_count} 带 MAC</Typography.Text>
				</li>)}
			</ul>}
			{(recognitionSummary.data.mac_attributed_event_count ?? 0) === 0 && <Alert showIcon type="warning" title="镜像事件尚未带链路层地址" description="Zeek 需要加载 mac-logging 才能给连接日志附加 MAC，按来源可见性可以看出是哪些日志缺少归属。" />}
		</>}
		{recognitionSummary.data.event_count > 0 && recognitionSummary.data.event_attribution_rate < 0.2 && <Alert showIcon type="warning" title={`最近 24 小时终端归属率 ${Math.round(recognitionSummary.data.event_attribution_rate * 100)}%，生态命中暂无法完整写入终端画像`} description={<Link to="/ingest">检查身份接入与标准事件 endpoint_id</Link>} />}
		</>}
	</div>}</details>
  </section>
}

function OwnershipAccess({ device }: { device: DeviceInventoryListItem }) {
  return <div className="device-context-cell">
    {device.current_account_conflict&&<div><Tag color="orange">关联账号冲突</Tag><Typography.Text className="brand-evidence-wrap">{(device.current_account_candidates??[]).join(' / ')}</Typography.Text></div>}
    {device.current_access_conflict&&<Tag color="orange">接入位置冲突</Tag>}
    {device.current_account?<div><Typography.Text type="secondary">关联账号</Typography.Text><Typography.Text className="brand-evidence-wrap">{device.current_account}</Typography.Text></div>:!device.current_account_conflict&&<div><Typography.Text type="secondary">关联账号</Typography.Text><span className="account-placeholder">无认证账号</span></div>}
    {(device.owner_name||device.owner_account)&&<div><Typography.Text type="secondary">登记归属</Typography.Text><Typography.Text className="brand-evidence-wrap">{[device.owner_name,device.owner_account].filter(Boolean).join(' · ')}</Typography.Text></div>}
    {device.current_access_id&&<div><Typography.Text type="secondary">接入位置</Typography.Text><Typography.Text className="brand-evidence-wrap" title={device.current_access_id}>{accessLocationLabel(device.current_access_id)}</Typography.Text></div>}
  </div>
}

function accessLocationLabel(value: string) {
  const fields = Object.fromEntries([...value.matchAll(/(?:^|;)(slot|subslot|port|vlanid)=([^;]+)/g)].map(([,key,item])=>[key,item]))
  if (fields.slot && fields.subslot && fields.port && fields.vlanid) return `端口 ${fields.slot}/${fields.subslot}/${fields.port} · VLAN ${fields.vlanid}`
  return value
}

function ipv4Address(value?: string) {
  if (!value) return ''
  const octets=value.split('.')
  return octets.length===4&&octets.every(part=>/^\d{1,3}$/.test(part)&&Number(part)<=255) ? value : ''
}

function ObservedTime({ value }: { value?: string }) {
  return <Typography.Text className="device-observed-time" title={value ? formatDateTime(value) : undefined}>{shortTime(value)}</Typography.Text>
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
