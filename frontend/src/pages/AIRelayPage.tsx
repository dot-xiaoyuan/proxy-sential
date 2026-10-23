import { useMemo, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Button, Input, Select, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { AppListHeader, AppListSection, AppServerPagination, AppTable, AppTableBar, formatDateTime, useMediaQuery } from '../shared/ui'
import { useAIRelayUsages } from '../shared/api/queries'
import { api } from '../shared/api/client'
import type { AIRelayUsageQuery } from '../shared/api/types'
import { detailPath } from '../app/navigation'

const ranges = [{label:'近 1 小时',value:'1h',hours:1},{label:'近 24 小时',value:'24h',hours:24},{label:'近 7 天',value:'7d',hours:168}]
const sourceLabel: Record<string,string> = {dns:'DNS 查询',tls:'TLS SNI',quic:'QUIC SNI',http:'HTTP Host',handshake_tls:'TLS SNI 汇总观测',handshake_http:'HTTP Host 汇总观测'}
const time = formatDateTime

type Usage = NonNullable<ReturnType<typeof useAIRelayUsages>['data']>['items'][number]

function domainSummary(item: Usage) {
  return <div className="ai-relay-domain-summary">{item.domains.map(value => <Tag key={value}>{item.domain_names[value] || value}</Tag>)}</div>
}

function RelayDetail({ item, location }: { item: Usage; location: { pathname: string; search: string } }) {
  const sources = [...new Set(item.events.map(event => event.source))]
  const sensors = [...new Set(item.events.map(event => event.sensor_id).filter(Boolean))]
  return <aside className="ai-relay-detail" aria-label="中转站访问详情">
    <div className="ai-relay-detail-head">
      <div><strong className="mono">{item.ip}</strong><span>{item.account_id ? `最近观测账号 ${item.account_id}` : '无认证账号'}</span></div>
      <Tag>{item.event_count} 条记录</Tag>
    </div>
    <dl className="ai-relay-detail-facts">
      <div><dt>首次观测</dt><dd>{time(item.first_seen)}</dd></div>
      <div><dt>最近观测</dt><dd>{time(item.last_seen)}</dd></div>
      {sources.length > 0 && <div><dt>证据来源</dt><dd className="ai-relay-detail-tags">{sources.map(source => <Tag key={source}>{sourceLabel[source] ?? source}</Tag>)}</dd></div>}
      {sensors.length > 0 && <div><dt>采集节点</dt><dd>{sensors.join('、')}</dd></div>}
    </dl>
    <section className="ai-relay-detail-section">
      <h5>命中域名</h5>
      <div className="ai-relay-detail-domains">{item.domains.map(value => <div className="ai-relay-detail-domain" key={value}><strong>{item.domain_names[value] || value}</strong>{item.domain_names[value] && <span className="ai-relay-domain">{value}</span>}</div>)}</div>
    </section>
    {item.events.length > 0 && <section className="ai-relay-detail-section">
      <h5>事件明细</h5>
      <div className="ai-relay-detail-events">{item.events.map(event => <div className="ai-relay-detail-event" key={`${event.sensor_id}:${event.event_id}`}>
        <span>{time(event.timestamp)}</span>
        <span className="ai-relay-domain">{event.domain}</span>
        <span>{sourceLabel[event.source] ?? event.source}</span>
        <span>{event.sensor_id}</span>
        <Link to={detailPath(`/events/${encodeURIComponent(event.event_id)}`, location.pathname + location.search)}>查看事件</Link>
      </div>)}</div>
    </section>}
  </aside>
}

export function AIRelayPage() {
  const location=useLocation()
  const wide=useMediaQuery('(min-width: 1800px)')
  const [range,setRange]=useState('7d')
  const [anchor,setAnchor]=useState(()=>Date.now())
  const [ip,setIP]=useState('')
  const [domain,setDomain]=useState('')
  const [campus,setCampus]=useState('')
  const [sensor,setSensor]=useState('')
  const [selectedIP,setSelectedIP]=useState('')
  const [cursors,setCursors]=useState<string[]>([])
  const [pageSize,setPageSize]=useState(20)
  const [jumping,setJumping]=useState(false)
  const [moreOpen,setMoreOpen]=useState(false)
  const reset=()=>{setCursors([]);setSelectedIP('')}
  const hours=ranges.find(item=>item.value===range)?.hours??168
  const query:AIRelayUsageQuery=useMemo(()=>({from:new Date(anchor-hours*3600000).toISOString(),to:new Date(anchor).toISOString(),ip:ip.trim()||undefined,domain:domain.trim()||undefined,campus_id:campus.trim()||undefined,sensor_id:sensor.trim()||undefined,limit:pageSize,cursor:cursors.at(-1)}),[anchor,hours,ip,domain,campus,sensor,cursors])
  const result=useAIRelayUsages(query)
  const items=result.data?.items??[]
  const total=result.data?.page.total??items.length
  const page=cursors.length+1
  const activeItem=items.find(item=>item.ip===selectedIP)??items[0]
  const changePage=async(next:number,size:number)=>{
    if(size!==pageSize){setPageSize(size);setCursors([]);return}
    if(next===page)return
    if(next<page){setCursors(current=>current.slice(0,Math.max(0,next-1)));return}
    const nextCursor=result.data?.page.next_cursor
    if(next===page+1){if(nextCursor)setCursors(current=>[...current,nextCursor]);return}
    setJumping(true)
    try{
      const stack=[...cursors]
      let cursor=stack.at(-1)
      for(let current=page;current<next;current++){
        const pageData=await api.aiRelayUsages({...query,cursor})
        const value=pageData.page.next_cursor
        if(!value)break
        stack.push(value);cursor=value
      }
      setCursors(stack)
    }catch{/* 保留当前页 */}finally{setJumping(false)}
  }
  const narrowColumns: ColumnsType<Usage> = [
    { title: '源 IP', key: 'ip', width: 170, render: (_, item) => <span className="ai-relay-ip mono">{item.ip}</span> },
    { title: '观测记录', dataIndex: 'event_count', width: 100 },
    { title: '首次观测', dataIndex: 'first_seen', width: 170, render: (value: string) => time(value) },
    { title: '最近观测', dataIndex: 'last_seen', width: 170, render: (value: string) => time(value) },
    { title: '最近观测账号', dataIndex: 'account_id', width: 170 },
    { title: '命中域名', key: 'domains', render: (_, item) => domainSummary(item) },
  ]
  const wideColumns: ColumnsType<Usage> = [
    { title: '源 IP', key: 'ip', width: 180, render: (_, item) => <span className="ai-relay-ip mono">{item.ip}</span> },
    { title: '观测记录', dataIndex: 'event_count', width: 100 },
    { title: '最近观测账号', dataIndex: 'account_id', width: 190, render: (value?: string) => value || <span className="account-placeholder">无认证账号</span> },
    { title: '命中域名', key: 'domains', render: (_, item) => domainSummary(item) },
    { title: '最近观测', dataIndex: 'last_seen', width: 180, render: (value: string) => time(value) },
  ]
  return <main className="page ai-relay-page">
    <p className="ai-relay-note">按域名访问记录汇总，含握手 SNI 和 Host；记录数不代表请求数，也不能证明发生了模型调用。<Link to="/settings/rules?tab=ai-relay">查看域名库</Link></p>
    <AppTableBar
      searchPlaceholder="搜索中转站域名"
      searchValue={domain}
      onSearchChange={value=>{setDomain(value);reset()}}
      filters={<>
        <Select aria-label="时间范围" value={range} options={ranges.map(({label,value})=>({label,value}))} onChange={value=>{setRange(value);setAnchor(Date.now());reset()}} />
        <Button size="small" type="text" onClick={()=>setMoreOpen(value=>!value)}>{moreOpen?'收起筛选':'更多筛选'}{[ip,campus,sensor].filter(value=>value.trim()).length?`（${[ip,campus,sensor].filter(value=>value.trim()).length}）`:''}</Button>
      </>}
      panel={moreOpen?<div className="app-filter-panel">
        <Input aria-label="源 IP" placeholder="源 IP" allowClear value={ip} onChange={event=>{setIP(event.target.value);reset()}} />
        <Input aria-label="校区 ID" placeholder="校区 ID" allowClear value={campus} onChange={event=>{setCampus(event.target.value);reset()}} />
        <Input aria-label="传感器 ID" placeholder="传感器 ID" allowClear value={sensor} onChange={event=>{setSensor(event.target.value);reset()}} />
      </div>:undefined}
    />
    <section className="surface">
      <AppListHeader title="中转站访问" count={`${total} 个源 IP`} description={result.data?.indicator_version ? `指标版本 ${result.data.indicator_version}` : undefined} />
      <AppListSection
        isError={result.isError}
        errorTitle="中转站访问记录读取失败"
        errorMessage={result.isError ? result.error.message : undefined}
        isLoading={result.isLoading}
        loadingRows={5}
        isEmpty={!items.length}
        emptyText="所选时间和条件下暂无中转站域名访问记录"
      >
        <div className={wide ? 'ai-relay-wide-layout' : undefined}>
          <div className="ai-relay-table-wrap">
            <AppTable
              rowKey="ip"
              columns={wide ? wideColumns : narrowColumns}
              dataSource={items}
              scroll={wide ? undefined : { x: 1000 }}
              rowClassName={wide ? item => item.ip === activeItem?.ip ? 'ai-relay-row-active' : '' : undefined}
              onRow={wide ? item => ({ onClick: () => setSelectedIP(item.ip) }) : undefined}
              expandable={wide ? undefined : { expandedRowRender: item => <div className="ai-relay-expanded">
                <div className="ai-relay-summary">{item.account_id && <span>最近观测账号：{item.account_id}</span>}<span>观测记录 {item.event_count} 条</span></div>
                <div className="ai-relay-domains"><Typography.Text strong>中转站</Typography.Text>{item.domains.map(value => <span key={value} className="ai-relay-domain-entry"><strong>{item.domain_names[value] || value}</strong>{item.domain_names[value] && <span className="ai-relay-domain">{value}</span>}</span>)}</div>
                {!!item.events.length && <div className="ai-relay-events">{item.events.map(event => <div key={`${event.sensor_id}:${event.event_id}`} className="ai-relay-event"><span>{time(event.timestamp)}</span><span className="ai-relay-domain">{event.domain}</span><span>{sourceLabel[event.source] ?? event.source}</span><Link to={detailPath(`/events/${encodeURIComponent(event.event_id)}`, location.pathname + location.search)}>查看事件</Link></div>)}</div>}
              </div> }}
            />
          </div>
          {wide && activeItem && <RelayDetail item={activeItem} location={location}/>}
        </div>
      </AppListSection>
      <AppServerPagination
        cursorMode
        disabled={result.isFetching||jumping}
        page={page}
        pageSize={pageSize}
        total={total}
        totalText={`共 ${total} 条`}
        onChange={changePage}
      />
    </section>
  </main>
}
