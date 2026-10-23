import { AppErrorAlert, AppListHeader, AppServerPagination, AppTable, AppTableBar, formatPercent } from '../../shared/ui'
import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Select, Spin, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { request } from '../../shared/api/client'
import type { components } from '../../shared/api/generated'

type Library = components['schemas']['AIRelayIndicatorLibrary']
type Indicator = Library['indicators'][number]
type Source = Library['sources'][number]

export function AIRelayIndicatorLibrary() {
  const query = useQuery({queryKey:['ai-relay','indicators'],queryFn:()=>request<Library>('/ai-relay/indicators')})
  const [search,setSearch]=useState('')
  const [category,setCategory]=useState('all')
  const [page,setPage]=useState(1)
  const [pageSize,setPageSize]=useState(20)
  const data=query.data
  const sources=useMemo(()=>new Map(data?.sources.map(source=>[source.id,source])??[]),[data])
  const indicators=useMemo(()=>data?.indicators.filter(item=>(category==='all'||item.category===category)&&`${item.domain} ${item.name??''} ${item.name_zh??''}`.toLowerCase().includes(search.trim().toLowerCase()))??[],[data,category,search])
  const pageCount=Math.max(1,Math.ceil(indicators.length/pageSize))
  const visiblePage=Math.min(page,pageCount)
  const visibleIndicators=indicators.slice((visiblePage-1)*pageSize,visiblePage*pageSize)
  const indicatorColumns: ColumnsType<Indicator> = [
    {title:'域名',dataIndex:'domain',width:190,render:(value:string)=><span className="ai-relay-domain">{value}</span>},
    {title:'名称',key:'name',width:200,render:(_,item)=><div className="ai-relay-library-names"><strong>{item.name_zh||item.name}</strong>{item.name_zh!==item.name&&item.name&&<span>{item.name}</span>}</div>},
    {title:'类别',key:'category',width:80,render:(_,item)=>item.category==='relay'?'中转站':'聚合站'},
    {title:'匹配方式',key:'match',width:110,render:(_,item)=>item.match_type==='subdomain'?'包含子域名':'仅精确域名'},
    {title:'置信度',key:'confidence',width:80,render:(_,item)=>formatPercent(item.confidence,0)},
    {title:'解析状态',key:'status',width:120,render:(_,item)=>item.status==='resolved'?'维护时可解析':'维护时未解析'},
    {title:'依据来源',key:'source',width:140,render:(_,item)=><IndicatorSource item={item} sources={sources}/>},
  ]
  if(query.isLoading) return <Spin />
  if(query.isError) return <AppErrorAlert title="中转站域名库读取失败" message={query.error.message} />
  return <div className="ai-relay-library">
    <Alert type="info" showIcon title="域名指标是访问线索，命中不等于模型调用。解析状态记录的是资产维护时的 DNS 核验结果，不代表当前可用性。" />
    <div className="ai-relay-library-meta"><Typography.Text strong>生效版本 {data?.version}</Typography.Text><span>更新日期 {data?.updated_at}</span><span>官方域名排除 {data?.official_domains.length??0} 条</span></div>
    <AppTableBar
      searchPlaceholder="搜索域名或名称"
      searchValue={search}
      onSearchChange={value=>{setSearch(value);setPage(1)}}
      filters={<Select aria-label="指标类别" value={category} onChange={value=>{setCategory(value);setPage(1)}} options={[{label:'全部类别',value:'all'},{label:'中转站',value:'relay'},{label:'聚合站',value:'aggregator'}]}/>}
    />
    <AppListHeader title="域名指标" count={`${indicators.length} 条`} />
    <div className="list-table-scroll"><AppTable rowKey={item=>`${item.match_type}:${item.domain}`} columns={indicatorColumns} dataSource={visibleIndicators} tableLayout="fixed" scroll={{x:920}} locale={{emptyText:'没有符合筛选条件的域名'}} /></div>
    <AppServerPagination page={visiblePage} pageSize={pageSize} total={indicators.length} onChange={(next,size)=>{setPage(next);setPageSize(size)}} totalText={`共 ${indicators.length} 条`} />
    <details className="ai-relay-library-official"><summary>官方域名排除规则（{data?.official_domains.length??0} 条）</summary><div>{data?.official_domains.map(domain=><span key={domain} className="ai-relay-domain">{domain}</span>)}</div></details>
  </div>
}

function IndicatorSource({item,sources}:{item:Indicator;sources:Map<string,Source>}) {
  const source=sources.get(item.source)
  if(!source) return null
  return <span>{source.name}{source.version?` · ${source.version}`:''}</span>
}
