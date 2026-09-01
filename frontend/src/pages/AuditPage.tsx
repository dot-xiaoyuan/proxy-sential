import { useEffect, useState } from 'react'
import { Pagination, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Link } from 'react-router-dom'

import { useAuditLogs } from '../shared/api/queries'
import type { AuditLog } from '../shared/api/types'
import { AppErrorAlert, AppLoadingState, AppPageHeader, AppTableBar } from '../shared/ui'

export function AuditPage() {
  const [page,setPage]=useState(1); const [pageSize,setPageSize]=useState(20)
  const [searchInput,setSearchInput]=useState(''); const [query,setQuery]=useState('')
  useEffect(()=>{const timer=globalThis.setTimeout(()=>{setQuery(searchInput.trim());setPage(1)},300);return()=>globalThis.clearTimeout(timer)},[searchInput])
  const logs=useAuditLogs({limit:pageSize,cursor:String((page-1)*pageSize),q:query})
  if(logs.isLoading)return <AppLoadingState rows={8}/>
  const columns:ColumnsType<AuditLog>=[
    {title:'时间',dataIndex:'created_at',width:180,render:(value:string)=>new Date(value).toLocaleString()},
    {title:'操作者',dataIndex:'actor',width:160,render:(value:string)=><Typography.Text className="list-cell-nowrap" title={value}>{value}</Typography.Text>},
    {title:'动作',dataIndex:'action',width:180,render:(value:string)=><Tag color="purple">{value}</Tag>},
    {title:'目标',dataIndex:'target',render:(value:string,row)=><Link className="mono list-cell-nowrap" title={value} to={`/audit/${encodeURIComponent(row.audit_id)}`}>{value}</Link>},
    {title:'结果',dataIndex:'outcome',width:200,render:(value:string)=><Typography.Text className="list-cell-nowrap" title={value}>{value}</Typography.Text>},
  ]
  return <main className="page"><AppPageHeader title="系统操作与策略审计日志" subtitle="单行展示操作轨迹，点击目标查看完整审计记录。" loading={logs.isFetching} onRefresh={()=>void logs.refetch()}/>{logs.isError&&<AppErrorAlert title="审计日志加载失败" message={logs.error.message}/>}<AppTableBar onClearFilters={()=>setSearchInput('')} onSearchChange={setSearchInput} searchPlaceholder="搜索操作者、动作、目标或结果" searchValue={searchInput} totalCount={logs.data?.page.total??0}/><section className="surface"><Table className="compact-list-table" columns={columns} dataSource={logs.data?.logs??[]} pagination={false} rowKey="audit_id" scroll={{x:900}} size="small"/><Pagination className="list-pagination" current={page} pageSize={pageSize} total={logs.data?.page.total??0} showSizeChanger pageSizeOptions={[20,50]} onChange={(next,size)=>{setPageSize(size);setPage(next)}}/></section></main>
}
