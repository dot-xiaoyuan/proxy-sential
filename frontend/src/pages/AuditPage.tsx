import { statusText } from '../shared/ui/status'
import { detailPath } from '../app/navigation'
import { useUrlState } from '../shared/ui/useUrlState'
import { Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Link,useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'

import { request } from '../shared/api/client'
import type { AuditLog } from '../shared/api/types'
import { AppErrorAlert, AppListHeader, AppLoadingState, AppTable, AppTableBar, formatDateTime } from '../shared/ui'
import { RecordCursorPagination, useRecordCursorPagination } from '../shared/ui/RecordCursorPagination'

export function AuditPage() {
  const location=useLocation();const [query,setQuery]=useUrlState('q','');
  const pagination=useRecordCursorPagination(`audit:${query}`)
  const params=new URLSearchParams({seek:'1',limit:String(pagination.pageSize)})
  if(query)params.set('q',query)
  if(pagination.cursor)params.set('cursor',pagination.cursor)
  const logs=useQuery({queryKey:['audit-logs','seek',params.toString()],queryFn:()=>request<{logs:AuditLog[];next_cursor?:string;has_more?:boolean;page?:{next_cursor:string|null}}>(`/audit-logs?${params}`)})
  const nextCursor=logs.data?.next_cursor??logs.data?.page?.next_cursor??''
  if(logs.isLoading)return <AppLoadingState rows={8}/>
  const columns:ColumnsType<AuditLog>=[
    {title:'时间',dataIndex:'created_at',width:180,render:(value:string)=>formatDateTime(value)},
    {title:'操作者',dataIndex:'actor',width:160,render:(value:string)=><Typography.Text className="list-cell-nowrap" title={value}>{value}</Typography.Text>},
    {title:'动作',dataIndex:'action',width:180,render:(value:string)=><Tag color="purple">{value}</Tag>},
    {title:'目标',dataIndex:'target',render:(value:string,row)=><Link className="mono list-cell-nowrap" title={value} to={detailPath(`/audit/${encodeURIComponent(row.audit_id)}`,location.pathname+location.search)}>{value}</Link>},
    {title:'结果',dataIndex:'outcome',width:200,render:(value:string)=><Typography.Text className="list-cell-nowrap" title={value}>{statusText(value)}</Typography.Text>},
  ]
  return <main className="page">{logs.isError&&<AppErrorAlert title="审计日志读取失败" message={logs.error.message}/>}<AppTableBar onClearFilters={()=>setQuery('')} onSearchChange={setQuery} searchPlaceholder="搜索操作者、动作、目标或结果" searchValue={query}/><section className="surface"><AppListHeader title="审计日志" count={`${logs.data?.logs.length ?? 0} 条`} /><AppTable className="compact-list-table" columns={columns} dataSource={logs.data?.logs??[]} pagination={false} rowKey="audit_id" scroll={{x:900}} size="small"/><RecordCursorPagination page={pagination.page} pageSize={pagination.pageSize} count={logs.data?.logs.length??0} nextCursor={nextCursor} fetching={logs.isFetching} onNext={()=>pagination.next(nextCursor)} onPrevious={pagination.previous} onPageSizeChange={pagination.changePageSize}/></section></main>
}
