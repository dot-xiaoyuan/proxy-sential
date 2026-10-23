import { statusText } from '../shared/ui/status'
import { detailPath } from '../app/navigation'
import { useUrlState } from '../shared/ui/useUrlState'
import { Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Link,useLocation } from 'react-router-dom'

import { useAuditLogs } from '../shared/api/queries'
import type { AuditLog } from '../shared/api/types'
import { AppErrorAlert, AppListHeader, AppLoadingState, AppServerPagination, AppTable, AppTableBar, formatDateTime, useServerPagination } from '../shared/ui'

export function AuditPage() {
	const pagination=useServerPagination()
  const location=useLocation();const [query,setQuery]=useUrlState('q','');
  const logs=useAuditLogs({limit:pagination.pageSize,cursor:pagination.cursor,q:query})
  if(logs.isLoading)return <AppLoadingState rows={8}/>
  const columns:ColumnsType<AuditLog>=[
    {title:'时间',dataIndex:'created_at',width:180,render:(value:string)=>formatDateTime(value)},
    {title:'操作者',dataIndex:'actor',width:160,render:(value:string)=><Typography.Text className="list-cell-nowrap" title={value}>{value}</Typography.Text>},
    {title:'动作',dataIndex:'action',width:180,render:(value:string)=><Tag color="purple">{value}</Tag>},
    {title:'目标',dataIndex:'target',render:(value:string,row)=><Link className="mono list-cell-nowrap" title={value} to={detailPath(`/audit/${encodeURIComponent(row.audit_id)}`,location.pathname+location.search)}>{value}</Link>},
    {title:'结果',dataIndex:'outcome',width:200,render:(value:string)=><Typography.Text className="list-cell-nowrap" title={value}>{statusText(value)}</Typography.Text>},
  ]
  return <main className="page">{logs.isError&&<AppErrorAlert title="审计日志读取失败" message={logs.error.message}/>}<AppTableBar onClearFilters={()=>setQuery('')} onSearchChange={setQuery} searchPlaceholder="搜索操作者、动作、目标或结果" searchValue={query}/><section className="surface"><AppListHeader title="审计日志" count={`${logs.data?.page.total ?? 0} 条`} /><AppTable className="compact-list-table" columns={columns} dataSource={logs.data?.logs??[]} pagination={false} rowKey="audit_id" scroll={{x:900}} size="small"/><AppServerPagination page={pagination.page} pageSize={pagination.pageSize} total={logs.data?.page.total??0} onChange={pagination.update}/></section></main>
}
