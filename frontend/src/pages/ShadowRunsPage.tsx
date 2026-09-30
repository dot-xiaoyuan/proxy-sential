import { ShadowEvaluationPanel } from './ShadowEvaluationPanel'
import { detailPath } from '../app/navigation'
import { statusText } from '../shared/ui/status'
import { Alert, Skeleton, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Link,useLocation } from 'react-router-dom'

import { useShadowRuns } from '../shared/api/queries'
import type { ShadowRun } from '../shared/api/types'
import { AppPageHeader, AppServerPagination, useServerPagination } from '../shared/ui'

export function ShadowRunsPage() {
	const pagination = useServerPagination()
  const runs = useShadowRuns({limit:pagination.pageSize,cursor:pagination.cursor})
  const location=useLocation()
  if (runs.isLoading) return <Skeleton active />
  const columns:ColumnsType<ShadowRun> = [
    {title:'运行 ID',dataIndex:'run_id',width:250,render:(value:string)=><Link className="mono list-cell-nowrap" title={value} to={detailPath(`/shadow-runs/${encodeURIComponent(value)}`,location.pathname+location.search)}>{value}</Link>},
    {title:'Sensor',dataIndex:'sensor_id',width:150,render:(value:string)=><Typography.Text className="list-cell-nowrap" title={value}>{value}</Typography.Text>},
    {title:'开始时间',dataIndex:'started_at',width:180,render:(value:string)=>new Date(value).toLocaleString()},
    {title:'标准化',key:'normalized',width:220,render:(_,run)=>`${run.normalized.read} 读取 · ${run.normalized.emitted} 产出 · ${run.normalized.malformed} 异常`},
    {title:'证据 / 风险',key:'result',width:150,render:(_,run)=>`${run.evidence_count} / ${run.risk_count}`},
    {title:'Zeek',dataIndex:'zeek_status',width:110,render:(value?:string)=><Tag color={value==='ok'?'green':value?'gold':'default'}>{statusText(value)}</Tag>},
    {title:'状态',dataIndex:'truncated',width:100,render:(value:boolean)=><Tag color={value?'gold':'green'}>{value?'截断':'完成'}</Tag>},
  ]
  return <main className="page"><AppPageHeader title="影子评估" subtitle="依据历史运行与人工真值检查复核覆盖和准入条件。" loading={runs.isFetching} onRefresh={()=>{void runs.refetch();}} />{runs.isError&&<Alert showIcon type="error" title="影子运行加载失败" />}<section className="surface"><ShadowEvaluationPanel/></section><details className="surface" open><summary>运行记录</summary><Table className="compact-list-table" columns={columns} dataSource={runs.data?.runs??[]} pagination={false} rowKey="run_id" scroll={{x:1160}} size="small"/><AppServerPagination page={pagination.page} pageSize={pagination.pageSize} total={runs.data?.page.total??0} onChange={pagination.update} /></details></main>
}
