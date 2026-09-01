import { useState } from 'react'
import { Alert, Pagination, Skeleton, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Link } from 'react-router-dom'

import { useShadowEvaluation, useShadowRuns } from '../shared/api/queries'
import type { ShadowRun } from '../shared/api/types'
import { AppPageHeader } from '../shared/ui'

export function ShadowRunsPage() {
  const [page,setPage] = useState(1)
  const [pageSize,setPageSize] = useState(20)
  const runs = useShadowRuns({limit:pageSize,cursor:String((page-1)*pageSize)})
  const evaluation = useShadowEvaluation()
  if (runs.isLoading) return <Skeleton active />
  const columns:ColumnsType<ShadowRun> = [
    {title:'运行 ID',dataIndex:'run_id',width:250,render:(value:string)=><Link className="mono list-cell-nowrap" title={value} to={`/shadow-runs/${encodeURIComponent(value)}`}>{value}</Link>},
    {title:'Sensor',dataIndex:'sensor_id',width:150,render:(value:string)=><Typography.Text className="list-cell-nowrap" title={value}>{value}</Typography.Text>},
    {title:'开始时间',dataIndex:'started_at',width:180,render:(value:string)=>new Date(value).toLocaleString()},
    {title:'标准化',key:'normalized',width:220,render:(_,run)=>`${run.normalized.read} 读取 · ${run.normalized.emitted} 产出 · ${run.normalized.malformed} 异常`},
    {title:'证据 / 风险',key:'result',width:150,render:(_,run)=>`${run.evidence_count} / ${run.risk_count}`},
    {title:'Zeek',dataIndex:'zeek_status',width:110,render:(value?:string)=><Tag color={value==='ok'?'green':value?'gold':'default'}>{value || '未启用'}</Tag>},
    {title:'状态',dataIndex:'truncated',width:100,render:(value:boolean)=><Tag color={value?'gold':'green'}>{value?'截断':'完成'}</Tag>},
  ]
  return <main className="page"><AppPageHeader title="影子运行" subtitle="单行展示运行结果，点击运行 ID 查看完整采集计数。" loading={runs.isFetching || evaluation.isFetching} onRefresh={()=>{void runs.refetch();void evaluation.refetch()}} />{runs.isError&&<Alert showIcon type="error" title="影子运行加载失败" />}{evaluation.isError&&<Alert showIcon type="warning" title="影子评估报告尚不可用" />}<section className="surface"><Table className="compact-list-table" columns={columns} dataSource={runs.data?.runs??[]} pagination={false} rowKey="run_id" scroll={{x:1160}} size="small"/><Pagination className="list-pagination" current={page} pageSize={pageSize} total={runs.data?.page.total??0} showSizeChanger pageSizeOptions={[20,50]} onChange={(next,size)=>{setPageSize(size);setPage(next)}} /></section></main>
}
