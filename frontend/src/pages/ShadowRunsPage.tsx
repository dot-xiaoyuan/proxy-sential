import { Alert, Skeleton, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import { useShadowRuns } from '../shared/api/queries'
import type { ShadowRun } from '../shared/api/types'

const columns: ColumnsType<ShadowRun> = [
  { title: 'Run ID', dataIndex: 'run_id', render: (value: string) => <span className="mono">{value}</span> },
  { title: 'Sensor', dataIndex: 'sensor_id', width: 140 },
  { title: 'Started', dataIndex: 'started_at', width: 190, render: (value: string) => new Date(value).toLocaleString() },
  { title: 'Offset', width: 210, render: (_, run) => `${run.previous_offset} -> ${run.new_offset}` },
  { title: 'Read', dataIndex: ['normalized', 'read'], width: 100 },
  { title: 'Emitted', dataIndex: ['normalized', 'emitted'], width: 100 },
  { title: 'Evidence', dataIndex: 'evidence_count', width: 100 },
  { title: 'Risk list', dataIndex: 'risk_list_count', width: 100 },
  {
    title: '状态',
    dataIndex: 'truncated',
    width: 110,
    render: (truncated: boolean) => (truncated ? <Tag color="gold">truncated</Tag> : <Tag color="green">ok</Tag>),
  },
]

export function ShadowRunsPage() {
  const runs = useShadowRuns()

  if (runs.isLoading) {
    return <Skeleton active />
  }

  return (
    <main className="page">
      <div className="page-header">
        <div>
          <Typography.Title className="page-title" level={3}>
            影子运行
          </Typography.Title>
          <Typography.Text type="secondary">展示 shadow run 产物摘要，不绑定本地文件路径。</Typography.Text>
        </div>
      </div>
      {runs.isError && <Alert showIcon title="影子运行加载失败" type="error" />}
      <section className="surface">
        <Table columns={columns} dataSource={runs.data?.runs ?? []} rowKey="run_id" scroll={{ x: 1080 }} />
      </section>
    </main>
  )
}
