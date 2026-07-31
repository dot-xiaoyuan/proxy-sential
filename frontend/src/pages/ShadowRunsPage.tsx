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
  {
    title: 'Device',
    width: 100,
    render: (_, run) => <Tag color={normalizedTypeCount(run.normalized, 'device') > 0 ? 'blue' : 'default'}>{normalizedTypeCount(run.normalized, 'device')}</Tag>,
  },
  {
    title: 'Zeek DHCP',
    width: 120,
    render: (_, run) => <Tag color={normalizedTypeCount(run.zeek_normalized, 'device') > 0 ? 'green' : 'default'}>{normalizedTypeCount(run.zeek_normalized, 'device')}</Tag>,
  },
  {
    title: 'Zeek 状态',
    width: 130,
    render: (_, run) => <Tag color={zeekStatusColor(run.zeek_status)}>{zeekStatusText(run.zeek_status)}</Tag>,
  },
  {
    title: 'Zeek Offset',
    width: 210,
    render: (_, run) => `${run.zeek_previous_offset ?? 0} -> ${run.zeek_new_offset ?? 0}`,
  },
  { title: 'Evidence', dataIndex: 'evidence_count', width: 100 },
  { title: 'Risk list', dataIndex: 'risk_list_count', width: 100 },
  {
    title: '状态',
    dataIndex: 'truncated',
    width: 110,
    render: (truncated: boolean) => (truncated ? <Tag color="gold">truncated</Tag> : <Tag color="green">ok</Tag>),
  },
]

function normalizedTypeCount(value: ShadowRun['normalized'] | ShadowRun['zeek_normalized'], eventType: string) {
  const byType = value && typeof value === 'object' && 'by_type' in value ? value.by_type : undefined
  if (!byType) {
    return 0
  }
  return byType[eventType] ?? 0
}

function zeekStatusText(status?: string) {
  switch (status) {
    case 'ok':
      return '正常'
    case 'no_dhcp_events':
      return '无 DHCP'
    case 'unavailable':
      return '不可用'
    case 'log_truncated':
      return '轮转'
    default:
      return '未启用'
  }
}

function zeekStatusColor(status?: string) {
  switch (status) {
    case 'ok':
      return 'green'
    case 'no_dhcp_events':
      return 'blue'
    case 'unavailable':
    case 'log_truncated':
      return 'gold'
    default:
      return 'default'
  }
}

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
        <Table columns={columns} dataSource={runs.data?.runs ?? []} rowKey="run_id" scroll={{ x: 1360 }} />
      </section>
    </main>
  )
}
