import { CheckCircleOutlined, ClockCircleOutlined, FileSearchOutlined, WarningOutlined } from '@ant-design/icons'
import { Alert, Skeleton, Table, Tag } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import { useShadowEvaluation, useShadowRuns } from '../shared/api/queries'
import type { ShadowRun } from '../shared/api/types'
import { AppMetricCard, AppPageHeader } from '../shared/ui'

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
  const evaluation = useShadowEvaluation()

  if (runs.isLoading || evaluation.isLoading) {
    return <Skeleton active />
  }

  const report = evaluation.data
  const coverage = report ? Math.round(report.review_coverage * 1000) / 10 : 0

  return (
    <main className="page">
      <AppPageHeader
        loading={runs.isFetching || evaluation.isFetching}
        onRefresh={() => {
          void runs.refetch()
          void evaluation.refetch()
        }}
        subtitle="展示运行摘要、连续观测天数与人工复核验收进度。"
        title="影子运行"
      />
      {runs.isError && <Alert showIcon title="影子运行加载失败" type="error" />}
      {evaluation.isError && <Alert showIcon title="影子评估报告尚不可用" type="warning" />}
      {report && (
        <>
          <section className="metric-grid shadow-evaluation-metrics">
            <AppMetricCard icon={<ClockCircleOutlined />} statusColor={report.longest_continuous_days >= report.required_days ? 'green' : 'orange'} statusText={`要求 ${report.required_days} 天`} title="连续运行" unit="天" value={report.longest_continuous_days} />
            <AppMetricCard icon={<CheckCircleOutlined />} title="已复核天数" unit="天" value={report.days_with_reviews} />
            <AppMetricCard icon={<FileSearchOutlined />} title="去重评估样本" value={report.evaluated_sample_count} />
            <AppMetricCard icon={<WarningOutlined />} statusColor={report.ready ? 'green' : 'orange'} statusText={report.ready ? '验收通过' : '待人工复核'} title="复核覆盖率" unit="%" value={coverage} />
          </section>
          <Alert
            className="shadow-evaluation-alert"
            description={report.ready ? '连续运行、人工复核覆盖和采集质量均已达到验收要求。' : (
              <ul className="shadow-evaluation-blockers">
                {report.blockers.map((blocker) => <li key={blocker}>{blocker}</li>)}
              </ul>
            )}
            showIcon
            title={report.ready ? '影子评估已通过' : `影子评估待完成（缺失 ${report.missing_review_buckets.length} 个日期/等级分桶）`}
            type={report.ready ? 'success' : 'warning'}
          />
        </>
      )}
      <section className="surface">
        <Table columns={columns} dataSource={runs.data?.runs ?? []} rowKey="run_id" scroll={{ x: 1360 }} />
      </section>
    </main>
  )
}
