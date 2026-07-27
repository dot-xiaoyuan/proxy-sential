import { Alert, Card, Col, Descriptions, Row, Skeleton, Space, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import {
  useEvents,
  useIngestDiagnostics,
  useIngestEventTypes,
  useIngestErrors,
  useIngestStatus,
} from '../shared/api/queries'
import type { IngestDiagnostic, NormalizedEventSummary } from '../shared/api/types'

const diagnosticColumns: ColumnsType<IngestDiagnostic> = [
  {
    title: '时间',
    dataIndex: 'timestamp',
    width: 190,
    render: (value: string) => new Date(value).toLocaleString(),
  },
  { title: '阶段', dataIndex: 'stage', width: 110 },
  { title: '类型', dataIndex: 'type', width: 150 },
  {
    title: '级别',
    dataIndex: 'severity',
    width: 110,
    render: (value: IngestDiagnostic['severity']) => {
      const color = value === 'error' ? 'red' : value === 'warning' ? 'gold' : 'green'
      return <Tag color={color}>{value}</Tag>
    },
  },
  {
    title: '说明',
    dataIndex: 'summary',
    render: (value: string) => <Typography.Text className="wrap-text">{value}</Typography.Text>,
  },
  {
    title: '计数',
    dataIndex: 'counters',
    width: 260,
    render: (value: Record<string, number> | undefined) => (
      <Typography.Text className="mono wrap-text">{JSON.stringify(value ?? {})}</Typography.Text>
    ),
  },
]

const eventColumns: ColumnsType<NormalizedEventSummary> = [
  { title: 'Event ID', dataIndex: 'event_id', width: 220, render: (value: string) => <span className="mono">{value}</span> },
  { title: '类型', dataIndex: 'type', width: 90 },
  { title: '时间', dataIndex: 'timestamp', width: 190, render: (value: string) => new Date(value).toLocaleString() },
  {
    title: 'Subject',
    dataIndex: 'subject',
    width: 190,
    render: (value: Record<string, unknown>) => <Typography.Text className="mono wrap-text">{JSON.stringify(value)}</Typography.Text>,
  },
  {
    title: 'Flow/Payload',
    render: (_, event) => (
      <Typography.Text className="mono wrap-text">
        {JSON.stringify({ flow: event.flow, payload: event.payload })}
      </Typography.Text>
    ),
  },
]

export function IngestPage() {
  const status = useIngestStatus()
  const eventTypes = useIngestEventTypes()
  const diagnostics = useIngestDiagnostics(50)
  const errors = useIngestErrors(50)
  const events = useEvents({ limit: 20 })

  if (status.isLoading) {
    return <Skeleton active />
  }

  if (status.isError || !status.data) {
    return <Alert showIcon title="采集诊断加载失败" type="error" />
  }

  const severityType = status.data.severity === 'error' ? 'error' : status.data.severity === 'warning' ? 'warning' : 'success'

  return (
    <main className="page">
      <div className="page-header">
        <div>
          <Typography.Title className="page-title" level={3}>
            采集诊断
          </Typography.Title>
          <Typography.Text type="secondary">
            面向生产的采集、解析和标准化健康度视图，不展示 Suricata 原始 EVE 明细。
          </Typography.Text>
        </div>
      </div>

      <Alert showIcon message={status.data.summary} type={severityType} />

      <section className="metric-grid">
        <Card className="metric-card">
          <Typography.Text type="secondary">读取</Typography.Text>
          <Typography.Title level={3}>{status.data.last_counters.read ?? 0}</Typography.Title>
        </Card>
        <Card className="metric-card">
          <Typography.Text type="secondary">标准事件</Typography.Text>
          <Typography.Title level={3}>{status.data.last_counters.emitted ?? 0}</Typography.Title>
        </Card>
        <Card className="metric-card">
          <Typography.Text type="secondary">跳过</Typography.Text>
          <Typography.Title level={3}>{status.data.last_counters.skipped ?? 0}</Typography.Title>
        </Card>
        <Card className="metric-card">
          <Typography.Text type="secondary">Malformed</Typography.Text>
          <Typography.Title level={3}>{status.data.last_counters.malformed ?? 0}</Typography.Title>
        </Card>
      </section>

      <section className="content-grid">
        <div className="surface">
          <Typography.Title level={4}>Collector</Typography.Title>
          <Descriptions column={1} size="small">
            <Descriptions.Item label="sensor">{status.data.sensor_id}</Descriptions.Item>
            <Descriptions.Item label="collector">{status.data.collector.kind}</Descriptions.Item>
            <Descriptions.Item label="version">{status.data.collector.version ?? '-'}</Descriptions.Item>
            <Descriptions.Item label="interface">{status.data.collector.interface ?? '-'}</Descriptions.Item>
            <Descriptions.Item label="storage">{status.data.storage_mode}</Descriptions.Item>
            <Descriptions.Item label="latest run">
              <Typography.Text className="mono">{status.data.latest_run_id ?? '-'}</Typography.Text>
            </Descriptions.Item>
          </Descriptions>
        </div>
        <div className="surface">
          <Typography.Title level={4}>事件类型分布</Typography.Title>
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            {(eventTypes.data?.event_types ?? []).map((item) => (
              <Row align="middle" justify="space-between" key={item.type}>
                <Col>
                  <Typography.Text className="mono">{item.type}</Typography.Text>
                </Col>
                <Col>
                  <Typography.Text strong>{item.count}</Typography.Text>
                </Col>
              </Row>
            ))}
          </Space>
        </div>
      </section>

      <section className="surface">
        <Typography.Title level={4}>诊断事件</Typography.Title>
        {(errors.data?.diagnostics ?? []).length > 0 && (
          <Alert
            showIcon
            style={{ marginBottom: 16 }}
            title={`最近 ${errors.data?.diagnostics.length ?? 0} 条 warning/error 诊断需要关注`}
            type="warning"
          />
        )}
        <Table
          columns={diagnosticColumns}
          dataSource={diagnostics.data?.diagnostics ?? []}
          loading={diagnostics.isLoading}
          rowKey="diagnostic_id"
          scroll={{ x: 980 }}
        />
      </section>

      <section className="surface">
        <Typography.Title level={4}>标准事件样本</Typography.Title>
        <Table
          columns={eventColumns}
          dataSource={events.data?.events ?? []}
          loading={events.isLoading}
          rowKey="event_id"
          scroll={{ x: 1100 }}
        />
      </section>
    </main>
  )
}
