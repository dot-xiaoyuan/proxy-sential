import { useState } from 'react'
import { Alert, Descriptions, Space, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import {
  useEvents,
  useIngestDiagnostics,
  useIngestEventTypes,
  useIngestErrors,
  useIngestStatus,
} from '../shared/api/queries'
import type { IngestDiagnostic, NormalizedEventSummary } from '../shared/api/types'
import {
  AppErrorAlert,
  AppLoadingState,
  AppMetricCard,
  AppPageHeader,
  type QuickWindow,
} from '../shared/ui'

const diagnosticColumns: ColumnsType<IngestDiagnostic> = [
  {
    title: '时间戳',
    dataIndex: 'timestamp',
    width: 180,
    render: (value: string) => new Date(value).toLocaleString(),
  },
  { title: '阶段', dataIndex: 'stage', width: 110 },
  { title: '类型', dataIndex: 'type', width: 140 },
  {
    title: '级别',
    dataIndex: 'severity',
    width: 100,
    render: (value: IngestDiagnostic['severity']) => {
      const color = value === 'error' ? 'red' : value === 'warning' ? 'gold' : 'green'
      return <Tag className="dpi-badge-tag" color={color}>{value}</Tag>
    },
  },
  {
    title: '诊断说明',
    dataIndex: 'summary',
    render: (value: string) => <Typography.Text className="wrap-text">{value}</Typography.Text>,
  },
  {
    title: '计数指标',
    dataIndex: 'counters',
    width: 240,
    render: (value: Record<string, number> | undefined) => (
      <Typography.Text className="mono wrap-text">{JSON.stringify(value ?? {})}</Typography.Text>
    ),
  },
]

const eventColumns: ColumnsType<NormalizedEventSummary> = [
  { title: 'Event ID', dataIndex: 'event_id', width: 200, render: (value: string) => <span className="mono wrap-text">{value}</span> },
  { title: '类型', dataIndex: 'type', width: 90, render: (v: string) => <Tag className="dpi-badge-tag" color="blue">{v}</Tag> },
  { title: '时间戳', dataIndex: 'timestamp', width: 180, render: (value: string) => new Date(value).toLocaleString() },
  {
    title: 'Subject',
    dataIndex: 'subject',
    width: 180,
    render: (value: Record<string, unknown>) => <Typography.Text className="mono wrap-text">{JSON.stringify(value)}</Typography.Text>,
  },
  {
    title: 'Flow/Payload 概要',
    render: (_, event) => (
      <Typography.Text className="mono wrap-text">
        {JSON.stringify({ flow: event.flow, payload: event.payload })}
      </Typography.Text>
    ),
  },
]

export function IngestPage() {
  const [quickWindow, setQuickWindow] = useState<QuickWindow>('1h')
  const status = useIngestStatus()
  const eventTypes = useIngestEventTypes()
  const diagnostics = useIngestDiagnostics(50)
  const errors = useIngestErrors(50)
  const events = useEvents({ limit: 20 })

  if (status.isLoading) {
    return <AppLoadingState rows={6} />
  }

  if (status.isError || !status.data) {
    return <AppErrorAlert title="采集诊断节点加载失败" />
  }

  const severityType = status.data.severity === 'error' ? 'error' : status.data.severity === 'warning' ? 'warning' : 'success'

  return (
    <main className="page">
      <AppPageHeader
        loading={status.isFetching}
        onQuickWindowChange={setQuickWindow}
        onRefresh={() => {
          void status.refetch()
          void diagnostics.refetch()
          void errors.refetch()
        }}
        quickWindow={quickWindow}
        subtitle="面向生产环境的 AF_XDP/Suricata 抓包引擎、丢包率与事件标准化诊断大图"
        title="采集诊断与节点性能"
      />

      <Alert showIcon style={{ marginBottom: 16 }} title={status.data.summary} type={severityType} />

      <section className="metric-grid">
        <AppMetricCard
          statusColor="blue"
          statusText="Raw Ingestion"
          title="数据包读取 (Read)"
          value={status.data.last_counters?.read ?? 0}
        />
        <AppMetricCard
          statusColor="green"
          statusText="Standardized"
          title="发射事件 (Emitted)"
          value={status.data.last_counters?.emitted ?? 0}
        />
        <AppMetricCard
          statusColor="orange"
          statusText="Dropped / Filtered"
          title="跳过数量 (Skipped)"
          value={status.data.last_counters?.skipped ?? 0}
        />
        <AppMetricCard
          statusColor="red"
          statusText="Malformed Rate"
          title="畸形包数量 (Malformed)"
          value={status.data.last_counters?.malformed ?? 0}
        />
      </section>

      <section className="surface">
        <Typography.Title level={4}>采集服务节点状态 (Collector Engine Node)</Typography.Title>
        <Descriptions column={{ xs: 1, sm: 2, md: 4 }} size="small">
          <Descriptions.Item label="Sensor ID">{status.data.sensor_id}</Descriptions.Item>
          <Descriptions.Item label="Collector Kind">{status.data.collector.kind}</Descriptions.Item>
          <Descriptions.Item label="Engine Version">{status.data.collector.version}</Descriptions.Item>
          <Descriptions.Item label="Interface">{status.data.collector.interface}</Descriptions.Item>
        </Descriptions>
      </section>

      <section className="content-grid">
        <div className="surface">
          <Typography.Title level={4}>按类型统计标准事件 (Event Types)</Typography.Title>
          <Space wrap size="small" style={{ marginTop: 8 }}>
            {(eventTypes.data?.event_types ?? []).map((item) => (
              <Tag className="dpi-badge-tag" color="blue" key={item.type}>
                {item.type}: {item.count}
              </Tag>
            ))}
          </Space>
        </div>

        <div className="surface">
          <Typography.Title level={4}>最近异常诊断日志 (Recent Diagnostic Logs)</Typography.Title>
          <Table<IngestDiagnostic>
            columns={diagnosticColumns}
            dataSource={errors.data?.diagnostics ?? []}
            pagination={false}
            rowKey="diagnostic_id"
            scroll={{ x: 700 }}
            size="small"
          />
        </div>
      </section>

      <section className="surface">
        <Typography.Title level={4}>采样标准事件流 (Sampled Standard Events)</Typography.Title>
        <Table<NormalizedEventSummary>
          columns={eventColumns}
          dataSource={events.data?.events ?? []}
          pagination={false}
          rowKey="event_id"
          scroll={{ x: 800 }}
          size="small"
        />
      </section>

      <section className="surface">
        <Typography.Title level={4}>全量诊断轨迹 (All Ingestion Diagnostics)</Typography.Title>
        <Table<IngestDiagnostic>
          columns={diagnosticColumns}
          dataSource={diagnostics.data?.diagnostics ?? []}
          pagination={{ pageSize: 10 }}
          rowKey="diagnostic_id"
          scroll={{ x: 800 }}
          size="small"
        />
      </section>
    </main>
  )
}
