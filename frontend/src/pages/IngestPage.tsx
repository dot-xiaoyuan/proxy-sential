import { useState } from 'react'
import { Link } from 'react-router-dom'
import { CodeOutlined } from '@ant-design/icons'
import { Alert, Button, Descriptions, Drawer, Space, Table, Tag, Typography } from 'antd'
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
	AppServerPagination,
	useServerPagination,
  type QuickWindow,
} from '../shared/ui'

export function IngestPage() {
  const [quickWindow, setQuickWindow] = useState<QuickWindow>('1h')
  const [inspectJson, setInspectJson] = useState<{ title: string; data: unknown } | null>(null)
	const errorPage = useServerPagination('errors_')
	const eventPage = useServerPagination('events_')
	const diagnosticPage = useServerPagination('diagnostics_')

  const status = useIngestStatus()
  const eventTypes = useIngestEventTypes()
  const diagnostics = useIngestDiagnostics({ limit: diagnosticPage.pageSize, cursor: diagnosticPage.cursor })
  const errors = useIngestErrors({ limit: errorPage.pageSize, cursor: errorPage.cursor })
  const events = useEvents({ limit: eventPage.pageSize, cursor: eventPage.cursor })

  if (status.isLoading) {
    return <AppLoadingState rows={6} />
  }

  if (status.isError || !status.data) {
    return <AppErrorAlert title="采集诊断节点加载失败" />
  }

  const severityType = status.data.severity === 'error' ? 'error' : status.data.severity === 'warning' ? 'warning' : 'success'
  const latestDiagnostic = diagnostics.data?.diagnostics?.[0]
  const zeekStatus = stringDetail(latestDiagnostic, 'zeek_status') || 'not_configured'
  const zeekNormalized = normalizedDetail(latestDiagnostic, 'zeek_normalized')
  const zeekDeviceCount = zeekNormalized?.by_type?.device ?? 0

  const diagnosticColumns: ColumnsType<IngestDiagnostic> = [
    {
      title: '时间戳',
      dataIndex: 'timestamp',
      width: 170,
      render: (value: string) => <span className="mono-path">{new Date(value).toLocaleString()}</span>,
    },
    { title: '阶段', dataIndex: 'stage', width: 100 },
    { title: '类型', dataIndex: 'type', width: 120 },
    {
      title: '级别',
      dataIndex: 'severity',
      width: 90,
      render: (value: IngestDiagnostic['severity']) => {
        const color = value === 'error' ? 'red' : value === 'warning' ? 'gold' : 'green'
        return <Tag className="dpi-badge-tag" color={color}>{value}</Tag>
      },
    },
    {
      title: '诊断说明',
      dataIndex: 'summary',
      width: 260,
      render: (value: string) => <Typography.Text className="list-cell-nowrap" title={value}>{value}</Typography.Text>,
    },
    {
      title: '计数指标',
      dataIndex: 'counters',
      width: 220,
      render: (value: Record<string, number> | undefined, record) =>
        renderCounters(value, () =>
          setInspectJson({
            title: `诊断指标详情 #${record.diagnostic_id}`,
            data: record.counters ?? {},
          }),
        ),
    },
    {
      title: '操作',
      width: 90,
      render: (_, record) => (
        <Link className="list-cell-nowrap" to={`/ingest/diagnostics/${encodeURIComponent(record.diagnostic_id)}`}>查看详情</Link>
      ),
    },
  ]

  const eventColumns: ColumnsType<NormalizedEventSummary> = [
    {
      title: 'Event ID',
      dataIndex: 'event_id',
      width: 180,
      render: (value: string) => <span className="mono-path">{value}</span>,
    },
    {
      title: '类型',
      dataIndex: 'type',
      width: 90,
      render: (v: string) => <Tag className="dpi-badge-tag" color="blue">{v}</Tag>,
    },
    {
      title: '时间戳',
      dataIndex: 'timestamp',
      width: 170,
      render: (value: string) => <span className="mono-path">{new Date(value).toLocaleString()}</span>,
    },
    {
      title: 'Subject (主体识别)',
      dataIndex: 'subject',
      width: 220,
      render: (value: Record<string, unknown> | undefined, event) =>
        renderSubject(value, () =>
          setInspectJson({
            title: `Subject 元数据 #${event.event_id}`,
            data: event.subject,
          }),
        ),
    },
    {
      title: 'Flow / Payload 概要',
      width: 320,
      render: (_, event) =>
        renderFlowPayloadSummary(event, () =>
          setInspectJson({
            title: `标准事件元数据 #${event.event_id}`,
            data: event,
          }),
        ),
    },
  ]

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

      <Alert className="ingest-status-alert" showIcon title={status.data.summary} type={severityType} />

      <section className="ingest-metric-grid">
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
        <AppMetricCard
          statusColor={zeekStatus === 'ok' ? 'green' : zeekStatus === 'no_dhcp_events' ? 'blue' : 'orange'}
          statusText={zeekStatusText(zeekStatus)}
          title="Zeek 设备事件"
          value={zeekDeviceCount}
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

      <section className="surface">
        <Typography.Title level={4}>Zeek 设备指纹采集</Typography.Title>
        <Descriptions column={{ xs: 1, sm: 2, md: 4 }} size="small">
          <Descriptions.Item label="状态">{zeekStatusText(zeekStatus)}</Descriptions.Item>
          <Descriptions.Item label="DHCP Log">
            <span className="mono-path">{stringDetail(latestDiagnostic, 'zeek_dhcp_path') || '-'}</span>
          </Descriptions.Item>
          <Descriptions.Item label="Offset">{`${numberDetail(latestDiagnostic, 'zeek_previous_offset')} -> ${numberDetail(latestDiagnostic, 'zeek_new_offset')}`}</Descriptions.Item>
          <Descriptions.Item label="轮转">{boolDetail(latestDiagnostic, 'zeek_truncated') ? '是' : '否'}</Descriptions.Item>
          <Descriptions.Item label="Software Log">
            <span className="mono-path">{stringDetail(latestDiagnostic, 'zeek_software_path') || '-'}</span>
          </Descriptions.Item>
          <Descriptions.Item label="Software Offset">{`${numberDetail(latestDiagnostic, 'zeek_software_previous_offset')} -> ${numberDetail(latestDiagnostic, 'zeek_software_new_offset')}`}</Descriptions.Item>
          <Descriptions.Item label="Software 轮转">{boolDetail(latestDiagnostic, 'zeek_software_truncated') ? '是' : '否'}</Descriptions.Item>
          <Descriptions.Item label="说明">
            <span className="wrap-text">{stringDetail(latestDiagnostic, 'zeek_reason') || zeekStatusDescription(zeekStatus)}</span>
          </Descriptions.Item>
        </Descriptions>
      </section>

      <section className="surface">
        <Typography.Title level={4}>按类型统计标准事件 (Event Types)</Typography.Title>
        <Space className="ingest-event-type-tags" size="middle" wrap>
          {(eventTypes.data?.event_types ?? []).map((item) => (
            <div className="ingest-event-type-bar" key={item.type}>
              <span className="ingest-event-type-name">{item.type.toUpperCase()}</span>
              <Tag className="dpi-badge-tag" color="blue">
                标准事件
              </Tag>
              <span className="ingest-event-type-count">{item.count.toLocaleString()} msg</span>
            </div>
          ))}
        </Space>
      </section>

      <section className="surface">
        <Typography.Title level={4}>最近异常诊断日志 (Recent Diagnostic Logs)</Typography.Title>
        <div className="ingest-table-container">
          <Table<IngestDiagnostic>
            columns={diagnosticColumns}
            dataSource={errors.data?.diagnostics ?? []}
            pagination={false}
            rowKey="diagnostic_id"
            scroll={{ x: 'max-content' }}
            size="small"
          />
		  <AppServerPagination page={errorPage.page} pageSize={errorPage.pageSize} total={errors.data?.page.total ?? 0} onChange={errorPage.update} />
        </div>
      </section>

      <section className="surface">
        <Typography.Title level={4}>采样标准事件流 (Sampled Standard Events)</Typography.Title>
        <div className="ingest-table-container">
          <Table<NormalizedEventSummary>
            columns={eventColumns}
            dataSource={events.data?.events ?? []}
            pagination={false}
            rowKey="event_id"
            scroll={{ x: 'max-content' }}
            size="small"
          />
		  <AppServerPagination page={eventPage.page} pageSize={eventPage.pageSize} total={events.data?.page.total ?? 0} onChange={eventPage.update} />
        </div>
      </section>

      <section className="surface">
        <Typography.Title level={4}>全量诊断轨迹 (All Ingestion Diagnostics)</Typography.Title>
        <div className="ingest-table-container">
          <Table<IngestDiagnostic>
            columns={diagnosticColumns}
            dataSource={diagnostics.data?.diagnostics ?? []}
            pagination={false}
            rowKey="diagnostic_id"
            scroll={{ x: 'max-content' }}
            size="small"
          />
		  <AppServerPagination page={diagnosticPage.page} pageSize={diagnosticPage.pageSize} total={diagnostics.data?.page.total ?? 0} onChange={diagnosticPage.update} />
        </div>
      </section>

      <Drawer
        onClose={() => setInspectJson(null)}
        open={!!inspectJson}
        title={inspectJson?.title ?? '原始元数据 JSON'}
        width={640}
      >
        {Boolean(inspectJson?.data) && (
          <pre className="ingest-drawer-pre">
            {JSON.stringify(inspectJson?.data, null, 2)}
          </pre>
        )}
      </Drawer>
    </main>
  )
}

type NormalizedDetail = {
  by_type?: Record<string, number>
}

function renderCounters(counters: Record<string, number> | undefined, onInspect: () => void) {
  if (!counters || Object.keys(counters).length === 0) return <span className="mono-path">-</span>
  const entries = Object.entries(counters)
  return (
    <div className="ingest-counters-wrap">
      {entries.slice(0, 3).map(([k, v]) => (
        <Tag className="dpi-badge-tag" color="blue" key={k}>
          {k}: {v}
        </Tag>
      ))}
      {entries.length > 3 && (
        <Button className="ingest-json-preview-btn" onClick={onInspect} size="small" type="link">
          +{entries.length - 3} 更多
        </Button>
      )}
    </div>
  )
}

function renderSubject(subject: Record<string, unknown> | undefined, onInspect: () => void) {
  if (!subject || Object.keys(subject).length === 0) return <span className="mono-path">-</span>
  const ip = typeof subject.ip === 'string' ? subject.ip : ''
  const mac = typeof subject.mac === 'string' ? subject.mac : ''
  const hostname = typeof subject.hostname === 'string' ? subject.hostname : ''

  return (
    <Space size="small" wrap>
      {ip && <span className="mono-path">{ip}</span>}
      {hostname && <Tag className="dpi-badge-tag">{hostname}</Tag>}
      {mac && <span className="mono-path">{mac}</span>}
      {!ip && !hostname && !mac && (
        <Button className="ingest-json-preview-btn" onClick={onInspect} size="small" type="dashed">
          查看 Subject
        </Button>
      )}
    </Space>
  )
}

function renderFlowPayloadSummary(event: NormalizedEventSummary, onInspect: () => void) {
  const flow = event.flow as Record<string, unknown> | undefined
  const payload = event.payload as Record<string, unknown> | undefined

  const src = flow?.src_ip ? `${flow.src_ip}:${flow.src_port ?? ''}` : ''
  const dst = flow?.dst_ip ? `${flow.dst_ip}:${flow.dst_port ?? ''}` : ''
  const flowStr = src && dst ? `${src} -> ${dst}` : ''

  const sni = typeof payload?.sni === 'string' ? payload.sni : ''
  const query = typeof payload?.query === 'string' ? payload.query : ''
  const method = typeof payload?.method === 'string' ? payload.method : ''
  const uri = typeof payload?.uri === 'string' ? payload.uri : ''

  const summary = sni ? `SNI: ${sni}` : query ? `DNS: ${query}` : method ? `${method} ${uri}` : ''

  return (
    <Space size="small" wrap>
      {flowStr && <Tag className="dpi-badge-tag" color="cyan">{flowStr}</Tag>}
      {summary && <span className="mono-path">{summary}</span>}
      <Button
        className="ingest-json-preview-btn"
        icon={<CodeOutlined />}
        onClick={onInspect}
        size="small"
        type="link"
      >
        JSON
      </Button>
    </Space>
  )
}

function detailValue(diagnostic: IngestDiagnostic | undefined, key: string) {
  const details = diagnostic?.details
  if (!details || typeof details !== 'object') {
    return undefined
  }
  return details[key]
}

function stringDetail(diagnostic: IngestDiagnostic | undefined, key: string) {
  const value = detailValue(diagnostic, key)
  return typeof value === 'string' ? value : ''
}

function numberDetail(diagnostic: IngestDiagnostic | undefined, key: string) {
  const value = detailValue(diagnostic, key)
  return typeof value === 'number' ? value : 0
}

function boolDetail(diagnostic: IngestDiagnostic | undefined, key: string) {
  return detailValue(diagnostic, key) === true
}

function normalizedDetail(diagnostic: IngestDiagnostic | undefined, key: string): NormalizedDetail | undefined {
  const value = detailValue(diagnostic, key)
  return value && typeof value === 'object' ? (value as NormalizedDetail) : undefined
}

function zeekStatusText(status: string) {
  switch (status) {
    case 'ok':
      return '正常'
    case 'no_dhcp_events':
      return '无设备数据'
    case 'unavailable':
      return '日志不可用'
    case 'log_truncated':
      return '日志轮转'
    default:
      return '未启用'
  }
}

function zeekStatusDescription(status: string) {
  switch (status) {
    case 'no_dhcp_events':
      return 'Zeek 日志存在，但最新 shadow run 没有转换出设备事件。'
    case 'unavailable':
      return 'Zeek 日志路径不可读，需检查 Zeek 服务、日志目录和权限。'
    case 'log_truncated':
      return 'Zeek 日志发生轮转或截断，offset 已重置。'
    default:
      return '最新 shadow run 未包含 Zeek 设备日志输入。'
  }
}
