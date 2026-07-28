import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Alert, Button, Drawer, Input, Select, Skeleton, Space, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import { useEvents } from '../shared/api/queries'
import type { EventQuery, NormalizedEventSummary } from '../shared/api/types'

type WindowValue = '10m' | '1h' | '24h'

const windowOptions = [
  { label: '10 分钟', value: '10m' },
  { label: '1 小时', value: '1h' },
  { label: '24 小时', value: '24h' },
]

const typeOptions = ['flow', 'dns', 'tls', 'http', 'quic', 'device', 'alert'].map((value) => ({ label: value, value }))

export function EventsPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [selectedEvent, setSelectedEvent] = useState<NormalizedEventSummary | null>(null)
  const query = useMemo(() => queryFromSearchParams(searchParams), [searchParams])
  const events = useEvents(query)

  const columns: ColumnsType<NormalizedEventSummary> = [
    {
      title: '时间',
      dataIndex: 'timestamp',
      width: 190,
      render: (value: string) => new Date(value).toLocaleString(),
    },
    {
      title: '类型',
      dataIndex: 'type',
      width: 90,
      render: (value: string) => <Tag>{value}</Tag>,
    },
    {
      title: '源 IP',
      width: 180,
      render: (_, event) => <Typography.Text className="mono wrap-text">{stringField(event.subject, 'ip') || stringField(event.flow, 'src_ip') || '-'}</Typography.Text>,
    },
    {
      title: '目的',
      width: 210,
      render: (_, event) => (
        <Typography.Text className="mono wrap-text">
          {stringField(event.flow, 'dst_ip') || '-'}
          {numberField(event.flow, 'dst_port') ? `:${numberField(event.flow, 'dst_port')}` : ''}
        </Typography.Text>
      ),
    },
    {
      title: '访问对象',
      render: (_, event) => <Typography.Text className="mono wrap-text">{eventTarget(event) || '-'}</Typography.Text>,
    },
    {
      title: 'Event ID',
      dataIndex: 'event_id',
      width: 220,
      render: (value: string) => <Typography.Text className="mono wrap-text">{value}</Typography.Text>,
    },
  ]

  if (events.isLoading) {
    return <Skeleton active />
  }

  return (
    <main className="page">
      <div className="page-header">
        <div>
          <Typography.Title className="page-title" level={3}>
            标准事件检索
          </Typography.Title>
          <Typography.Text type="secondary">按时间、IP、访问对象和协议检索标准事件，不展示采集器原始日志。</Typography.Text>
        </div>
      </div>

      {events.isError && <Alert showIcon title="标准事件加载失败" type="error" />}

      <section className="surface">
        <EventFilters query={query} onChange={setSearchParams} />
      </section>

      <section className="surface">
        <div className="section-toolbar">
          <Typography.Text type="secondary">共 {events.data?.page.total ?? 0} 条标准事件</Typography.Text>
          <Space wrap>
            <Button disabled={!events.data?.page.next_cursor} onClick={() => updateQuery(setSearchParams, { ...query, cursor: events.data?.page.next_cursor ?? undefined })}>
              下一页
            </Button>
            <Button disabled={!query.cursor} onClick={() => updateQuery(setSearchParams, { ...query, cursor: undefined })}>
              回到第一页
            </Button>
          </Space>
        </div>
        <Table<NormalizedEventSummary>
          columns={columns}
          dataSource={events.data?.events ?? []}
          loading={events.isFetching}
          onRow={(event) => ({ onClick: () => setSelectedEvent(event) })}
          pagination={false}
          rowKey="event_id"
          scroll={{ x: 1050 }}
          size="small"
        />
      </section>

      <Drawer
        className="event-detail-drawer"
        onClose={() => setSelectedEvent(null)}
        open={!!selectedEvent}
        title="标准事件详情"
        width={720}
      >
        {selectedEvent && (
          <pre className="json-block">
            {JSON.stringify(
              {
                event_id: selectedEvent.event_id,
                source: selectedEvent.source,
                type: selectedEvent.type,
                timestamp: selectedEvent.timestamp,
                observer: selectedEvent.observer,
                subject: selectedEvent.subject,
                flow: selectedEvent.flow,
                payload: selectedEvent.payload,
                confidence: selectedEvent.confidence,
                raw_ref: selectedEvent.raw_ref,
              },
              null,
              2,
            )}
          </pre>
        )}
      </Drawer>
    </main>
  )
}

function EventFilters({ query, onChange }: { query: EventQuery; onChange: (nextInit: URLSearchParams) => void }) {
  return (
    <div className="event-filter-grid">
      <Select allowClear className="event-filter-control" onChange={(value) => updateQuery(onChange, { ...query, window: value as WindowValue | undefined, cursor: undefined })} options={windowOptions} placeholder="时间窗口" value={query.window} />
      <Select allowClear className="event-filter-control" onChange={(value) => updateQuery(onChange, { ...query, type: value, cursor: undefined })} options={typeOptions} placeholder="事件类型" value={query.type} />
      <Input allowClear className="event-filter-control" onChange={(event) => updateQuery(onChange, { ...query, from: event.target.value, window: undefined, cursor: undefined })} placeholder="开始时间 RFC3339" value={query.from ?? ''} />
      <Input allowClear className="event-filter-control" onChange={(event) => updateQuery(onChange, { ...query, to: event.target.value, window: undefined, cursor: undefined })} placeholder="结束时间 RFC3339" value={query.to ?? ''} />
      <Input allowClear className="event-filter-control" onChange={(event) => updateQuery(onChange, { ...query, src_ip: event.target.value, cursor: undefined })} placeholder="源 IP" value={query.src_ip ?? ''} />
      <Input allowClear className="event-filter-control" onChange={(event) => updateQuery(onChange, { ...query, dst_ip: event.target.value, cursor: undefined })} placeholder="目的 IP" value={query.dst_ip ?? ''} />
      <Input allowClear className="event-filter-control" onChange={(event) => updateQuery(onChange, { ...query, domain: event.target.value, cursor: undefined })} placeholder="域名 / Host / SNI" value={query.domain ?? ''} />
      <Input allowClear className="event-filter-control" onChange={(event) => updateQuery(onChange, { ...query, user_agent: event.target.value, cursor: undefined })} placeholder="User-Agent" value={query.user_agent ?? ''} />
      <Input allowClear className="event-filter-control" onChange={(event) => updateQuery(onChange, { ...query, fingerprint: event.target.value, cursor: undefined })} placeholder="JA3 / JA4 指纹" value={query.fingerprint ?? ''} />
      <Input allowClear className="event-filter-control" onChange={(event) => updateQuery(onChange, { ...query, port: parseOptionalPort(event.target.value), cursor: undefined })} placeholder="目的端口" value={query.port ? String(query.port) : ''} />
      <Input allowClear className="event-filter-control" onChange={(event) => updateQuery(onChange, { ...query, proto: event.target.value, cursor: undefined })} placeholder="协议 tcp/udp/icmp" value={query.proto ?? ''} />
    </div>
  )
}

function queryFromSearchParams(params: URLSearchParams): EventQuery {
  return {
    q: optionalString(params.get('q')),
    type: optionalString(params.get('type')),
    sensor_id: optionalString(params.get('sensor_id')),
    from: optionalString(params.get('from')),
    to: optionalString(params.get('to')),
    window: optionalWindow(params.get('window')),
    src_ip: optionalString(params.get('src_ip')),
    dst_ip: optionalString(params.get('dst_ip')),
    domain: optionalString(params.get('domain')),
    user_agent: optionalString(params.get('user_agent')),
    fingerprint: optionalString(params.get('fingerprint')),
    port: parseOptionalPort(params.get('port') ?? ''),
    proto: optionalString(params.get('proto')),
    limit: 50,
    cursor: optionalString(params.get('cursor')),
  }
}

function updateQuery(onChange: (nextInit: URLSearchParams) => void, query: EventQuery) {
  const next = new URLSearchParams()
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== '') {
      next.set(key, String(value))
    }
  }
  onChange(next)
}

function optionalString(value: string | null) {
  return value && value.trim() ? value.trim() : undefined
}

function optionalWindow(value: string | null): WindowValue | undefined {
  return value === '10m' || value === '1h' || value === '24h' ? value : undefined
}

function parseOptionalPort(value: string) {
  const trimmed = value.trim()
  if (!trimmed) {
    return undefined
  }
  const parsed = Number(trimmed)
  return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined
}

function stringField(values: Record<string, unknown> | undefined, key: string) {
  const value = values?.[key]
  return typeof value === 'string' ? value : ''
}

function numberField(values: Record<string, unknown> | undefined, key: string) {
  const value = values?.[key]
  return typeof value === 'number' ? value : 0
}

function eventTarget(event: NormalizedEventSummary) {
  return stringField(event.payload, 'query') || stringField(event.payload, 'host') || stringField(event.payload, 'sni')
}
