import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Button, Drawer, Input, Select, Space, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import { useEvents } from '../shared/api/queries'
import type { EventQuery, NormalizedEventSummary } from '../shared/api/types'
import {
  AppErrorAlert,
  AppLoadingState,
  AppPageHeader,
  AppTableBar,
  type QuickWindow,
} from '../shared/ui'

export function EventsPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [selectedEvent, setSelectedEvent] = useState<NormalizedEventSummary | null>(null)

  const query = useMemo(() => queryFromSearchParams(searchParams), [searchParams])
  const quickWindow: QuickWindow = query.window ?? '1h'
  const activeType = query.type ?? ''
  const events = useEvents({ ...query, window: quickWindow })

  const columns: ColumnsType<NormalizedEventSummary> = [
    {
      title: '时间戳',
      dataIndex: 'timestamp',
      width: 180,
      render: (value: string) => new Date(value).toLocaleString(),
    },
    {
      title: '协议/类型',
      dataIndex: 'type',
      width: 100,
      render: (value: string) => <Tag className="dpi-badge-tag" color="blue">{value}</Tag>,
    },
    {
      title: '源 IP',
      width: 170,
      render: (_, event) => (
        <Typography.Text className="mono wrap-text">
          {stringField(event.subject, 'ip') || stringField(event.flow, 'src_ip') || '-'}
        </Typography.Text>
      ),
    },
    {
      title: '目的地址',
      width: 190,
      render: (_, event) => (
        <Typography.Text className="mono wrap-text">
          {stringField(event.flow, 'dst_ip') || '-'}
          {numberField(event.flow, 'dst_port') ? `:${numberField(event.flow, 'dst_port')}` : ''}
        </Typography.Text>
      ),
    },
    {
      title: 'L7 访问对象',
      render: (_, event) => <Typography.Text className="mono wrap-text">{eventTarget(event) || '-'}</Typography.Text>,
    },
    {
      title: 'Event ID',
      dataIndex: 'event_id',
      width: 220,
      render: (value: string) => <Typography.Text className="mono wrap-text">{value}</Typography.Text>,
    },
  ]

  const filterOptions = [
    { key: 'flow', label: 'Flow 会话', active: activeType === 'flow' },
    { key: 'dns', label: 'DNS 查询', active: activeType === 'dns' },
    { key: 'tls', label: 'TLS 握手', active: activeType === 'tls' },
    { key: 'http', label: 'HTTP 请求', active: activeType === 'http' },
    { key: 'quic', label: 'QUIC', active: activeType === 'quic' },
  ]

  if (events.isLoading) {
    return <AppLoadingState rows={8} />
  }

  return (
    <main className="page">
      <AppPageHeader
        loading={events.isFetching}
        onQuickWindowChange={(value) => updateQuery(setSearchParams, { ...query, window: value, cursor: undefined })}
        onRefresh={() => {
          void events.refetch()
        }}
        quickWindow={quickWindow}
        subtitle="按时间、源/目的 IP、L7 访问对象与协议快速检索解耦后的标准事件流"
        title="DPI 标准事件检索"
      />

      {events.isError && <AppErrorAlert title="标准事件列表加载失败" />}

      <AppTableBar
        filterOptions={filterOptions}
        onClearFilters={() => {
          setSearchParams({})
        }}
        onFilterToggle={(key) =>
          updateQuery(setSearchParams, {
            ...query,
            type: activeType === key ? undefined : key,
            cursor: undefined,
          })
        }
        onSearchChange={(val) => {
          updateQuery(setSearchParams, { ...query, q: val || undefined, cursor: undefined })
        }}
        searchPlaceholder="快速检索 (Event ID / IP / 域名 / SNI / UA)..."
        searchValue={searchParams.get('q') || ''}
        totalCount={events.data?.page.total ?? 0}
      />

      <section className="surface event-filter-panel">
        <div className="event-filter-grid">
          <Input
            allowClear
            onChange={(event) =>
              updateQuery(setSearchParams, { ...query, src_ip: event.target.value || undefined, cursor: undefined })
            }
            placeholder="源 IP"
            value={query.src_ip ?? ''}
          />
          <Input
            allowClear
            onChange={(event) =>
              updateQuery(setSearchParams, { ...query, dst_ip: event.target.value || undefined, cursor: undefined })
            }
            placeholder="目的 IP"
            value={query.dst_ip ?? ''}
          />
          <Input
            allowClear
            onChange={(event) =>
              updateQuery(setSearchParams, { ...query, domain: event.target.value || undefined, cursor: undefined })
            }
            placeholder="域名 / Host / SNI"
            value={query.domain ?? ''}
          />
          <Input
            allowClear
            onChange={(event) =>
              updateQuery(setSearchParams, {
                ...query,
                user_agent: event.target.value || undefined,
                cursor: undefined,
              })
            }
            placeholder="User-Agent"
            value={query.user_agent ?? ''}
          />
          <Input
            allowClear
            onChange={(event) =>
              updateQuery(setSearchParams, {
                ...query,
                fingerprint: event.target.value || undefined,
                cursor: undefined,
              })
            }
            placeholder="JA3 / JA4 指纹"
            value={query.fingerprint ?? ''}
          />
          <Input
            allowClear
            onChange={(event) =>
              updateQuery(setSearchParams, {
                ...query,
                port: event.target.value ? Number(event.target.value) : undefined,
                cursor: undefined,
              })
            }
            placeholder="目的端口"
            type="number"
            value={query.port ?? ''}
          />
          <Input
            allowClear
            onChange={(event) =>
              updateQuery(setSearchParams, { ...query, proto: event.target.value || undefined, cursor: undefined })
            }
            placeholder="传输协议 TCP / UDP"
            value={query.proto ?? ''}
          />
          <Select
            className="filter-select"
            onChange={(value) => updateQuery(setSearchParams, { ...query, limit: value, cursor: undefined })}
            options={[
              { label: '50 条 / 页', value: 50 },
              { label: '100 条 / 页', value: 100 },
              { label: '200 条 / 页', value: 200 },
            ]}
            value={query.limit ?? 50}
          />
        </div>
      </section>

      <section className="surface">
        <Table<NormalizedEventSummary>
          columns={columns}
          dataSource={events.data?.events ?? []}
          onRow={(record) => ({ onClick: () => setSelectedEvent(record) })}
          pagination={false}
          rowKey="event_id"
          scroll={{ x: 960 }}
          size="middle"
        />

        <div className="section-toolbar section-toolbar-spaced">
          <Typography.Text type="secondary">
            第 {query.cursor ? 'N' : '1'} 页
          </Typography.Text>
          <Space wrap>
            <Button
              className="dpi-badge-tag"
              disabled={!query.cursor}
              onClick={() => updateQuery(setSearchParams, { ...query, cursor: undefined })}
            >
              回到第一页
            </Button>
            <Button
              className="dpi-badge-tag"
              disabled={!events.data?.page.next_cursor}
              onClick={() =>
                updateQuery(setSearchParams, { ...query, cursor: events.data?.page.next_cursor ?? undefined })
              }
              type="primary"
            >
              下一页 ➔
            </Button>
          </Space>
        </div>
      </section>

      <Drawer
        onClose={() => setSelectedEvent(null)}
        open={Boolean(selectedEvent)}
        size="large"
        title={`标准事件明细 - ${selectedEvent?.event_id ?? ''}`}
      >
        {selectedEvent && <pre className="dpi-drawer-json">{JSON.stringify(selectedEvent, null, 2)}</pre>}
      </Drawer>
    </main>
  )
}

function queryFromSearchParams(params: URLSearchParams): EventQuery {
  const port = params.get('port')
  const limit = params.get('limit')
  return {
    q: params.get('q') || undefined,
    type: params.get('type') || undefined,
    sensor_id: params.get('sensor_id') || undefined,
    from: params.get('from') || undefined,
    to: params.get('to') || undefined,
    window: parseQuickWindow(params.get('window')),
    src_ip: params.get('src_ip') || undefined,
    dst_ip: params.get('dst_ip') || undefined,
    domain: params.get('domain') || undefined,
    user_agent: params.get('user_agent') || undefined,
    fingerprint: params.get('fingerprint') || undefined,
    port: port ? Number(port) : undefined,
    proto: params.get('proto') || undefined,
    limit: limit ? Number(limit) : 50,
    cursor: params.get('cursor') || undefined,
  }
}

function updateQuery(setSearchParams: (params: URLSearchParams) => void, query: EventQuery) {
  const params = new URLSearchParams()
  if (query.q) params.set('q', query.q)
  if (query.type) params.set('type', query.type)
  if (query.sensor_id) params.set('sensor_id', query.sensor_id)
  if (query.from) params.set('from', query.from)
  if (query.to) params.set('to', query.to)
  if (query.window) params.set('window', query.window)
  if (query.src_ip) params.set('src_ip', query.src_ip)
  if (query.dst_ip) params.set('dst_ip', query.dst_ip)
  if (query.domain) params.set('domain', query.domain)
  if (query.user_agent) params.set('user_agent', query.user_agent)
  if (query.fingerprint) params.set('fingerprint', query.fingerprint)
  if (query.port) params.set('port', String(query.port))
  if (query.proto) params.set('proto', query.proto)
  if (query.limit) params.set('limit', String(query.limit))
  if (query.cursor) params.set('cursor', query.cursor)
  setSearchParams(params)
}

function parseQuickWindow(value: string | null): QuickWindow | undefined {
  if (value === '10m' || value === '1h' || value === '24h') {
    return value
  }
  return undefined
}

function stringField(source: unknown, key: string): string | undefined {
  if (!source || typeof source !== 'object') return undefined
  const value = (source as Record<string, unknown>)[key]
  return typeof value === 'string' ? value : undefined
}

function numberField(source: unknown, key: string): number | undefined {
  if (!source || typeof source !== 'object') return undefined
  const value = (source as Record<string, unknown>)[key]
  return typeof value === 'number' ? value : undefined
}

function eventTarget(event: NormalizedEventSummary): string | undefined {
  return (
    stringField(event.payload, 'host') ||
    stringField(event.payload, 'sni') ||
    stringField(event.payload, 'query') ||
    stringField(event.payload, 'user_agent')
  )
}
