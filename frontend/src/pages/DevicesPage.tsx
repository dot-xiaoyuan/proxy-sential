import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Progress, Space, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import { BrandLogo } from '../entities/device/BrandLogo'
import { useDevices } from '../shared/api/queries'
import type { EndpointDeviceInventory } from '../shared/api/types'
import {
  AppErrorAlert,
  AppLoadingState,
  AppMetricCard,
  AppPageHeader,
  AppTableBar,
  type QuickWindow,
} from '../shared/ui'

type RegistrationStatus = EndpointDeviceInventory['registration_status'] | 'all'
type EndpointDeviceRow = EndpointDeviceInventory & { row_key: string }

export function DevicesPage() {
  const [quickWindow, setQuickWindow] = useState<QuickWindow>('24h')
  const [searchValue, setSearchValue] = useState('')
  const [status, setStatus] = useState<RegistrationStatus>('all')
  const devices = useDevices({ window: quickWindow, q: searchValue, limit: 200 })

  const rawItems = useMemo(
    () => (devices.data?.items ?? []).map((item) => coerceEndpointDevice(item)),
    [devices.data?.items],
  )
  const items = useMemo(
    () => rawItems.filter((item) => status === 'all' || item.registration_status === status),
    [rawItems, status],
  )
  const tableItems = useMemo(
    () =>
      items.map((item, index) => ({
        ...item,
        row_key: item.endpoint_id || item.primary_mac || item.current_ip || `${item.summary}-${index}`,
      })),
    [items],
  )

  const registeredCount = rawItems.filter((item) => item.registration_status === 'registered').length
  const unregisteredCount = rawItems.filter((item) => item.registration_status === 'unregistered').length
  const multiAccountCount = rawItems.filter((item) => endpointAccounts(item).length > 1).length
  const activeAccessCount = new Set(rawItems.flatMap((item) => endpointAccessIDs(item))).size

  const filterOptions = [
    { key: 'registered', label: '已登记', active: status === 'registered' },
    { key: 'unregistered', label: '未登记', active: status === 'unregistered' },
    { key: 'ignored', label: '已忽略', active: status === 'ignored' },
    { key: 'retired', label: '已退役', active: status === 'retired' },
  ]

  if (devices.isLoading) {
    return <AppLoadingState rows={8} />
  }

  return (
    <main className="page">
      <AppPageHeader
        loading={devices.isFetching}
        onQuickWindowChange={setQuickWindow}
        onRefresh={() => {
          void devices.refetch()
        }}
        quickWindow={quickWindow}
        subtitle="按 endpoint 汇总账号、IP、接入位置和登记状态，作为设备登记管理入口"
        title="设备登记"
      />

      <section className="metric-grid">
        <AppMetricCard statusColor="blue" statusText="endpoint inventory" title="终端实体" value={rawItems.length} />
        <AppMetricCard statusColor="green" statusText="registered" title="已登记" value={registeredCount} />
        <AppMetricCard statusColor="orange" statusText="unregistered" title="未登记" value={unregisteredCount} />
        <AppMetricCard statusColor="red" statusText="needs review" title="多账号终端" value={multiAccountCount} />
      </section>

      {devices.isError && <AppErrorAlert title="设备登记列表加载失败" />}

      <AppTableBar
        filterOptions={filterOptions}
        onClearFilters={() => {
          setStatus('all')
          setSearchValue('')
        }}
        onFilterToggle={(key) => setStatus(status === key ? 'all' : (key as RegistrationStatus))}
        onSearchChange={setSearchValue}
        searchPlaceholder="搜索 endpoint、MAC、账号、责任人、资产编号、IP 或接入位置..."
        searchValue={searchValue}
        totalCount={items.length}
      />

      <section className="surface">
        <Table<EndpointDeviceRow>
          columns={columns}
          dataSource={tableItems}
          locale={{ emptyText: '没有匹配的终端登记结果' }}
          pagination={{ pageSize: 10, showSizeChanger: false }}
          rowKey="row_key"
          scroll={{ x: 1420 }}
          size="middle"
          summary={() => (
            <Table.Summary fixed>
              <Table.Summary.Row>
                <Table.Summary.Cell index={0} colSpan={9}>
                  <Typography.Text type="secondary">
                    当前筛选范围覆盖 {activeAccessCount} 个接入位置；IP 维度候选详情仍保留在 IP 详情页。
                  </Typography.Text>
                </Table.Summary.Cell>
              </Table.Summary.Row>
            </Table.Summary>
          )}
        />
      </section>
    </main>
  )
}

const columns: ColumnsType<EndpointDeviceRow> = [
  {
    title: 'Endpoint',
    dataIndex: 'endpoint_id',
    width: 210,
    render: (value: string) =>
      value ? (
        <Link className="mono wrap-text" to={`/devices/${encodeURIComponent(value)}`}>
          {value}
        </Link>
      ) : (
        <Typography.Text type="secondary">-</Typography.Text>
      ),
  },
  {
    title: '设备品牌',
    width: 150,
    render: (_, row) => <BrandLogo device={row} />,
  },
  {
    title: '登记状态',
    dataIndex: 'registration_status',
    width: 110,
    render: (value: EndpointDeviceInventory['registration_status']) => (
      <Tag className="tag-margin-zero" color={registrationStatusColor(value)}>{registrationStatusText(value)}</Tag>
    ),
  },
  {
    title: '责任人',
    width: 160,
    render: (_, row) => {
      const name = row.owner_name || row.owner_account
      if (!name) return <Typography.Text type="secondary">-</Typography.Text>
      return (
        <Space orientation="vertical" size={0}>
          <Typography.Text strong className="font-size-md">{name}</Typography.Text>
          {row.owner_department && <Typography.Text type="secondary" className="font-size-xs">{row.owner_department}</Typography.Text>}
        </Space>
      )
    },
  },
  {
    title: '当前账号',
    dataIndex: 'current_account',
    width: 130,
    render: (value?: string) => <Typography.Text className="mono">{value || '-'}</Typography.Text>,
  },
  {
    title: '当前 IP',
    dataIndex: 'current_ip',
    width: 140,
    render: (value?: string) => <Typography.Text className="mono">{value || '-'}</Typography.Text>,
  },
  {
    title: '接入位置',
    dataIndex: 'current_access_id',
    width: 160,
    render: (value?: string) => <Typography.Text>{value || '-'}</Typography.Text>,
  },
  {
    title: '关联规模',
    width: 180,
    render: (_, row) => (
      <Space size="small" wrap>
        <Tag className="tag-margin-zero" color={endpointAccounts(row).length > 1 ? 'orange' : 'blue'}>账号 {endpointAccounts(row).length}</Tag>
        <Tag className="tag-margin-zero">IP {endpointIPs(row).length}</Tag>
        <Tag className="tag-margin-zero">位置 {endpointAccessIDs(row).length}</Tag>
      </Space>
    ),
  },
  {
    title: '置信度',
    dataIndex: 'identity_confidence',
    width: 140,
    render: (value: number) => {
      const pct = Math.round(value * 100)
      const color = pct >= 80 ? '#059669' : pct >= 60 ? '#0284c7' : '#d97706'
      return <Progress percent={pct} size="small" strokeColor={color} />
    },
  },
  {
    title: '摘要',
    dataIndex: 'summary',
    minWidth: 280,
    render: (value: string) => (
      <Typography.Paragraph className="device-page-summary margin-zero font-size-sm" ellipsis={{ rows: 2, tooltip: value }}>
        {value}
      </Typography.Paragraph>
    ),
  },
  {
    title: '最近出现',
    dataIndex: 'last_seen',
    width: 170,
    render: (value?: string) => (
      <Typography.Text className="table-time font-size-sm" type="secondary">
        {value ? new Date(value).toLocaleString() : '-'}
      </Typography.Text>
    ),
  },
]

function registrationStatusText(status: EndpointDeviceInventory['registration_status']) {
  switch (status) {
    case 'registered':
      return '已登记'
    case 'ignored':
      return '已忽略'
    case 'retired':
      return '已退役'
    default:
      return '未登记'
  }
}

function registrationStatusColor(status: EndpointDeviceInventory['registration_status']) {
  switch (status) {
    case 'registered':
      return 'green'
    case 'ignored':
      return 'default'
    case 'retired':
      return 'red'
    default:
      return 'orange'
  }
}

function endpointAccounts(item: EndpointDeviceInventory) {
  return item.accounts ?? []
}

function endpointIPs(item: EndpointDeviceInventory) {
  return item.ips ?? []
}

function endpointAccessIDs(item: EndpointDeviceInventory) {
  return item.access_ids ?? []
}

function coerceEndpointDevice(item: EndpointDeviceInventory): EndpointDeviceInventory {
  if (item.endpoint_id) {
    return {
      ...item,
      accounts: item.accounts ?? [],
      ips: item.ips ?? [],
      access_ids: item.access_ids ?? [],
    }
  }
  const legacy = item as unknown as {
    ip?: string
    summary?: string
    first_seen?: string
    last_seen?: string
    confidence?: number
    devices?: Array<{
      device_id?: string
      endpoint_id?: string
      primary_mac?: string
      account_id?: string
      access_id?: string
      confidence?: number
    }>
  }
  const device = legacy.devices?.[0]
  const endpointId = device?.endpoint_id || device?.device_id || ''
  const account = device?.account_id || ''
  const access = device?.access_id || ''
  return {
    endpoint_id: endpointId,
    primary_mac: device?.primary_mac,
    entity_role: 'endpoint',
    registration_status: 'unregistered',
    merge_status: 'active',
    current_account: account,
    current_ip: legacy.ip,
    current_access_id: access,
    accounts: account ? [account] : [],
    ips: legacy.ip ? [legacy.ip] : [],
    access_ids: access ? [access] : [],
    first_seen: legacy.first_seen,
    last_seen: legacy.last_seen,
    identity_confidence: device?.confidence ?? legacy.confidence ?? 0,
    summary: legacy.summary || '旧版 IP inventory 兼容行，等待 endpoint 身份事件补齐',
  }
}
