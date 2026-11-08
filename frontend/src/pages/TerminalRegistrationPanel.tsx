import { useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Empty, Select, Space, Tag, Typography } from 'antd'
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons'
import { useSearchParams } from 'react-router-dom'
import { request } from '../shared/api/client'
import { useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
import { AppErrorAlert, AppListHeader, AppServerPagination, AppTable, AppTableBar, useCursorPagePosition } from '../shared/ui'
import { observedTimeLabel, observedTimeTitle } from '../shared/ui/observedTime'
import { deviceTypeLabel } from '../entities/device/DeviceInventoryCells'
import type { components } from '../shared/api/generated'

export type RegistrationRow = components['schemas']['EndpointRegistrationRecord']

type RegistrationPage = components['schemas']['EndpointRegistrationPage']
type RegistrationMetadata = { total: number; as_of: string }
type Props = { onCreate: () => void; onEdit: (row: RegistrationRow) => void }

const statuses: Record<string, string> = { registered: '已登记', unregistered: '待登记', ignored: '已忽略', retired: '已退役' }
const ownerships: Record<string, string> = { school_asset: '学校资产', public_terminal: '公共终端', infrastructure: '基础设施', byod: '个人终端' }

export function TerminalRegistrationPanel({ onCreate, onEdit }: Props) {
  const [params, setParams] = useSearchParams()
  const queryClient=useQueryClient()
  const search = params.get('registration_search') || ''
  const status = params.get('registration_status') || ''
  const deviceType = params.get('registration_type') || ''
  const ownership = params.get('registration_ownership') || ''
  const [draft, setDraft] = useState(search)
  const [pageSize, setPageSize] = useState(20)
  const session = useSession()
  const writable = can(session.data, 'endpoints:write')
  useEffect(() => setDraft(search), [search])

  const scope = new URLSearchParams()
  if (search) scope.set('search', search)
  if (status) scope.set('status', status)
  if (deviceType) scope.set('type', deviceType)
  if (ownership) scope.set('ownership_class', ownership)
  const scopeKey = scope.toString()
  const filterKey = `${scopeKey}|${pageSize}`
  const [paging, setPaging] = useState({ key: filterKey, page: 0 })
  useEffect(()=>setPaging(current=>current.key===filterKey?current:{key:filterKey,page:0}),[filterKey])
  const page = paging.key === filterKey ? paging.page : 0
  const position = useCursorPagePosition({ path: '/endpoints/registrations/position', query: scope, page: page + 1, pageSize })
  const query = new URLSearchParams(scope)
  query.set('limit', String(pageSize))
  if (position.cursor) query.set('cursor', position.cursor)

  const records = useQuery({
    queryKey: ['terminal-registrations', query.toString()],
    queryFn: ({ signal }) => request<RegistrationPage>(`/endpoints/registrations?${query}`, { signal }),
    enabled: position.ready,
  })
  const metadata = useQuery({
    queryKey: ['terminal-registration-metadata', scopeKey],
    queryFn: ({ signal }) => request<RegistrationMetadata>(`/endpoints/registrations/metadata${scopeKey ? `?${scopeKey}` : ''}`, { signal }),
  })
  const catalogue = useQuery({
    queryKey: ['discovery-types'],
    queryFn: ({ signal }) => request<components['schemas']['DiscoveryTypeCatalogue']>('/discovery/types', { signal }),
  })
  const types = Object.fromEntries((catalogue.data?.items ?? []).map(item => [item.id, item.label]))
  const items = position.ready ? records.data?.items ?? [] : []
  const filtered = Boolean(search || status || deviceType || ownership)

  const change = (key: string, value: string) => setParams(current => {
    const next = new URLSearchParams(current)
    if (value) next.set(`registration_${key}`, value)
    else next.delete(`registration_${key}`)
    return next
  }, { replace: true })
  const clearFilters = () => {
    setDraft('')
    setParams(current => {
      const next = new URLSearchParams(current)
      for (const key of ['search', 'status', 'type', 'ownership']) next.delete(`registration_${key}`)
      return next
    }, { replace: true })
  }
  const refresh = () => { const first=new URLSearchParams(query);first.delete('cursor');setPaging({key:filterKey,page:0});void position.invalidate();void metadata.refetch();void queryClient.invalidateQueries({queryKey:['terminal-registrations'],refetchType:'none'});void queryClient.refetchQueries({queryKey:['terminal-registrations',first.toString()],exact:true}) }
  const columns = [
    {
      title: '设备 / MAC', key: 'identity', width: 225,
      render: (_: unknown, row: RegistrationRow) => <div className="discovery-ledger-stack">
        {row.registration_details.name && <Typography.Text strong>{row.registration_details.name}</Typography.Text>}
        <Typography.Text className="discovery-identifier" copyable={{ text: row.primary_mac }}>{row.primary_mac}</Typography.Text>
        {row.asset_tag && <Typography.Text type="secondary">资产编号 · {row.asset_tag}</Typography.Text>}
      </div>,
    },
    {
      title: '登记类型 / 型号', key: 'type', width: 160,
      render: (_: unknown, row: RegistrationRow) => <div className="discovery-ledger-stack">
        {row.registration_details.device_type && <Typography.Text>{types[row.registration_details.device_type] ?? deviceTypeLabel(row.registration_details.device_type)}</Typography.Text>}
        <Typography.Text type="secondary">{[row.registration_details.manufacturer, row.registration_details.model].filter(Boolean).join(' · ')}</Typography.Text>
      </div>,
    },
    {
      title: '责任人 / 部门', key: 'owner', width: 160,
      render: (_: unknown, row: RegistrationRow) => <div className="discovery-ledger-stack">
        <Typography.Text>{[row.owner_name, row.owner_account].filter(Boolean).join(' · ')}</Typography.Text>
        <Typography.Text type="secondary">{row.owner_department}</Typography.Text>
      </div>,
    },
    {
      title: '位置 / 登记 IP', key: 'location', width: 180,
      render: (_: unknown, row: RegistrationRow) => <div className="discovery-ledger-stack">
        <Typography.Text>{row.registration_details.location}</Typography.Text>
        <Typography.Text type="secondary" className="discovery-identifier">{row.registration_details.registered_ip}</Typography.Text>
      </div>,
    },
    {
      title: '登记状态 / 归属', key: 'status', width: 140,
      render: (_: unknown, row: RegistrationRow) => <div className="discovery-ledger-stack">
        {statuses[row.registration_status] && <Tag color={row.registration_status === 'registered' ? 'green' : row.registration_status === 'unregistered' ? 'gold' : undefined}>{statuses[row.registration_status]}</Tag>}
        <Typography.Text type="secondary">{ownerships[row.ownership_class] ?? ''}</Typography.Text>
      </div>,
    },
    {
      title: '最近登记更新', key: 'updated', width: 140,
      render: (_: unknown, row: RegistrationRow) => <div className="discovery-ledger-stack">
        {row.registration_updated_at && <Typography.Text title={observedTimeTitle(row.registration_updated_at)}>{observedTimeLabel(row.registration_updated_at)}</Typography.Text>}
        <Typography.Text type="secondary">{row.registration_updated_by}</Typography.Text>
      </div>,
    },
    ...(writable ? [{ title: '操作', key: 'action', width: 100, fixed: 'right' as const, render: (_: unknown, row: RegistrationRow) => <Button type="link" onClick={() => onEdit(row)}>编辑登记</Button> }] : []),
  ]

  return <section className="terminal-registration-panel">
    <AppTableBar
      searchValue={draft}
      onSearchChange={value => { setDraft(value); if (!value) change('search', '') }}
      onSearch={value => change('search', value.trim())}
      searchPlaceholder="搜索名称、MAC、资产编号或责任人"
      filters={<>
        <Select aria-label="登记状态筛选" value={status} options={[{ value: '', label: '全部登记状态' }, ...Object.entries(statuses).map(([value, label]) => ({ value, label }))]} onChange={value => change('status', value)} />
        <Select aria-label="登记类型筛选" value={deviceType} showSearch optionFilterProp="label" options={[{ value: '', label: '全部登记类型' }, ...(catalogue.data?.items ?? []).map(item => ({ value: item.id, label: item.label }))]} onChange={value => change('type', value)} />
        <Select aria-label="终端归属筛选" value={ownership} options={[{ value: '', label: '全部归属' }, ...Object.entries(ownerships).map(([value, label]) => ({ value, label }))]} onChange={value => change('ownership', value)} />
        <Button onClick={() => change('search', draft.trim())}>查询</Button>
        {filtered && <Button type="text" onClick={clearFilters}>清空筛选</Button>}
      </>}
    />
    {catalogue.isError && <AppErrorAlert title="读取登记类型失败" message={catalogue.error.message} />}
    {position.isError && <AppErrorAlert title="页码定位失败" message={position.error.message} action={<Button onClick={() => void position.refetch()}>重试定位</Button>} />}
    {metadata.isError && <AppErrorAlert title="读取登记数量失败" message={metadata.error.message} action={<Button onClick={() => void metadata.refetch()}>重试统计</Button>} />}
    {records.isError ? <AppErrorAlert title="读取登记台账失败" message={records.error.message} action={<Button onClick={() => void records.refetch()}>重新读取</Button>} /> : <section className="surface center-list-surface">
      <AppListHeader
        title="登记台账"
        count={metadata.data ? `共 ${metadata.data.total} 条登记记录` : undefined}
        description="维护设备资料、责任人和位置"
        actions={<Space wrap><Button icon={<ReloadOutlined />} loading={records.isFetching || metadata.isFetching} onClick={refresh}>刷新</Button>{writable && <Button type="primary" icon={<PlusOutlined />} onClick={onCreate}>新增登记</Button>}</Space>}
      />
      <AppTable
        className="passive-ledger-table terminal-registration-table"
        rowKey="endpoint_id"
        columns={columns}
        dataSource={items}
        tableLayout="fixed"
        loading={records.isPending||position.isLocating}
        scroll={{ x: writable ? 1105 : 1005 }}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={filtered ? '当前筛选下暂无登记记录' : '还没有登记设备'}>{filtered ? <Button onClick={clearFilters}>清空筛选</Button> : <Space orientation="vertical"><Typography.Text type="secondary">从设备发现选择登记，或直接录入已有资产。</Typography.Text>{writable && <Button type="primary" onClick={onCreate}>登记第一台设备</Button>}</Space>}</Empty> }}
      />
      {(items.length > 0 || page > 0) && <AppServerPagination
        disabled={records.isFetching || position.isLocating}
        page={page + 1}
        pageSize={pageSize}
        total={metadata.data?.total}
        totalText={metadata.data ? `共 ${metadata.data.total} 条` : metadata.isError ? '数量读取失败' : '正在读取总数'}
        onChange={(nextPage, nextSize) => {
          if (nextSize !== pageSize) { setPageSize(nextSize); return }
          setPaging({ key: filterKey, page: nextPage - 1 })
        }}
      />}
    </section>}
  </section>
}
