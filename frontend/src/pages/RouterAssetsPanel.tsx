import { useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Empty, Modal, Segmented, Select, Space, Tag, Tooltip, Typography } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { Link, useSearchParams } from 'react-router-dom'
import { request } from '../shared/api/client'
import type { components } from '../shared/api/generated'
import { AppErrorAlert, AppListHeader, AppServerPagination, AppTable, AppTableBar, useCursorPagePosition } from '../shared/ui'
import { DeviceAddress } from '../entities/device/DeviceAddress'
import { DiscoveryDeviceIcon } from '../entities/device/DiscoveryDeviceIcon'
import { observedTimeLabel, observedTimeTitle } from '../shared/ui/observedTime'
import { routerSourceLabels } from './routerLabels'
import { DiscoveryEvidenceSummary } from './DiscoveryEvidenceSummary'

type Device = components['schemas']['DiscoveryDevice']
type DevicePage = components['schemas']['DiscoveryDevicePage']
type Metadata = components['schemas']['DiscoveryDeviceMetadata']
type ChassisCandidate = components['schemas']['DiscoveryChassisCandidate']

function rowKey(item: Device) {
  return JSON.stringify([item.id, item.sensor_id, item.site, item.domain, item.vlan, item.mac, item.observations.map(row => row.id).sort()])
}

function currentAddresses(item: Device) {
  return item.current_addresses ?? (item.current && item.primary_ip ? [item.primary_ip] : [])
}

function discoveryLink(item: Device) {
  return `/devices?${new URLSearchParams({ tab: 'discovery', discovery_search: item.mac || item.primary_ip || item.name || '' })}`
}

export function RouterAssetsPanel() {
  const [params, setParams] = useSearchParams()
  const queryClient=useQueryClient()
  const view = params.get('routers_view') === 'ap' ? 'ap' : 'router'
  const type = view === 'ap' ? 'access_point' : 'router'
  const label = view === 'ap' ? '接入点' : '路由器'
  const search = params.get('routers_search') || ''
  const state = params.get('routers_state') || ''
  const window = params.get('routers_window') || '24h'
  const [draft, setDraft] = useState(search)
  const [pageSize, setPageSize] = useState(20)
  const [selected, setSelected] = useState<Device>()
  useEffect(() => setDraft(search), [search])
  const scope = new URLSearchParams({ mode: 'passive', type, window })
  if (search) scope.set('search', search)
  if (state) scope.set('state', state)
  const scopeKey = scope.toString()
  const filterKey = `${scopeKey}|${pageSize}`
  const [paging, setPaging] = useState({ key: filterKey, page: 0 })
  useEffect(()=>setPaging(current=>current.key===filterKey?current:{key:filterKey,page:0}),[filterKey])
  const page = paging.key === filterKey ? paging.page : 0
  const position = useCursorPagePosition({ path: '/discovery/devices/position', query: scope, page: page + 1, pageSize })
  const query = new URLSearchParams(scope)
  query.set('limit', String(pageSize))
  if (position.cursor) query.set('cursor', position.cursor)
  const devices = useQuery({
    queryKey: ['router-assets', query.toString()],
    queryFn: ({ signal }) => request<DevicePage>(`/discovery/devices?${query}`, { signal }),
    enabled: position.ready,
  })
  const metadata = useQuery({
    queryKey: ['router-assets-metadata', scopeKey],
    queryFn: ({ signal }) => request<Metadata>(`/discovery/devices/metadata?${scope}`, { signal }),
  })
  const chassisCandidates = useQuery({
    queryKey: ['router-chassis-candidates', window],
    queryFn: ({ signal }) => request<{ items: ChassisCandidate[] }>(`/discovery/chassis-candidates?window=${window}`, { signal }),
  })
  const candidateByNeighbor = new Map((chassisCandidates.data?.items ?? []).map(candidate => [(candidate.neighbor_mac ?? '').toLowerCase(), candidate]))
  const change = (key: string, value: string) => setParams(current => {
    const next = new URLSearchParams(current)
    if (value) next.set(`routers_${key}`, value)
    else next.delete(`routers_${key}`)
    next.delete('routers_page')
    return next
  }, { replace: true })
  const reset = () => {
    setDraft('')
    setParams(current => {
      const next = new URLSearchParams(current)
      for (const key of ['search', 'state', 'window', 'page']) next.delete(`routers_${key}`)
      return next
    }, { replace: true })
  }
  const refresh = () => { const first=new URLSearchParams(query);first.delete('cursor');setPaging({key:filterKey,page:0});void position.invalidate();void metadata.refetch();void queryClient.invalidateQueries({queryKey:['router-assets'],refetchType:'none'});void queryClient.refetchQueries({queryKey:['router-assets',first.toString()],exact:true}) }
  const items = position.ready ? devices.data?.items ?? [] : []
  const filtered = Boolean(search || state || window !== '24h')
  const columns = [
    {
      title: '设备', key: 'identity', width: 250,
      render: (_: unknown, item: Device) => {
        const candidate = candidateByNeighbor.get((item.mac ?? '').toLowerCase())
        return <div className="router-device-cell">
          <DiscoveryDeviceIcon type={type} />
          <DeviceAddress name={item.name} ip={currentAddresses(item)[0]} addresses={currentAddresses(item)} mac={item.mac} historicalIP={item.last_observed_ip} />
          {candidate && <Tooltip title={(candidate.evidence ?? []).join('；')}>
            <Typography.Text type="secondary" className="router-chassis-candidate">疑似同一机箱：{candidate.partner_ip} · {Math.round(candidate.confidence * 100)}%</Typography.Text>
          </Tooltip>}
        </div>
      },
    },
    {
      title: '类型 / 厂商型号', key: 'type', width: 175,
      render: (_: unknown, item: Device) => <div className="router-identity">
        <Tag color={item.classification_status === 'expired' ? undefined : 'blue'}>{item.classification_status === 'expired' ? `历史${label}` : label}</Tag>
        {(item.manufacturer || item.model_name) && <Typography.Text type="secondary">{[item.manufacturer, item.model_name].filter(Boolean).join(' · ')}</Typography.Text>}
      </div>,
    },
    {
      title: '识别依据', key: 'evidence', width: 175,
      render: (_: unknown, item: Device) => <div className="router-recognition-evidence">
        {(item.protocols ?? []).map(protocol => <Tag key={protocol} className="router-source">{routerSourceLabels[protocol] || protocol.toUpperCase()}</Tag>)}
        {item.classification_status === 'expired' && <Typography.Text type="secondary">类型证据已过期</Typography.Text>}
        {item.classification?.reason && <span className="router-verdict-reason">{item.classification.reason}</span>}
      </div>,
    },
    {
      title: '网络范围', key: 'scope', width: 110,
      render: (_: unknown, item: Device) => <div className="router-identity"><span>{item.domain}</span>{item.vlan && <Typography.Text type="secondary">VLAN {item.vlan}</Typography.Text>}</div>,
    },
    { title: '最近观测', key: 'last_seen', width: 105, render: (_: unknown, item: Device) => <span title={observedTimeTitle(item.last_seen)}>{observedTimeLabel(item.last_seen)}</span> },
    { title: '操作', key: 'action', width: 85, render: (_: unknown, item: Device) => <Button type="link" onClick={() => setSelected(item)}>查看设备</Button> },
  ]
  return <section className="router-observations-panel">
    <div className="router-view-switch"><Segmented aria-label="网络设备类型" value={view} options={[{ value: 'router', label: '路由器' }, { value: 'ap', label: '接入点' }]} onChange={value => change('view', String(value))} /></div>
    <AppTableBar
      searchPlaceholder="搜索设备名称、IP 或 MAC"
      searchValue={draft}
      onSearchChange={value => { setDraft(value); if (!value) change('search', '') }}
      onSearch={value => change('search', value.trim())}
      filters={<>
        <Select aria-label="类型证据状态" value={state} options={[{ value: '', label: '全部类型记录' }, { value: 'identified', label: '当前类型' }, { value: 'expired', label: '历史类型' }]} onChange={value => change('state', value)} />
        <Select aria-label="设备观测范围" value={window} options={[{ value: '24h', label: '近 24 小时' }, { value: '168h', label: '近 7 天' }, { value: '720h', label: '近 30 天' }]} onChange={value => change('window', value)} />
        <Button onClick={() => change('search', draft.trim())}>查询</Button>
        {filtered && <Button type="text" onClick={reset}>清空筛选</Button>}
      </>}
    />
    {position.isError && <AppErrorAlert title="页码定位失败" message={position.error.message} action={<Button onClick={() => void position.refetch()}>重试定位</Button>} />}
    {metadata.isError && <AppErrorAlert title="读取设备数量失败" message={metadata.error.message} action={<Button onClick={() => void metadata.refetch()}>重试统计</Button>} />}
    <section className="surface center-list-surface">
      <AppListHeader
        title={`${label}设备`}
        count={metadata.data ? `共 ${metadata.data.total} 条设备记录` : undefined}
        description="设备类型用于资产管理；违规与共享行为需另行核验。"
        actions={<Button aria-label="刷新设备" icon={<ReloadOutlined />} loading={devices.isFetching || metadata.isFetching} onClick={refresh}>刷新</Button>}
      />
      {devices.isError ? <AppErrorAlert title="读取网络设备失败" message={devices.error.message} action={<Button onClick={() => void devices.refetch()}>重新读取</Button>} /> : <>
        <AppTable className="passive-ledger-table" rowKey={rowKey} columns={columns} dataSource={items} loading={devices.isPending||position.isLocating} tableLayout="fixed" scroll={{ x: 900 }} locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={`当前观测范围内暂无匹配的${label}设备`}>{filtered && <Button onClick={reset}>清空筛选</Button>}</Empty> }} />
        {(items.length > 0 || page > 0) && <AppServerPagination page={page + 1} pageSize={pageSize} disabled={devices.isFetching || position.isLocating}
          total={metadata.data?.total}
          totalText={metadata.data ? `共 ${metadata.data.total} 条` : metadata.isError ? '数量读取失败' : '正在读取总数'}
          onChange={(nextPage, nextSize) => {
            if (nextSize !== pageSize) { setPageSize(nextSize); return }
            setPaging({ key: filterKey, page: nextPage - 1 })
          }} />}
      </>}
    </section>
    <Modal title="设备资料" className="discovery-evidence-modal" open={Boolean(selected)} onCancel={() => setSelected(undefined)} footer={selected ? <Link to={discoveryLink(selected)}>在发现设备中查看</Link> : null}>
      {selected && <>
        <DeviceAddress name={selected.name} ip={currentAddresses(selected)[0]} addresses={currentAddresses(selected)} mac={selected.mac} historicalIP={selected.last_observed_ip} />
        <dl className="discovery-detail-facts">
          {[
            ['设备类型', selected.classification_status === 'expired' ? `历史${label}（类型证据已过期）` : label],
            ['厂商', selected.manufacturer], ['型号', selected.model_name], ['网络域', selected.domain], ['VLAN', selected.vlan],
            ['采集传感器', selected.sensor_id], ['首次观测', observedTimeTitle(selected.first_seen)], ['最近观测', observedTimeTitle(selected.last_seen)],
          ].filter(([, value]) => Boolean(value)).map(([title, value]) => <div key={title}><dt>{title}</dt><dd>{value}</dd></div>)}
        </dl>
        {selected.classification?.reason && <Typography.Paragraph>{selected.classification.reason}</Typography.Paragraph>}
        <Space wrap>{(selected.protocols ?? []).map(protocol => <Tag key={protocol}>{routerSourceLabels[protocol] || protocol.toUpperCase()}</Tag>)}</Space>
        <DiscoveryEvidenceSummary observations={selected.observations ?? []} />
      </>}
    </Modal>
  </section>
}
