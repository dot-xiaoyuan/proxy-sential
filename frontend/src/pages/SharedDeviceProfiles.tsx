import { Notice as Alert } from '../shared/ui/Notice'
import { Button, Drawer, Select, Space, Tag, Typography } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { Link, useLocation, useSearchParams } from 'react-router-dom'
import { detailPath } from '../app/navigation'
import { request } from '../shared/api/client'
import { AppEmptyState, AppErrorAlert, AppListHeader, AppListSection, AppLoadingState, AppServerPagination, AppTable, AppTableBar, formatDateTime, useServerPagination } from '../shared/ui'
import type { ColumnsType } from 'antd/es/table'
import type { components } from '../shared/api/generated'
import { formatDeviceName } from './sharedDeviceProfileFormat'
import { routerRoleLabels, routerStatusLabels } from './routerLabels'

type Profile = components['schemas']['SharedDeviceProfile']
type ProfilePage = components['schemas']['SharedDeviceProfilePage']
type AuthBinding = components['schemas']['RouterAuthBinding']
type ProfileDetail = components['schemas']['SharedDeviceProfileDetail']

const time = formatDateTime
const identityStates: Record<string, string> = { supported: '身份当前有效', historical: '身份已过期', reference: '辅助线索' }
const profileRoles: Record<string, string> = { ...routerRoleLabels, gateway: '网关' }

export function SharedDeviceProfiles() {
  const location = useLocation()
  const [params, setParams] = useSearchParams()
  const [selectedProfile, setSelectedProfile] = useState<string | null>(null)
  const pagination = useServerPagination('shared_devices_')
  const keyword = params.get('device_keyword') || ''
  const role = params.get('device_role') || ''
  const identityState = params.get('device_identity_state') || ''
  const routerStatus = params.get('device_router_status') || ''
  const currentShared = params.get('device_current_shared') || ''
  const accountConflict = params.get('device_account_conflict') || ''
  const query = { hasAccount: true, keyword, role, identityState, routerStatus, currentShared, accountConflict, limit: pagination.pageSize, cursor: pagination.cursor }
  const profiles = useQuery({
    queryKey: ['shared-device-profiles', query],
    queryFn: () => request<ProfilePage>(`/shared-access/devices?has_account=true&limit=${query.limit}&cursor=${query.cursor}&keyword=${encodeURIComponent(keyword)}&role=${encodeURIComponent(role)}&identity_state=${encodeURIComponent(identityState)}&router_status=${encodeURIComponent(routerStatus)}&current_shared=${encodeURIComponent(currentShared)}&account_conflict=${encodeURIComponent(accountConflict)}`),
    placeholderData: () => undefined,
    staleTime: 5 * 60_000,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    refetchInterval: false,
  })
  const detail = useQuery({
    queryKey: ['shared-device-profile-detail', selectedProfile],
    queryFn: () => request<ProfileDetail>(`/shared-access/devices/${encodeURIComponent(selectedProfile || '')}`),
    enabled: Boolean(selectedProfile),
    staleTime: 5 * 60_000,
    refetchOnWindowFocus: false,
  })
  const [knownTotal, setKnownTotal] = useState(0)
  const [moreOpen, setMoreOpen] = useState(false)
  useEffect(() => {
    if (profiles.data && profiles.data.items.length === 0 && pagination.page > 1) pagination.reset()
  }, [pagination, profiles.data])
  useEffect(() => {
    if (profiles.data) setKnownTotal(profiles.data.page.total)
  }, [profiles.data])
  const [searchInput, setSearchInput] = useState(keyword)
  useEffect(() => {
    const timer = globalThis.setTimeout(() => {
      if (searchInput.trim() !== keyword) search(searchInput)
    }, 300)
    return () => globalThis.clearTimeout(timer)
  }, [searchInput])
  const search = (value: string) => setParams(current => {
    const next = new URLSearchParams(current)
    const normalized = value.trim()
    if (normalized) next.set('device_keyword', normalized)
    else next.delete('device_keyword')
    next.set('shared_devices_page', '1')
    next.set('shared_devices_limit', String(pagination.pageSize))
    return next
  }, { replace: true })
  const filter = (name: string, value?: string) => setParams(current => {
    const next = new URLSearchParams(current)
    if (value) next.set(name, value)
    else next.delete(name)
    next.set('shared_devices_page', '1')
    next.set('shared_devices_limit', String(pagination.pageSize))
    return next
  }, { replace: true })
  const items = profiles.data?.items || []
  const total = profiles.data?.page.total ?? knownTotal
  const columns: ColumnsType<Profile> = [
    { title: '设备身份', key: 'device', width: 260, render: (_, item) => <><DeviceIdentity item={item} /><ProfileState item={item} /></> },
    { title: '网络身份', key: 'network', width: 220, render: (_, item) => <NetworkIdentity item={item} /> },
    { title: '认证身份', key: 'auth', width: 180, render: (_, item) => <AuthIdentity item={item} /> },
    { title: '最近记录', key: 'times', width: 160, render: (_, item) => <ProfileTimes item={item} /> },
    { title: '操作', key: 'actions', width: 140, render: (_, item) => <ProfileActions item={item} locationPath={location.pathname + location.search} onHistory={() => setSelectedProfile(item.profile_id)} /> },
  ]

  const alerts = (
    <>
    {profiles.data?.freshness_state === 'stale' && <Alert className="shared-profile-activity-alert" type="warning" showIcon title="终端档案物化暂有延迟" description={profiles.data.materializer_error || `列表继续展示最后一次成功物化的数据${profiles.data.pending_jobs ? `，当前待处理 ${profiles.data.pending_jobs} 项` : ''}。`} />}
    {profiles.data?.freshness_state === 'initializing' && <Alert className="shared-profile-activity-alert" type="info" showIcon title="正在建立新的终端档案" description="本次上线不回填旧记录，新设备证据到达后会逐步出现。" />}
    </>
  )

  const searchBar = (
    <AppTableBar
      searchPlaceholder="IP、MAC、账号、品牌或型号"
      searchValue={searchInput}
      onSearchChange={setSearchInput}
      filters={<>
        <Select className="shared-profile-filter" value={role || undefined} allowClear placeholder="设备角色" onChange={value => filter('device_role', value)} options={[{ value: 'router', label: '路由器' }, { value: 'ap', label: '接入点' }, { value: 'gateway', label: '网关' }, { value: 'switch', label: '交换机' }, { value: 'firewall', label: '防火墙' }, { value: 'shared_gateway', label: '共享网关' }]} />
        <Button size="small" type="text" onClick={() => setMoreOpen(value => !value)}>{moreOpen ? '收起筛选' : '更多筛选'}{[identityState, routerStatus, currentShared, accountConflict].filter(Boolean).length ? `（${[identityState, routerStatus, currentShared, accountConflict].filter(Boolean).length}）` : ''}</Button>
      </>}
      panel={moreOpen ? <div className="app-filter-panel">
        <Select className="shared-profile-filter" value={identityState || undefined} allowClear placeholder="身份状态" onChange={value => filter('device_identity_state', value)} options={Object.entries(identityStates).map(([value, label]) => ({ value, label }))} />
        <Select className="shared-profile-filter" value={routerStatus || undefined} allowClear placeholder="路由身份状态" onChange={value => filter('device_router_status', value)} options={Object.entries(routerStatusLabels).map(([value, label]) => ({ value, label }))} />
        <Select className="shared-profile-filter" value={currentShared || undefined} allowClear placeholder="共享状态" onChange={value => filter('device_current_shared', value)} options={[{ value: 'true', label: '当前共享' }, { value: 'false', label: '非当前共享' }]} />
        <Select className="shared-profile-filter" value={accountConflict || undefined} allowClear placeholder="账号状态" onChange={value => filter('device_account_conflict', value)} options={[{ value: 'true', label: '账号冲突' }, { value: 'false', label: '账号无冲突' }]} />
      </div> : undefined}
    />
  )

  const sharedTail = (
    <>
    <details className="shared-profile-help"><summary>数据口径</summary><p className="shared-access-muted">仅展示有关联认证账号的终端档案；历史认证关联不代表账号当前在线。最后观测来自身份、地址、认证、发现或共享证据，不代表设备当前在线。</p></details>
    <Drawer title="终端档案历史" rootClassName="shared-profile-history-drawer" open={Boolean(selectedProfile)} onClose={() => setSelectedProfile(null)}>
      {detail.isError ? <AppErrorAlert title="档案历史读取失败" /> : detail.isPending ? <AppLoadingState rows={5} /> : <div className="shared-profile-history">
        {(detail.data?.history || []).map((entry, index) => <article key={`${entry.observed_at}-${index}`} className="shared-profile-history-item">
          <div className="shared-profile-history-head"><strong>{time(entry.observed_at)}</strong><Tag>{entry.kind === 'projection' ? '档案变化' : entry.kind}</Tag></div>
          <div className="shared-profile-history-content"><span>{entry.snapshot.display_name}</span>{entry.snapshot.latest_account_id && <span>账号 {entry.snapshot.latest_account_id}</span>}{entry.snapshot.ip && <span>地址 {entry.snapshot.ip}</span>}{profileRoles[entry.snapshot.role || ''] && <span>角色 {profileRoles[entry.snapshot.role || '']}</span>}</div>
        </article>)}
        {!detail.data?.history.length && <AppEmptyState description="暂无档案变化记录" />}
      </div>}
    </Drawer>
    </>
  )

  return <>
    {alerts}
    {searchBar}
    <section className="surface">
      <AppListHeader title="终端档案" count={`${total} 条`} actions={<span className="shared-access-muted">仅显示有认证账号的档案</span>} />
      <AppListSection isError={profiles.isError} errorTitle="终端档案读取失败" isLoading={profiles.isFetching} loadingRows={6} isEmpty={!items.length} emptyText="当前筛选下暂无有认证账号的终端档案">
        <AppTable rowKey="profile_id" columns={columns} dataSource={items} scroll={{ x: 960 }} />
      </AppListSection>
      {total > 0 && <AppServerPagination disabled={profiles.isFetching} page={pagination.page} pageSize={pagination.pageSize} total={total} onChange={pagination.update} />}
    </section>
    {sharedTail}
  </>
}

const roleSourceSuffix: Record<string, string> = { discovery_hint: '线索', inferred_shared_gateway: '（推断）' }

function DeviceIdentity({ item }: { item: Profile }) {
  const title = item.display_name || formatDeviceName(item.brand_reference_only ? '' : item.brand, item.model, item.ip || item.mac)
  const role = profileRoles[item.role || '']
  const suffix = roleSourceSuffix[item.role_source || '']
  return <div className="shared-profile-device"><strong>{title}</strong>{role && <span className={suffix ? 'shared-profile-role-hint' : 'shared-profile-role-assessed'}>{role}{suffix}</span>}{item.brand_reference_only && item.brand && <span className="shared-profile-role-hint">厂商线索：{item.brand}</span>}{item.identity_basis && <Typography.Text ellipsis={{ tooltip: item.identity_basis }}>{item.identity_basis}</Typography.Text>}</div>
}

function NetworkIdentity({ item }: { item: Profile }) {
  const duplicateEndpoint = item.endpoint_id === `mac:${item.mac}`
  return <div className="shared-profile-network">{item.ip && <strong>{item.ip}</strong>}{item.mac && <span>{item.mac}</span>}{item.endpoint_id && !duplicateEndpoint && <span>{item.endpoint_id}</span>}{(item.addresses?.length || 0) > 1 && <span>其他地址 {item.addresses!.length - 1} 个</span>}{item.address_state === 'reassigned' && <Tag color="error">地址已转移</Tag>}{item.address_state === 'verified' && <Tag color="blue">地址已核验</Tag>}</div>
}

function AuthIdentity({ item }: { item: Profile }) {
  const bindings: AuthBinding[] = item.auth_bindings || []
  if (!bindings.length) return <span className="account-placeholder">无认证账号</span>
  const binding = bindings[0]
  return <div className={`shared-profile-auth ${item.account_conflict ? 'shared-profile-auth-ambiguous' : ''}`}><strong>{binding.account_id}</strong>{binding.assigned_ips.length > 0 && <span>{binding.assigned_ips.join('、')}</span>}<span>{binding.match_basis === 'exact_endpoint' ? '终端标识精确匹配' : 'MAC 精确匹配'}{item.latest_account_active ? ' · 会话活跃' : ''}</span>{item.account_conflict && <Tag color="warning">账号身份冲突</Tag>}</div>
}

function ProfileState({ item }: { item: Profile }) {
  return <Space wrap size={[4, 4]}>{routerStatusLabels[item.router_status || ''] && <Tag className={`router-status router-status-${item.router_status}`}>{routerStatusLabels[item.router_status || '']}</Tag>}{identityStates[item.identity_state] && <Tag color={item.identity_current ? 'blue' : undefined}>{identityStates[item.identity_state]}</Tag>}{item.identity_conflict && <Tag color="error">身份冲突</Tag>}{item.current_shared && <Tag color="green">已确认当前共享</Tag>}</Space>
}

function ProfileTimes({ item }: { item: Profile }) {
  const records = [['最后观测', item.last_observed_at], ['账号关联', item.latest_account_at], ['共享确认', item.last_shared_at]]
  return <div className="shared-profile-times">{records.map(([label, value]) => time(value) && <div className="shared-profile-time" key={label}><span>{label}</span><time dateTime={value}>{time(value)}</time></div>)}</div>
}

function ProfileActions({ item, locationPath, onHistory }: { item: Profile; locationPath: string; onHistory: () => void }) {
  return <div className="shared-profile-actions"><Button type="link" className="shared-profile-history-button" onClick={onHistory}>档案历史</Button>{item.identity_assessment_id && <Link to={detailPath(`/discovery/routers/${encodeURIComponent(item.identity_assessment_id)}`, locationPath)}>身份记录</Link>}{item.last_shared_observation_id && <Link to={detailPath(`/shared-access/observations/${encodeURIComponent(item.last_shared_observation_id)}`, locationPath)}>共享记录</Link>}</div>
}
