import { ReloadOutlined } from '@ant-design/icons'
import { Alert, Button, Drawer, Empty, Input, Select, Space, Tag, Typography } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { request } from '../shared/api/client'
import { AppErrorAlert, AppLoadingState, AppServerPagination, useServerPagination } from '../shared/ui'
import type { components } from '../shared/api/generated'
import { formatDeviceName } from './sharedDeviceProfileFormat'

type Profile = components['schemas']['SharedDeviceProfile']
type ProfilePage = components['schemas']['SharedDeviceProfilePage']
type AuthBinding = components['schemas']['RouterAuthBinding']
type ProfileDetail = components['schemas']['SharedDeviceProfileDetail']

const time = (value?: string) => value && !value.startsWith('0001-') ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : ''
const identityStates: Record<string, string> = { supported: '当前身份依据', historical: '历史身份依据', reference: '辅助识别线索' }

export function SharedDeviceProfiles() {
  const [params, setParams] = useSearchParams()
  const [selectedProfile, setSelectedProfile] = useState<string | null>(null)
  const pagination = useServerPagination('shared_devices_')
  const keyword = params.get('device_keyword') || ''
  const role = params.get('device_role') || ''
  const identityState = params.get('device_identity_state') || ''
  const currentShared = params.get('device_current_shared') || ''
  const accountConflict = params.get('device_account_conflict') || ''
  const query = { keyword, role, identityState, currentShared, accountConflict, limit: pagination.pageSize, cursor: pagination.cursor }
  const profiles = useQuery({
    queryKey: ['shared-device-profiles', query],
    queryFn: () => request<ProfilePage>(`/shared-access/devices?limit=${query.limit}&cursor=${query.cursor}&keyword=${encodeURIComponent(keyword)}&role=${encodeURIComponent(role)}&identity_state=${encodeURIComponent(identityState)}&current_shared=${encodeURIComponent(currentShared)}&account_conflict=${encodeURIComponent(accountConflict)}`),
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
  useEffect(() => {
    if (profiles.data && profiles.data.items.length === 0 && pagination.page > 1) pagination.reset()
  }, [pagination, profiles.data])
  useEffect(() => {
    if (profiles.data) setKnownTotal(profiles.data.page.total)
  }, [profiles.data])
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
  return <section className="shared-profile-panel">
    <div className="shared-profile-heading"><Typography.Title level={4}>设备档案</Typography.Title><div className="shared-profile-heading-actions"><Typography.Text type="secondary">共 {total} 条</Typography.Text><Button icon={<ReloadOutlined />} loading={profiles.isFetching} onClick={() => profiles.refetch()}>刷新</Button></div></div>
    {profiles.data?.freshness_state === 'stale' && <Alert className="shared-profile-activity-alert" type="warning" showIcon title="设备档案物化暂有延迟" description={profiles.data.materializer_error || `列表继续展示最后一次成功物化的数据${profiles.data.pending_jobs ? `，当前待处理 ${profiles.data.pending_jobs} 项` : ''}。`} />}
    {profiles.data?.freshness_state === 'initializing' && <Alert className="shared-profile-activity-alert" type="info" showIcon title="正在建立新的设备档案" description="本次上线不回填旧记录，新设备证据到达后会逐步出现。" />}
    <div className="shared-profile-toolbar">
      <Input.Search key={keyword} className="shared-profile-search" defaultValue={keyword} placeholder="IP、MAC、账号、品牌或型号" allowClear onSearch={search} />
      <Select className="shared-profile-filter" value={role || undefined} allowClear placeholder="设备角色" onChange={value => filter('device_role', value)} options={[{ value: 'router', label: '路由器' }, { value: 'ap', label: '无线接入点' }, { value: 'gateway', label: '网关' }, { value: 'switch', label: '交换机' }, { value: 'shared_gateway', label: '共享网关' }]} />
      <Select className="shared-profile-filter" value={identityState || undefined} allowClear placeholder="身份状态" onChange={value => filter('device_identity_state', value)} options={[{ value: 'supported', label: '当前身份依据' }, { value: 'historical', label: '历史身份依据' }, { value: 'reference', label: '辅助识别线索' }]} />
      <Select className="shared-profile-filter" value={currentShared || undefined} allowClear placeholder="共享状态" onChange={value => filter('device_current_shared', value)} options={[{ value: 'true', label: '当前共享' }, { value: 'false', label: '非当前共享' }]} />
      <Select className="shared-profile-filter" value={accountConflict || undefined} allowClear placeholder="账号状态" onChange={value => filter('device_account_conflict', value)} options={[{ value: 'true', label: '账号冲突' }, { value: 'false', label: '账号无冲突' }]} />
    </div>
    {profiles.isError ? <AppErrorAlert title="设备档案读取失败" /> : profiles.isFetching ? <div className="shared-profile-page-loading" aria-live="polite"><Typography.Text type="secondary">正在加载第 {pagination.page} 页</Typography.Text><AppLoadingState rows={6} /></div> : items.length ? <>
      <div className="shared-profile-column-heading" aria-hidden="true"><span>设备身份</span><span>网络身份</span><span>认证身份</span><span>最近记录</span></div>
      <div className="shared-profile-mobile-list" role="list">{items.map(item => <article className={`shared-profile-mobile-row ${item.identity_state === 'reference' ? 'shared-profile-reference' : ''}`} key={item.profile_id} role="listitem">
        <div className="shared-profile-mobile-block shared-profile-block-device">
          <span className="shared-profile-mobile-label">设备身份</span>
          <DeviceIdentity item={item} />
          <ProfileState item={item} />
        </div>
        <div className="shared-profile-mobile-block shared-profile-block-network">
          <span className="shared-profile-mobile-label">网络身份</span>
          <NetworkIdentity item={item} />
        </div>
        <div className={`shared-profile-mobile-block shared-profile-block-auth ${(item.auth_bindings || []).length ? '' : 'shared-profile-block-empty'}`}>
          {(item.auth_bindings || []).length > 0 && <><span className="shared-profile-mobile-label">认证身份</span><AuthIdentity item={item} /></>}
        </div>
        <div className="shared-profile-mobile-block shared-profile-block-records">
          <span className="shared-profile-mobile-label">最近记录</span>
          <ProfileTimes item={item} />
          <ProfileActions item={item} onHistory={() => setSelectedProfile(item.profile_id)} />
        </div>
      </article>)}</div>
    </> : <Empty description="暂无设备身份档案" />}
    {total > 0 && <AppServerPagination disabled={profiles.isFetching} page={pagination.page} pageSize={pagination.pageSize} total={total} onChange={pagination.update} />}
    <details className="shared-profile-help"><summary>数据口径</summary><p className="shared-access-muted">列表直接读取持久化设备档案，不在页面请求时临时关联。最后观测来自身份、地址、认证、发现或共享证据，不代表设备当前在线。</p></details>
    <Drawer title="设备档案历史" rootClassName="shared-profile-history-drawer" open={Boolean(selectedProfile)} onClose={() => setSelectedProfile(null)}>
      {detail.isError ? <AppErrorAlert title="档案历史读取失败" /> : detail.isPending ? <AppLoadingState rows={5} /> : <div className="shared-profile-history">
        {(detail.data?.history || []).map((entry, index) => <article key={`${entry.observed_at}-${index}`} className="shared-profile-history-item">
          <div className="shared-profile-history-head"><strong>{time(entry.observed_at)}</strong><Tag>{entry.kind === 'projection' ? '档案变化' : entry.kind}</Tag></div>
          <div className="shared-profile-history-content"><span>{entry.snapshot.display_name}</span>{entry.snapshot.latest_account_id && <span>账号 {entry.snapshot.latest_account_id}</span>}{entry.snapshot.ip && <span>地址 {entry.snapshot.ip}</span>}{entry.snapshot.role && <span>角色 {entry.snapshot.role}</span>}</div>
        </article>)}
        {!detail.data?.history.length && <Empty description="暂无档案变化记录" />}
      </div>}
    </Drawer>
  </section>
}

function DeviceIdentity({ item }: { item: Profile }) {
  const title = item.display_name || formatDeviceName(item.brand, item.model, item.ip || item.mac)
  const roles: Record<string, string> = { router: '路由器', ap: '无线接入点', access_point: '无线接入点', gateway: '网关', switch: '交换机', shared_gateway: '共享网关' }
  return <div className="shared-profile-device"><strong>{title}</strong>{roles[item.role || ''] && <span>{roles[item.role || '']}</span>}{item.identity_basis && <Typography.Text ellipsis={{ tooltip: item.identity_basis }}>{item.identity_basis}</Typography.Text>}</div>
}

function NetworkIdentity({ item }: { item: Profile }) {
  const duplicateEndpoint = item.endpoint_id === `mac:${item.mac}`
  return <div className="shared-profile-network">{item.ip && <strong>{item.ip}</strong>}{item.mac && <span>{item.mac}</span>}{item.endpoint_id && !duplicateEndpoint && <span>{item.endpoint_id}</span>}{(item.addresses?.length || 0) > 1 && <span>其他地址 {item.addresses!.length - 1} 个</span>}{item.address_state === 'reassigned' && <Tag color="error">地址已转移</Tag>}{item.address_state === 'verified' && <Tag color="blue">地址已核验</Tag>}</div>
}

function AuthIdentity({ item }: { item: Profile }) {
  const bindings: AuthBinding[] = item.auth_bindings || []
  if (!bindings.length) return null
  const binding = bindings[0]
  return <div className={`shared-profile-auth ${item.account_conflict ? 'shared-profile-auth-ambiguous' : ''}`}><strong>{binding.account_id}</strong>{binding.assigned_ips.length > 0 && <span>{binding.assigned_ips.join('、')}</span>}<span>{binding.match_basis === 'exact_endpoint' ? '终端标识精确匹配' : 'MAC 精确匹配'}{item.latest_account_active ? ' · 会话活跃' : ''}</span>{item.account_conflict && <Tag color="warning">账号身份冲突</Tag>}</div>
}

function ProfileState({ item }: { item: Profile }) {
  return <Space wrap size={[4, 4]}><Tag color={item.identity_current ? 'blue' : undefined}>{identityStates[item.identity_state] || ''}</Tag>{item.identity_conflict && <Tag color="error">身份冲突</Tag>}{item.current_shared && <Tag color="green">已确认当前共享</Tag>}</Space>
}

function ProfileTimes({ item }: { item: Profile }) {
  const records = [['最后观测', item.last_observed_at], ['账号关联', item.latest_account_at], ['共享确认', item.last_shared_at]]
  return <div className="shared-profile-times">{records.map(([label, value]) => time(value) && <div className="shared-profile-time" key={label}><span>{label}</span><time dateTime={value}>{time(value)}</time></div>)}</div>
}

function ProfileActions({ item, onHistory }: { item: Profile; onHistory: () => void }) {
  return <div className="shared-profile-actions"><Button type="link" className="shared-profile-history-button" onClick={onHistory}>档案历史</Button>{item.identity_assessment_id && <Link to={`/discovery/routers/${encodeURIComponent(item.identity_assessment_id)}`}>身份记录</Link>}{item.last_shared_observation_id && <Link to={`/shared-access/observations/${encodeURIComponent(item.last_shared_observation_id)}`}>共享记录</Link>}</div>
}
