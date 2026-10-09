import { Alert, Empty, Input, Space, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
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

const time = (value?: string) => value && !value.startsWith('0001-') ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : ''
const identityStates: Record<string, string> = { supported: '当前身份依据', historical: '历史身份依据', reference: '辅助识别线索' }

export function SharedDeviceProfiles() {
  const [params, setParams] = useSearchParams()
  const pagination = useServerPagination('shared_devices_')
  const keyword = params.get('device_keyword') || ''
  const query = { keyword, limit: pagination.pageSize, cursor: pagination.cursor }
  const profiles = useQuery({
    queryKey: ['shared-device-profiles', query],
    queryFn: () => request<ProfilePage>(`/shared-access/devices?limit=${query.limit}&cursor=${query.cursor}&keyword=${encodeURIComponent(keyword)}`),
    placeholderData: () => undefined,
    staleTime: 5 * 60_000,
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
  const items = profiles.data?.items || []
  const total = profiles.data?.page.total ?? knownTotal
  const columns: ColumnsType<Profile> = [
    { title: '设备', key: 'device', width: 230, render: (_, item) => <DeviceIdentity item={item} /> },
    { title: '网络身份', key: 'network', width: 265, render: (_, item) => <NetworkIdentity item={item} /> },
    { title: '认证身份', key: 'auth', width: 270, render: (_, item) => <AuthIdentity bindings={item.auth_bindings || []} /> },
    { title: '身份与共享状态', key: 'state', width: 230, render: (_, item) => <ProfileState item={item} checkedAt={profiles.data?.checked_at} /> },
    { title: '最近时间', key: 'activity', width: 190, render: (_, item) => <ProfileTimes item={item} /> },
    { title: '操作', key: 'actions', width: 110, render: (_, item) => <ProfileActions item={item} /> },
  ]
  return <section className="shared-profile-panel">
    <div className="shared-profile-heading"><Typography.Title level={4}>设备档案</Typography.Title><Typography.Text type="secondary">共 {total} 条</Typography.Text></div>
    {profiles.data?.activity_state === 'unavailable' && <Alert className="shared-profile-activity-alert" type="warning" showIcon title="最近流量暂时读取失败" description="设备身份档案继续保留，在线情况请稍后核对。" />}
    <Input.Search key={keyword} className="shared-profile-search" defaultValue={keyword} placeholder="IP、MAC、品牌或型号" allowClear onSearch={search} />
    {profiles.isError ? <AppErrorAlert title="设备档案读取失败" /> : profiles.isFetching ? <div className="shared-profile-page-loading" aria-live="polite"><Typography.Text type="secondary">正在加载第 {pagination.page} 页</Typography.Text><AppLoadingState rows={6} /></div> : items.length ? <>
      <div className="shared-profile-desktop-list"><Table rowKey="profile_id" size="small" columns={columns} dataSource={items} pagination={false} scroll={{ x: 1295 }} rowClassName={item => item.identity_state === 'reference' ? 'shared-profile-reference' : ''} /></div>
      <div className="shared-profile-mobile-list" role="list">{items.map(item => <article className={`shared-profile-mobile-row ${item.identity_state === 'reference' ? 'shared-profile-reference' : ''}`} key={item.profile_id} role="listitem">
        <div className="shared-profile-mobile-block">
          <span className="shared-profile-mobile-label">设备身份</span>
          <DeviceIdentity item={item} />
          <ProfileState item={item} checkedAt={profiles.data?.checked_at} />
        </div>
        <div className="shared-profile-mobile-block">
          <span className="shared-profile-mobile-label">网络身份</span>
          <NetworkIdentity item={item} />
        </div>
        {(item.auth_bindings || []).length > 0 && <div className="shared-profile-mobile-block">
          <span className="shared-profile-mobile-label">认证身份</span>
          <AuthIdentity bindings={item.auth_bindings || []} />
        </div>}
        <div className="shared-profile-mobile-block">
          <span className="shared-profile-mobile-label">最近状态</span>
          <ProfileTimes item={item} />
          <ProfileActions item={item} />
        </div>
      </article>)}</div>
    </> : <Empty description="暂无设备身份档案" />}
    {total > 0 && <AppServerPagination disabled={profiles.isFetching} page={pagination.page} pageSize={pagination.pageSize} total={total} onChange={pagination.update} />}
    <details className="shared-profile-help"><summary>数据口径</summary><p className="shared-access-muted">设备身份依据和历史记录持续保留。最近流量、地址归属与当前共享分别核验；设备静默不会删除档案，历史身份不直接证明当前共享。</p></details>
  </section>
}

function DeviceIdentity({ item }: { item: Profile }) {
  const title = formatDeviceName(item.brand, item.model, item.ip || item.mac)
  const roleLabel = item.role === 'router' ? (item.identity_state === 'reference' ? '路由器线索' : '路由器画像') : item.role === 'ap' ? '无线接入点画像' : ''
  return <div className="shared-profile-device"><strong>{title}</strong>{roleLabel && <span>{roleLabel}</span>}{item.identity_basis && <Typography.Text ellipsis={{ tooltip: item.identity_basis }}>{item.identity_basis}</Typography.Text>}</div>
}

function NetworkIdentity({ item }: { item: Profile }) {
  return <div className="shared-profile-network">{item.ip && <strong>{item.ip}</strong>}{item.mac && <span>{item.mac}</span>}{item.endpoint_id && <span>{item.endpoint_id}</span>}{item.address_state === 'reassigned' && <Tag color="error">地址已转移</Tag>}{item.address_state === 'verified' && <Tag color="blue">地址已核验</Tag>}</div>
}

function AuthIdentity({ bindings }: { bindings: AuthBinding[] }) {
  if (!bindings.length) return null
  const certain = bindings.filter(binding => !binding.ambiguous)
  if (!certain.length) return <div className="shared-profile-auth shared-profile-auth-ambiguous"><Tag color="warning">多会话精确命中</Tag><span>{bindings.length} 个当前认证会话</span></div>
  const binding = certain[0]
  return <div className="shared-profile-auth"><strong>{binding.account_id}</strong><span>{binding.assigned_ips.join('、')}</span><span>{binding.match_basis === 'exact_endpoint' ? '终端标识精确匹配' : 'MAC 精确匹配'}</span></div>
}

function ProfileState({ item, checkedAt }: { item: Profile; checkedAt?: string }) {
  const activityRecent = Boolean(item.address_last_activity_at && item.address_state === 'verified' && checkedAt && new Date(checkedAt).getTime() - new Date(item.address_last_activity_at).getTime() >= 0 && new Date(checkedAt).getTime() - new Date(item.address_last_activity_at).getTime() <= 15 * 60 * 1000)
  return <Space wrap size={[4, 4]}><Tag color={item.identity_current ? 'blue' : undefined}>{identityStates[item.identity_state] || ''}</Tag>{activityRecent && <Tag color="blue">最近有流量</Tag>}{item.current_shared && <Tag color="green">已确认当前共享</Tag>}</Space>
}

function ProfileTimes({ item }: { item: Profile }) {
  return <div className="shared-profile-times"><span>身份依据 {time(item.identity_at)}</span>{item.address_last_activity_at && <span>地址流量 {time(item.address_last_activity_at)}</span>}{item.last_shared_at && <span>共享确认 {time(item.last_shared_at)}</span>}</div>
}

function ProfileActions({ item }: { item: Profile }) {
  return <Space orientation="vertical" size={2}>{item.identity_assessment_id && <Link to={`/discovery/routers/${encodeURIComponent(item.identity_assessment_id)}`}>身份记录</Link>}{item.last_shared_observation_id && <Link to={`/shared-access/observations/${encodeURIComponent(item.last_shared_observation_id)}`}>共享记录</Link>}</Space>
}
