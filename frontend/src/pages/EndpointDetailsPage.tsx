import { useEffect, useMemo } from 'react'
import { Link, useParams } from 'react-router-dom'
import { App as AntApp, Alert, Button, Descriptions, Form, Input, Progress, Select, Skeleton, Space, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import { useDevices, useDeviceSignals, useEndpointIdentity, useSession, useUpdateEndpointRegistration } from '../shared/api/queries'
import type {
  AccountSession,
  DeviceSignal,
  EndpointIdentityProfile,
  IdentityAccessHistory,
  IdentityIPMACHistory,
  UpdateEndpointRegistrationRequest,
} from '../shared/api/types'
import { can } from '../shared/auth/permissions'

export function EndpointDetailsPage() {
  const rawEndpointId = useParams().endpointId ?? ''
  const endpointId = decodeURIComponent(rawEndpointId)
  const { message } = AntApp.useApp()
  const [registrationForm] = Form.useForm<UpdateEndpointRegistrationRequest>()
  const identity = useEndpointIdentity(endpointId, { limit: 500 })
  const signals = useDeviceSignals({ window: '24h', q: endpointId, include_weak: true, limit: 200 })
  const inventory = useDevices({ window: '24h', q: endpointId, limit: 1 })
  const session = useSession()
  const updateRegistration = useUpdateEndpointRegistration()

  const profile = identity.data ?? fallbackEndpointProfile(endpointId)
  const canUpdateRegistration = can(session.data, 'endpoints:write')
  const mergeStatus = Form.useWatch('merge_status', registrationForm)
  const latestIP = profile?.ip_history?.[0]?.ip ?? ''
  const latestAccess = profile?.access_history?.[0]?.access_id ?? ''
  const signalItems = signals.data?.items ?? []
  const recognition = inventory.data?.items.find((item) => item.endpoint_id === endpointId)
  const uniqueIPs = useMemo(() => uniqueValues(profile?.ip_history?.map((item) => item.ip ?? '') ?? []), [profile])
  const uniqueAccessIDs = useMemo(
    () => uniqueValues(profile?.access_history?.map((item) => item.access_id) ?? []),
    [profile],
  )

  useEffect(() => {
    if (!identity.data) {
      return
    }
    const endpoint = identity.data.endpoint
    registrationForm.setFieldsValue({
      registration_status: endpoint.registration_status,
      owner_account: endpoint.owner_account ?? '',
      owner_name: endpoint.owner_name ?? '',
      owner_department: endpoint.owner_department ?? '',
      asset_tag: endpoint.asset_tag ?? '',
      ownership_class: endpoint.ownership_class ?? 'unknown',
      registration_note: endpoint.registration_note ?? '',
      merge_status: endpoint.merge_status ?? 'active',
      merged_into_endpoint_id: endpoint.merged_into_endpoint_id ?? '',
      split_from_endpoint_id: endpoint.split_from_endpoint_id ?? '',
    })
  }, [identity.data, registrationForm])

  if (identity.isLoading) {
    return <Skeleton active />
  }

  return (
    <main className="page">
      <div className="page-header">
        <div>
          <Typography.Title className="page-title mono" level={3}>
            {profile.endpoint_id}
          </Typography.Title>
          <Typography.Text type="secondary">终端登记、账号历史、IP 历史、接入位置和设备信号。</Typography.Text>
        </div>
        <Space wrap>
          <Tag color={registrationStatusColor(profile.endpoint.registration_status)}>
            {registrationStatusText(profile.endpoint.registration_status)}
          </Tag>
          <Tag color={profile.accounts.length > 1 ? 'orange' : 'blue'}>账号 {profile.accounts.length}</Tag>
        </Space>
      </div>

      <section className="metric-grid">
        <div className="surface metric-card">
          <Typography.Text type="secondary">关联账号</Typography.Text>
          <Typography.Title className="metric-card-value" level={3}>
            {profile.accounts.length}
          </Typography.Title>
        </div>
        <div className="surface metric-card">
          <Typography.Text type="secondary">历史 IP</Typography.Text>
          <Typography.Title className="metric-card-value" level={3}>
            {uniqueIPs.length}
          </Typography.Title>
        </div>
        <div className="surface metric-card">
          <Typography.Text type="secondary">接入位置</Typography.Text>
          <Typography.Title className="metric-card-value" level={3}>
            {uniqueAccessIDs.length}
          </Typography.Title>
        </div>
        <div className="surface metric-card">
          <Typography.Text type="secondary">身份置信度</Typography.Text>
          <Progress percent={Math.round(profile.endpoint.identity_confidence * 100)} size="small" />
        </div>
      </section>

      <section className="details-grid">
        {identity.isError && (
          <Alert
            className="endpoint-detail-alert"
            showIcon
            title="终端身份历史暂不可用，当前展示最小 endpoint 视图"
            type="warning"
          />
        )}
        <div className="surface">
          <Typography.Title level={4}>登记信息</Typography.Title>
          <Descriptions column={1} size="small">
            <Descriptions.Item label="登记状态">{registrationStatusText(profile.endpoint.registration_status)}</Descriptions.Item>
            <Descriptions.Item label="责任账号">{profile.endpoint.owner_account || '-'}</Descriptions.Item>
            <Descriptions.Item label="责任人">{profile.endpoint.owner_name || '-'}</Descriptions.Item>
            <Descriptions.Item label="部门">{profile.endpoint.owner_department || '-'}</Descriptions.Item>
            <Descriptions.Item label="资产编号">{profile.endpoint.asset_tag || '-'}</Descriptions.Item>
            <Descriptions.Item label="终端归属">{ownershipClassText(profile.endpoint.ownership_class)}</Descriptions.Item>
            <Descriptions.Item label="合并状态">{profile.endpoint.merge_status || 'active'}</Descriptions.Item>
            <Descriptions.Item label="备注">{profile.endpoint.registration_note || '-'}</Descriptions.Item>
          </Descriptions>
        </div>

        <div className="surface">
          <Typography.Title level={4}>当前观察</Typography.Title>
          <Descriptions column={1} size="small">
            <Descriptions.Item label="MAC">{profile.endpoint.primary_mac || '-'}</Descriptions.Item>
            <Descriptions.Item label="当前账号">{profile.accounts[0] || '-'}</Descriptions.Item>
            <Descriptions.Item label="当前 IP">
              {latestIP ? <Link className="mono" to={`/ips/${encodeURIComponent(latestIP)}`}>{latestIP}</Link> : '-'}
            </Descriptions.Item>
            <Descriptions.Item label="当前接入">{latestAccess || '-'}</Descriptions.Item>
            <Descriptions.Item label="首次发现">{formatTime(profile.first_seen)}</Descriptions.Item>
            <Descriptions.Item label="最近活跃">{formatTime(profile.last_seen)}</Descriptions.Item>
          </Descriptions>
        </div>
        <div className="surface">
          <Typography.Title level={4}>设备识别</Typography.Title>
          <Descriptions column={1} size="small">
            <Descriptions.Item label="注册厂商">{recognition?.vendor || '未知'}（{confidenceText(recognition?.vendor_confidence)}）</Descriptions.Item>
            <Descriptions.Item label="终端品牌">{recognition?.brand || '未知'}（{confidenceText(recognition?.brand_confidence)}）</Descriptions.Item>
            <Descriptions.Item label="型号">{recognition?.model || '未知'}（{confidenceText(recognition?.model_confidence)}）</Descriptions.Item>
            <Descriptions.Item label="类型">{recognition?.device_type || '未知'}（{confidenceText(recognition?.device_type_confidence)}）</Descriptions.Item>
            <Descriptions.Item label="操作系统">{recognition?.os_family || '未知'}（{confidenceText(recognition?.os_family_confidence)}）</Descriptions.Item>
            <Descriptions.Item label="规则版本"><Typography.Text className="mono list-cell-nowrap">{recognition?.fingerprint_version || '-'}</Typography.Text></Descriptions.Item>
            <Descriptions.Item label="随机 MAC">{recognition?.randomized_mac ? '是；不使用 OUI 判断厂商' : '否'}</Descriptions.Item>
            <Descriptions.Item label="识别冲突">{recognition?.recognition_conflict ? '是；列表按未知设备处理' : '否'}</Descriptions.Item>
            <Descriptions.Item label="识别证据">{recognition?.recognition_evidence?.join('；') || '暂无'}</Descriptions.Item>
          </Descriptions>
        </div>
      </section>

      <section className="surface endpoint-registration-editor">
        <div className="surface-title-row">
          <Typography.Title className="surface-title" level={4}>更新设备登记</Typography.Title>
          <Typography.Text className="surface-subtitle" type="secondary">保存后记录操作者、时间和审计日志</Typography.Text>
        </div>
        {!canUpdateRegistration && (
          <Alert showIcon title="当前会话没有 endpoints:write 权限，登记表单只读" type="warning" />
        )}
        <Form<UpdateEndpointRegistrationRequest>
          className="endpoint-registration-form"
          disabled={!canUpdateRegistration}
          form={registrationForm}
          layout="vertical"
          onFinish={(payload) => {
            updateRegistration.mutate(
              { endpointId, payload },
              {
                onError: (error) => message.error(error.message),
                onSuccess: () => message.success('设备登记已更新'),
              },
            )
          }}
        >
          <div className="endpoint-registration-grid">
            <Form.Item label="登记状态" name="registration_status" rules={[{ required: true }]}>
              <Select options={[
                { label: '未登记', value: 'unregistered' },
                { label: '已登记', value: 'registered' },
                { label: '已忽略', value: 'ignored' },
                { label: '已退役', value: 'retired' },
              ]} />
            </Form.Item>
            <Form.Item label="责任账号" name="owner_account">
              <Input placeholder="账号或工号" />
            </Form.Item>
            <Form.Item
              dependencies={['registration_status', 'owner_account', 'asset_tag']}
              label="责任人"
              name="owner_name"
              rules={[({ getFieldValue }) => ({
                validator: (_, value) => {
                  if (getFieldValue('registration_status') !== 'registered' || value || getFieldValue('owner_account') || getFieldValue('asset_tag')) {
                    return Promise.resolve()
                  }
                  return Promise.reject(new Error('已登记设备至少填写责任账号、责任人或资产编号之一'))
                },
              })]}
            >
              <Input placeholder="人工确认的责任人" />
            </Form.Item>
            <Form.Item label="部门" name="owner_department">
              <Input placeholder="部门或管理单位" />
            </Form.Item>
            <Form.Item label="资产编号" name="asset_tag">
              <Input placeholder="资产编号" />
            </Form.Item>
            <Form.Item label="终端归属" name="ownership_class" rules={[{ required: true }]}>
              <Select options={[{ label: '未知', value: 'unknown' }, { label: '个人终端（BYOD）', value: 'byod' }, { label: '学校资产', value: 'school_asset' }, { label: '公共终端', value: 'public_terminal' }, { label: '基础设施', value: 'infrastructure' }]} />
            </Form.Item>
            <Form.Item label="合并状态" name="merge_status" rules={[{ required: true }]}>
              <Select options={[
                { label: '正常', value: 'active' },
                { label: '已合并', value: 'merged' },
                { label: '拆分来源', value: 'split' },
              ]} />
            </Form.Item>
            {mergeStatus === 'merged' && (
              <Form.Item label="合并到 Endpoint" name="merged_into_endpoint_id" rules={[{ required: true, message: '请填写合并目标 Endpoint' }]}>
                <Input className="mono" placeholder="mac:xx:xx:xx:xx:xx:xx" />
              </Form.Item>
            )}
            {mergeStatus === 'split' && (
              <Form.Item label="拆分自 Endpoint" name="split_from_endpoint_id">
                <Input className="mono" placeholder="原 Endpoint ID" />
              </Form.Item>
            )}
            <Form.Item className="endpoint-registration-note" label="登记备注" name="registration_note">
              <Input.TextArea placeholder="记录人工确认依据、设备类型或例外原因" rows={3} />
            </Form.Item>
          </div>
          <div className="endpoint-registration-actions">
            <Button htmlType="submit" loading={updateRegistration.isPending} type="primary">保存登记</Button>
          </div>
        </Form>
      </section>

      <section className="surface">
        <div className="surface-title-row">
          <Typography.Title className="surface-title" level={4}>账号会话历史</Typography.Title>
          <Typography.Text className="surface-subtitle" type="secondary">按认证会话和 endpoint 关联生成</Typography.Text>
        </div>
        <Table<AccountSession>
          columns={sessionColumns}
          dataSource={profile.sessions}
          pagination={{ pageSize: 8, showSizeChanger: false }}
          rowKey="session_id"
          scroll={{ x: 860 }}
          size="small"
        />
      </section>

      <section className="surface">
        <div className="surface-title-row">
          <Typography.Title className="surface-title" level={4}>IP 与接入历史</Typography.Title>
          <Typography.Text className="surface-subtitle" type="secondary">动态 IP 不再被当成终端身份</Typography.Text>
        </div>
        <div className="endpoint-detail-history-grid">
          <Table<IdentityIPMACHistory>
            columns={ipColumns}
            dataSource={profile.ip_history}
            pagination={{ pageSize: 8, showSizeChanger: false }}
            rowKey="event_id"
            scroll={{ x: 680 }}
            size="small"
          />
          <Table<IdentityAccessHistory>
            columns={accessColumns}
            dataSource={profile.access_history}
            pagination={{ pageSize: 8, showSizeChanger: false }}
            rowKey="event_id"
            scroll={{ x: 760 }}
            size="small"
          />
        </div>
      </section>

      <section className="surface">
        <div className="surface-title-row">
          <Typography.Title className="surface-title" level={4}>设备信号</Typography.Title>
          <Typography.Text className="surface-subtitle" type="secondary">DHCP、Software、指纹和其他终端线索</Typography.Text>
        </div>
        {signals.isError ? (
          <Alert showIcon title="设备信号加载失败" type="warning" />
        ) : (
          <Table<DeviceSignal>
            columns={signalColumns}
            dataSource={signalItems}
            locale={{ emptyText: '暂无该 endpoint 的设备信号' }}
            pagination={{ pageSize: 8, showSizeChanger: false }}
            rowKey="signal_id"
            scroll={{ x: 920 }}
            size="small"
          />
        )}
      </section>
    </main>
  )
}

const sessionColumns: ColumnsType<AccountSession> = [
  { title: '账号', dataIndex: 'account_id', width: 150, render: (value: string) => <Typography.Text className="mono">{value}</Typography.Text> },
  { title: 'IP', dataIndex: 'ip', width: 140, render: (value?: string) => value || '-' },
  { title: 'MAC', dataIndex: 'mac', width: 170, render: (value?: string) => <Typography.Text className="mono">{value || '-'}</Typography.Text> },
  { title: '接入位置', dataIndex: 'access_id', width: 180, render: (value?: string) => value || '-' },
  { title: '来源', dataIndex: 'source', width: 120 },
  { title: '开始时间', dataIndex: 'started_at', width: 180, render: formatTime },
  { title: '置信度', dataIndex: 'identity_confidence', width: 130, render: (value: number) => <Progress percent={Math.round(value * 100)} size="small" /> },
]

const ipColumns: ColumnsType<IdentityIPMACHistory> = [
  { title: 'IP', dataIndex: 'ip', width: 150, render: (value?: string) => value ? <Link className="mono" to={`/ips/${encodeURIComponent(value)}`}>{value}</Link> : '-' },
  { title: 'MAC', dataIndex: 'mac', width: 170, render: (value?: string) => <Typography.Text className="mono">{value || '-'}</Typography.Text> },
  { title: '账号', dataIndex: 'account_id', width: 150, render: (value?: string) => <Typography.Text className="mono">{value || '-'}</Typography.Text> },
  { title: '来源', dataIndex: 'source', width: 120 },
  { title: '最近出现', dataIndex: 'last_seen', width: 180, render: formatTime },
]

const accessColumns: ColumnsType<IdentityAccessHistory> = [
  { title: '接入 ID', dataIndex: 'access_id', width: 180 },
  { title: 'AP', dataIndex: 'ap', width: 150, render: (value?: string) => value || '-' },
  { title: '交换机', dataIndex: 'switch_id', width: 150, render: (value?: string) => value || '-' },
  { title: '端口', dataIndex: 'switch_port', width: 120, render: (value?: string) => value || '-' },
  { title: 'VLAN', dataIndex: 'vlan', width: 100, render: (value?: string) => value || '-' },
  { title: '最近出现', dataIndex: 'last_seen', width: 180, render: formatTime },
]

const signalColumns: ColumnsType<DeviceSignal> = [
  { title: '来源', dataIndex: 'source', width: 130 },
  { title: '类型', dataIndex: 'kind', width: 150 },
  { title: '值', dataIndex: 'value', minWidth: 260, render: (value: string) => <Typography.Text className="wrap-text">{value}</Typography.Text> },
  { title: '强度', dataIndex: 'strength', width: 100, render: (value: string) => <Tag color={signalStrengthColor(value)}>{value}</Tag> },
  { title: '置信度', dataIndex: 'confidence', width: 130, render: (value: number) => <Progress percent={Math.round(value * 100)} size="small" /> },
  { title: '最近出现', dataIndex: 'last_seen', width: 180, render: formatTime },
]

function registrationStatusText(status?: string) {
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

function registrationStatusColor(status?: string) {
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

function ownershipClassText(value?: string) {
  return ({ byod: '个人终端（BYOD）', school_asset: '学校资产', public_terminal: '公共终端', infrastructure: '基础设施', unknown: '未知' } as Record<string, string>)[value ?? 'unknown'] ?? '未知'
}

function confidenceText(value?: number) {
  return `${Math.round((value ?? 0) * 100)}%`
}

function signalStrengthColor(value: string) {
  switch (value) {
    case 'strong':
      return 'green'
    case 'medium':
      return 'blue'
    default:
      return 'default'
  }
}

function formatTime(value?: string) {
  return value ? new Date(value).toLocaleString() : '-'
}

function uniqueValues(values: string[]) {
  return Array.from(new Set(values.filter(Boolean))).sort()
}

function fallbackEndpointProfile(endpointId: string): EndpointIdentityProfile {
  const now = new Date().toISOString()
  return {
    endpoint_id: endpointId,
    summary: `终端 ${endpointId} 暂无完整身份历史`,
    endpoint: {
      endpoint_id: endpointId,
      entity_role: 'endpoint',
      first_seen: now,
      last_seen: now,
      identity_confidence: 0,
      attributes: {},
      registration_status: 'unregistered',
      ownership_class: 'unknown',
      merge_status: 'active',
    },
    accounts: [],
    sessions: [],
    ip_history: [],
    access_history: [],
    first_seen: now,
    last_seen: now,
  }
}
