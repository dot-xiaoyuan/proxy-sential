import { Notice as Alert } from '../shared/ui/Notice'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query'
import { Button, Card, Descriptions, Empty, Form, Input, InputNumber, Modal, Select, Space, Switch, Table, Tabs, Tag, Typography, message } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { request } from '../shared/api/client'
import { useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
import { AppFactBar, AppLoadingState, AppPageHeader, AppServerPagination, useServerPagination } from '../shared/ui'
import { statusText } from '../shared/ui/status'
import { useUrlState } from '../shared/ui/useUrlState'
import type { components } from '../shared/api/generated'

type Channel = components['schemas']['BehaviorReportChannel']
type ChannelPage = components['schemas']['BehaviorReportChannelPage']
type OutboxRow = components['schemas']['BehaviorReportOutboxRow']
type OutboxPage = components['schemas']['BehaviorReportOutboxPage']
type OutboxDetail = components['schemas']['BehaviorReportOutboxDetail']

const authTypes: Record<string, string> = { none: '无鉴权', bearer: 'Bearer 令牌', oauth2_client_credentials: 'OAuth2 客户端凭据' }
const eventTypes: Record<string, string> = { poison_behavior: '投毒行为', proxy_behavior: '代理行为', ai_relay_audit: 'AI 中转站审计' }
const statusFilters = ['queued', 'sending', 'sent', 'failed', 'cancelled']
const when = (value?: string) => (value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '')

const defaultMapping = {
  behavior_type: 'event_type',
  account: 'account',
  source_ip: 'ip',
  occurred_at: 'occurred_at',
  target: 'target',
}

export function BehaviorReportsPage() {
  const session = useSession()
  const writable = can(session.data, 'behavior-reports:manage')
  const cache = useQueryClient()
  const [tab, setTab] = useUrlState('tab', 'channels', ['channels', 'outbox'])
  const channels = useQuery({ queryKey: ['behavior-reports', 'channels'], queryFn: () => request<ChannelPage>('/behavior-reports/channels') })
  const invalidate = () => void cache.invalidateQueries({ queryKey: ['behavior-reports'] })
  return (
    <section className="page behavior-reports-page">
      <AppPageHeader title="网络安全行为上报" subtitle="向外部安全平台上报投毒、代理与 AI 中转站行为" onRefresh={invalidate} />
      <AppFactBar label="行为上报规则" items={['通道默认关闭，未启用时不会有任何外发','上报只写外部平台，不产生策略动作','字段映射可填“=常量”写固定值，或填证据字段名取值']} />
      <Card>
        <Tabs activeKey={tab} onChange={setTab} items={[
          { key: 'channels', label: '上报通道', children: <ChannelsPanel channels={channels} writable={writable} invalidate={invalidate} /> },
          { key: 'outbox', label: '上报队列', children: <OutboxPanel writable={writable} /> },
        ]} />
      </Card>
    </section>
  )
}

function ChannelsPanel({ channels, writable, invalidate }: { channels: UseQueryResult<ChannelPage>; writable: boolean; invalidate: () => void }) {
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<Channel>()
  const [preview, setPreview] = useState<string>()
  const [form] = Form.useForm()
  const save = useMutation({
    mutationFn: (value: Record<string, unknown>) => request<Channel>(editing ? `/behavior-reports/channels/${encodeURIComponent(editing.channel_id ?? '')}` : '/behavior-reports/channels', { method: editing ? 'PUT' : 'POST', body: JSON.stringify(value) }),
    onSuccess: () => { invalidate(); setOpen(false); message.success('通道已保存') },
    onError: (error: Error) => message.error(error.message),
  })
  const remove = useMutation({
    mutationFn: (id: string) => request(`/behavior-reports/channels/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    onSuccess: () => { invalidate(); message.success('通道已删除') },
    onError: (error: Error) => message.error(error.message),
  })
  const test = useMutation({
    mutationFn: (id: string) => request<{ status: string; http_status: number; remote_id?: string; error?: string }>(`/behavior-reports/channels/${encodeURIComponent(id)}/test`, { method: 'POST' }),
    onSuccess: (data) => (data.status === 'succeeded' ? message.success('平台已接受测试上报') : message.error(data.error || '平台拒绝或不可用')),
    onError: (error: Error) => message.error(error.message),
  })
  const runPreview = useMutation({
    mutationFn: (id: string) => request<{ payload: Record<string, unknown> }>(`/behavior-reports/channels/${encodeURIComponent(id)}/preview`, { method: 'POST' }),
    onSuccess: (data) => setPreview(JSON.stringify(data.payload, null, 2)),
    onError: (error: Error) => message.error(error.message),
  })
  const edit = (item?: Channel) => {
    setEditing(item)
    form.resetFields()
    form.setFieldsValue(item ? { ...item, secret: undefined } : { auth_type: 'none', token_method: 'GET', enabled: false, batch_size: 100, timeout_seconds: 10, success_status_codes: '200', field_mapping: JSON.stringify(defaultMapping, null, 2) })
    setOpen(true)
  }
  const columns: ColumnsType<Channel> = [
    { title: '名称', dataIndex: 'name', render: (value: string, row) => <div><strong>{value}</strong><div className="notifications-muted">{row.channel_id}</div></div> },
    { title: '鉴权', dataIndex: 'auth_type', width: 160, render: (value: string) => authTypes[value] ?? value },
    { title: '密钥', dataIndex: 'has_secret', width: 90, render: (value: boolean) => (value ? <Tag color="blue">已配置</Tag> : '') },
    { title: '批量', dataIndex: 'batch_size', width: 80 },
    { title: '状态', dataIndex: 'enabled', width: 90, render: (value: boolean) => <Tag color={value ? 'blue' : undefined}>{value ? '已启用' : '已停用'}</Tag> },
    {
      title: '操作', width: 230,
      render: (_value, row) => (
        <Space wrap>
          <Button size="small" loading={test.isPending && test.variables === row.channel_id} onClick={() => test.mutate(row.channel_id)}>测试</Button>
          <Button size="small" loading={runPreview.isPending && runPreview.variables === row.channel_id} onClick={() => { setPreview(undefined); runPreview.mutate(row.channel_id) }}>试算</Button>
          <Button size="small" disabled={!writable} onClick={() => edit(row)}>编辑</Button>
          <Button size="small" danger disabled={!writable} onClick={() => remove.mutate(row.channel_id)}>删除</Button>
        </Space>
      ),
    },
  ]
  return (
    <>
      <div className="notifications-toolbar">
        <Typography.Text type="secondary">密钥使用处置主密钥加密保存，接口不会回显；编辑时留空保持原密钥，填写“-”清空。</Typography.Text>
        <Button type="primary" disabled={!writable} onClick={() => edit()}>新增通道</Button>
      </div>
      {channels.isError ? <Alert type="error" showIcon title="通道读取失败" description={String(channels.error)} /> : channels.isLoading ? <AppLoadingState rows={3} /> : channels.data?.items.length ? <Table rowKey="channel_id" className="compact-list-table" columns={columns} dataSource={channels.data.items} pagination={false} scroll={{ x: 1000 }} /> : <Empty description="暂无上报通道" />}
      <Modal forceRender width={700} title={editing ? '编辑上报通道' : '新增上报通道'} open={open} confirmLoading={save.isPending} onCancel={() => setOpen(false)} onOk={() => void form.validateFields().then((value) => {
        let mapping: Record<string, string> = {}
        try {
          mapping = value.field_mapping ? JSON.parse(String(value.field_mapping)) as Record<string, string> : {}
        } catch {
          message.error('字段映射必须是 JSON 对象')
          return
        }
        const codes = String(value.success_status_codes ?? '200').split(',').map((item: string) => Number(item.trim())).filter((item: number) => Number.isFinite(item))
        save.mutate({ ...value, field_mapping: mapping, success_status_codes: codes })
      }).catch(() => undefined)}>
        <Form form={form} layout="vertical">
          <Form.Item name="channel_id" label="通道标识" rules={[{ required: !editing, max: 128 }]}><Input disabled={!!editing} placeholder="例如 ncu-behavior" /></Form.Item>
          <Form.Item name="name" label="名称" rules={[{ required: true, max: 128 }]}><Input /></Form.Item>
          <Form.Item name="endpoint_url" label="上报地址" rules={[{ required: true }]}><Input placeholder="https://.../security-behavior/report" /></Form.Item>
          <Form.Item name="auth_type" label="鉴权方式" rules={[{ required: true }]}><Select options={Object.entries(authTypes).map(([value, label]) => ({ value, label }))} /></Form.Item>
          <Form.Item noStyle shouldUpdate={(previous, next) => previous.auth_type !== next.auth_type}>
            {({ getFieldValue }) => getFieldValue('auth_type') === 'oauth2_client_credentials' && (
              <>
                <Form.Item name="token_endpoint" label="令牌地址"><Input placeholder="https://.../api/v1/auth/get-access-token" /></Form.Item>
                <Form.Item name="token_method" label="令牌请求方法"><Select options={[{ value: 'GET', label: 'GET' }, { value: 'POST', label: 'POST' }]} /></Form.Item>
                <Form.Item name="token_scope" label="令牌范围"><Input /></Form.Item>
              </>
            )}
          </Form.Item>
          <Form.Item name="secret" label="密钥 / 凭据"><Input.Password placeholder={editing ? '留空保持不变' : ''} autoComplete="new-password" /></Form.Item>
          <Form.Item name="source_system_ip" label="来源系统 IP"><Input /></Form.Item>
          <Form.Item name="source_system_name" label="来源系统名称"><Input placeholder="校园 DPI 系统" /></Form.Item>
          <Form.Item name="field_mapping" label="字段映射（JSON）"><Input.TextArea rows={6} placeholder='{"behavior_type":"event_type","account":"account"}' /></Form.Item>
          <Form.Item name="success_status_codes" label="成功状态码（逗号分隔）"><Input placeholder="200" /></Form.Item>
          <Form.Item name="batch_size" label="单批条数" rules={[{ required: true }]}><InputNumber min={1} max={500} /></Form.Item>
          <Form.Item name="timeout_seconds" label="超时（秒）" rules={[{ required: true }]}><InputNumber min={1} max={120} /></Form.Item>
          <Form.Item name="tls_skip_verify" label="跳过 TLS 校验" valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="enabled" label="启用通道" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
      <Modal width={640} footer={null} title="试算载荷" open={!!preview} onCancel={() => setPreview(undefined)}>
        {preview ? <Input.TextArea className="behavior-report-preview" readOnly autoSize={{ minRows: 8, maxRows: 20 }} value={preview} /> : <AppLoadingState rows={3} />}
      </Modal>
    </>
  )
}

function OutboxPanel({ writable }: { writable: boolean }) {
  const pagination = useServerPagination('behavior_report_outbox_')
  const [status, setStatus] = useUrlState('status', '', statusFilters, ['behavior_report_outbox_page'])
  const [detail, setDetail] = useState<string>()
  const query = new URLSearchParams({ limit: String(pagination.pageSize), cursor: pagination.cursor })
  if (status) query.set('status', status)
  const outbox = useQuery({ queryKey: ['behavior-reports', 'outbox', query.toString()], queryFn: () => request<OutboxPage>(`/behavior-reports/outbox?${query}`), refetchInterval: 15000 })
  const detailQuery = useQuery({ queryKey: ['behavior-reports', 'outbox', 'detail', detail], queryFn: () => request<OutboxDetail>(`/behavior-reports/outbox/${encodeURIComponent(detail!)}`), enabled: !!detail })
  const operate = useMutation({
    mutationFn: ({ id, op }: { id: string; op: 'retry' | 'cancel' }) => request(`/behavior-reports/outbox/${encodeURIComponent(id)}/${op}`, { method: 'POST' }),
    onSuccess: () => { void outbox.refetch(); message.success('已提交') },
    onError: (error: Error) => message.error(error.message),
  })
  const columns: ColumnsType<OutboxRow> = [
    { title: '事件', dataIndex: 'event_type', width: 130, render: (value: string) => eventTypes[value] ?? value },
    { title: '终端', dataIndex: 'ip', render: (value: string, row) => <div><strong>{value}</strong>{row.account_id && <div className="notifications-muted">{row.account_id}</div>}</div> },
    { title: '通道', dataIndex: 'channel_id' },
    { title: '状态', dataIndex: 'status', width: 110, render: (value: string) => <Tag color={value === 'sent' ? 'green' : value === 'failed' ? 'red' : value === 'queued' ? 'blue' : undefined}>{statusText(value)}</Tag> },
    { title: '尝试', dataIndex: 'attempts', width: 80 },
    { title: '发生时间', dataIndex: 'occurred_at', width: 180, render: (value: string) => when(value) },
    { title: '最后错误', dataIndex: 'last_error', render: (value: string) => <span className="notifications-wrap">{value}</span> },
    {
      title: '操作', width: 190,
      render: (_value, row) => (
        <Space wrap>
          <Button size="small" onClick={() => setDetail(row.report_id)}>详情</Button>
          <Button size="small" disabled={!writable || !['failed', 'cancelled'].includes(row.status)} onClick={() => operate.mutate({ id: row.report_id, op: 'retry' })}>重试</Button>
          <Button size="small" disabled={!writable || !['queued', 'sending', 'failed'].includes(row.status)} onClick={() => operate.mutate({ id: row.report_id, op: 'cancel' })}>取消</Button>
        </Space>
      ),
    },
  ]
  return (
    <>
      <div className="notifications-toolbar">
        <Select aria-label="上报状态筛选" allowClear placeholder="全部状态" value={status || undefined} onChange={(value) => setStatus(value ?? '')} options={statusFilters.map((value) => ({ value, label: statusText(value) }))} />
      </div>
      {outbox.isError ? <Alert type="error" showIcon title="上报队列读取失败" description={String(outbox.error)} /> : outbox.isLoading ? <AppLoadingState rows={4} /> : outbox.data?.items.length ? <Table rowKey="report_id" className="compact-list-table" columns={columns} dataSource={outbox.data.items} pagination={false} scroll={{ x: 1200 }} /> : <Empty description="暂无上报记录" />}
      <AppServerPagination page={pagination.page} pageSize={pagination.pageSize} total={outbox.data?.page.total ?? 0} onChange={pagination.update} />
      <Modal width={720} footer={null} title="上报详情" open={!!detail} onCancel={() => setDetail(undefined)}>
        {detailQuery.isLoading ? <AppLoadingState rows={3} /> : detailQuery.data ? (
          <>
            <Descriptions column={1} size="small" items={[
              { key: 'event', label: '事件类型', children: eventTypes[detailQuery.data.report.event_type] ?? detailQuery.data.report.event_type },
              { key: 'ip', label: '终端', children: detailQuery.data.report.ip },
              { key: 'account', label: '账号', children: detailQuery.data.report.account_id },
              { key: 'channel', label: '通道', children: detailQuery.data.report.channel_id },
              { key: 'status', label: '状态', children: statusText(detailQuery.data.report.status) },
              { key: 'attempts', label: '尝试次数', children: String(detailQuery.data.report.attempts) },
              { key: 'sent', label: '送达时间', children: when(detailQuery.data.report.sent_at) },
              { key: 'remote', label: '平台回执', children: detailQuery.data.report.remote_id },
              { key: 'error', label: '最后错误', children: detailQuery.data.report.last_error },
            ]} />
            <Table rowKey="attempt_id" size="small" className="compact-list-table" pagination={false} dataSource={detailQuery.data.attempts} columns={[
              { title: '第几次', dataIndex: 'attempt', width: 80 },
              { title: '结果', dataIndex: 'status', width: 90, render: (value: string) => statusText(value) },
              { title: 'HTTP', dataIndex: 'http_status', width: 80 },
              { title: '错误', dataIndex: 'error', render: (value: string) => <span className="notifications-wrap">{value}</span> },
              { title: '时间', dataIndex: 'finished_at', width: 180, render: (value: string) => when(value) },
            ]} />
          </>
        ) : <Alert type="error" showIcon title="上报详情读取失败" description={String(detailQuery.error)} />}
      </Modal>
    </>
  )
}
