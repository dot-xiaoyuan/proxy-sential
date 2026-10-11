import { useState } from 'react'
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query'
import { Alert, Button, Card, Descriptions, Empty, Form, Input, InputNumber, Modal, Select, Space, Switch, Table, Tabs, Tag, Typography, message } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { request } from '../shared/api/client'
import { useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
import { AppLoadingState, AppPageHeader, AppServerPagination, useServerPagination } from '../shared/ui'
import { statusText } from '../shared/ui/status'
import { useUrlState } from '../shared/ui/useUrlState'
import type { components } from '../shared/api/generated'

type Template = components['schemas']['NotificationTemplate']
type TemplatePage = components['schemas']['NotificationTemplatePage']
type Channel = components['schemas']['NotificationChannel']
type ChannelPage = components['schemas']['NotificationChannelPage']
type OutboxRow = components['schemas']['NotificationOutboxRow']
type OutboxPage = components['schemas']['NotificationOutboxPage']
type OutboxDetail = components['schemas']['NotificationOutboxDetail']
type TestResult = components['schemas']['NotificationTestResult']

const channelTypes = { http: '通用 HTTP', srun_sms: '短信消息中心' }
const authTypes = { none: '无鉴权', bearer: 'Bearer 令牌', basic: 'Basic 用户名口令', oauth2_client_credentials: 'OAuth2 客户端凭据' }
const statusFilters = ['queued', 'sending', 'sent', 'failed', 'cancelled']
const when = (value?: string) => (value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '')

const emptyChannel: Partial<Channel> = { channel_type: 'http', auth_type: 'none', enabled: false, is_default: false, config: { timeout_seconds: 10 } }

export function NotificationsPage() {
  const session = useSession()
  const writable = can(session.data, 'notifications:manage')
  const cache = useQueryClient()
  const [tab, setTab] = useUrlState('tab', 'templates', ['templates', 'channels', 'outbox', 'test'])

  const templates = useQuery({ queryKey: ['notifications', 'templates'], queryFn: () => request<TemplatePage>('/notifications/templates') })
  const channels = useQuery({ queryKey: ['notifications', 'channels'], queryFn: () => request<ChannelPage>('/notifications/channels') })

  const invalidate = () => {
    void cache.invalidateQueries({ queryKey: ['notifications'] })
  }

  return (
    <section className="notifications-page">
      <AppPageHeader title="通知模板与通道" subtitle="策略提醒的模板、发送通道与投递状态" onRefresh={invalidate} />
      <Alert
        type="info"
        showIcon
        title="入队不等于送达"
        description="策略执行成功只表示通知已受理。实际送达状态以投递记录为准；未配置通道时会明确记为失败，不会停留在等待状态。"
      />
      <Card>
        <Tabs
          activeKey={tab}
          onChange={setTab}
          items={[
            { key: 'templates', label: '通知模板', children: <TemplatesPanel templates={templates} allowed={templates.data?.allowed_variables ?? []} writable={writable} invalidate={invalidate} /> },
            { key: 'channels', label: '发送通道', children: <ChannelsPanel channels={channels} writable={writable} invalidate={invalidate} /> },
            { key: 'outbox', label: '投递记录', children: <OutboxPanel writable={writable} invalidate={invalidate} /> },
            { key: 'test', label: '测试发送', children: <TestPanel channels={channels.data?.items ?? []} templates={templates.data?.items ?? []} writable={writable} /> },
          ]}
        />
      </Card>
    </section>
  )
}

function TemplatesPanel({ templates, allowed, writable, invalidate }: { templates: UseQueryResult<TemplatePage>; allowed: string[]; writable: boolean; invalidate: () => void }) {
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<Template>()
  const [form] = Form.useForm()
  const save = useMutation({
    mutationFn: (value: Record<string, unknown>) =>
      request<Template>(editing ? `/notifications/templates/${encodeURIComponent(editing.template_id ?? '')}` : '/notifications/templates', { method: editing ? 'PUT' : 'POST', body: JSON.stringify(value) }),
    onSuccess: () => {
      invalidate()
      setOpen(false)
      message.success('模板已保存')
    },
    onError: (error: Error) => message.error(error.message),
  })
  const remove = useMutation({
    mutationFn: (id: string) => request(`/notifications/templates/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    onSuccess: () => {
      invalidate()
      message.success('模板已删除')
    },
    onError: (error: Error) => message.error(error.message),
  })
  const edit = (item?: Template) => {
    setEditing(item)
    form.resetFields()
    form.setFieldsValue(item ? { ...item } : { enabled: true })
    setOpen(true)
  }
  const columns: ColumnsType<Template> = [
    { title: '名称', dataIndex: 'name', render: (value: string, row) => <div><strong>{value}</strong><div className="notifications-muted">{row.template_id}</div></div> },
    { title: '标题', dataIndex: 'subject' },
    { title: '变量', dataIndex: 'variables', render: (values: string[]) => (values?.length ? <Space wrap>{values.map((value) => <Tag key={value}>{value}</Tag>)}</Space> : '') },
    { title: '状态', dataIndex: 'enabled', render: (value: boolean) => <Tag color={value ? 'blue' : undefined}>{value ? '已启用' : '已停用'}</Tag> },
    { title: '版本', dataIndex: 'revision', width: 80 },
    {
      title: '操作',
      width: 160,
      render: (_value, row) => (
        <Space wrap>
          <Button size="small" disabled={!writable} onClick={() => edit(row)}>编辑</Button>
          <Button size="small" danger disabled={!writable} onClick={() => remove.mutate(row.template_id ?? '')}>删除</Button>
        </Space>
      ),
    },
  ]
  return (
    <>
      <div className="notifications-toolbar">
        <Typography.Text type="secondary">正文与标题只能引用白名单变量，例如 {'{{account}}'}、{'{{ip}}'}、{'{{policy_name}}'}。</Typography.Text>
        <Button type="primary" disabled={!writable} onClick={() => edit()}>新增模板</Button>
      </div>
      {templates.isError ? <Alert type="error" showIcon title="模板读取失败" description={String(templates.error)} /> : templates.isLoading ? <AppLoadingState rows={3} /> : templates.data?.items.length ? <Table rowKey="template_id" className="compact-list-table" columns={columns} dataSource={templates.data.items} pagination={false} scroll={{ x: 900 }} /> : <Empty description="暂无通知模板" />}
      <Modal forceRender title={editing ? '编辑模板' : '新增模板'} open={open} confirmLoading={save.isPending} onCancel={() => setOpen(false)} onOk={() => void form.validateFields().then((value) => save.mutate(value)).catch(() => undefined)}>
        <Form form={form} layout="vertical">
          <Form.Item name="template_id" label="模板标识" rules={[{ required: !editing, max: 128 }]}>
            <Input disabled={!!editing} placeholder="例如 proxy-reminder" />
          </Form.Item>
          <Form.Item name="name" label="名称" rules={[{ required: true, max: 128 }]}><Input /></Form.Item>
          <Form.Item name="subject" label="消息标题"><Input maxLength={512} /></Form.Item>
          <Form.Item name="body" label="消息正文" rules={[{ required: true, max: 8192 }]}><Input.TextArea rows={4} placeholder="账号 {{account}} 在 {{ip}} 触发 {{policy_name}}" /></Form.Item>
          <Form.Item label="可用变量"><Space wrap>{allowed.map((value) => <Tag key={value}>{`{{${value}}}`}</Tag>)}</Space></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
    </>
  )
}

function ChannelsPanel({ channels, writable, invalidate }: { channels: UseQueryResult<ChannelPage>; writable: boolean; invalidate: () => void }) {
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<Channel>()
  const [form] = Form.useForm()
  const save = useMutation({
    mutationFn: (value: Record<string, unknown>) =>
      request<Channel>(editing ? `/notifications/channels/${encodeURIComponent(editing.channel_id ?? '')}` : '/notifications/channels', { method: editing ? 'PUT' : 'POST', body: JSON.stringify(value) }),
    onSuccess: () => {
      invalidate()
      setOpen(false)
      message.success('通道已保存')
    },
    onError: (error: Error) => message.error(error.message),
  })
  const remove = useMutation({
    mutationFn: (id: string) => request(`/notifications/channels/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    onSuccess: () => {
      invalidate()
      message.success('通道已删除')
    },
    onError: (error: Error) => message.error(error.message),
  })
  const edit = (item?: Channel) => {
    setEditing(item)
    form.resetFields()
    form.setFieldsValue(item ? { ...item, secret: undefined } : { ...emptyChannel })
    setOpen(true)
  }
  const columns: ColumnsType<Channel> = [
    { title: '名称', dataIndex: 'name', render: (value: string, row) => <div><strong>{value}</strong><div className="notifications-muted">{row.channel_id}</div></div> },
    { title: '类型', dataIndex: 'channel_type', render: (value: string) => channelTypes[value as keyof typeof channelTypes] ?? value },
    { title: '鉴权', dataIndex: 'auth_type', render: (value: string) => authTypes[value as keyof typeof authTypes] ?? value },
    { title: '密钥', dataIndex: 'has_secret', width: 90, render: (value: boolean) => (value ? <Tag color="blue">已配置</Tag> : '') },
    { title: '默认', dataIndex: 'is_default', width: 80, render: (value: boolean) => (value ? <Tag color="blue">默认</Tag> : '') },
    { title: '状态', dataIndex: 'enabled', width: 90, render: (value: boolean) => <Tag color={value ? 'blue' : undefined}>{value ? '已启用' : '已停用'}</Tag> },
    {
      title: '操作',
      width: 160,
      render: (_value, row) => (
        <Space wrap>
          <Button size="small" disabled={!writable} onClick={() => edit(row)}>编辑</Button>
          <Button size="small" danger disabled={!writable} onClick={() => remove.mutate(row.channel_id ?? '')}>删除</Button>
        </Space>
      ),
    },
  ]
  return (
    <>
      <div className="notifications-toolbar">
        <Typography.Text type="secondary">密钥使用处置主密钥加密保存，接口不会回显；编辑时留空表示保持原密钥，填写“-”表示清空。</Typography.Text>
        <Button type="primary" disabled={!writable} onClick={() => edit()}>新增通道</Button>
      </div>
      {channels.isError ? <Alert type="error" showIcon title="通道读取失败" description={String(channels.error)} /> : channels.isLoading ? <AppLoadingState rows={3} /> : channels.data?.items.length ? <Table rowKey="channel_id" className="compact-list-table" columns={columns} dataSource={channels.data.items} pagination={false} scroll={{ x: 1000 }} /> : <Empty description="暂无通知通道" />}
      <Modal forceRender width={640} title={editing ? '编辑通道' : '新增通道'} open={open} confirmLoading={save.isPending} onCancel={() => setOpen(false)} onOk={() => void form.validateFields().then((value) => save.mutate(value)).catch(() => undefined)}>
        <Form form={form} layout="vertical">
          <Form.Item name="channel_id" label="通道标识" rules={[{ required: !editing, max: 128 }]}><Input disabled={!!editing} placeholder="例如 duty-webhook" /></Form.Item>
          <Form.Item name="name" label="名称" rules={[{ required: true, max: 128 }]}><Input /></Form.Item>
          <Form.Item name="channel_type" label="通道类型" rules={[{ required: true }]}><Select options={Object.entries(channelTypes).map(([value, label]) => ({ value, label }))} /></Form.Item>
          <Form.Item name="endpoint_url" label="消息地址" rules={[{ required: true }]}><Input placeholder="https://..." /></Form.Item>
          <Form.Item name="auth_type" label="鉴权方式" rules={[{ required: true }]}><Select options={Object.entries(authTypes).map(([value, label]) => ({ value, label }))} /></Form.Item>
          <Form.Item noStyle shouldUpdate={(previous, next) => previous.auth_type !== next.auth_type || previous.channel_type !== next.channel_type}>
            {({ getFieldValue }) => (
              <>
                {['basic', 'oauth2_client_credentials'].includes(getFieldValue('auth_type')) && <Form.Item name={['config', 'client_id']} label="客户端标识"><Input /></Form.Item>}
                {getFieldValue('auth_type') === 'oauth2_client_credentials' && (
                  <>
                    <Form.Item name="token_endpoint" label="令牌地址" rules={[{ required: true }]}><Input placeholder="https://.../oauth2/token" /></Form.Item>
                    <Form.Item name="token_scope" label="令牌范围"><Input placeholder="messagecenter:v1:sendMessage" /></Form.Item>
                  </>
                )}
                {getFieldValue('channel_type') === 'srun_sms' && (
                  <>
                    <Form.Item name={['config', 'message_type_code']} label="消息类型编码" rules={[{ required: true }]}><Input /></Form.Item>
                    <Form.Item name={['config', 'send_types']} label="发送渠道"><Select mode="tags" placeholder="SMS, WECHAT" /></Form.Item>
                  </>
                )}
              </>
            )}
          </Form.Item>
          <Form.Item name="secret" label="密钥"><Input.Password placeholder={editing ? '留空保持不变' : ''} autoComplete="new-password" /></Form.Item>
          <Form.Item name={['config', 'timeout_seconds']} label="超时（秒）"><InputNumber min={0} max={120} /></Form.Item>
          <Form.Item name={['config', 'tls_skip_verify']} label="跳过 TLS 校验" valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="is_default" label="设为默认通道" valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
    </>
  )
}

function OutboxPanel({ writable, invalidate }: { writable: boolean; invalidate: () => void }) {
  const pagination = useServerPagination('notification_outbox_')
  const [status, setStatus] = useUrlState('status', '', statusFilters, ['notification_outbox_page'])
  const [detail, setDetail] = useState<string>()
  const query = new URLSearchParams({ limit: String(pagination.pageSize), cursor: pagination.cursor })
  if (status) query.set('status', status)
  const outbox = useQuery({ queryKey: ['notifications', 'outbox', query.toString()], queryFn: () => request<OutboxPage>(`/notifications/outbox?${query}`), refetchInterval: 15000 })
  const detailQuery = useQuery({ queryKey: ['notifications', 'outbox', 'detail', detail], queryFn: () => request<OutboxDetail>(`/notifications/outbox/${encodeURIComponent(detail!)}`), enabled: !!detail })
  const operate = useMutation({
    mutationFn: ({ id, op }: { id: string; op: 'retry' | 'cancel' }) => request(`/notifications/outbox/${encodeURIComponent(id)}/${op}`, { method: 'POST' }),
    onSuccess: () => {
      invalidate()
      void outbox.refetch()
      message.success('已提交')
    },
    onError: (error: Error) => message.error(error.message),
  })
  const columns: ColumnsType<OutboxRow> = [
    { title: '账号', dataIndex: 'account_id', render: (value: string, row) => <div><strong>{value}</strong><div className="notifications-muted">{row.notification_id}</div></div> },
    { title: '模板', dataIndex: 'template', render: (value: string) => <span className="notifications-wrap">{value}</span> },
    { title: '状态', dataIndex: 'status', width: 110, render: (value: string) => <Tag color={value === 'sent' ? 'green' : value === 'failed' ? 'red' : value === 'queued' ? 'blue' : undefined}>{statusText(value)}</Tag> },
    { title: '尝试', dataIndex: 'attempts', width: 80 },
    { title: '送达时间', dataIndex: 'sent_at', width: 180, render: (value: string) => when(value) },
    { title: '最后错误', dataIndex: 'last_error', render: (value: string) => <span className="notifications-wrap">{value}</span> },
    {
      title: '操作',
      width: 190,
      render: (_value, row) => (
        <Space wrap>
          <Button size="small" onClick={() => setDetail(row.notification_id)}>详情</Button>
          <Button size="small" disabled={!writable || !['failed', 'cancelled'].includes(row.status)} onClick={() => operate.mutate({ id: row.notification_id, op: 'retry' })}>重试</Button>
          <Button size="small" disabled={!writable || !['queued', 'sending', 'failed'].includes(row.status)} onClick={() => operate.mutate({ id: row.notification_id, op: 'cancel' })}>取消</Button>
        </Space>
      ),
    },
  ]
  return (
    <>
      <div className="notifications-toolbar">
        <Select aria-label="投递状态筛选" allowClear placeholder="全部状态" value={status || undefined} onChange={(value) => setStatus(value ?? '')} options={statusFilters.map((value) => ({ value, label: statusText(value) }))} />
      </div>
      {outbox.isError ? <Alert type="error" showIcon title="投递记录读取失败" description={String(outbox.error)} /> : outbox.isLoading ? <AppLoadingState rows={4} /> : outbox.data?.items.length ? <Table rowKey="notification_id" className="compact-list-table" columns={columns} dataSource={outbox.data.items} pagination={false} scroll={{ x: 1200 }} /> : <Empty description="暂无投递记录" />}
      <AppServerPagination page={pagination.page} pageSize={pagination.pageSize} total={outbox.data?.page.total ?? 0} onChange={pagination.update} />
      <Modal width={720} footer={null} title="投递详情" open={!!detail} onCancel={() => setDetail(undefined)}>
        {detailQuery.isLoading ? <AppLoadingState rows={3} /> : detailQuery.data ? (
          <>
            <Descriptions column={1} size="small" items={[
              { key: 'account', label: '账号', children: detailQuery.data.notification.account_id },
              { key: 'template', label: '模板', children: detailQuery.data.notification.template },
              { key: 'status', label: '状态', children: statusText(detailQuery.data.notification.status) },
              { key: 'channel', label: '通道', children: detailQuery.data.notification.channel_id },
              { key: 'attempts', label: '尝试次数', children: String(detailQuery.data.notification.attempts) },
              { key: 'sent', label: '送达时间', children: when(detailQuery.data.notification.sent_at) },
              { key: 'remote', label: '通道回执', children: detailQuery.data.notification.remote_id },
              { key: 'error', label: '最后错误', children: detailQuery.data.notification.last_error },
              { key: 'variables', label: '变量', children: Object.entries(detailQuery.data.notification.parameters ?? {}).map(([key, value]) => `${key}=${value}`).join(' · ') },
            ]} />
            <Table rowKey="attempt_id" size="small" className="compact-list-table" pagination={false} dataSource={detailQuery.data.attempts} columns={[
              { title: '第几次', dataIndex: 'attempt', width: 80 },
              { title: '结果', dataIndex: 'status', width: 90, render: (value: string) => statusText(value) },
              { title: 'HTTP', dataIndex: 'http_status', width: 80 },
              { title: '错误', dataIndex: 'error', render: (value: string) => <span className="notifications-wrap">{value}</span> },
              { title: '时间', dataIndex: 'finished_at', width: 180, render: (value: string) => when(value) },
            ]} />
          </>
        ) : <Alert type="error" showIcon title="投递详情读取失败" description={String(detailQuery.error)} />}
      </Modal>
    </>
  )
}

function TestPanel({ channels, templates, writable }: { channels: Channel[]; templates: Template[]; writable: boolean }) {
  const [form] = Form.useForm()
  const [result, setResult] = useState<TestResult>()
  const send = useMutation({
    mutationFn: (value: { channel_id?: string; template_id?: string; variables?: Record<string, string> }) => request<TestResult>('/notifications/test', { method: 'POST', body: JSON.stringify(value) }),
    onSuccess: (data) => setResult(data),
    onError: (error: Error) => message.error(error.message),
  })
  return (
    <div className="notifications-test">
      <Typography.Paragraph type="secondary">测试发送绕过投递队列，直接调用通道并返回真实结果。变量留空时模板中的占位符渲染为空。</Typography.Paragraph>
      <Form
        form={form}
        layout="vertical"
        onFinish={(value: { channel_id?: string; template_id?: string; variables?: string }) => {
          let variables: Record<string, string> = {}
          if (value.variables?.trim()) {
            try {
              variables = JSON.parse(value.variables) as Record<string, string>
            } catch {
              message.error('变量必须是 JSON 对象')
              return
            }
          }
          send.mutate({ channel_id: value.channel_id, template_id: value.template_id, variables })
        }}
      >
        <Form.Item name="channel_id" label="通道"><Select allowClear placeholder="使用默认通道" options={channels.map((item) => ({ value: item.channel_id, label: item.name }))} /></Form.Item>
        <Form.Item name="template_id" label="模板"><Select allowClear placeholder="使用固定测试文案" options={templates.map((item) => ({ value: item.template_id, label: item.name }))} /></Form.Item>
        <Form.Item name="variables" label="变量（JSON）"><Input.TextArea rows={3} placeholder='{"account":"test01","ip":"10.0.0.9"}' /></Form.Item>
        <Button type="primary" htmlType="submit" disabled={!writable} loading={send.isPending}>发送测试</Button>
      </Form>
      {result && (
        <Alert
          className="notifications-test-result"
          type={result.status === 'succeeded' ? 'success' : 'error'}
          showIcon
          title={result.status === 'succeeded' ? '通道已接受消息' : '通道拒绝或不可用'}
          description={result.error || `通道回执：${result.remote_id || '未返回回执编号'}（HTTP ${result.http_status}）`}
        />
      )}
    </div>
  )
}
