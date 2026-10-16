import { Notice as Alert } from '../shared/ui/Notice'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Card, Empty, Form, Input, InputNumber, Select, Space, Switch, Table, Tabs, Tag, Typography, message } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { request } from '../shared/api/client'
import { useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
import { AppFactBar, AppFormModal, AppLoadingState, AppPageHeader, AppServerPagination, useServerPagination } from '../shared/ui'
import { useUrlState } from '../shared/ui/useUrlState'
import type { components } from '../shared/api/generated'

type Rule = components['schemas']['DestinationTargetRule']
type RulePage = components['schemas']['DestinationTargetRulePage']
type Finding = components['schemas']['DestinationTargetFinding']
type FindingPage = components['schemas']['DestinationTargetFindingPage']
type Preview = components['schemas']['DestinationTargetPreview']

const behaviorTypes: Record<string, string> = { configured_ip_range: '按配置目标判定', high_frequency_internal: '高频内网访问' }
const targetTypes: Record<string, string> = { ip: 'IP 地址', cidr: '网段（CIDR）', domain: '域名' }
const directions: Record<string, string> = { any: '不限方向', up: '仅上行', down: '仅下行' }
const when = (value?: string) => (value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '')

export function DestinationTargetsPage() {
  const session = useSession()
  const writable = can(session.data, 'destination-targets:manage')
  const cache = useQueryClient()
  const [tab, setTab] = useUrlState('tab', 'rules', ['rules', 'findings'])
  const rules = useQuery({ queryKey: ['destination-targets', 'rules'], queryFn: () => request<RulePage>('/destination-targets/rules') })
  const invalidate = () => void cache.invalidateQueries({ queryKey: ['destination-targets'] })

  return (
    <section className="page destination-targets-page">
      <AppPageHeader title="内网目标访问检测" subtitle="识别访问敏感网段或高频访问内网目标的终端" onRefresh={invalidate} />
      <AppFactBar label="内网目标访问检测规则" items={['规则默认关闭，启用前先用试算核对命中范围','命中生成风险证据，该线索单独不足以认定代理或共享']} />
      <Card>
        <Tabs activeKey={tab} onChange={setTab} items={[
          { key: 'rules', label: '检测规则', children: <RulesPanel rules={rules} writable={writable} invalidate={invalidate} /> },
          { key: 'findings', label: '发现记录', children: <FindingsPanel /> },
        ]} />
      </Card>
    </section>
  )
}

function RulesPanel({ rules, writable, invalidate }: { rules: ReturnType<typeof useQuery<RulePage>>; writable: boolean; invalidate: () => void }) {
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<Rule>()
  const [preview, setPreview] = useState<Preview>()
  const [form] = Form.useForm()
  const save = useMutation({
    mutationFn: (value: Record<string, unknown>) => request<Rule>(editing ? `/destination-targets/rules/${encodeURIComponent(editing.rule_id ?? '')}` : '/destination-targets/rules', { method: editing ? 'PUT' : 'POST', body: JSON.stringify(value) }),
    onSuccess: () => { invalidate(); setOpen(false); message.success('规则已保存') },
    onError: (error: Error) => message.error(error.message),
  })
  const remove = useMutation({
    mutationFn: (id: string) => request(`/destination-targets/rules/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    onSuccess: () => { invalidate(); message.success('规则已删除') },
    onError: (error: Error) => message.error(error.message),
  })
  const runPreview = useMutation({
    mutationFn: (id: string) => request<Preview>(`/destination-targets/rules/${encodeURIComponent(id)}/preview`, { method: 'POST' }),
    onSuccess: (data) => setPreview(data),
    onError: (error: Error) => message.error(error.message),
  })
  const edit = (item?: Rule) => {
    setEditing(item)
    form.resetFields()
    form.setFieldsValue(item ? { ...item, targets: item.targets ?? [] } : { enabled: false, behavior_type: 'configured_ip_range', target_type: 'cidr', targets: [], window_seconds: 3600, threshold: 3, direction: 'any' })
    setOpen(true)
  }
  const columns: ColumnsType<Rule> = [
    { title: '名称', dataIndex: 'name', render: (value: string, row) => <div><strong>{value}</strong><div className="notifications-muted">{row.rule_id}</div></div> },
    { title: '判定方式', dataIndex: 'behavior_type', width: 150, render: (value: string) => behaviorTypes[value] ?? value },
    { title: '目标', dataIndex: 'targets', render: (values: string[], row) => (row.behavior_type === 'high_frequency_internal' ? <Typography.Text type="secondary">内网目标</Typography.Text> : <Space wrap>{(values ?? []).map((value) => <Tag key={value}>{value}</Tag>)}</Space>) },
    { title: '窗口', dataIndex: 'window_seconds', width: 100, render: (value: number) => `${value} 秒` },
    { title: '阈值', dataIndex: 'threshold', width: 80 },
    { title: '方向', dataIndex: 'direction', width: 100, render: (value: string) => directions[value] ?? value },
    { title: '状态', dataIndex: 'enabled', width: 90, render: (value: boolean) => <Tag color={value ? 'blue' : undefined}>{value ? '已启用' : '未启用'}</Tag> },
    {
      title: '操作', width: 220, fixed: 'right',
      render: (_value, row) => (
        <Space wrap>
          <Button size="small" loading={runPreview.isPending && runPreview.variables === row.rule_id} onClick={() => { setPreview(undefined); runPreview.mutate(row.rule_id) }}>试算</Button>
          <Button size="small" disabled={!writable} onClick={() => edit(row)}>编辑</Button>
          <Button size="small" danger disabled={!writable} onClick={() => remove.mutate(row.rule_id)}>删除</Button>
        </Space>
      ),
    },
  ]
  return (
    <>
      <div className="notifications-toolbar">
        <Typography.Text type="secondary">窗口最小 60 秒，最大 24 小时；阈值是窗口内命中次数的下限。</Typography.Text>
        <Button type="primary" disabled={!writable} onClick={() => edit()}>新增规则</Button>
      </div>
      {rules.isError ? <Alert type="error" showIcon title="规则读取失败" description={String(rules.error)} /> : rules.isLoading ? <AppLoadingState rows={3} /> : rules.data?.items.length ? <Table rowKey="rule_id" className="compact-list-table" columns={columns} dataSource={rules.data.items} pagination={false} scroll={{ x: 1100 }} /> : <Empty description="暂无检测规则" />}
      <AppFormModal width={680} title={editing ? '编辑规则' : '新增规则'} open={open} confirmLoading={save.isPending} onCancel={() => setOpen(false)} onOk={() => void form.validateFields().then((value) => save.mutate({ ...value, targets: value.targets ?? [] })).catch(() => undefined)}>
        <Form form={form} layout="vertical">
          <Form.Item name="rule_id" label="规则标识" rules={[{ required: !editing, max: 128 }]}><Input disabled={!!editing} placeholder="例如 ncu-sensitive-range" /></Form.Item>
          <Form.Item name="name" label="名称" rules={[{ required: true, max: 128 }]}><Input /></Form.Item>
          <Form.Item name="behavior_type" label="判定方式" rules={[{ required: true }]}><Select options={Object.entries(behaviorTypes).map(([value, label]) => ({ value, label }))} /></Form.Item>
          <Form.Item noStyle shouldUpdate={(previous, next) => previous.behavior_type !== next.behavior_type}>
            {({ getFieldValue }) => getFieldValue('behavior_type') === 'configured_ip_range' && (
              <>
                <Form.Item name="target_type" label="目标类型" rules={[{ required: true }]}><Select options={Object.entries(targetTypes).map(([value, label]) => ({ value, label }))} /></Form.Item>
                <Form.Item name="targets" label="目标列表" rules={[{ required: true, type: 'array', min: 1 }]}><Select mode="tags" placeholder="10.155.32.0/24" /></Form.Item>
              </>
            )}
          </Form.Item>
          <Form.Item name="window_seconds" label="观测窗口（秒）" rules={[{ required: true }]}><InputNumber min={60} max={86400} /></Form.Item>
          <Form.Item name="threshold" label="命中次数阈值" rules={[{ required: true }]}><InputNumber min={1} /></Form.Item>
          <Form.Item name="direction" label="方向" rules={[{ required: true }]}><Select options={Object.entries(directions).map(([value, label]) => ({ value, label }))} /></Form.Item>
          <Form.Item name="push_enabled" label="纳入北向上报" valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="push_without_account" label="无账号时也上报" valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="enabled" label="启用规则" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </AppFormModal>
      <AppFormModal width={760} footer={null} title="试算结果" open={!!preview} onCancel={() => setPreview(undefined)}>
        {preview ? (
          <>
            <Alert type="info" showIcon title={`当前窗口命中 ${preview.items.length} 个终端`} description={`规则状态：${preview.rule_enabled ? '已启用' : '未启用'}；观测数据 ${preview.observations} 条聚合记录；窗口 ${preview.window_seconds} 秒。试算不写入任何记录。`} />
            {preview.items.length ? <Table rowKey="subject_ip" size="small" className="compact-list-table" pagination={false} dataSource={preview.items} columns={[
              { title: '终端 IP', dataIndex: 'subject_ip' },
              { title: '命中次数', dataIndex: 'hit_count', width: 100 },
              { title: '内网目标数', dataIndex: 'unique_destinations', width: 110 },
              { title: '命中目标', dataIndex: 'matched_targets', render: (values: string[]) => <Space wrap>{(values ?? []).map((value) => <Tag key={value}>{value}</Tag>)}</Space> },
            ]} /> : <Empty description="当前窗口没有命中" />}
          </>
        ) : <AppLoadingState rows={3} />}
      </AppFormModal>
    </>
  )
}

function FindingsPanel() {
  const pagination = useServerPagination('destination_target_findings_')
  const query = new URLSearchParams({ limit: String(pagination.pageSize), cursor: pagination.cursor })
  const findings = useQuery({ queryKey: ['destination-targets', 'findings', query.toString()], queryFn: () => request<FindingPage>(`/destination-targets/findings?${query}`), refetchInterval: 60000 })
  const columns: ColumnsType<Finding> = [
    { title: '终端', dataIndex: 'subject_ip', render: (value: string, row) => <div><strong>{value}</strong>{row.account_id && <div className="notifications-muted">{row.account_id}</div>}</div> },
    { title: '规则', dataIndex: 'rule_name', render: (value: string, row) => value || row.rule_id },
    { title: '判定方式', dataIndex: 'behavior_type', width: 150, render: (value: string) => behaviorTypes[value] ?? value },
    { title: '命中次数', dataIndex: 'hit_count', width: 100 },
    { title: '内网目标数', dataIndex: 'unique_destinations', width: 110 },
    { title: '命中目标', dataIndex: 'matched_targets', render: (values: string[]) => <Space wrap>{(values ?? []).map((value) => <Tag key={value}>{value}</Tag>)}</Space> },
    { title: '最近观测', dataIndex: 'last_seen', width: 180, render: (value: string) => when(value) },
    { title: '上报', dataIndex: 'pushed', width: 90, render: (value: boolean, row) => (value ? <Tag color="green">已上报</Tag> : row.push_error ? <Tag color="red">上报失败</Tag> : '') },
  ]
  return (
    <>
      {findings.isError ? <Alert type="error" showIcon title="发现记录读取失败" description={String(findings.error)} /> : findings.isLoading ? <AppLoadingState rows={4} /> : findings.data?.items.length ? <Table rowKey="finding_id" className="compact-list-table" columns={columns} dataSource={findings.data.items} pagination={false} scroll={{ x: 1200 }} /> : <Empty description="暂无发现记录" />}
      <AppServerPagination page={pagination.page} pageSize={pagination.pageSize} total={findings.data?.page.total ?? 0} onChange={pagination.update} />
    </>
  )
}
