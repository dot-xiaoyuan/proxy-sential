import { useEffect, useMemo, useState } from 'react'
import { Alert, Button, Checkbox, Form, Input, InputNumber, Modal, Select, Space, Steps, Switch, Typography } from 'antd'

import type { ActionConnector } from '../../shared/api/types'
import type { FourKDirectory, Policy, Stage } from './api'

type TriggerBasis = 'duration' | 'notify' | 'rate_limit'

interface ActionEditor {
  notify_enabled?: boolean
  notify_after_seconds?: number
  notify_interval_seconds?: number
  notify_template?: string
  notify_connector_id?: string
  disconnect_enabled?: boolean
  disconnect_basis?: TriggerBasis
  disconnect_value?: number
  disconnect_connector_id?: string
  disconnect_sync_notify?: boolean
  rate_limit_enabled?: boolean
  rate_limit_basis?: TriggerBasis
  rate_limit_value?: number
  rate_limit_connector_id?: string
  rate_kbps?: number
  rate_duration_seconds?: number
  rate_sync_notify?: boolean
  disable_enabled?: boolean
  disable_basis?: TriggerBasis
  disable_value?: number
  disable_connector_id?: string
  disable_duration_seconds?: number
  disable_sync_notify?: boolean
}

interface StrategyForm extends Policy {
  actions: ActionEditor
}

const actionLabel: Record<string, string> = {
  notify: '消息提醒',
  disconnect: '强制下线',
  rate_limit: '带宽降速',
  disable_account: '用户封禁',
}

const stageOf = (policy: Policy, action: string) => policy.stages.find(stage => stage.action === action)

function actionValues(policy: Policy): ActionEditor {
  const notify = stageOf(policy, 'notify')
  const disconnect = stageOf(policy, 'disconnect')
  const rate = stageOf(policy, 'rate_limit')
  const disable = stageOf(policy, 'disable_account')
  const basis = (stage?: Stage): TriggerBasis => stage?.depends_on?.[0] === 'notify' ? 'notify' : stage?.depends_on?.[0] === 'rate_limit' ? 'rate_limit' : 'duration'
  const value = (stage?: Stage) => stage?.depends_on?.length ? Math.max(stage.min_episodes || 1, 1) : Math.max(stage?.after_seconds || 1, 1)
  return {
    notify_enabled: Boolean(notify),
    notify_after_seconds: notify?.after_seconds || 60,
    notify_interval_seconds: notify?.interval_seconds || 300,
    notify_template: notify?.template || '',
    notify_connector_id: notify?.connector_id || '',
    disconnect_enabled: Boolean(disconnect),
    disconnect_basis: basis(disconnect),
    disconnect_value: value(disconnect),
    disconnect_connector_id: disconnect?.connector_id || '',
    disconnect_sync_notify: disconnect?.sync_notify || false,
    rate_limit_enabled: Boolean(rate),
    rate_limit_basis: basis(rate),
    rate_limit_value: value(rate),
    rate_limit_connector_id: rate?.connector_id || '',
    rate_kbps: rate?.rate_kbps || 1024,
    rate_duration_seconds: rate?.duration_seconds || 600,
    rate_sync_notify: rate?.sync_notify || false,
    disable_enabled: Boolean(disable),
    disable_basis: basis(disable),
    disable_value: value(disable),
    disable_connector_id: disable?.connector_id || '',
    disable_duration_seconds: disable?.duration_seconds || 7200,
    disable_sync_notify: disable?.sync_notify || false,
  }
}

function toStage(action: string, enabled: boolean | undefined, basis: TriggerBasis | undefined, value: number | undefined, connector: string | undefined, extra: Partial<Stage> = {}): Stage[] {
  if (!enabled) return []
  const dependency = basis && basis !== 'duration' ? [basis] : []
  return [{
    action,
    connector_id: connector || '',
    after_seconds: dependency.length ? 0 : Math.max(value || 0, 0),
    min_episodes: dependency.length ? Math.max(value || 1, 1) : 1,
    duration_seconds: 0,
    rate_kbps: 0,
    template: '',
    depends_on: dependency,
    interval_seconds: 0,
    sync_notify: false,
    put_black: false,
    ...extra,
  }]
}

function buildPolicy(original: Policy, values: StrategyForm): Policy {
  const action = values.actions || {}
  const stages: Stage[] = [
    ...toStage('notify', action.notify_enabled, 'duration', action.notify_after_seconds, action.notify_connector_id, {
      template: action.notify_template || '',
      interval_seconds: action.notify_interval_seconds || 0,
    }),
    ...toStage('disconnect', action.disconnect_enabled, action.disconnect_basis, action.disconnect_value, action.disconnect_connector_id, {
      sync_notify: action.disconnect_sync_notify || false,
    }),
    ...toStage('disable_account', action.disable_enabled, action.disable_basis, action.disable_value, action.disable_connector_id, {
      duration_seconds: action.disable_duration_seconds || 0,
      sync_notify: action.disable_sync_notify || false,
    }),
  ]
  return {
    ...original,
    ...values,
    trigger: 'quota_exceeded',
    action_model: 'dpi-strategy/v1',
    scope: { accounts: values.scope?.accounts || [], sources: directorySource(values, original), products: values.scope?.products || [], groups: values.scope?.groups || [], vlans: values.scope?.vlans || [] },
    exempt: original.exempt || {},
    limits: { total: values.limits?.total ?? null, mobile: values.limits?.mobile ?? null, pc: values.limits?.pc ?? null, sessions: null },
    stages,
  }
}

function directorySource(values: StrategyForm, original: Policy): string[] {
  return values.scope?.sources?.length ? values.scope.sources : original.scope?.sources || []
}

function connectorSupports(connector: ActionConnector, action: string) {
  if (!connector.enabled) return false
  const mapping = connector.action_mapping || {}
  return mapping.account_policy_v1 === 'supported' && Boolean(mapping[action] || mapping[`session.${action}`] || mapping[`account.${action}`])
}

function ActionDevice({ name, action, connectors, managedConnectorId }: { name: (string | number)[]; action: string; connectors: ActionConnector[]; managedConnectorId?: string }) {
  const options = connectors.filter(connector => connectorSupports(connector, action)).map(connector => ({ value: connector.connector_id, label: connector.name }))
  const managed = managedConnectorId && connectors.find(connector => connector.connector_id === managedConnectorId && connector.connector_type === 'srun4k' && connectorSupports(connector, action))
  if (managed) {
    return <Form.Item name={name} hidden><Input /></Form.Item>
  }
  return <Form.Item name={name} label={`${actionLabel[action]}执行设备`} rules={[{ required: true, message: `请选择${actionLabel[action]}执行设备` }]}>
    <Select options={options} placeholder={options.length ? '请选择执行设备' : '尚无已验证的执行设备'} />
  </Form.Item>
}

function BasisFields({ prefix, allowRate }: { prefix: 'disconnect' | 'rate_limit' | 'disable'; allowRate?: boolean }) {
  const basis = Form.useWatch(['actions', `${prefix}_basis`]) as TriggerBasis | undefined
  const notifyEnabled = Form.useWatch(['actions', 'notify_enabled']) as boolean | undefined
  const rateEnabled = Form.useWatch(['actions', 'rate_limit_enabled']) as boolean | undefined
  const options = [{ value: 'duration', label: '配额超限持续时间' }]
  if (notifyEnabled) options.push({ value: 'notify', label: '消息提醒次数' })
  if (allowRate && rateEnabled) options.push({ value: 'rate_limit', label: '带宽降速次数' })
  return <div className="policy-action-fields">
    <Form.Item name={['actions', `${prefix}_basis`]} label="触发依据" rules={[{ required: true }]}><Select options={options} /></Form.Item>
    <Form.Item name={['actions', `${prefix}_value`]} label={basis === 'duration' ? '持续秒数' : '达到次数'} rules={[{ required: true }]}><InputNumber min={1} precision={0} /></Form.Item>
  </div>
}

export function PolicyStrategyEditor({ policy, creating, directory, connectors, saving, onCancel, onSave }: {
  policy: Policy
  creating: boolean
  directory?: FourKDirectory
  connectors: ActionConnector[]
  saving: boolean
  onCancel: () => void
  onSave: (policy: Policy) => void
}) {
  const [form] = Form.useForm<StrategyForm>()
  const [step, setStep] = useState(0)
  const actions = Form.useWatch('actions', form) as ActionEditor | undefined
  const products = useMemo(() => (directory?.products || []).map(item => ({ value: item.id, label: item.name ? `${item.name} (${item.id})` : item.id })), [directory])
  const groups = useMemo(() => (directory?.groups || []).map(item => ({ value: item.id, label: item.name ? `${item.name} (${item.id})` : item.id })), [directory])
  const accounts = useMemo(() => (directory?.accounts || []).map(item => ({ value: item.id, label: item.name || item.id })), [directory])
  const vlans = useMemo(() => (directory?.vlans || []).map(item => ({ value: item.id, label: item.name || item.id })), [directory])
  const managedConnectorId = directory?.source.startsWith('srun4k:') ? directory.source.slice('srun4k:'.length) : undefined

  useEffect(() => {
    const nextActions = actionValues(policy)
    const srun = connectors.find(connector => connector.connector_id === managedConnectorId && connector.enabled)
      || connectors.find(connector => connector.connector_type === 'srun4k' && connector.enabled)
    if (srun) {
      nextActions.notify_connector_id ||= srun.connector_id
      nextActions.disconnect_connector_id ||= srun.connector_id
      nextActions.disable_connector_id ||= srun.connector_id
    }
    const scopedPolicy = directory?.source ? {...policy,scope:{...policy.scope,sources:[directory.source]}} : policy
    form.setFieldsValue({ ...scopedPolicy, actions: nextActions })
    setStep(0)
  }, [connectors, directory?.source, form, managedConnectorId, policy])

  const next = async () => {
    const fields = step === 0 ? [['name'], ['scope', 'products'], ['scope', 'groups'], ['scope', 'vlans']] : [['limits', 'total'], ['limits', 'mobile'], ['limits', 'pc']]
    await form.validateFields(fields)
    setStep(current => Math.min(current + 1, 2))
  }
  const finish = async () => {
    const values = await form.validateFields()
    if (values.limits?.total == null && values.limits?.mobile == null && values.limits?.pc == null) {
      setStep(1)
      form.setFields([{name:['limits','total'],errors:['至少填写一项设备阈值']}])
      return
    }
    if (!values.actions?.notify_enabled && !values.actions?.disconnect_enabled && !values.actions?.disable_enabled) {
      form.setFields([{name:['actions','notify_enabled'],errors:['至少配置一项处理动作']}])
      return
    }
    onSave(buildPolicy(policy, values))
  }

  return <Modal className="policy-modal policy-strategy-modal" title={creating ? '新增设备配额策略' : '编辑设备配额策略'} open width={900} destroyOnHidden onCancel={onCancel} footer={
    <Space wrap className="policy-editor-footer">
      <Button onClick={onCancel}>返回列表</Button>
      {step > 0 && <Button onClick={() => setStep(current => current - 1)}>上一步</Button>}
      {step < 2 ? <Button type="primary" onClick={() => void next()}>下一步</Button> : <Button type="primary" loading={saving} onClick={() => void finish()}>保存设置</Button>}
    </Space>
  }>
    <Steps className="policy-editor-steps" current={step} responsive items={[{ title: '策略信息' }, { title: '配额超限认定条件' }, { title: '配额超限处理动作' }]} />
    <Form form={form} layout="vertical" className="policy-editor-form">
      <section className={step === 0 ? 'policy-editor-step is-active' : 'policy-editor-step'} aria-hidden={step !== 0}>
        <Typography.Title level={5}>策略信息</Typography.Title>
        <Form.Item name="name" label="策略名称" rules={[{ required: true, message: '请输入策略名称' }]}><Input placeholder="请输入名称" /></Form.Item>
        <Alert type="info" showIcon title={creating ? '新策略保存后默认为停用' : '策略开关在列表中管理'} description="4K只同步身份和匹配目录；认定条件与处理动作由当前策略配置。" />
        <Form.Item name="mode" label="运行模式" rules={[{required:true}]}><Select options={[{value:'automatic',label:'真实执行'},{value:'observe',label:'仅记录'},{value:'manual',label:'人工确认'}]} /></Form.Item>
        <Typography.Title level={5}>管控目标</Typography.Title>
        <div className="policy-form-grid">
          <Form.Item name={['scope', 'products']} label="选择产品"><Select mode="multiple" options={products} placeholder="请选择产品" /></Form.Item>
          <Form.Item name={['scope', 'groups']} label="选择用户组"><Select mode="multiple" options={groups} placeholder="请选择用户组" /></Form.Item>
          <Form.Item name={['scope', 'vlans']} label="VLAN"><Select mode="tags" options={vlans} tokenSeparators={[',']} placeholder="选择或输入VLAN" /></Form.Item>
          <Form.Item name={['scope', 'accounts']} label="限定账号"><Select mode="tags" options={accounts} tokenSeparators={[',']} placeholder="选择或输入账号" /></Form.Item>
        </div>
      </section>
      <section className={step === 1 ? 'policy-editor-step is-active' : 'policy-editor-step'} aria-hidden={step !== 1}>
        <Typography.Title level={5}>配额超限认定条件</Typography.Title>
        <Typography.Paragraph type="secondary">设备数量满足任意一项就会触发</Typography.Paragraph>
        <div className="policy-condition-grid">
          <Form.Item name={['limits', 'total']} label="全部设备数大于"><InputNumber min={0} precision={0} /></Form.Item>
          <span className="policy-condition-or">或者</span>
          <Form.Item name={['limits', 'pc']} label="电脑数量大于"><InputNumber min={0} precision={0} /></Form.Item>
          <span className="policy-condition-or">或者</span>
          <Form.Item name={['limits', 'mobile']} label="移动设备数量大于"><InputNumber min={0} precision={0} /></Form.Item>
        </div>
        <Alert type="warning" showIcon title="至少填写一项设备阈值" description="只统计身份覆盖完整且具有独立设备证据的在线终端；双栈地址不会重复计数。" />
      </section>
      <section className={step === 2 ? 'policy-editor-step is-active' : 'policy-editor-step'} aria-hidden={step !== 2}>
        <Typography.Title level={5}>配额超限处理动作</Typography.Title>
        <Alert type="info" showIcon title="动作由策略建立" description="同步4K信息不会生成动作。只有策略满足认定条件后，启用的动作才进入影子判定或执行流程。" />
        <article className="policy-action-card">
          <Form.Item name={['actions', 'notify_enabled']} label="消息提醒" valuePropName="checked"><Switch aria-label="消息提醒" /></Form.Item>
          {actions?.notify_enabled && <div className="policy-action-fields">
            <Form.Item name={['actions', 'notify_template']} label="消息内容" rules={[{ required: true }]}><Input.TextArea rows={3} /></Form.Item>
            <ActionDevice name={['actions', 'notify_connector_id']} action="notify" connectors={connectors} managedConnectorId={managedConnectorId}/>
            <Form.Item name={['actions', 'notify_after_seconds']} label="配额超限持续秒数" rules={[{ required: true }]}><InputNumber min={1} precision={0} /></Form.Item>
            <Form.Item name={['actions', 'notify_interval_seconds']} label="执行间隔秒数" rules={[{ required: true }]}><InputNumber min={1} precision={0} /></Form.Item>
          </div>}
        </article>
        <article className="policy-action-card">
          <Form.Item name={['actions', 'disconnect_enabled']} label="强制下线" valuePropName="checked"><Switch aria-label="强制下线" /></Form.Item>
          {actions?.disconnect_enabled && <><BasisFields prefix="disconnect"/><ActionDevice name={['actions', 'disconnect_connector_id']} action="disconnect" connectors={connectors} managedConnectorId={managedConnectorId}/><Form.Item name={['actions', 'disconnect_sync_notify']} valuePropName="checked"><Checkbox>同时消息提醒用户</Checkbox></Form.Item></>}
        </article>
        <article className="policy-action-card">
          <Form.Item name={['actions', 'disable_enabled']} label="用户禁用" valuePropName="checked"><Switch aria-label="用户禁用" /></Form.Item>
          {actions?.disable_enabled && <><BasisFields prefix="disable"/><Form.Item name={['actions', 'disable_duration_seconds']} label="禁用秒数" rules={[{ required: true }]}><InputNumber min={1} precision={0}/></Form.Item><ActionDevice name={['actions', 'disable_connector_id']} action="disable_account" connectors={connectors} managedConnectorId={managedConnectorId}/><Form.Item name={['actions', 'disable_sync_notify']} valuePropName="checked"><Checkbox>同时消息提醒用户</Checkbox></Form.Item></>}
        </article>
      </section>
    </Form>
  </Modal>
}
