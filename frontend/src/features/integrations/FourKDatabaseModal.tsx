import { useEffect, useState } from 'react'
import { Alert, Button, Descriptions, Form, Input, InputNumber, Modal, Space, Spin } from 'antd'

import { api, ApiError } from '../../shared/api/client'
import type { SRun4KIntegration, SRun4KSyncResult, SRun4KTestResult } from '../../shared/api/types'

type ConnectionForm = { host:string; reconcile_interval_hours?:number }

export function FourKDatabaseModal({ connectorId, initialHost, onClose, onSaved }: { connectorId?:string; initialHost?:string; onClose:()=>void; onSaved?:()=>void }) {
  const [form] = Form.useForm<ConnectionForm>()
  const enteredHost = Form.useWatch('host', form)
  const [integration, setIntegration] = useState<SRun4KIntegration>()
  const [check, setCheck] = useState<SRun4KTestResult>()
  const [sync, setSync] = useState<SRun4KSyncResult>()
  const [loading, setLoading] = useState(Boolean(connectorId))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const hostChanged = Boolean(integration && enteredHost?.trim() && enteredHost.trim() !== integration.host)
  const eventState = hostChanged ? 'waiting' : check?.channels.event_channel ?? integration?.event_channel_state
  const syncConnectionState = integration?.connection_state ?? sync?.connection_state

  useEffect(() => {
    let active = true
    form.setFieldsValue({host:initialHost,reconcile_interval_hours:6})
    if (!connectorId) return () => { active = false }
    api.srun4KIntegration(connectorId).then(value => {
      if (!active) return
      setIntegration(value)
      form.setFieldsValue({host:value.host,reconcile_interval_hours:value.reconcile_interval_hours})
    }).catch(reason => {
      if (!active || (reason instanceof ApiError && reason.status === 404)) return
      setError(reason instanceof Error ? reason.message : '4K接入读取失败')
    })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [connectorId, form, initialHost])

  const save = async (synchronize:boolean) => {
    const value = await form.validateFields()
    setBusy(true); setError(''); setCheck(undefined); setSync(undefined)
    let savedId:string | undefined
    try {
      const saved = connectorId
        ? await api.updateSRun4KIntegration(connectorId, value)
        : await api.createSRun4KIntegration(value)
      setIntegration(saved)
      savedId = saved.connector_id
      onSaved?.()
      const tested = await api.testSRun4KIntegration(saved.connector_id)
      setCheck(tested)
      if (synchronize) {
        const result = await api.syncSRun4KIntegration(saved.connector_id)
        setSync(result)
        setIntegration(await api.srun4KIntegration(saved.connector_id))
        setCheck(undefined)
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '4K接入检查或同步失败')
      if (savedId) {
        setCheck(undefined)
        try { setIntegration(await api.srun4KIntegration(savedId)) } catch { /* Keep the operation error when refreshing also fails. */ }
      }
    } finally { setBusy(false) }
  }

  return <Modal className="four-k-database-modal" title="深澜 4K 接入" open onCancel={onClose} destroyOnHidden footer={
    <Space wrap className="four-k-database-actions">
      <Button onClick={onClose}>关闭</Button>
      <Button disabled={loading} loading={busy} onClick={() => void save(false)}>保存并测试</Button>
      <Button type="primary" disabled={loading} loading={busy} onClick={() => void save(true)}>保存并立即同步</Button>
    </Space>
  }>
    <div className="four-k-database-content">
      <Alert type="info" showIcon title="只需填写 4K 地址" description="数据库、Redis 与北向接口参数由部署配置提供。同步仅更新在线身份和产品、用户组、VLAN匹配目录，不会创建防代理策略或动作。" />
      {!loading && eventState !== 'healthy' && (hostChanged || !connectorId || eventState === 'waiting' || eventState === 'interrupted') && <Alert type="warning" showIcon title={eventState === 'interrupted' ? '上线、下线事件通道已中断' : '上线、下线事件通道等待接入'} description="事件通道验收前可以同步目录和试算策略，所有真实动作会被服务端阻断。" />}
      {!hostChanged && sync && syncConnectionState === 'failed' && <Alert type="error" showIcon title="当前连接检查失败" description="目录同步已完成，最新连接检查仍为失败，请重新检查。" />}
      {hostChanged && <Alert type="info" showIcon title="更换地址后将重新校验身份来源" description="保存后使用新的身份来源，清空本接入的同步摘要并恢复影子模式。原来源的历史证据保留，原身份源配置停用。请同步新网关并检查相关策略范围。" />}
      {error && <Alert type="error" showIcon title={error} />}
      {loading && <Spin />}
      <Form className={`four-k-database-form${loading ? ' is-loading' : ''}`} form={form} layout="vertical" initialValues={{reconcile_interval_hours:6}} onValuesChange={() => { setCheck(undefined); setSync(undefined) }}>
        <Form.Item name="host" label="4K 地址" rules={[{required:true,message:'请输入4K地址'},{validator:(_,value:string) => !value || /^[a-zA-Z0-9.:[\]-]+$/.test(value) ? Promise.resolve() : Promise.reject(new Error('请输入有效的IP或主机名'))}]}><Input placeholder="例如 192.168.0.190" /></Form.Item>
        <Form.Item name="reconcile_interval_hours" label="全量校准周期（小时）" extra="可选，默认每6小时校准一次。"><InputNumber min={1} max={168} precision={0} /></Form.Item>
      </Form>
      {check && <Descriptions className="four-k-database-result" column={1} size="small" title="通道检查" items={[
        {key:'authorization',label:'授权库',children:check.channels.authorization_database === 'healthy' ? '正常' : check.channels.authorization_database},
        {key:'redis',label:'Redis',children:check.channels.redis === 'healthy' ? '正常' : check.channels.redis},
        {key:'api',label:'北向接口',children:check.channels.northbound_api === 'healthy' ? '正常' : check.channels.northbound_api},
        {key:'event',label:'上线、下线事件',children:check.channels.event_channel === 'healthy' ? '正常' : '等待事件通道接入'},
        {key:'online',label:'在线用户',children:check.online_total},
      ]} />}
      {!hostChanged && !check && integration && <Descriptions className="four-k-database-result" column={1} size="small" title="通道状态" items={[
        {key:'authorization',label:'授权库',children:integration.channels?.authorization_database === 'healthy' ? '正常' : integration.channels?.authorization_database === 'failed' ? '连接失败' : ''},
        {key:'redis',label:'Redis',children:integration.channels?.redis === 'healthy' ? '正常' : integration.channels?.redis === 'failed' ? '连接失败' : ''},
        {key:'api',label:'北向接口',children:integration.channels?.northbound_api === 'healthy' ? '正常' : integration.channels?.northbound_api === 'failed' ? '连接失败' : ''},
        {key:'event',label:'上线、下线事件',children:integration.channels?.event_channel === 'healthy' ? '正常' : '等待事件通道接入'},
      ]} />}
      {sync && <Descriptions className="four-k-sync-summary" column={1} size="small" title="最近同步摘要" items={[
        {key:'identity',label:'身份关联',children:`${sync.identity_accounts}个账号 / ${sync.identity_sessions}个会话 / ${sync.address_records}个地址`},
        {key:'catalog',label:'匹配目录',children:`${sync.products}个产品 / ${sync.groups}个用户组 / ${sync.controls}个来源控制策略`},
        {key:'action',label:'接入条件',children:syncConnectionState === 'failed' ? '连接检查失败' : eventState === 'healthy' ? '连接与事件通道正常' : eventState === 'interrupted' ? '事件通道已中断' : '等待事件通道接入'},
      ]} />}
      {!hostChanged && integration && (integration.last_identity_poll_at || integration.last_identity_event_at) && <Descriptions className="four-k-sync-summary" column={1} size="small" title="身份接入进度" items={[
        ...(integration.last_identity_poll_at ? [{key:'poll',label:'在线清单最近检查',children:new Date(integration.last_identity_poll_at).toLocaleString()}] : []),
        ...(integration.last_identity_event_at ? [{key:'event',label:'最近认证事件',children:new Date(integration.last_identity_event_at).toLocaleString()}] : []),
      ]} />}
      {!hostChanged && !sync && integration?.last_synced_at && <Descriptions className="four-k-sync-summary" column={1} size="small" title="最近同步摘要" items={[
        {key:'time',label:'同步时间',children:new Date(integration.last_synced_at).toLocaleString()},
        {key:'identity',label:'身份关联',children:`${integration.identity_accounts}个账号 / ${integration.identity_sessions}个会话`},
        {key:'catalog',label:'匹配目录',children:`${integration.products}个产品 / ${integration.groups}个用户组 / ${integration.controls}个来源控制策略`},
      ]} />}
    </div>
  </Modal>
}
