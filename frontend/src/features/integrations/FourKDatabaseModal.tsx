import { useEffect, useState } from 'react'
import { Alert, Button, Descriptions, Form, Input, InputNumber, Modal, Space, Spin } from 'antd'

import { api, ApiError } from '../../shared/api/client'
import type { SRun4KIntegration, SRun4KIntegrationRequest, SRun4KSyncResult, SRun4KTestResult } from '../../shared/api/types'

type ConnectionForm = SRun4KIntegrationRequest

const channelLabels: Record<string, string> = {
  authorization_database: '授权数据库', online_redis: '在线清单 Redis', catalog_redis: '产品/控制目录 Redis',
  event_redis: '上下线事件 Redis', northbound_api: '北向 API', event_channel: '事件消费状态',
}

function stateLabel(value?: string) {
  if (value === 'healthy') return '正常'
  if (value === 'failed' || value === 'interrupted') return '连接失败'
  if (value === 'waiting') return '等待事件通道接入'
  return ''
}

function channelItems(channels?: Record<string, string>) {
  if (!channels) return []
  return Object.entries(channelLabels).filter(([key]) => channels[key]).map(([key, label]) => ({ key, label, children: stateLabel(channels[key]) }))
}

export function FourKDatabaseModal({ connectorId, initialHost, onClose, onSaved }: { connectorId?:string; initialHost?:string; onClose:()=>void; onSaved?:()=>void }) {
  const [form] = Form.useForm<ConnectionForm>()
  const watched = Form.useWatch([], form) as ConnectionForm | undefined
  const [integration, setIntegration] = useState<SRun4KIntegration>()
  const [check, setCheck] = useState<SRun4KTestResult>()
  const [sync, setSync] = useState<SRun4KSyncResult>()
  const [loading, setLoading] = useState(Boolean(connectorId))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const onlineChanged = Boolean(integration && watched?.online_redis_host?.trim() && watched.online_redis_host.trim() !== integration.online_redis_host)
  const endpointChanged = Boolean(integration && watched && (
    watched.authorization_database_host !== integration.authorization_database_host || watched.online_redis_host !== integration.online_redis_host ||
    watched.catalog_redis_host !== integration.catalog_redis_host || watched.event_redis_host !== integration.event_redis_host || watched.northbound_api_host !== integration.northbound_api_host
  ))

  useEffect(() => {
    let active = true
    const initial = initialHost ? { authorization_database_host: initialHost, online_redis_host: initialHost, catalog_redis_host: initialHost, northbound_api_host: initialHost } : {}
    form.setFieldsValue({ ...initial, reconcile_interval_hours: 6 })
    if (!connectorId) return () => { active = false }
    api.srun4KIntegration(connectorId).then(value => {
      if (!active) return
      setIntegration(value)
      form.setFieldsValue({
        authorization_database_host: value.authorization_database_host,
        online_redis_host: value.online_redis_host,
        catalog_redis_host: value.catalog_redis_host,
        event_redis_host: value.event_redis_host,
        northbound_api_host: value.northbound_api_host,
        reconcile_interval_hours: value.reconcile_interval_hours,
      })
    }).catch(reason => {
      if (!active || (reason instanceof ApiError && reason.status === 404)) return
      setError(reason instanceof Error ? reason.message : '4K接入读取失败')
    }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [connectorId, form, initialHost])

  const save = async (synchronize:boolean) => {
    const value = await form.validateFields()
    setBusy(true); setError(''); setCheck(undefined); setSync(undefined)
    let savedId:string | undefined
    try {
      const saved = connectorId ? await api.updateSRun4KIntegration(connectorId, value) : await api.createSRun4KIntegration(value)
      setIntegration(saved); savedId = saved.connector_id; onSaved?.()
      const tested = await api.testSRun4KIntegration(saved.connector_id)
      setCheck(tested)
      if (synchronize) {
        const result = await api.syncSRun4KIntegration(saved.connector_id)
        setSync(result); setIntegration(await api.srun4KIntegration(saved.connector_id)); setCheck(undefined)
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '4K接入检查或同步失败')
      if (savedId) {
        setCheck(undefined)
        try { setIntegration(await api.srun4KIntegration(savedId)) } catch { /* Keep the operation error when refreshing also fails. */ }
      }
    } finally { setBusy(false) }
  }

  const refreshAuthorization = async () => {
    if (!integration) return
    setBusy(true); setError('')
    try { setIntegration(await api.refreshSRun4KAuthorization(integration.connector_id)); onSaved?.() }
    catch (reason) { setError(reason instanceof Error ? reason.message : '北向授权刷新失败') }
    finally { setBusy(false) }
  }

  const channels = check?.channels ?? integration?.channels
  const eventState = channels?.event_channel ?? integration?.event_channel_state

  return <Modal className="four-k-database-modal" title="深澜 4K 接入" open onCancel={onClose} destroyOnHidden footer={
    <Space wrap className="four-k-database-actions">
      <Button onClick={onClose}>关闭</Button>
      {integration && <Button disabled={loading} loading={busy} onClick={() => void refreshAuthorization()}>刷新北向授权</Button>}
      <Button disabled={loading} loading={busy} onClick={() => void save(false)}>保存并测试</Button>
      <Button type="primary" disabled={loading} loading={busy} onClick={() => void save(true)}>保存并立即同步</Button>
    </Space>
  }>
    <div className="four-k-database-content">
      <Alert type="info" showIcon title="按实际服务分别填写地址" description="数据库、Redis 的端口与凭据，以及北向 API 协议、端口和证书由部署配置提供。授权仅在首次校验或手动刷新时读取；日常同步使用加密保存的北向授权。" />
      {eventState !== 'healthy' && <Alert type="warning" showIcon title="真实动作暂不可用" description="上下线事件 Redis 尚未完成接入或验收。可继续检查与同步目录，服务端会阻止真实动作。" />}
      {onlineChanged && <Alert type="info" showIcon title="在线清单地址变化" description="保存后将建立新的身份来源版本并清空当前同步摘要；其他通道地址变化只重置对应连接状态，不改变身份来源。" />}
      {error && <Alert type="error" showIcon title={error} />}
      {loading && <Spin />}
      <Form className={`four-k-database-form${loading ? ' is-loading' : ''}`} form={form} layout="vertical" initialValues={{reconcile_interval_hours:6}} onValuesChange={() => { setCheck(undefined); setSync(undefined) }}>
        <Form.Item name="authorization_database_host" label="授权数据库地址" rules={[{required:true,message:'请输入授权数据库地址'}, {pattern:/^[a-zA-Z0-9.:[\]-]+$/,message:'请输入有效的IP或主机名'}]}><Input placeholder="MySQL 主机或 IP" /></Form.Item>
        <Form.Item name="online_redis_host" label="在线清单 Redis 地址" rules={[{required:true,message:'请输入在线清单 Redis 地址'}, {pattern:/^[a-zA-Z0-9.:[\]-]+$/,message:'请输入有效的IP或主机名'}]}><Input placeholder="在线用户清单所在主机" /></Form.Item>
        <Form.Item name="catalog_redis_host" label="产品/控制目录 Redis 地址" rules={[{required:true,message:'请输入产品/控制目录 Redis 地址'}, {pattern:/^[a-zA-Z0-9.:[\]-]+$/,message:'请输入有效的IP或主机名'}]}><Input placeholder="产品与控制目录所在主机" /></Form.Item>
        <Form.Item name="event_redis_host" label="上下线事件 Redis 地址" extra="未接入时可留空；真实动作将保持阻断。" rules={[{pattern:/^[a-zA-Z0-9.:[\]-]+$/,message:'请输入有效的IP或主机名'}]}><Input placeholder="事件通道所在主机" /></Form.Item>
        <Form.Item name="northbound_api_host" label="北向 API 地址" rules={[{required:true,message:'请输入北向 API 地址'}, {pattern:/^[a-zA-Z0-9.:[\]-]+$/,message:'请输入有效的IP或主机名'}]}><Input placeholder="北向接口主机或 IP" /></Form.Item>
        <Form.Item name="reconcile_interval_hours" label="全量校准周期（小时）" extra="默认每6小时校准一次，可设置为1至168小时。"><InputNumber min={1} max={168} precision={0} /></Form.Item>
      </Form>
      {integration && <div className="four-k-authorization-state"><span>北向授权</span><strong>{integration.authorization_ready ? '已验证并加密保存' : ''}</strong>{integration.authorization_refreshed_at && <small>最近刷新 {new Date(integration.authorization_refreshed_at).toLocaleString()}</small>}</div>}
      {!endpointChanged && channels && <Descriptions className="four-k-database-result" column={1} size="small" title="通道状态" items={channelItems(channels)} />}
      {check && <Descriptions className="four-k-database-result" column={1} size="small" title="连接测试" items={[{key:'online',label:'在线用户数量',children:check.online_total}]} />}
      {sync && <Descriptions className="four-k-sync-summary" column={1} size="small" title="最近同步摘要" items={[
        {key:'identity',label:'身份关联',children:`${sync.identity_accounts}个账号 / ${sync.identity_sessions}个会话 / ${sync.address_records}个地址`},
        {key:'catalog',label:'匹配目录',children:`${sync.products}个产品 / ${sync.groups}个用户组 / ${sync.controls}个来源控制策略`},
      ]} />}
      {!endpointChanged && !sync && integration?.last_synced_at && <Descriptions className="four-k-sync-summary" column={1} size="small" title="最近同步摘要" items={[
        {key:'time',label:'同步时间',children:new Date(integration.last_synced_at).toLocaleString()},
        {key:'identity',label:'身份关联',children:`${integration.identity_accounts}个账号 / ${integration.identity_sessions}个会话`},
        {key:'catalog',label:'匹配目录',children:`${integration.products}个产品 / ${integration.groups}个用户组 / ${integration.controls}个来源控制策略`},
      ]} />}
    </div>
  </Modal>
}
