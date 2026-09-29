import { useEffect, useState } from 'react'
import { Alert, Button, Descriptions, Form, Input, InputNumber, Modal, Space, Spin, Switch } from 'antd'
import { api } from '../../shared/api/client'
import type { FourKDatabaseConfig, FourKAuthorizationCheck } from '../../shared/api/types'

export function FourKDatabaseModal({ connectorId, onClose }: { connectorId: string; onClose: () => void }) {
  const [form] = Form.useForm<FourKDatabaseConfig>()
  const [configured, setConfigured] = useState(false)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)
  const [check, setCheck] = useState<FourKAuthorizationCheck>()
  useEffect(() => {
    let active = true
    api.fourKDatabase(connectorId).then(value => {
      if (!active) return
      form.setFieldsValue({ ...value.configuration, password: '' })
      setConfigured(value.password_configured)
    }).catch(reason => { if (active) setError(reason instanceof Error ? reason.message : '配置读取失败') })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [connectorId, form])
  const save = async (test: boolean) => {
    const value = await form.validateFields()
    setBusy(true); setError(''); setSaved(false); setCheck(undefined)
    try {
      await api.saveFourKDatabase(connectorId, { ...value, authorization_id: value.authorization_id ?? 0, password: value.password ?? '' })
      setConfigured(true); form.setFieldValue('password', ''); setSaved(true)
      if (test) setCheck(await api.checkFourKDatabase(connectorId))
      else onClose()
    } catch (reason) { setError(reason instanceof Error ? reason.message : '数据库配置或授权查询失败') }
    finally { setBusy(false) }
  }
  return <Modal className="four-k-database-modal" title="4K 数据库授权" open onCancel={onClose} destroyOnHidden footer={
    <Space wrap className="four-k-database-actions">
      <Button onClick={onClose}>关闭</Button>
      <Button disabled={loading} loading={busy} onClick={() => void save(true)}>保存并检查授权</Button>
      <Button type="primary" disabled={loading} loading={busy} onClick={() => void save(false)}>保存</Button>
    </Space>
  }>
    <div className="four-k-database-content">
      <Alert type="info" title="自动读取管理授权" description="从 authorization 表读取启用且未过期的授权，用于申请管理接口令牌。多条有效授权时需指定记录 ID。检查操作不会下线用户。" showIcon />
      {error && <Alert type="error" title={error} showIcon />}
      {saved && <Alert type="success" title="配置已保存，数据库密码不会回显" showIcon />}
      {loading ? <Spin /> : <Form className="four-k-database-form" form={form} layout="vertical" initialValues={{ port: 3306, tls: false }} onValuesChange={() => { setSaved(false); setCheck(undefined) }}>
        <Form.Item name="host" label="数据库地址" rules={[{ required: true }]}><Input placeholder="例如 192.168.0.190" /></Form.Item>
        <Form.Item name="port" label="数据库端口" rules={[{ required: true }]}><InputNumber min={1} max={65535} precision={0} /></Form.Item>
        <Form.Item name="database" label="数据库名" rules={[{ required: true }]}><Input /></Form.Item>
        <Form.Item name="username" label="数据库用户名" rules={[{ required: true }]}><Input autoComplete="off" /></Form.Item>
        <Form.Item name="password" label={configured ? '数据库密码（留空保持不变）' : '数据库密码'} rules={configured ? [] : [{ required: true }]}><Input.Password autoComplete="new-password" /></Form.Item>
        <Form.Item name="authorization_id" label="授权记录 ID" extra="留空自动选择唯一有效授权；有多条时填写指定 ID。"><InputNumber min={1} precision={0} /></Form.Item>
        <Form.Item name="tls" label="数据库 TLS" valuePropName="checked"><Switch /></Form.Item>
      </Form>}
      {check && <div className="four-k-database-result"><Descriptions column={1} size="small" title="只读授权检查通过" items={[
        { key: 'id', label: '授权记录', children: check.authorization_id },
        { key: 'app', label: 'App ID', children: check.app_id },
        { key: 'organization', label: '接入组织', children: check.organization },
        { key: 'expiry', label: '有效期', children: check.expires_at === 0 ? '长期有效' : new Date(check.expires_at * 1000).toLocaleString() },
        { key: 'scope', label: '检查范围', children: '已读取数据库授权；管理接口及在线清单需另行检查。' },
      ]} /></div>}
    </div>
  </Modal>
}
