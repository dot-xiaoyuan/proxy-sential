import { useEffect, useState } from 'react'
import { Alert, Button, Form, Input, InputNumber, Modal, Select, Space, Spin, Switch } from 'antd'
import { api } from '../../shared/api/client'
import type { ManagedIdentityConfiguration } from '../../shared/api/types'

export function IdentitySourceModal({ connectorId, onClose }: { connectorId: string; onClose: () => void }) {
  const [form] = Form.useForm<ManagedIdentityConfiguration & { cidrs: string }>()
  const [version, setVersion] = useState(0)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [state, setState] = useState('')
  const [tokenConfigured, setTokenConfigured] = useState(false)
  const kind = Form.useWatch('kind', form)
  useEffect(() => {
    let active = true
    api.identitySource(connectorId).then(result => {
      if (!active) return
      form.setFieldsValue({ ...result.configuration, token: '', cidrs: result.configuration.user_cidrs?.join('\n') ?? '' })
      setVersion(result.config_version); setState(result.state); setTokenConfigured(result.token_configured)
    }).catch(reason => { if (active) setError(reason instanceof Error ? reason.message : '身份配置读取失败') })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [connectorId, form])
  const save = async () => {
    const value = await form.validateFields()
    setBusy(true); setError('')
    try {
      const { cidrs, ...configuration } = value
      await api.saveIdentitySource(connectorId, {
        configuration: { ...configuration, user_cidrs: cidrs.split(/[\s,，]+/).filter(Boolean), inventory_url: kind === 'complete_inventory' ? value.inventory_url : '', token: kind === 'complete_inventory' ? value.token ?? '' : '' },
        config_version: version,
      })
      onClose()
    } catch (reason) { setError(reason instanceof Error ? reason.message : '身份配置保存失败') }
    finally { setBusy(false) }
  }
  return <Modal className="four-k-database-modal" title="身份来源与接入范围" open onCancel={onClose} destroyOnHidden footer={<Space wrap className="four-k-database-actions"><Button onClick={onClose}>取消</Button><Button type="primary" disabled={loading} loading={busy} onClick={() => void save()}>保存</Button></Space>}>
    <div className="four-k-database-content">
      <Alert type="info" showIcon title="每五秒同步，完整性不足时阻断处置" description="原生 online-equipment 仅支持条件查询，尚不能证明全接入域清单完整。只有已部署且提供完整性契约的清单接口才可提交权威快照。办公室测试可填写独立测试范围。" />
      {error && <Alert type="error" showIcon title={error} />}
      {state && <Alert type="info" title={`同步状态：${({ pending: '等待检查', unavailable: '来源不可用', healthy: '最近同步成功', not_configured: '尚未配置' } as Record<string, string>)[state] ?? state}`} />}
      {loading ? <Spin /> : <Form form={form} layout="vertical" className="four-k-database-form identity-source-form">
        <Form.Item className="identity-source-kind" name="kind" label="身份来源" rules={[{ required: true }]}><Select options={[{ value: 'online_equipment', label: '4K 原生在线设备接口（完整性待验收）' }, { value: 'complete_inventory', label: '已有完整在线清单接口' }]} /></Form.Item>
        <Form.Item name="source" label="来源标识" rules={[{ required: true }]}><Input /></Form.Item>
        <Form.Item name="sensor_id" label="关联采集器" rules={[{ required: true }]}><Input /></Form.Item>
        <Form.Item name="campus_id" label="校区 / 测试范围" rules={[{ required: true }]}><Input placeholder="例如 office-test" /></Form.Item>
        <Form.Item name="access_domain" label="接入域" rules={[{ required: true }]}><Input placeholder="例如 office-lan" /></Form.Item>
        <Form.Item name="cidrs" label="受控用户网段（CIDR）" rules={[{ required: true }]} extra="每行一个网段，只填写本次受控范围；不会据此修改采集器配置。"><Input.TextArea rows={3} placeholder="例如 192.168.0.0/24，须与实际网络一致" /></Form.Item>
        {kind === 'complete_inventory' && <>
          <Form.Item name="inventory_url" label="已有完整清单接口地址" rules={[{ required: true }]}><Input placeholder="https://认证系统/已有清单接口" /></Form.Item>
          <Form.Item name="token" label={tokenConfigured ? '清单凭据（留空保持；更换地址必须重新填写）' : '已有清单 Bearer 凭据'} rules={tokenConfigured ? [] : [{ required: true }]}><Input.Password autoComplete="new-password" /></Form.Item>
        </>}
        <Form.Item name="max_records" label="清单记录上限" rules={[{ required: true }]}><InputNumber min={1} max={10000} precision={0} /></Form.Item>
        <Form.Item name="enabled" label="启用只读身份同步" valuePropName="checked"><Switch /></Form.Item>
      </Form>}
    </div>
  </Modal>
}
