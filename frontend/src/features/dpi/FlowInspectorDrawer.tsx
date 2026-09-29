import { useState } from 'react'
import {
  CheckCircleOutlined,
  CloseOutlined,
  CodeOutlined,
  FieldTimeOutlined,
  TagOutlined,
} from '@ant-design/icons'
import { Alert, Button, Card, Descriptions, Drawer, message, Modal, Space, Table, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import { RiskLevelTag } from '../../entities/risk/RiskLevelTag'
import {
  useCreateLabel,
  useDpiIpFlows,
  useIpEvidence,
  useIpRisk,
  useReloadRules,
  useSession,
} from '../../shared/api/queries'
import type { CreateLabelRequest, DpiFlowSample } from '../../shared/api/types'

interface FlowInspectorDrawerProps {
  ip: string | null
  open: boolean
  onClose: () => void
}

export function FlowInspectorDrawer({ ip, open, onClose }: FlowInspectorDrawerProps) {
  const [selectedFlow, setSelectedFlow] = useState<DpiFlowSample | null>(null)
  const session = useSession()
  const risk = useIpRisk(ip ?? '')
  const evidence = useIpEvidence(ip ?? '')
  const flowSamples = useDpiIpFlows(ip ?? '', { window: '1h', limit: 50 })
  const createLabel = useCreateLabel()
  const reloadRules = useReloadRules()

  if (!ip) return null

  const permissions = session.data?.permissions ?? []
  const canCreateLabel = permissions.includes('labels:create')
  const canReloadRules = permissions.includes('rules:reload')
  const rows = flowSamples.data?.items ?? []
  const firstFlow = rows[0]
  const snapshot = risk.data

  const handleCreateLabel = async (label: CreateLabelRequest['label']) => {
    if (!canCreateLabel) {
      message.warning('当前控制面为只读模式，复核标签写入已禁用')
      return
    }
    try {
      await createLabel.mutateAsync({
        target_type: 'ip',
        target_id: ip,
        label,
        reason: label === 'confirmed_proxy' ? 'DPI Flow 样本追查确认代理/共享风险' : 'DPI Flow 样本追查标记误报或良性',
        evidence_ids: evidence.data?.evidence.map((item) => item.evidence_id) ?? [],
      })
      message.success(`成功为 IP ${ip} 添加标签 [${label}]`)
    } catch {
      message.error('标签添加失败')
    } finally {
    }
  }

  const handleTriggerShadow = async () => {
    if (!canReloadRules) {
      message.warning('当前控制面为只读模式，规则 reload 已禁用')
      return
    }
    try {
      await reloadRules.mutateAsync()
      Modal.success({
        title: '影子审计任务已发起',
        content: `IP ${ip} 的 DPI 特征规则已重新加载并加入影子审计，审计日志可至【影子运行】页面查验。`,
      })
    } catch {
      message.error('触发影子审计失败')
    } finally {
    }
  }

  const columns: ColumnsType<DpiFlowSample> = [
    { title: '时间戳', dataIndex: 'timestamp', width: 170, render: (v: string) => new Date(v).toLocaleString() },
    { title: '协议', dataIndex: 'protocol', width: 70 },
    { title: '应用协议', dataIndex: 'app_protocol', width: 110 },
    { title: '源端口', dataIndex: 'src_port', width: 80 },
    { title: '目的端口', dataIndex: 'dst_port', width: 90 },
    { title: 'SNI / Domain', render: (_, row) => row.tls_sni || row.domain || '' },
    { title: 'TTL', dataIndex: 'ttl', width: 60 },
    { title: 'Payload 摘要', dataIndex: 'payload_summary', render: (v: string) => <span className="mono wrap-text">{v}</span> },
  ]

  return (
    <Drawer
      extra={
        <Button icon={<CloseOutlined />} onClick={onClose} type="text" />
      }
      onClose={onClose}
      open={open}
      size="large"
      title={
        <div className="drawer-title-row">
          <CodeOutlined className="dpi-card-title-icon" />
          <span>标准化会话追查 - </span>
          <span className="mono wrap-text drawer-title-ip">
            {ip}
          </span>
          {snapshot && <RiskLevelTag level={snapshot.level} />}
        </div>
      }
      width={780}
    >
      <div className="drawer-stack">
        <Alert
          description="当前展示标准化 DPI Flow 元数据、风险摘要与证据上下文，不展示 Suricata 原始 EVE 或 payload 全量内容。"
          showIcon
          type="info"
        />

        <Card size="small" title="IP 深度概览与采集上下文">
          <Descriptions column={2} size="small">
            <Descriptions.Item label="目标 IP">{ip}</Descriptions.Item>
            <Descriptions.Item label="风险等级">{snapshot ? <RiskLevelTag level={snapshot.level} /> : ''}</Descriptions.Item>
            <Descriptions.Item label="风险评分">{snapshot?.score ?? ''}</Descriptions.Item>
            <Descriptions.Item label="证据条数">{evidence.data?.evidence.length ?? 0}</Descriptions.Item>
            <Descriptions.Item label="活跃 Sensor">{firstFlow?.sensor_id ?? ''}</Descriptions.Item>
            <Descriptions.Item label="采集接口">{firstFlow?.interface_name ?? ''}</Descriptions.Item>
          </Descriptions>
        </Card>

        <Card size="small" title="复核动作 (read-only 时禁用)">
          <Space size="middle" wrap>
            <Button
              className="dpi-badge-tag"
              disabled={!canCreateLabel}
              icon={<TagOutlined />}
              loading={createLabel.isPending}
              onClick={() => handleCreateLabel('confirmed_proxy')}
              type="primary"
            >
              确认违规共享上网
            </Button>
            <Button
              className="dpi-badge-tag"
              disabled={!canCreateLabel}
              icon={<CheckCircleOutlined />}
              loading={createLabel.isPending}
              onClick={() => handleCreateLabel('false_positive')}
            >
              标记误报 / 白名单
            </Button>
            <Button
              className="dpi-badge-tag"
              disabled={!canReloadRules}
              icon={<FieldTimeOutlined />}
              loading={reloadRules.isPending}
              onClick={handleTriggerShadow}
            >
              一键加入影子审计
            </Button>
          </Space>
        </Card>

        <Card size="small" title="DPI Flow 样本 (标准化事件元数据)">
          <Table<DpiFlowSample>
            columns={columns}
            dataSource={rows}
            loading={flowSamples.isLoading}
            onRow={(record) => ({ onClick: () => setSelectedFlow(record) })}
            pagination={false}
            rowKey="flow_id"
            scroll={{ x: 700 }}
            size="small"
          />
        </Card>

        {(selectedFlow || firstFlow) && (
          <Card size="small" title="标准化 Flow 样本 JSON">
            <Typography.Text className="drawer-json-caption" type="secondary">
              仅包含标准化元数据字段，不包含原始报文。
            </Typography.Text>
            <pre className="dpi-drawer-json">{JSON.stringify(selectedFlow ?? firstFlow, null, 2)}</pre>
          </Card>
        )}
      </div>
    </Drawer>
  )
}
