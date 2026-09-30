import { useEffect, useState } from 'react'
import {
  CheckCircleOutlined,
  CloseOutlined,
  CodeOutlined,
  TagOutlined,
} from '@ant-design/icons'
import { Alert, Button, Card, Descriptions, Drawer, message, Space, Table, Typography } from 'antd'
import { Link } from 'react-router-dom'
import type { ColumnsType } from 'antd/es/table'

import { RiskLevelTag } from '../../entities/risk/RiskLevelTag'
import {
  useCreateLabel,
  useDpiIpFlows,
  useIpEvidence,
  useIpRisk,
  useSession,
} from '../../shared/api/queries'
import type { CreateLabelRequest, DpiFlowSample, EventQuery } from '../../shared/api/types'

interface FlowInspectorDrawerProps {
  ip: string | null
  open: boolean
  onClose: () => void
  context?: EventQuery
}

export function FlowInspectorDrawer({ ip, open, onClose, context }: FlowInspectorDrawerProps) {
  const [selectedFlow, setSelectedFlow] = useState<DpiFlowSample | null>(null)
  const session = useSession()
  const permissions = session.data?.permissions ?? []
  const risk = useIpRisk(ip ?? '', open && permissions.includes('risks:read'))
  const evidence = useIpEvidence(ip ?? '', {limit:20}, open && permissions.includes('evidence:read'))
  const flowSamples = useDpiIpFlows(ip ?? '', { window: '1h', ...context, limit: 50 }, open && permissions.includes('dpi:read'))
  const createLabel = useCreateLabel()
  useEffect(() => setSelectedFlow(null), [ip])

  if (!ip) return null

  const canCreateLabel = permissions.includes('labels:create') && !evidence.isFetching && !evidence.isError && Boolean(evidence.data?.evidence.length)
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
    >
      <div className="drawer-stack">
        <Alert
          description={`Flow 查询窗口：${context?.window || '1h'}。风险与复核依据为当前风险快照，历史回放请进入样本复核。`}
          showIcon
          type="info"
        />
        {risk.isError && <Alert type="error" showIcon title="当前风险快照读取失败" />}
        {evidence.isError && <Alert type="error" showIcon title="复核证据读取失败" />}
        {flowSamples.isError && <Alert type="error" showIcon title="Flow 样本读取失败" />}

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
              确认代理
            </Button>
            <Button
              className="dpi-badge-tag"
              disabled={!canCreateLabel}
              icon={<CheckCircleOutlined />}
              loading={createLabel.isPending}
              onClick={() => handleCreateLabel('false_positive')}
            >
              标记误报
            </Button>
            {permissions.includes('shadow:read') && <Link to="/shadow-runs">查看影子评估</Link>}
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
