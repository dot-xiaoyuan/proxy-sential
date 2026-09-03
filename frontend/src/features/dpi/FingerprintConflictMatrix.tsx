import { ApartmentOutlined, SearchOutlined } from '@ant-design/icons'
import { Button, Card, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import { RiskLevelTag } from '../../entities/risk/RiskLevelTag'
import type { FingerprintConflictItem } from '../../shared/api/types'

interface FingerprintConflictMatrixProps {
  items: FingerprintConflictItem[]
  onInspectIp?: (ip: string) => void
}

export function FingerprintConflictMatrix({ items, onInspectIp }: FingerprintConflictMatrixProps) {
  const totalConflicts = items.length
	const columns: ColumnsType<FingerprintConflictItem> = [
		{ title: 'IP', dataIndex: 'ip', width: 150, render: (value: string) => <span className="list-cell-nowrap mono" title={value}>{value}</span> },
		{ title: '风险', dataIndex: 'risk_level', width: 90, render: (value) => <RiskLevelTag level={value} /> },
		{ title: '一致性检查', dataIndex: 'type_label', width: 170, render: (value: string) => <Tag className="dpi-badge-tag" color="purple">{value}</Tag> },
		{ title: '评估', dataIndex: 'assessment', width: 130, render: (value: string) => <Tag>{value === 'conflict' ? '冲突' : '需要独立证据复核'}</Tag> },
		{ title: '样本', dataIndex: 'sample_count', width: 80 },
		{ title: '说明', dataIndex: 'reason', ellipsis: true, render: (value: string) => <Typography.Text className="list-cell-nowrap" title={value}>{value}</Typography.Text> },
		{ title: '操作', key: 'action', width: 90, render: (_, item) => <Button icon={<SearchOutlined />} onClick={() => onInspectIp?.(item.ip)} size="small">追查</Button> },
	]

  return (
    <Card className="surface-card" size="small">
      <div className="dpi-card-header">
        <div className="dpi-card-title">
          <ApartmentOutlined className="dpi-card-title-icon" />
          <span>多源指纹一致性</span>
          <Tag className="dpi-badge-tag" color="purple">
            {totalConflicts} 项待复核
          </Tag>
        </div>
        <Typography.Text className="dpi-card-hint" type="secondary">
          UA 仅作为客户端软件标识，不参与设备计数；网络栈差异必须结合身份、MAC 或 DHCP 证据判断。
        </Typography.Text>
      </div>

      {items.length === 0 ? (
        <Typography.Text className="rank-card-empty" type="secondary">
          当前窗口下暂无需要复核的多源指纹差异
        </Typography.Text>
      ) : (
		<Table className="compact-list-table" columns={columns} dataSource={items} pagination={{ pageSize: 10, showSizeChanger: false }} rowKey="id" size="small" />
      )}
    </Card>
  )
}
