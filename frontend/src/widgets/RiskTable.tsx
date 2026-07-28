import { Link } from 'react-router-dom'
import { Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import { RiskScore } from '../entities/risk/RiskScore'
import type { RiskSnapshot } from '../shared/api/types'

const columns: ColumnsType<RiskSnapshot> = [
  {
    title: 'IP',
    dataIndex: 'ip',
    width: 150,
    render: (ip: string) => (
      <Link className="mono wrap-text" to={`/ips/${encodeURIComponent(ip)}`}>
        {ip}
      </Link>
    ),
  },
  {
    title: '等级',
    dataIndex: 'level',
    width: 100,
    render: (level: RiskSnapshot['level']) => <RiskLevelTag level={level} />,
  },
  {
    title: '分数',
    dataIndex: 'score',
    width: 90,
    render: (score: number) => <RiskScore score={score} />,
  },
  {
    title: '解释',
    dataIndex: 'summary',
    minWidth: 360,
    render: (summary: string) => (
      <Typography.Paragraph
        ellipsis={{ rows: 2, tooltip: summary }}
        style={{ margin: 0, fontSize: 13, color: 'var(--ps-text-primary)' }}
      >
        {summary}
      </Typography.Paragraph>
    ),
  },
  {
    title: '证据',
    dataIndex: 'evidence_ids',
    width: 80,
    render: (ids: string[]) => <Tag style={{ margin: 0 }}>{ids.length}</Tag>,
  },
  {
    title: '建议动作',
    dataIndex: 'recommended_action',
    width: 150,
    render: (action: string) => (
      <Tag color="blue" style={{ borderRadius: 4, margin: 0 }}>
        {action}
      </Tag>
    ),
  },
  {
    title: '更新时间',
    dataIndex: 'updated_at',
    width: 170,
    render: (value: string) => (
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        {new Date(value).toLocaleString()}
      </Typography.Text>
    ),
  },
]

export function RiskTable({
  data,
  loading,
  emptyText = '没有匹配的风险快照',
}: {
  data: RiskSnapshot[]
  loading?: boolean
  emptyText?: string
}) {
  return (
    <Table
      columns={columns}
      dataSource={data}
      loading={loading}
      locale={{ emptyText }}
      pagination={{ pageSize: 10, showSizeChanger: false }}
      rowKey="ip"
      scroll={{ x: 960 }}
      size="middle"
    />
  )
}
