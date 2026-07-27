import { Link } from 'react-router-dom'
import { Table, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import { RiskScore } from '../entities/risk/RiskScore'
import type { RiskSnapshot } from '../shared/api/types'

const columns: ColumnsType<RiskSnapshot> = [
  {
    title: 'IP',
    dataIndex: 'ip',
    width: 180,
    render: (ip: string) => (
      <Link className="mono wrap-text" to={`/ips/${encodeURIComponent(ip)}`}>
        {ip}
      </Link>
    ),
  },
  {
    title: '等级',
    dataIndex: 'level',
    width: 110,
    render: (level: RiskSnapshot['level']) => <RiskLevelTag level={level} />,
  },
  {
    title: '分数',
    dataIndex: 'score',
    width: 110,
    render: (score: number) => <RiskScore score={score} />,
  },
  {
    title: '解释',
    dataIndex: 'summary',
    render: (summary: string) => <Typography.Text className="wrap-text">{summary}</Typography.Text>,
  },
  {
    title: '证据',
    dataIndex: 'evidence_ids',
    width: 90,
    render: (ids: string[]) => ids.length,
  },
  {
    title: '建议动作',
    dataIndex: 'recommended_action',
    width: 170,
  },
  {
    title: '更新时间',
    dataIndex: 'updated_at',
    width: 190,
    render: (value: string) => new Date(value).toLocaleString(),
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
      scroll={{ x: 980 }}
      size="middle"
    />
  )
}
