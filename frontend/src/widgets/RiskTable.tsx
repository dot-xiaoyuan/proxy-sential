import { Link } from 'react-router-dom'
import { Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import { RiskScore } from '../entities/risk/RiskScore'
import { ReviewStatusTag } from '../entities/risk/ReviewStatusTag'
import type { RiskSnapshot } from '../shared/api/types'

const columns: ColumnsType<RiskSnapshot> = [
  {
    title: 'IP',
    dataIndex: 'ip',
    width: 150,
    render: (ip: string) => (
      <Link className="mono list-cell-nowrap" title={ip} to={`/ips/${encodeURIComponent(ip)}`}>
        {ip}
      </Link>
    ),
  },
  {
    title: '等级',
    dataIndex: 'assessment_level',
    width: 80,
    render: (_, row) => <RiskLevelTag level={row.assessment_level ?? (row.level === 'confirmed' ? 'high' : row.level)} />,
  },
  {
    title: '分数',
    dataIndex: 'score',
    width: 72,
    render: (score: number) => <RiskScore score={score} />,
  },
  {
    title: '复核',
    dataIndex: 'review_status',
    width: 88,
    render: (_, row) => <ReviewStatusTag reason={row.review_reason} status={row.review_status} />,
  },
  {
    title: '解释',
    dataIndex: 'summary',
    width: 320,
    render: (summary: string) => (
      <Typography.Text className="list-cell-nowrap" title={summary}>
        {summary}
      </Typography.Text>
    ),
  },
  {
    title: '疑似设备',
    width: 120,
    render: (_, row) => (
      <div className="list-inline-tags">
        <Tag color={row.suspected_device_count > 1 ? 'orange' : 'blue'}>{row.suspected_device_count}</Tag>
        <Typography.Text className="list-cell-nowrap" title={row.device_summary} type="secondary">
          {row.device_summary || '暂无设备信号'}
        </Typography.Text>
      </div>
    ),
  },
  {
    title: '证据',
    dataIndex: 'evidence_ids',
    width: 64,
    render: (ids: string[]) => <Tag className="table-tag">{ids.length}</Tag>,
  },
  {
    title: '建议动作',
    dataIndex: 'recommended_action',
    width: 100,
    render: (action: string) => (
      <Tag className="table-tag" color="blue">
        {action}
      </Tag>
    ),
  },
  {
    title: '更新时间',
    dataIndex: 'updated_at',
    width: 110,
    render: (value: string) => (
      <Typography.Text className="table-time" type="secondary">
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
	  className="compact-list-table"
      columns={columns}
      dataSource={data}
      loading={loading}
      locale={{ emptyText }}
      pagination={false}
      rowKey="ip"
      scroll={{ x: 1000 }}
      size="small"
    />
  )
}
