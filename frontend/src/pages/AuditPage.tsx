import { Alert, Skeleton, Table, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import { useAuditLogs } from '../shared/api/queries'
import type { AuditLog } from '../shared/api/types'

const columns: ColumnsType<AuditLog> = [
  { title: '时间', dataIndex: 'created_at', width: 190, render: (value: string) => new Date(value).toLocaleString() },
  { title: '操作者', dataIndex: 'actor', width: 140 },
  { title: '动作', dataIndex: 'action', width: 170 },
  { title: '目标', dataIndex: 'target', render: (value: string) => <span className="mono wrap-text">{value}</span> },
  { title: '结果', dataIndex: 'outcome', width: 160 },
]

export function AuditPage() {
  const logs = useAuditLogs()

  if (logs.isLoading) {
    return <Skeleton active />
  }

  return (
    <main className="page">
      <div className="page-header">
        <div>
          <Typography.Title className="page-title" level={3}>
            审计日志
          </Typography.Title>
          <Typography.Text type="secondary">第一阶段接 mock，后续标注、规则 reload 和策略动作都写入这里。</Typography.Text>
        </div>
      </div>
      {logs.isError && <Alert showIcon title="审计日志加载失败" type="error" />}
      <section className="surface">
        <Table columns={columns} dataSource={logs.data?.logs ?? []} rowKey="audit_id" />
      </section>
    </main>
  )
}
