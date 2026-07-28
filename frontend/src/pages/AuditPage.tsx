import { useState } from 'react'
import { Table, Tag } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import { useAuditLogs } from '../shared/api/queries'
import type { AuditLog } from '../shared/api/types'
import {
  AppErrorAlert,
  AppLoadingState,
  AppPageHeader,
  AppTableBar,
  type QuickWindow,
} from '../shared/ui'

const columns: ColumnsType<AuditLog> = [
  {
    title: '审计时间戳',
    dataIndex: 'created_at',
    width: 180,
    render: (value: string) => new Date(value).toLocaleString(),
  },
  { title: '操作账号', dataIndex: 'actor', width: 140 },
  {
    title: '操作动作',
    dataIndex: 'action',
    width: 160,
    render: (v: string) => <Tag className="dpi-badge-tag" color="purple">{v}</Tag>,
  },
  {
    title: '作用目标',
    dataIndex: 'target',
    render: (value: string) => <span className="mono wrap-text">{value}</span>,
  },
  { title: '执行结果 / 策略标签', dataIndex: 'outcome', width: 180 },
]

export function AuditPage() {
  const [quickWindow, setQuickWindow] = useState<QuickWindow>('1h')
  const [searchQuery, setSearchQuery] = useState('')
  const logs = useAuditLogs()

  if (logs.isLoading) {
    return <AppLoadingState rows={5} />
  }

  const items = (logs.data?.logs ?? []).filter(
    (item) =>
      !searchQuery ||
      item.actor.includes(searchQuery) ||
      item.action.includes(searchQuery) ||
      item.target.includes(searchQuery) ||
      item.outcome.includes(searchQuery),
  )

  return (
    <main className="page">
      <AppPageHeader
        loading={logs.isFetching}
        onQuickWindowChange={setQuickWindow}
        onRefresh={() => void logs.refetch()}
        quickWindow={quickWindow}
        subtitle="记录影子运行评估、规则重载 (Reload)、人工标注与白名单解封的全量审计轨迹"
        title="系统操作与策略审计日志"
      />

      {logs.isError && <AppErrorAlert title="审计日志加载失败" />}

      <AppTableBar
        onClearFilters={() => setSearchQuery('')}
        onSearchChange={setSearchQuery}
        searchPlaceholder="搜索操作者 / 动作 / IP 目标..."
        searchValue={searchQuery}
        totalCount={items.length}
      />

      <section className="surface">
        <Table<AuditLog>
          columns={columns}
          dataSource={items}
          pagination={{ pageSize: 15 }}
          rowKey="audit_id"
          scroll={{ x: 800 }}
          size="middle"
        />
      </section>
    </main>
  )
}
