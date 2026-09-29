import { useEffect, useState } from 'react'
import { Select, Table, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Link } from 'react-router-dom'

import { ReviewStatusTag } from '../entities/risk/ReviewStatusTag'
import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import { useProxyReviews } from '../shared/api/queries'
import type { ProxyReviewCase } from '../shared/api/types'
import { AppEmptyState, AppErrorAlert, AppLoadingState, AppPageHeader, AppServerPagination, AppTableBar, useServerPagination } from '../shared/ui'

type ReviewWindow = '24h' | '7d'

export function ReviewPage() {
  const [reviewWindow, setReviewWindow] = useState<ReviewWindow>('7d')
	const pagination = useServerPagination()
  const [searchInput, setSearchInput] = useState('')
  const [query, setQuery] = useState('')

  useEffect(() => {
    const timer = globalThis.setTimeout(() => { setQuery(searchInput.trim()); pagination.reset() }, 300)
    return () => globalThis.clearTimeout(timer)
  }, [searchInput])

  const reviews = useProxyReviews({ window: reviewWindow, limit: pagination.pageSize, cursor: pagination.cursor, q: query, view: 'summary' })
  const columns: ColumnsType<ProxyReviewCase> = [
    { title: '对象 IP', dataIndex: 'ip', width: 170, render: (value: string, item) => <Link className="list-cell-nowrap mono" title={value} to={`/review/${encodeURIComponent(item.case_id)}?window=${reviewWindow}`}>{value}</Link> },
    { title: '关联身份', key: 'identity', width: 230, render: (_, item) => { const value = [item.account_id, item.endpoint_id].filter(Boolean).join(' / ') || ''; return <Typography.Text className="list-cell-nowrap" title={value}>{value}</Typography.Text> } },
    { title: '风险', key: 'risk', width: 170, render: (_, item) => <span className="list-inline-tags"><RiskLevelTag level={item.risk_level} /><span>{item.risk_score} 分</span></span> },
    { title: '置信度', dataIndex: 'confidence_level', width: 90 },
    { title: '复核状态', key: 'review_status', width: 130, render: (_, item) => <ReviewStatusTag reason={item.review_reason} status={item.review_status} /> },
    { title: '事件摘要', key: 'events', width: 240, render: (_, item) => { const value = `共 ${item.event_count} 条 · TLS ${item.tls_count} · QUIC ${item.quic_count} · Alert ${item.alert_count}`; return <Typography.Text className="list-cell-nowrap" title={value}>{value}</Typography.Text> } },
    { title: '最后发现', dataIndex: 'last_seen', width: 180, render: (value: string) => new Date(value).toLocaleString() },
  ]

  return <main className="page">
    <AppPageHeader title="翻墙监测复核" subtitle="列表仅显示待处理摘要，点击对象进入完整证据与复核页面。" loading={reviews.isFetching} onRefresh={() => void reviews.refetch()} />
    <AppTableBar searchPlaceholder="搜索 IP、账号或终端" searchValue={searchInput} onSearchChange={setSearchInput} totalCount={reviews.data?.page.total ?? 0} extra={<Select value={reviewWindow} onChange={(value) => { setReviewWindow(value); pagination.reset() }} options={[{label:'最近 24 小时',value:'24h'},{label:'最近 7 天',value:'7d'}]} />} />
    <section className="surface">
      {reviews.isLoading ? <AppLoadingState rows={8} /> : reviews.isError ? <AppErrorAlert title="复核数据加载失败" message={reviews.error.message} /> : (reviews.data?.items.length ?? 0) === 0 ? <AppEmptyState description="当前筛选条件下没有复核对象" /> : <>
        <Table className="compact-list-table" columns={columns} dataSource={reviews.data?.items ?? []} pagination={false} rowKey="case_id" scroll={{x:1180}} size="small" />
        <AppServerPagination page={pagination.page} pageSize={pagination.pageSize} total={reviews.data?.page.total ?? 0} onChange={pagination.update} />
      </>}
    </section>
  </main>
}
