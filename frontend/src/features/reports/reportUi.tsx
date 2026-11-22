import type { ReactNode } from 'react'
import type { UseQueryResult } from '@tanstack/react-query'
import { Tag } from 'antd'
import { Link } from 'react-router-dom'

import { ApiError } from '../../shared/api/client'
import { AppErrorAlert, AppLoadingState, formatDateTime } from '../../shared/ui'
import { displayField, statusColor, statusText } from '../../shared/ui/status'

type PanelProps<T> = {
  title: string
  query: UseQueryResult<T, Error>
  detail?: { to: string; label: string }
  extra?: ReactNode
  disabledCode?: string
  children: (data: T) => ReactNode
}

export function ReportPanel<T>({ title, query, detail, extra, disabledCode, children }: PanelProps<T>) {
  const disabled = disabledCode && query.error instanceof ApiError && query.error.message.includes(disabledCode)
  return (
    <section className="surface report-panel" aria-label={title}>
      <header className="report-panel-heading">
        <h2>{title}</h2>
        {detail && <Link className="report-link" to={detail.to}>{detail.label}</Link>}
        {extra}
      </header>
      {query.isPending ? <AppLoadingState rows={2} /> : disabled ? (
        <p className="report-meta">模块未启用</p>
      ) : query.isError ? (
        <AppErrorAlert title={`${title}读取失败`} message="请刷新报表以重试。" />
      ) : query.data !== undefined ? children(query.data) : (
        <p className="report-meta">暂无数据</p>
      )}
    </section>
  )
}

type Fact = readonly [label: string, value: string | number | null | undefined]

export function ReportFacts({ items }: { items: Fact[] }) {
  const values = items.filter(([, value]) => typeof value === 'number' ? Number.isFinite(value) : displayField(value))
  if (!values.length) return null
  return <dl className="report-facts">{values.map(([label, value]) => (
    <div key={label}>
      <dt>{label}</dt>
      <dd>{typeof value === 'number' ? value.toLocaleString('zh-CN') : value}</dd>
    </div>
  ))}</dl>
}

export function ReportTime({ label = '数据时间', value }: { label?: string; value?: string | null }) {
  const text = formatDateTime(value)
  return text ? <p className="report-meta">{label} <time dateTime={value ?? undefined}>{text}</time></p> : null
}

const reportStates: Record<string, string> = {
  waiting: '等待数据', processing: '处理中', delayed: '处理延迟', backfilling: '回补中',
  quiet: '近期无新输入', expired: '已过期', insufficient: '证据不足',
  partial: '覆盖不足', verified: '覆盖已验证', matched: '已命中',
  candidate: '候选', likely: '待核验', confirmed: '已确认', recorded: '仅记录，未执行',
  file_mode: '文件模式', memory_mode: '内存模式', no_data: '无数据', idle: '空闲',
}

export function ReportStatus({ value, label }: { value?: string; label?: string }) {
  const text = label || (value && reportStates[value]) || displayField(statusText(value)) || (value === 'unknown' ? '尚未核验' : '')
  return text ? <Tag className="report-status" color={statusColor(value)}>{text}</Tag> : null
}

export type ReportRow = {
  key: string
  title: string
  detail?: string
  status?: string
  statusLabel?: string
  at?: string | null
  to?: string
}

export function ReportRows({ rows, empty = '暂无记录' }: { rows: ReportRow[]; empty?: string }) {
  if (!rows.length) return <p className="report-meta">{empty}</p>
  return <ul className="report-records">{rows.map((row) => (
    <li key={row.key}>
      <div className="report-record-main">
        {row.to ? <Link to={row.to}>{displayField(row.title)}</Link> : <strong>{displayField(row.title)}</strong>}
        {displayField(row.detail) && <span>{row.detail}</span>}
      </div>
      <ReportStatus value={row.status} label={row.statusLabel} />
      {formatDateTime(row.at) && <time dateTime={row.at ?? undefined}>{formatDateTime(row.at)}</time>}
    </li>
  ))}</ul>
}
