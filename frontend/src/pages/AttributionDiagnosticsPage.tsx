import { useState } from 'react'
import { Alert, Input, Select, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Link } from 'react-router-dom'

import { useAttributionComparison, useAttributionDiagnostics, useDeviceRecognitionSummary } from '../shared/api/queries'
import type { AttributionDiagnostic } from '../shared/api/types'
import { AppPageHeader, AppServerPagination, useServerPagination } from '../shared/ui'

const reasons: Record<string, string> = {
  attributed: '已归属', missing_identity: '缺少身份', time_mismatch: '身份时点不匹配',
  identity_conflict: '身份冲突', no_unique_endpoint: '无唯一终端', legacy_unknown: '历史记录待重算',
}

export function AttributionDiagnosticsPage() {
  const pagination = useServerPagination()
  const [hours, setHours] = useState(24)
  const [sensorID, setSensorID] = useState('')
  const [status, setStatus] = useState('unattributed')
  const [reason, setReason] = useState<string>()
  const [beforeVersion, setBeforeVersion] = useState('')
  const [afterVersion, setAfterVersion] = useState('')
  const [windowEnd, setWindowEnd] = useState(() => Date.now())
  const summary = useDeviceRecognitionSummary()
  const query = useAttributionDiagnostics({
    from: new Date(windowEnd - hours * 3600_000).toISOString(), to: new Date(windowEnd).toISOString(),
    sensor_id: sensorID || undefined, status, reason, rule_version: summary.data?.domain_rule_version || undefined,
    limit: pagination.pageSize, cursor: pagination.cursor,
  })
  const comparison = useAttributionComparison({ from: new Date(windowEnd - hours * 3600_000).toISOString(), to: new Date(windowEnd).toISOString(), sensor_id: sensorID || undefined, before_version: beforeVersion.trim(), after_version: afterVersion.trim() })
  const columns: ColumnsType<AttributionDiagnostic> = [
    { title: '观测时间', dataIndex: 'observed_at', width: 175, render: (value: string) => new Date(value).toLocaleString() },
    { title: '事件 / IP', key: 'event', width: 235, render: (_, row) => <div className="list-primary-cell"><Link className="mono list-cell-nowrap" title={row.event_id} to={`/events/${encodeURIComponent(row.event_id)}`}>{row.event_id}</Link><Typography.Text className="mono" type="secondary">{row.ip || 'IP 未记录'}</Typography.Text></div> },
    { title: '域名 / 生态', key: 'domain', width: 240, render: (_, row) => <div className="list-primary-cell"><Typography.Text className="list-cell-nowrap" title={row.domain}>{row.domain}</Typography.Text><Typography.Text type="secondary">{row.ecosystem}</Typography.Text></div> },
    { title: '归属解释', key: 'reason', width: 190, render: (_, row) => <Tag>{reasons[row.reason] || row.reason}</Tag> },
    { title: '终端 / 方法', key: 'endpoint', width: 200, render: (_, row) => <Typography.Text className="wrap-text mono">{row.endpoint_id || '-'} {row.attribution_method || ''}</Typography.Text> },
    { title: 'Sensor / 规则', key: 'source', width: 190, render: (_, row) => <Typography.Text className="wrap-text mono">{row.sensor_id} / {row.rule_version}</Typography.Text> },
  ]

  return <main className="page">
    <AppPageHeader title="终端归属诊断" subtitle="按标准事件和身份时点解释生态线索是否归属终端；生态线索不等于硬件品牌。" loading={query.isFetching} onRefresh={() => { setWindowEnd(Date.now()); void summary.refetch() }} />
    <section className="surface"><div className="attribution-filter-bar"><Select aria-label="时间窗口" value={hours} options={[{ label: '最近 24 小时', value: 24 }, { label: '最近 7 天', value: 168 }]} onChange={value => { setHours(value); setWindowEnd(Date.now()); pagination.reset() }} /><Input aria-label="Sensor ID" placeholder="Sensor ID" value={sensorID} onChange={event => { setSensorID(event.target.value); pagination.reset() }} /><Select aria-label="归属状态" value={status} options={[{ label: '未归属', value: 'unattributed' }, { label: '已归属', value: 'attributed' }, { label: '全部', value: 'all' }]} onChange={value => { setStatus(value); pagination.reset() }} /><Select aria-label="归属原因" allowClear placeholder="全部原因" value={reason} options={Object.entries(reasons).map(([value, label]) => ({ value, label }))} onChange={value => { setReason(value); pagination.reset() }} /></div>
      <Typography.Text type="secondary">规则版本：{summary.data?.domain_rule_version || '全部'} · 最近 24 小时标准事件自带终端 ID 比例：{summary.data ? `${Math.round(summary.data.event_attribution_rate * 100)}%` : '加载中'} · 下方诊断展示域名生态证据的身份时点归属；历史记录可通过域名回填任务重算。</Typography.Text>
    </section>
    <section className="surface"><Typography.Title level={4}>身份修正前后对比</Typography.Title><Typography.Paragraph type="secondary">填写修正前后两次版本化回填的规则版本，仅对相同时间窗口、Sensor、事件 ID 和生态类型的共同样本比较归属率与冲突量。</Typography.Paragraph><div className="attribution-compare-bar"><Input aria-label="修正前版本" placeholder="修正前版本" value={beforeVersion} onChange={event => setBeforeVersion(event.target.value)} /><Input aria-label="修正后版本" placeholder="修正后版本" value={afterVersion} onChange={event => setAfterVersion(event.target.value)} /></div>{comparison.isError && <Alert showIcon type="error" title="归属对比加载失败" description={comparison.error.message} />}{comparison.data && <div className="attribution-compare-results"><span>修正前 <strong>{comparison.data.before.attributed}/{comparison.data.before.total}（{Math.round(comparison.data.before.rate * 100)}%）</strong> · 冲突 {comparison.data.before.conflicts}</span><span>修正后 <strong>{comparison.data.after.attributed}/{comparison.data.after.total}（{Math.round(comparison.data.after.rate * 100)}%）</strong> · 冲突 {comparison.data.after.conflicts}</span></div>}</section>
    <section className="surface">{query.isError ? <Alert showIcon type="error" title="归属诊断加载失败" description={query.error.message} /> : <><Table className="compact-list-table attribution-diagnostic-table" columns={columns} dataSource={query.data?.items || []} pagination={false} rowKey={row => `${row.rule_version}:${row.event_id}:${row.ecosystem}`} scroll={{ x: 1230 }} size="small" locale={{ emptyText: '当前条件下没有记录' }} /><div className="attribution-diagnostic-cards">{query.data?.items.map(row => <article className="attribution-diagnostic-card" key={`${row.rule_version}:${row.event_id}:${row.ecosystem}`}><strong className="wrap-text">{row.domain}</strong><span>{row.ecosystem} · {new Date(row.observed_at).toLocaleString()}</span><Tag>{reasons[row.reason] || row.reason}</Tag><Link className="mono wrap-text" to={`/events/${encodeURIComponent(row.event_id)}`}>{row.event_id}</Link><span className="mono wrap-text">{row.ip || 'IP 未记录'} · {row.sensor_id}</span></article>)}</div><AppServerPagination page={pagination.page} pageSize={pagination.pageSize} total={query.data?.page.total || 0} onChange={pagination.update} /></>}</section>
  </main>
}
