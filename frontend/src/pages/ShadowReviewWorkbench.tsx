import { useEffect, useState } from 'react'
import { Alert, Button, Drawer, Select, Skeleton, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Link } from 'react-router-dom'

import { LabelPanel } from '../features/labels/LabelPanel'
import { useSession, useShadowEvaluation, useShadowReviewSamples } from '../shared/api/queries'
import type { LabelKind, ShadowReviewSample } from '../shared/api/types'
import { can } from '../shared/auth/permissions'

const levels = ['confirmed', 'high', 'suspicious', 'normal'] as const
const levelNames: Record<string, string> = { confirmed: '确认代理', high: '高风险', suspicious: '可疑', normal: '正常' }
const reviewNames: Record<string, string> = { unreviewed: '待复核', confirmed: '已确认', confirmed_proxy: '已确认', false_positive: '误报', benign: '良性', needs_more_data: '待补数据' }

function sampleKey(sample: ShadowReviewSample) {
  const target = sampleTarget(sample)
  return `${sample.date}:${target?.type || 'unknown'}:${target?.id || sample.ip}:${sample.source_run_id}`
}

function sampleTarget(sample: ShadowReviewSample): { type: 'ip' | 'account' | 'endpoint'; id: string } | null {
  if (sample.subject_type === 'account' && sample.subject_id) return { type: 'account', id: sample.subject_id }
  if (sample.subject_type === 'endpoint' && sample.subject_id) return { type: 'endpoint', id: sample.subject_id }
  if (sample.subject_type === 'ip' && sample.subject_id) return { type: 'ip', id: sample.subject_id }
  if (sample.account_id) return { type: 'account', id: sample.account_id }
  if (sample.endpoint_id) return { type: 'endpoint', id: sample.endpoint_id }
  if (sample.ip) return { type: 'ip', id: sample.ip }
  return null
}

export function ShadowReviewWorkbench() {
  const evaluation = useShadowEvaluation()
  const session = useSession()
  const [date, setDate] = useState('')
  const [level, setLevel] = useState<string>()
  const [cursor, setCursor] = useState<string>()
  const [history, setHistory] = useState<string[]>([])
  const [selected, setSelected] = useState<ShadowReviewSample | null>(null)
  const [submitted, setSubmitted] = useState<Record<string, LabelKind>>({})
  const report = evaluation.data
  useEffect(() => {
    if (!date && report?.daily?.length) setDate(report.daily[report.daily.length - 1].date || '')
  }, [date, report])
  const samples = useShadowReviewSamples({ date, level, limit: 10, cursor })
  const target = selected ? sampleTarget(selected) : null
  const resetPage = () => { setCursor(undefined); setHistory([]) }
  const columns: ColumnsType<ShadowReviewSample> = [
    { title: '主体', key: 'subject', render: (_, item) => <Typography.Text className="mono wrap-text">{sampleTarget(item)?.id || '未知'}</Typography.Text> },
    { title: '等级 / 评分', key: 'risk', width: 150, render: (_, item) => `${levelNames[item.level] || item.level} · ${item.score}` },
    { title: '证据', key: 'evidence', width: 90, render: (_, item) => item.evidence_ids.length },
    { title: '复核', key: 'review', width: 115, render: (_, item) => <Tag>{reviewNames[submitted[sampleKey(item)] || item.review_status] || item.review_status}</Tag> },
    { title: '操作', key: 'action', width: 100, render: (_, item) => <Button onClick={() => setSelected(item)} size="small">查看与复核</Button> },
  ]

  return <>
    {evaluation.isError && <Alert showIcon type="warning" title="影子评估报告尚不可用" />}
    {report && <section className="surface shadow-evaluation-surface">
      <div className="shadow-section-heading"><Typography.Title level={4}>影子评估结果</Typography.Title><Tag color={report.ready ? 'green' : 'gold'}>{report.ready ? '已达评估门槛' : '仍有验收阻塞'}</Tag></div>
      <Typography.Text type="secondary">报告生成于 {new Date(report.generated_at).toLocaleString()}。提交标注后，汇总指标在下一次定时评估时更新。</Typography.Text>
      <div className="shadow-evaluation-metrics"><span>连续运行 <strong>{report.longest_continuous_days}/{report.required_days} 天</strong></span><span>复核天数 <strong>{report.days_with_reviews}/{report.required_days} 天</strong></span><span>已复核 <strong>{report.reviewed_snapshot_count}/{report.evaluated_sample_count}</strong></span><span>覆盖率 <strong>{Math.round(report.review_coverage * 100)}%</strong></span><span>高风险确认率 <strong>{Math.round(report.high_risk_precision * 100)}%</strong></span><span>候选有效复核 <strong>{report.candidate_reviewed}</strong></span><span>正常人工真值 <strong>{report.normal_truth_count}</strong></span></div>
      {report.blockers.length > 0 && <Alert showIcon type="warning" title="验收阻塞" description={<ul className="shadow-compact-list">{report.blockers.map(item => <li key={item}>{item}</li>)}</ul>} />}
      <div className="shadow-daily-list">{report.daily?.map(day => <div className="shadow-daily-item" key={day.date}><strong>{day.date}</strong>{levels.map(item => { const stats = day.level_stats?.[item]; return stats?.total ? <span key={item}>{levelNames[item]} {stats.reviewed || 0}/{stats.total}</span> : null })}</div>)}</div>
      {(report.false_positive_reasons?.length || report.false_positive_evidence?.length) ? <div className="shadow-false-positive"><div><strong>误报原因</strong><p>{report.false_positive_reasons?.map(item => `${item.value}（${item.count}）`).join(' · ') || '暂无'}</p></div><div><strong>误报证据</strong><p>{report.false_positive_evidence?.map(item => `${item.value}（${item.count}）`).join(' · ') || '暂无'}</p></div></div> : null}
    </section>}
    <section className="surface">
      <div className="shadow-section-heading"><Typography.Title level={4}>每日复核样本</Typography.Title><div className="shadow-review-filters"><Select aria-label="复核日期" placeholder="选择日期" value={date || undefined} options={report?.daily?.map(day => ({ label: day.date, value: day.date })) || []} onChange={value => { setDate(value); resetPage() }} /><Select aria-label="风险等级" allowClear placeholder="全部等级" value={level} options={levels.map(item => ({ label: levelNames[item], value: item }))} onChange={value => { setLevel(value); resetPage() }} /></div></div>
      {!date ? <Typography.Text type="secondary">评估报告生成后可查看每日样本。</Typography.Text> : samples.isLoading ? <Skeleton active /> : samples.isError ? <Alert showIcon type="warning" title="每日复核样本加载失败" /> : <>
        <Table className="compact-list-table shadow-sample-table" columns={columns} dataSource={samples.data?.samples || []} pagination={false} rowKey={sampleKey} size="small" locale={{ emptyText: '当前筛选条件下没有样本' }} />
        <div className="shadow-sample-cards">{samples.data?.samples.map(item => <article className="shadow-sample-card" key={sampleKey(item)}><strong className="wrap-text mono">{sampleTarget(item)?.id || '未知'}</strong><span>{levelNames[item.level] || item.level} · {item.score} 分 · {item.evidence_ids.length} 条证据</span><Tag>{reviewNames[submitted[sampleKey(item)] || item.review_status] || item.review_status}</Tag><Button onClick={() => setSelected(item)}>查看与复核</Button></article>)}</div>
        <div className="shadow-review-actions"><Typography.Text type="secondary">共 {samples.data?.page.total || 0} 条</Typography.Text><Button disabled={!history.length} onClick={() => { setCursor(history.at(-1) || undefined); setHistory(items => items.slice(0, -1)) }}>上一页</Button><Button disabled={!samples.data?.page.next_cursor} onClick={() => { setHistory(items => [...items, cursor || '']); setCursor(samples.data?.page.next_cursor || undefined) }}>下一页</Button></div>
      </>}
    </section>
    <Drawer title="复核样本" open={Boolean(selected)} onClose={() => setSelected(null)} width={480}>
      {selected && <div className="shadow-review-detail"><p>主体：<Typography.Text className="wrap-text mono">{target?.type}:{target?.id}</Typography.Text></p><p>等级：{levelNames[selected.level] || selected.level} · {selected.score} 分 · 置信度 {Math.round(selected.confidence * 100)}%</p><p>来源运行：<span className="mono wrap-text">{selected.source_run_id}</span></p><p>快照时间：{selected.snapshot_time ? new Date(selected.snapshot_time).toLocaleString() : '-'}</p><strong>证据 ID</strong><ul className="shadow-compact-list">{selected.evidence_ids.map(id => <li className="mono wrap-text" key={id}>{id}</li>)}</ul>{selected.ip && <Link to={`/ips/${encodeURIComponent(selected.ip)}`}>查看 IP 风险详情</Link>}{target && <LabelPanel key={sampleKey(selected)} targetType={target.type} targetId={target.id} evidenceIds={selected.evidence_ids} disabled={!can(session.data, 'labels:create')} onSubmitted={label => setSubmitted(items => ({ ...items, [sampleKey(selected)]: label }))} />}</div>}
    </Drawer>
  </>
}
