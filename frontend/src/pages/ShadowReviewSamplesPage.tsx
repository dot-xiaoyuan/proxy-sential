import { App as AntApp, Button, Card, Input, List, Modal, Select, Space, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { useState } from 'react'

import { ReviewStatusTag } from '../entities/risk/ReviewStatusTag'
import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import { can } from '../shared/auth/permissions'
import { useCreateLabel, useSession, useShadowReviewSamples } from '../shared/api/queries'
import type { CreateLabelRequest, LabelKind, ShadowReviewSample } from '../shared/api/types'
import { AppErrorAlert, AppLoadingState, AppPageHeader } from '../shared/ui'

const labelActions: Array<{ label: string; value: LabelKind }> = [
  { label: '确认代理', value: 'confirmed_proxy' },
  { label: '误报', value: 'false_positive' },
  { label: '良性', value: 'benign' },
  { label: '需补数据', value: 'needs_more_data' },
]

type ReviewDraft = { sample: ShadowReviewSample; action: LabelKind; actionLabel: string }

export function ShadowReviewSamplesPage() {
  const [date, setDate] = useState<string>()
  const [draft, setDraft] = useState<ReviewDraft>()
  const [reason, setReason] = useState('')
  const samples = useShadowReviewSamples(date)
  const session = useSession()
  const createLabel = useCreateLabel()
  const { message } = AntApp.useApp()
  const writable = can(session.data, 'labels:create')

  const openReview = (sample: ShadowReviewSample, action: LabelKind, actionLabel: string) => {
    setDraft({ sample, action, actionLabel })
    setReason(`影子分层样本复核：${actionLabel}`)
  }
  const submitReview = () => {
    if (!draft || reason.trim().length < 2) return
    createLabel.mutate({
      ...reviewTarget(draft.sample),
      label: draft.action,
      reason: reason.trim(),
      evidence_ids: draft.sample.evidence_ids,
    }, {
      onSuccess: () => {
        setDraft(undefined)
        void message.success('人工真值已提交')
      },
    })
  }
  const renderActions = (sample: ShadowReviewSample) => (
    <div className="shadow-review-actions">
      {labelActions.map(action => (
        <Button
          key={action.value}
          disabled={!writable || sample.evidence_ids.length === 0}
          onClick={() => openReview(sample, action.value, action.label)}
          size="small"
        >
          {action.label}
        </Button>
      ))}
    </div>
  )
  const columns: ColumnsType<ShadowReviewSample> = [
    { title: '对象', key: 'subject', width: 175, render: (_, sample) => <div className="case-subject-cell"><Typography.Text className="mono list-cell-nowrap" title={sample.ip || sample.subject_id}>{sample.ip || sample.subject_id || '未知'}</Typography.Text><Typography.Text type="secondary">{sample.account_id || sample.endpoint_id || sample.subject_type || 'ip'}</Typography.Text></div> },
    { title: '风险', key: 'risk', width: 120, render: (_, sample) => <Space size={4}><RiskLevelTag level={sample.level} /><Typography.Text>{sample.score} 分</Typography.Text></Space> },
    { title: '置信度', dataIndex: 'confidence', width: 70, render: value => `${Math.round(Number(value) * 100)}%` },
    { title: '证据', dataIndex: 'evidence_ids', width: 65, render: value => <Tag>{value.length} 项</Tag> },
    { title: '复核状态', key: 'review_status', width: 95, render: (_, sample) => <ReviewStatusTag reason={sample.review_reason} status={sample.review_status} /> },
    { title: '快照时间', dataIndex: 'snapshot_time', width: 150, render: value => <span className="nowrap-cell">{new Date(value).toLocaleString()}</span> },
    { title: '人工真值', key: 'actions', width: 290, render: (_, sample) => renderActions(sample) },
  ]

  if (samples.isLoading) return <AppLoadingState rows={8} />
  if (samples.isError || !samples.data) return <AppErrorAlert title="影子复核样本加载失败" message={samples.error?.message} />
  const selectedDate = date ?? samples.data.date
  return <main className="page">
    <AppPageHeader
      title="影子分层复核"
      subtitle="每日按 normal、suspicious、high、confirmed 分层抽样；人工真值将计入七天准确率门槛。"
      loading={samples.isFetching}
      onRefresh={() => void samples.refetch()}
      extra={<Select aria-label="复核日期" value={selectedDate} onChange={setDate} options={samples.data.dates.map(value => ({ value, label: value }))} />}
    />
    <section className="surface">
      <div className="shadow-review-summary"><Typography.Text>日期 {samples.data.date}</Typography.Text><Typography.Text>每等级最多 {samples.data.samples_per_level} 个样本</Typography.Text><Typography.Text>共 {samples.data.samples.length} 个</Typography.Text></div>
      <div className="desktop-only"><Table className="compact-list-table" columns={columns} dataSource={samples.data.samples} pagination={false} rowKey={sample => sampleKey(sample)} scroll={{ x: 965 }} tableLayout="fixed" /></div>
      <List className="mobile-only" dataSource={samples.data.samples} renderItem={sample => <List.Item><Card className="mobile-case-card" size="small"><div className="mobile-case-head"><Typography.Text className="mono list-cell-nowrap">{sample.ip || sample.subject_id}</Typography.Text><RiskLevelTag level={sample.level} /><Typography.Text>{sample.score} 分</Typography.Text></div><div className="mobile-case-row"><ReviewStatusTag reason={sample.review_reason} status={sample.review_status} /><span>{Math.round(sample.confidence * 100)}% · {sample.evidence_ids.length} 项证据</span></div>{renderActions(sample)}</Card></List.Item>} />
    </section>
    <Modal title={`提交人工真值：${draft?.actionLabel ?? ''}`} open={!!draft} confirmLoading={createLabel.isPending} okButtonProps={{ disabled: reason.trim().length < 2 }} okText="提交标注" cancelText="取消" onCancel={() => setDraft(undefined)} onOk={submitReview}>
      <Typography.Paragraph type="secondary">请说明判断依据；该原因会进入误报类型和规则归因汇总。</Typography.Paragraph>
      <Input.TextArea aria-label="复核原因" autoSize={{ minRows: 3, maxRows: 6 }} maxLength={500} showCount value={reason} onChange={event => setReason(event.target.value)} />
    </Modal>
  </main>
}

function reviewTarget(sample: ShadowReviewSample): Pick<CreateLabelRequest, 'target_type' | 'target_id'> {
  return { target_type: 'risk_snapshot', target_id: sample.source_run_id }
}

function sampleKey(sample: ShadowReviewSample) {
  return `${sample.date}:${sample.subject_type ?? 'ip'}:${sample.subject_id || sample.ip}`
}
