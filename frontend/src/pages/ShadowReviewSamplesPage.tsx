import { Alert, Drawer, Descriptions, App as AntApp, Button, Card, Input, List, Modal, Select, Space, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { request } from '../shared/api/client'
import { EvidenceList } from '../entities/evidence/EvidenceList'
import type { ShadowSampleDetail } from '../shared/api/types'
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
  const [params,setParams]=useSearchParams()
  const date=params.get('date')||undefined
  const setDate=(value:string)=>setParams(current=>{const next=new URLSearchParams(current);next.set('date',value);next.delete('sample');return next})
  const samples=useShadowReviewSamples(date);
  const inspecting=samples.data?.samples.find(sample=>sample.sample_id===params.get('sample'));
  const setInspecting=(sample?:ShadowReviewSample)=>setParams(current=>{const next=new URLSearchParams(current);if(sample){next.set('sample',sample.sample_id);next.set('date',sample.date)}else next.delete('sample');return next});
  const historical=useQuery({queryKey:['shadow-sample-detail',inspecting?.sample_id,inspecting?.date],queryFn:()=>request<ShadowSampleDetail>(`/shadow/review-samples/${encodeURIComponent(inspecting!.sample_id)}?date=${encodeURIComponent(inspecting!.date)}`),enabled:!!inspecting,retry:false})
  const [draft, setDraft] = useState<ReviewDraft>()
  const [reason, setReason] = useState('')
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
      sample_date: draft.sample.date,
    }, {
      onSuccess: () => {
        setDraft(undefined)
        void message.success('人工真值已提交')
      },
    })
  }
  const renderActions = (sample:ShadowReviewSample)=><Button size="small" onClick={()=>setInspecting(sample)}>查看证据与复核</Button>
  const columns: ColumnsType<ShadowReviewSample> = [
    { title: '对象', key: 'subject', width: 175, render: (_, sample) => <div className="case-subject-cell"><Typography.Text className="mono list-cell-nowrap" title={sample.ip || sample.subject_id}>{sample.ip || sample.subject_id || ''}</Typography.Text><Typography.Text type="secondary">{sample.account_id || sample.endpoint_id || sample.subject_type || 'ip'}</Typography.Text></div> },
    { title: '风险', key: 'risk', width: 120, render: (_, sample) => <Space size={4}><RiskLevelTag level={sample.level} /><Typography.Text>{sample.score} 分</Typography.Text></Space> },
    { title: '置信度', dataIndex: 'confidence', width: 70, render: value => `${Math.round(Number(value) * 100)}%` },
    { title: '证据', dataIndex: 'evidence_ids', width: 65, render: value => <Tag>{value.length} 项</Tag> },
    { title: '复核状态', key: 'review_status', width: 95, render: (_, sample) => <ReviewStatusTag reason={sample.review_reason} status={sample.review_status} /> },
    { title: '快照时间', dataIndex: 'snapshot_time', width: 150, render: value => <span className="nowrap-cell">{new Date(value).toLocaleString()}</span> },
    { title: '人工真值', key: 'actions', width: 170, render: (_, sample) => renderActions(sample) },
  ]

  if (samples.isLoading) return <AppLoadingState rows={8} />
  if (samples.isError || !samples.data) return <AppErrorAlert title="影子复核样本加载失败" message={samples.error?.message} />
  const selectedDate = date ?? samples.data.date
  return <main className="page">
    <AppPageHeader
      title="样本复核"
      subtitle="按风险等级分层抽样；核对历史证据后提交人工结论，用于七天评估。"
      loading={samples.isFetching}
      onRefresh={() => void samples.refetch()}
      extra={<Select aria-label="复核日期" value={selectedDate} onChange={setDate} options={samples.data.dates.map(value => ({ value, label: value }))} />}
    />
    <section className="surface">
      <div className="shadow-review-summary"><Typography.Text>日期 {samples.data.date}</Typography.Text><Typography.Text>每等级最多 {samples.data.samples_per_level} 个样本</Typography.Text><Typography.Text>共 {samples.data.samples.length} 个</Typography.Text></div>
      <div className="desktop-only"><Table className="compact-list-table" columns={columns} dataSource={samples.data.samples} pagination={false} rowKey={sample => sampleKey(sample)} scroll={{ x: 965 }} tableLayout="fixed" /></div>
      <List className="mobile-only" dataSource={samples.data.samples} renderItem={sample => <List.Item><Card className="mobile-case-card" size="small"><div className="mobile-case-head"><Typography.Text className="mono list-cell-nowrap">{sample.ip || sample.subject_id}</Typography.Text><RiskLevelTag level={sample.level} /><Typography.Text>{sample.score} 分</Typography.Text></div><div className="mobile-case-row"><ReviewStatusTag reason={sample.review_reason} status={sample.review_status} /><span>{Math.round(sample.confidence * 100)}% · {sample.evidence_ids.length} 项证据</span></div>{renderActions(sample)}</Card></List.Item>} />
    </section>
    <Drawer title="历史样本证据与复核" open={!!inspecting} onClose={()=>setInspecting(undefined)} size="large" className="sample-review-drawer">
      {inspecting&&<>
        <Descriptions column={1} items={[
          {key:'subject',label:'对象',children:inspecting.subject_id||inspecting.ip},
          {key:'risk',label:'风险',children:<Space wrap><RiskLevelTag level={inspecting.level}/><span>{inspecting.score} 分 · {Math.round(inspecting.confidence*100)}%</span></Space>},
          {key:'time',label:'快照时间',children:new Date(inspecting.snapshot_time).toLocaleString('zh-CN')},
          {key:'run',label:'来源运行',children:<span className="wrap-text mono">{inspecting.source_run_id}</span>},
          {key:'summary',label:'快照解释',children:historical.data?.snapshot?.summary||''},
          {key:'window',label:'观测窗口',children:historical.data?.snapshot?.window||''},
          {key:'rules',label:'证据规则版本',children:[...new Set(historical.data?.evidence.flatMap(proof=>[proof.shared_access?.rule_version,proof.proxy_protocol?.rule_version]).filter(Boolean))].join('、')},
        ]}/>
        {inspecting.review_conflict&&<Alert type="warning" showIcon title="历史标注存在对象歧义，请重新核对证据"/>}
        {historical.isPending?<AppLoadingState rows={3}/>:historical.isError?<AppErrorAlert title="历史样本证据读取失败" message={historical.error.message}/>:<>
          {historical.data.missing_evidence_ids.length>0&&<Alert type="error" showIcon title="历史证据不完整" description={<span className="wrap-text">{historical.data.missing_evidence_ids.join('、')}</span>}/>}
          {historical.data.evidence.map(proof=><EvidenceList key={proof.evidence_id} evidence={[{...proof,samples:proof.samples??[]}]}/>)}
          <details className="filter-disclosure"><summary>技术详情与事件引用</summary><pre className="record-json">{JSON.stringify(historical.data,null,2)}</pre></details>
        </>}
        <div className="shadow-review-actions">{labelActions.map(action=><Button key={action.value} disabled={!writable||(action.value!=='needs_more_data'&&(!inspecting.evidence_ids.length||(!historical.data||historical.isFetching||historical.isError||historical.data.missing_evidence_ids.length>0||historical.data.evidence.length===0)))} onClick={()=>openReview(inspecting,action.value,action.label)}>{action.label}</Button>)}</div>
      </>}
    </Drawer>
    <Modal title={`提交人工真值：${draft?.actionLabel ?? ''}`} open={!!draft} confirmLoading={createLabel.isPending} okButtonProps={{ disabled: reason.trim().length < 2 }} okText="提交标注" cancelText="取消" onCancel={() => setDraft(undefined)} onOk={submitReview}>
      <Typography.Paragraph type="secondary">请说明判断依据；该原因会进入误报类型和规则归因汇总。</Typography.Paragraph>
      <Input.TextArea aria-label="复核原因" autoSize={{ minRows: 3, maxRows: 6 }} maxLength={500} showCount value={reason} onChange={event => setReason(event.target.value)} />
    </Modal>
  </main>
}

function reviewTarget(sample: ShadowReviewSample): Pick<CreateLabelRequest, 'target_type' | 'target_id'> {
  return { target_type: 'risk_snapshot', target_id: sample.sample_id }
}

function sampleKey(sample: ShadowReviewSample) {
  return sample.sample_id
}
