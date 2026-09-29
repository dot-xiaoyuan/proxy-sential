import { Alert, Tag, Typography } from 'antd'
import { BrandLogo } from './BrandLogo'
import type { BrandInference } from '../../shared/api/types'

export function BrandInferenceLabel({ value }: { value?: BrandInference }) {
  if (!value || value.status === 'insufficient') return null
  return <div className="brand-inference-label">
    {value.status === 'inferred' && <BrandLogo brandKey={value.brand} showName={false} />}
    <Tag color={value.status === 'conflict' ? 'orange' : 'blue'}>{value.status === 'conflict' ? '品牌线索冲突' : `推测 ${value.brand}`}</Tag>
    <Typography.Text type="secondary" className="brand-inference-source">{value.status === 'inferred' ? `域名证据 · 评分 ${Math.round(value.confidence * 100)}%` : value.candidates.map(item => item.brand).join(' / ')}</Typography.Text>
  </div>
}

export function BrandInferenceDetails({ value }: { value?: BrandInference }) {
  if (!value) return null
  return <section className="surface brand-inference-details">
    <Typography.Title level={4}>推测品牌与依据</Typography.Title>
    <BrandInferenceLabel value={value} />
    <Alert showIcon type={value.status === 'conflict' ? 'warning' : 'info'} title={value.explanation} />
    <Typography.Paragraph type="secondary" className="brand-evidence-wrap">最近 7 天 · 规则 {value.rule_version || '尚未生效'} · 截至 {new Date(value.as_of).toLocaleString()}。域名推测不确认具体型号，评分不是统计概率。</Typography.Paragraph>
    {value.candidates.map(candidate => <div key={candidate.brand} className="brand-candidate">
      <Typography.Title level={5}>{candidate.brand} · 评分 {Math.round(candidate.confidence * 100)}%</Typography.Title>
      <ul className="brand-evidence-list">{candidate.evidence.map((evidence, index) => <li key={`${evidence.match.domain}-${evidence.event_source}-${index}`}>
        <Typography.Text strong className="brand-evidence-wrap mono">{evidence.match.domain}</Typography.Text>
        <Typography.Paragraph className="brand-evidence-wrap">{evidence.match.purpose || evidence.match.category} · {evidence.event_source?.toUpperCase()} · {evidence.count} 次</Typography.Paragraph>
        <Typography.Paragraph type="secondary" className="brand-evidence-wrap">{new Date(evidence.first_seen).toLocaleString()} — {new Date(evidence.last_seen).toLocaleString()}</Typography.Paragraph>
        <Typography.Paragraph className="brand-evidence-wrap">来源：{evidence.match.source_url && /^https?:\/\//.test(evidence.match.source_url) ? <a href={evidence.match.source_url} target="_blank" rel="noreferrer">{evidence.match.source}</a> : evidence.match.source} · {evidence.match.source_version}</Typography.Paragraph>
        <details><summary>事件引用与匹配规则</summary><p className="brand-evidence-wrap mono">{evidence.match.rule_domain}</p><p className="brand-evidence-wrap mono">{evidence.event_ids?.join('、') || '无事件样本'}</p></details>
      </li>)}</ul>
    </div>)}
  </section>
}
