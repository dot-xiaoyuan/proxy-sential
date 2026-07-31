import { Tag, Typography } from 'antd'

import type { Evidence } from '../../shared/api/types'

const maxVisibleEvidence = 6
const maxSamplesPerEvidence = 3

export function EvidenceList({ evidence }: { evidence: Evidence[] }) {
  if (evidence.length === 0) {
    return <Typography.Text type="secondary">暂无有效风险证据。</Typography.Text>
  }

  const visibleEvidence = evidence.slice(0, maxVisibleEvidence)
  const hiddenCount = evidence.length - visibleEvidence.length

  return (
    <div className="evidence-compact-list">
      {visibleEvidence.map((item) => (
        <article className="evidence-compact-card" key={item.evidence_id}>
          <div className="evidence-compact-main">
            <div className="evidence-item__head">
              <Typography.Text className="evidence-type-title">{item.type}</Typography.Text>
              <Tag className="compact-tag" color={severityColor(item.severity)}>{item.severity}</Tag>
              <Typography.Text className="evidence-meta-text">
                score {item.score} · confidence {Math.round(item.confidence * 100)}% · {item.window}
              </Typography.Text>
            </div>
            <Typography.Text className="evidence-reason-text wrap-text">{item.reason}</Typography.Text>
            <Typography.Text className="mono wrap-text evidence-meta-text">{item.evidence_id}</Typography.Text>
          </div>
          <div className="sample-list evidence-sample-preview">
            {item.samples.slice(0, maxSamplesPerEvidence).map((sample) => (
              <code className="sample-token" key={sample}>
                {sample}
              </code>
            ))}
            {item.samples.length > maxSamplesPerEvidence && (
              <code className="sample-token">+{item.samples.length - maxSamplesPerEvidence}</code>
            )}
          </div>
        </article>
      ))}
      {hiddenCount > 0 && (
        <Typography.Text className="compact-muted-row" type="secondary">
          已收起 {hiddenCount} 条较新的证据，完整审计请使用事件检索或 evidence_id 下钻。
        </Typography.Text>
      )}
    </div>
  )
}

function severityColor(severity: string) {
  if (severity === 'high') return 'red'
  if (severity === 'medium') return 'orange'
  return 'blue'
}
