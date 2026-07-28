import { Timeline, Typography } from 'antd'

import type { Evidence } from '../../shared/api/types'

export function EvidenceList({ evidence }: { evidence: Evidence[] }) {
  if (evidence.length === 0) {
    return <Typography.Text type="secondary">暂无有效风险证据。</Typography.Text>
  }

  return (
    <Timeline
      className="evidence-timeline"
      items={evidence.map((item) => ({
        color: item.severity === 'high' ? '#dc2626' : item.severity === 'medium' ? '#ea580c' : '#0284c7',
        content: (
          <article className="evidence-item-card">
            <div className="evidence-item__head">
              <Typography.Text className="evidence-type-title">{item.type}</Typography.Text>
              <Typography.Text className="evidence-meta-text">
                score {item.score} · confidence {Math.round(item.confidence * 100)}% · window {item.window}
              </Typography.Text>
            </div>
            <Typography.Paragraph className="evidence-reason-text wrap-text">{item.reason}</Typography.Paragraph>
            <Typography.Text className="mono wrap-text evidence-meta-text">
              {item.evidence_id}
            </Typography.Text>
            <div className="sample-list">
              {item.samples.map((sample) => (
                <code className="sample-token" key={sample}>
                  {sample}
                </code>
              ))}
            </div>
          </article>
        ),
      }))}
    />
  )
}
