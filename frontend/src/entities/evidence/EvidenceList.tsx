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
        color: item.severity === 'high' ? 'red' : item.severity === 'medium' ? 'orange' : 'blue',
        content: (
          <article className="evidence-item">
            <div className="evidence-item__head">
              <Typography.Text strong>{item.type}</Typography.Text>
              <Typography.Text type="secondary">
                score {item.score} · confidence {Math.round(item.confidence * 100)}% · {item.window}
              </Typography.Text>
            </div>
            <Typography.Paragraph className="wrap-text">{item.reason}</Typography.Paragraph>
            <Typography.Text className="mono wrap-text" type="secondary">
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
