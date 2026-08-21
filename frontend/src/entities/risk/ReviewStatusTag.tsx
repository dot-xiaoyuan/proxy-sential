import { Tag, Tooltip } from 'antd'

import type { RiskSnapshot } from '../../shared/api/types'

type ReviewStatus = NonNullable<RiskSnapshot['review_status']>

const reviewStatusMeta: Record<ReviewStatus, { color: string; label: string }> = {
  unreviewed: { color: 'default', label: '未复核' },
  confirmed_proxy: { color: 'red', label: '确认代理' },
  false_positive: { color: 'green', label: '误报' },
  benign: { color: 'blue', label: '良性' },
  needs_more_data: { color: 'gold', label: '需补数据' },
}

export function ReviewStatusTag({
  reason,
  status = 'unreviewed',
}: {
  reason?: string
  status?: ReviewStatus
}) {
  const meta = reviewStatusMeta[status] ?? reviewStatusMeta.unreviewed
  const tag = (
    <Tag className="review-status-tag" color={meta.color}>
      {meta.label}
    </Tag>
  )
  if (!reason) {
    return tag
  }
  return <Tooltip title={reason}>{tag}</Tooltip>
}
