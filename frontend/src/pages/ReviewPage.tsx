import { App as AntApp, Alert, Button, Skeleton, Space, Typography } from 'antd'

import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import { useCreateLabel, useRisks, useSession } from '../shared/api/queries'
import type { LabelKind, RiskLevel } from '../shared/api/types'
import { can } from '../shared/auth/permissions'

const reviewLevels: RiskLevel[] = ['confirmed', 'high']
const actions: Array<{ label: string; value: LabelKind }> = [
  { label: '确认代理', value: 'confirmed_proxy' },
  { label: '误报', value: 'false_positive' },
  { label: '良性', value: 'benign' },
  { label: '需要更多数据', value: 'needs_more_data' },
]

export function ReviewPage() {
  const session = useSession()
  const { message } = AntApp.useApp()
  const createLabel = useCreateLabel()
  const risks = useRisks({ limit: 100 })
  const canReview = can(session.data, 'labels:create')

  if (risks.isLoading) {
    return <Skeleton active />
  }

  const items = (risks.data?.items ?? []).filter((risk) => reviewLevels.includes(risk.level))

  return (
    <main className="page">
      <div className="page-header">
        <div>
          <Typography.Title className="page-title" level={3}>
            人工复核
          </Typography.Title>
          <Typography.Text type="secondary">优先处理 confirmed 与 high 风险快照。</Typography.Text>
        </div>
      </div>

      {!canReview && <Alert showIcon title="当前会话没有 labels:create 权限，复核动作不可用" type="warning" />}

      <section className="surface">
        {items.length === 0 ? (
          <Typography.Text type="secondary">暂无待复核风险</Typography.Text>
        ) : (
          <div className="review-list">
            {items.map((item) => (
              <article className="review-row" key={item.ip}>
                <div className="review-info-main">
                  <Space wrap>
                    <Typography.Text className="mono" strong>
                      {item.ip}
                    </Typography.Text>
                    <RiskLevelTag level={item.level} />
                    <Typography.Text type="secondary">score {item.score}</Typography.Text>
                  </Space>
                  <Typography.Paragraph className="wrap-text review-summary-text">
                    {item.summary}
                  </Typography.Paragraph>
                </div>
                <Space wrap>
                  {actions.map((action) => (
                <Button
                  disabled={!canReview}
                  key={action.value}
                  loading={createLabel.isPending}
                  onClick={() =>
                    createLabel.mutate(
                      {
                        target_type: 'ip',
                        target_id: item.ip,
                        label: action.value,
                        reason: `复核队列快速标注：${action.label}`,
                        evidence_ids: item.evidence_ids,
                      },
                      { onSuccess: () => message.success('复核标注已提交') },
                    )
                  }
                >
                  {action.label}
                </Button>
                  ))}
                </Space>
              </article>
            ))}
          </div>
        )}
      </section>
    </main>
  )
}
