import { useState } from 'react'
import { FileSearchOutlined, GlobalOutlined, LaptopOutlined, SafetyCertificateOutlined, UserOutlined } from '@ant-design/icons'
import { App as AntApp, Alert, Button, Select, Space, Tag, Typography } from 'antd'
import { Link } from 'react-router-dom'

import { ReviewStatusTag } from '../entities/risk/ReviewStatusTag'
import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import { useCreateLabel, useProxyReviews, useSession } from '../shared/api/queries'
import type { CreateLabelRequest, LabelKind, ProxyReviewCase } from '../shared/api/types'
import { can } from '../shared/auth/permissions'
import { AppEmptyState, AppErrorAlert, AppLoadingState, AppMetricCard, AppPageHeader } from '../shared/ui'

type ReviewWindow = '24h' | '7d'

const actions: Array<{ label: string; value: LabelKind }> = [
  { label: '确认代理', value: 'confirmed_proxy' },
  { label: '误报', value: 'false_positive' },
  { label: '良性', value: 'benign' },
  { label: '需要更多数据', value: 'needs_more_data' },
]

export function ReviewPage() {
  const [window, setWindow] = useState<ReviewWindow>('7d')
  const session = useSession()
  const { message } = AntApp.useApp()
  const createLabel = useCreateLabel()
  const reviews = useProxyReviews({ window, limit: 50000 })
  const canReview = can(session.data, 'labels:create')

  return (
    <main className="page">
      <AppPageHeader
        extra={
          <Select
            aria-label="复核统计窗口"
            className="review-window-select"
            onChange={setWindow}
            options={[
              { label: '最近 24 小时', value: '24h' },
              { label: '最近 7 天', value: '7d' },
            ]}
            value={window}
          />
        }
        loading={reviews.isFetching}
        onRefresh={() => void reviews.refetch()}
        subtitle="按账号与终端聚合 TLS、QUIC、目的对象和规则命中；所有结论仅进入影子复核。"
        title="翻墙监测复核"
      />

      {!canReview && <Alert showIcon title="当前会话没有 labels:create 权限，复核动作不可用" type="warning" />}

      {reviews.isLoading ? (
        <section className="surface"><AppLoadingState rows={6} /></section>
      ) : reviews.isError ? (
        <section className="surface"><AppErrorAlert message={reviews.error.message} title="复核数据加载失败" /></section>
      ) : (
        <>
          <section className="metric-grid proxy-review-metrics">
            <AppMetricCard icon={<FileSearchOutlined />} title="复核对象" value={reviews.data?.case_count ?? 0} />
            <AppMetricCard icon={<SafetyCertificateOutlined />} statusColor="red" statusText="需优先处理" title="高置信命中" value={reviews.data?.high_confidence_count ?? 0} />
            <AppMetricCard icon={<UserOutlined />} title="关联账号" value={reviews.data?.account_count ?? 0} />
            <AppMetricCard icon={<LaptopOutlined />} title="关联终端" value={reviews.data?.endpoint_count ?? 0} />
            <AppMetricCard icon={<GlobalOutlined />} title="目的对象" value={reviews.data?.destination_count ?? 0} />
          </section>

          <section className="surface">
            {(reviews.data?.items.length ?? 0) === 0 ? (
              <AppEmptyState description="当前窗口没有 TLS、QUIC 或明确代理规则事件" />
            ) : (
              <div className="proxy-review-list">
                {reviews.data?.items.map((item) => (
                  <ProxyReviewCard
                    canReview={canReview}
                    item={item}
                    key={item.case_id}
                    loading={createLabel.isPending}
                    onReview={(action) => {
                      const target = reviewTarget(item)
                      createLabel.mutate(
                        {
                          ...target,
                          label: action.value,
                          reason: `翻墙监测复核：${action.label}`,
                          evidence_ids: item.evidence_ids,
                        },
                        { onSuccess: () => message.success('复核标注已提交') },
                      )
                    }}
                  />
                ))}
              </div>
            )}
          </section>
        </>
      )}
    </main>
  )
}

function ProxyReviewCard({ canReview, item, loading, onReview }: {
  canReview: boolean
  item: ProxyReviewCase
  loading: boolean
  onReview: (action: (typeof actions)[number]) => void
}) {
  const reviewDisabled = !canReview || item.evidence_ids.length === 0
  return (
    <article className="proxy-review-card">
      <div className="proxy-review-card-head">
        <div className="proxy-review-identity">
          <Space wrap>
            <ConfidenceTag level={item.confidence_level} />
            <RiskLevelTag level={item.risk_level} />
            <ReviewStatusTag reason={item.review_reason} status={item.review_status} />
            <Typography.Text type="secondary">风险分 {item.risk_score}</Typography.Text>
          </Space>
          <div className="proxy-review-subjects">
            <Typography.Text className="mono" strong>
              <Link to={`/ips/${encodeURIComponent(item.ip)}`}>{item.ip}</Link>
            </Typography.Text>
            <Typography.Text className="wrap-text" type="secondary">账号：{item.account_id || '未关联'}</Typography.Text>
            <Typography.Text className="wrap-text" type="secondary">
              终端：{item.endpoint_id ? <Link to={`/devices/${encodeURIComponent(item.endpoint_id)}`}>{item.endpoint_id}</Link> : '未关联'}
            </Typography.Text>
            <Typography.Text className="wrap-text" type="secondary">接入位置：{item.access_ids.join('、') || '未关联'}</Typography.Text>
          </div>
        </div>
        <div className="proxy-review-timing">
          <Typography.Text type="secondary">持续 {formatDuration(item.duration_seconds)}</Typography.Text>
          <Typography.Text type="secondary">{formatTimeRange(item.first_seen, item.last_seen)}</Typography.Text>
        </div>
      </div>

      <div className="proxy-review-facts">
        <ReviewFact label="事件统计" value={`${item.event_count} 条 · TLS ${item.tls_count} · QUIC ${item.quic_count} · Alert ${item.alert_count}`} />
        <ReviewFact label="协议分布" value={item.protocols.map((entry) => `${entry.value} ${entry.count}`).join(' · ') || '无'} />
        <ReviewFact label="目的域名 / SNI" value={formatCounts(item.destination_domains)} />
        <ReviewFact label="目的 IP" value={formatCounts(item.destination_ips)} />
        <ReviewFact label="JA3 / JA4" value={formatCounts(item.tls_fingerprints)} />
      </div>

      <div className="proxy-review-rule-section">
        <Typography.Text className="proxy-review-section-title" strong>规则命中</Typography.Text>
        {item.rule_matches.length === 0 ? (
          <Alert showIcon title="未命中明确代理规则，仅作为低/中置信行为线索，不能单独定性" type="info" />
        ) : (
          <div className="proxy-review-rule-list">
            {item.rule_matches.map((rule) => (
              <div className="proxy-review-rule" key={rule.event_id}>
                <Typography.Text className="wrap-text" strong>{rule.signature}</Typography.Text>
                <Typography.Text className="wrap-text" type="secondary">
                  {[rule.category, rule.action, rule.severity ? `severity ${rule.severity}` : ''].filter(Boolean).join(' · ')}
                </Typography.Text>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="proxy-review-actions">
        {item.evidence_ids.length === 0 && <Typography.Text type="secondary">暂无标准证据，复核动作已禁用</Typography.Text>}
        <Space wrap>
          {actions.map((action) => (
            <Button disabled={reviewDisabled} key={action.value} loading={loading} onClick={() => onReview(action)}>
              {action.label}
            </Button>
          ))}
        </Space>
      </div>
    </article>
  )
}

function ReviewFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="proxy-review-fact">
      <Typography.Text type="secondary">{label}</Typography.Text>
      <Typography.Text className="wrap-text">{value}</Typography.Text>
    </div>
  )
}

function formatCounts(items: ProxyReviewCase['destinations']) {
  return items.map((entry) => `${entry.value} (${entry.count})`).join('、') || '无'
}

function ConfidenceTag({ level }: { level: ProxyReviewCase['confidence_level'] }) {
  const meta = {
    high: { color: 'red', label: '高置信' },
    medium: { color: 'gold', label: '中置信' },
    low: { color: 'blue', label: '低置信' },
  }[level]
  return <Tag className="proxy-confidence-tag" color={meta.color}>{meta.label}</Tag>
}

function reviewTarget(item: ProxyReviewCase): Pick<CreateLabelRequest, 'target_type' | 'target_id'> {
  if (item.endpoint_id) return { target_type: 'endpoint', target_id: item.endpoint_id }
  if (item.account_id) return { target_type: 'account', target_id: item.account_id }
  return { target_type: 'ip', target_id: item.ip }
}

function formatDuration(seconds: number) {
  if (seconds < 60) return `${seconds} 秒`
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时 ${Math.floor((seconds % 3600) / 60)} 分钟`
  return `${Math.floor(seconds / 86400)} 天 ${Math.floor((seconds % 86400) / 3600)} 小时`
}

function formatTimeRange(firstSeen: string, lastSeen: string) {
  const first = new Date(firstSeen).toLocaleString()
  const last = new Date(lastSeen).toLocaleString()
  return first === last ? first : `${first} 至 ${last}`
}
