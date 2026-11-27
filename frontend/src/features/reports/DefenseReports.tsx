import '../../styles/pages/reports.css'
import { lazy, Suspense, type ReactNode } from 'react'
import type { UseQueryResult } from '@tanstack/react-query'
import { Select, Tag } from 'antd'
import { Link } from 'react-router-dom'

import { routerStatusLabels } from '../../pages/routerLabels'
import { request } from '../../shared/api/client'
import type { components } from '../../shared/api/generated'
import { AppErrorAlert, AppLoadingState, formatDateTime } from '../../shared/ui'
import { displayField, statusColor, statusText } from '../../shared/ui/status'
import { useUrlState } from '../../shared/ui/useUrlState'
import { useReportQuery } from './useReportQuery'

type RouterObservationReport = components['schemas']['RouterObservationReport']
type SharedDecisionTrend = components['schemas']['SharedDecisionTrend']

const SharedTrendChart = lazy(() =>
  import('./SharedTrendChart').then((module) => ({ default: module.SharedTrendChart })),
)

type SharedStatus = {
  checked_at?: string
  collection?: {
    state?: string
    sources?: {
      source?: string
      sensor_id?: string
      campus_id?: string
      access_domain?: string
      state?: string
      covered_to?: string | null
    }[]
  }
  materialization?: {
    state?: string
    pending?: number
    failed?: number
    oldest_pending_at?: string | null
  }
  policy?: { coverage_partial?: number }
  attribution?: { insufficient?: number }
}

const sourceLabels: Record<string, string> = {
  'packet-sidecar': '报文采集',
  'handshake-sidecar': '握手采集',
  'flow-syn-sidecar': 'TCP SYN 采集',
}

const coverageLabels: Record<string, string> = {
  healthy: '覆盖完整',
  partial: '覆盖不足',
  insufficient: '覆盖不足',
  waiting: '等待覆盖',
  pending: '等待检查',
  stale: '覆盖已过期',
  unavailable: '来源不可用',
  failed: '采集失败',
  disabled: '已停用',
}

const decisionLabels = { matched: '策略命中', insufficient: '证据不足', expired: '证据过期' }

const windowOptions = [
  { value: '15m', label: '近 15 分钟' },
  { value: '1h', label: '近 1 小时' },
]

function ReportPanel<T>({
  title,
  query,
  extra,
  children,
}: {
  title: string
  query: UseQueryResult<T, Error>
  extra?: ReactNode
  children: (data: T) => ReactNode
}) {
  return (
    <section className="surface report-panel" aria-label={title}>
      <header className="report-panel-heading">
        <h2>{title}</h2>
        {extra}
      </header>
      {query.isPending ? (
        <AppLoadingState rows={3} />
      ) : query.isError || query.data === undefined ? (
        <AppErrorAlert title={`${title}读取失败`} message="刷新报表可重试。" />
      ) : (
        children(query.data)
      )}
    </section>
  )
}

type Metric = { label: string; value: number; tone?: 'blue' | 'amber' | 'slate' }

function MeterChart({ label, items, max }: { label: string; items: Metric[]; max: number }) {
  return (
    <div className="report-meters" role="group" aria-label={label}>
      {items.map((item, index) => (
        <div className={`report-meter tone-${item.tone ?? 'blue'}`} key={item.label}>
          <div className="report-meter-label">
            <span id={`${label}-${index}`}>{item.label}</span>
            <strong>{(item.value ?? 0).toLocaleString('zh-CN')}</strong>
          </div>
          <meter
            min={0}
            max={Math.max(max || 1, 1)}
            value={item.value ?? 0}
            aria-labelledby={`${label}-${index}`}
          />
        </div>
      ))}
    </div>
  )
}

export function RouterReport() {
  const query = useReportQuery('router-summary', (signal) =>
    request<RouterObservationReport>('/router-observations/summary', { signal }),
  )
  return (
    <ReportPanel title="路由器识别分布" query={query}>
      {({ as_of, candidate = 0, likely = 0, confirmed = 0 }) => {
        const total = candidate + likely + confirmed
        return (
          <>
            <div className="report-total">
              <strong>{total.toLocaleString('zh-CN')}</strong>
              <span>台当前观测设备</span>
            </div>
            <MeterChart
              label="路由器身份状态"
              max={total}
              items={[
                { label: routerStatusLabels.candidate, value: candidate, tone: 'slate' },
                { label: routerStatusLabels.likely, value: likely, tone: 'amber' },
                { label: routerStatusLabels.confirmed, value: confirmed, tone: 'blue' },
              ]}
            />
            <p className="report-meta">
              有地址及有效路由角色证据，按设备去重。身份确认与共享判定分别统计。
            </p>
            <footer className="report-panel-footer">
              <time className="report-meta" dateTime={as_of}>
                {formatDateTime(as_of)}
              </time>
              <Link className="report-link" to="/devices?tab=network&routers_view=router">
                查看路由器观察
              </Link>
            </footer>
          </>
        )
      }}
    </ReportPanel>
  )
}

export function SharingTrendReport() {
  const [window, setWindow] = useUrlState('window', '1h', ['15m', '1h'])
  const query = useReportQuery(`shared-trend-${window}`, (signal) =>
    request<SharedDecisionTrend>(`/policy-decisions/shared-trend?window=${window}`, { signal }),
  )
  return (
    <ReportPanel
      title="镜像共享判定趋势"
      query={query}
      extra={
        <Select
          className="report-select"
          aria-label="共享趋势时间窗口"
          value={window}
          options={windowOptions}
          onChange={setWindow}
          virtual={false}
        />
      }
    >
      {({ from, to, buckets, bucket_minutes }) => {
        const totals = buckets.reduce(
          (total, item) => ({
            matched: total.matched + item.matched,
            insufficient: total.insufficient + item.insufficient,
            expired: total.expired + item.expired,
          }),
          { matched: 0, insufficient: 0, expired: 0 },
        )
        return (
          <>
            <dl className="report-facts">
              {(Object.keys(decisionLabels) as Array<keyof typeof decisionLabels>).map((key) => (
                <div key={key}>
                  <dt>{decisionLabels[key]}</dt>
                  <dd>{totals[key].toLocaleString('zh-CN')}</dd>
                </div>
              ))}
            </dl>
            {totals.matched + totals.insufficient + totals.expired > 0 ? (
              <Suspense fallback={<AppLoadingState rows={2} />}>
                <SharedTrendChart buckets={buckets} />
              </Suspense>
            ) : (
              <p className="report-no-trend">窗口内暂无已记录的判定</p>
            )}
            <p className="report-meta">
              每 {bucket_minutes} 分钟的判定记录数，同一对象可能多次判定。
            </p>
            <footer className="report-panel-footer">
              <span className="report-meta">
                截至 <time dateTime={to}>{formatDateTime(to)}</time>
              </span>
              <Link
                className="report-link"
                to={`/actions?${new URLSearchParams({
                  tab: 'decisions',
                  decision_result: 'all',
                  decision_from: from,
                  decision_to: to,
                })}`}
              >
                查看策略判定明细
              </Link>
            </footer>
          </>
        )
      }}
    </ReportPanel>
  )
}

function CoverageTag({ state, aggregate = false }: { state?: string; aggregate?: boolean }) {
  const label =
    aggregate && state === 'healthy'
      ? '覆盖正常'
      : (coverageLabels[state ?? ''] ?? displayField(statusText(state)))
  return label ? (
    <Tag className="report-status" color={statusColor(state)}>
      {label}
    </Tag>
  ) : null
}

export function SharedBehaviorReport() {
  const [window, setWindow] = useUrlState('sharing_window', '15m', ['15m', '1h', 'today'])
  const query = useReportQuery('shared-observation-summary-' + window, (signal) =>
    request<components['schemas']['SharedBehaviorReport']>(
      '/shared-access/observations/summary?window=' + window,
      { signal },
    ),
  )
  return (
    <ReportPanel
      title="当前镜像共享行为"
      query={query}
      extra={
        <Select
          aria-label="共享统计时段"
          value={window}
          onChange={setWindow}
          options={[...windowOptions, { value: 'today', label: '今日' }]}
        />
      }
    >
      {(report) => {
        const rows = [
          ['outlets', '候选出口', report.outlets],
          ['accounts', '已归属账号', report.accounts],
          ['unattributed', '曾缺少归属的出口', report.unattributed],
          ['router_pending', '路由器待核验账号', report.router_pending],
          ['exempt', '白名单豁免账号', report.exempt],
          ['confirmed', '确认共享账号', report.confirmed],
          ['router', '路由器共享账号', report.router],
          ['multiple', '多终端共享账号', report.multiple],
          ['cases', '共享案件', report.cases],
          ['actions', '仅记录处置', report.actions],
        ] as const
        const unattributedReasons = [
          ['认证覆盖缺口', report.coverage_gap_outlets],
          ['缺少同窗绑定', report.missing_binding_outlets],
          ['镜像 MAC 或 VLAN 不符', report.mirror_mismatch_outlets],
        ] as const
        const link = (outcome: string) =>
          '/shared-access?' +
          new URLSearchParams({
            tab: 'associations',
            from: report.from ?? '',
            to: report.as_of,
            outcome,
          })
        return (
          <>
            <div className="report-total">
              <strong>{report.confirmed}</strong>
              <span>个账号确认共享</span>
            </div>
            <dl className="sharing-report-counts">
              {rows.map(([key, label, count]) => (
                <div key={key}>
                  <dt>
                    <Link to={link(key)}>{label}</Link>
                  </dt>
                  <dd>{count?.toLocaleString('zh-CN')}</dd>
                </div>
              ))}
            </dl>
            <h3>时段内始终未归属的出口</h3>
            <p className="report-meta">每项按出口去重，同一出口可有多种原因。</p>
            <dl className="sharing-report-counts sharing-report-reasons">
              {unattributedReasons.map(([label, count]) => (
                <div key={label}>
                  <dt>{label}</dt>
                  <dd>{count?.toLocaleString('zh-CN')}</dd>
                </div>
              ))}
            </dl>
            <footer className="report-panel-footer">
              <span className="report-meta">
                {formatDateTime(report.from)} 至 {formatDateTime(report.as_of)}
              </span>
              <Link to={link('outlets')}>查看共享行为明细</Link>
            </footer>
          </>
        )
      }}
    </ReportPanel>
  )
}

export function SharingCoverageReport() {
  const query = useReportQuery('shared-coverage', (signal) =>
    request<SharedStatus>('/shared-access/status', { signal }),
  )
  return (
    <ReportPanel title="共享识别卡点" query={query}>
      {({ collection, materialization, policy, attribution, checked_at }) => {
        const issues = [
          { label: '采集覆盖不足', value: policy?.coverage_partial },
          { label: '身份归因不足', value: attribution?.insufficient },
          { label: '判定待处理', value: materialization?.pending },
          { label: '判定处理失败', value: materialization?.failed },
        ].filter((item): item is { label: string; value: number } => item.value !== undefined)
        const sources = collection?.sources ?? []
        return (
          <>
            <div className="report-coverage-grid">
              <div>
                <h3>当前共享任务</h3>
                {issues.length ? (
                  <>
                    <MeterChart
                      label="当前共享任务卡点"
                      max={Math.max(...issues.map((item) => item.value))}
                      items={issues}
                    />
                    <p className="report-meta">各项可能重叠，数量按任务统计。</p>
                    {formatDateTime(materialization?.oldest_pending_at) && (
                      <p className="report-meta">
                        最早待办 {formatDateTime(materialization?.oldest_pending_at)}
                      </p>
                    )}
                  </>
                ) : (
                  <p className="report-meta">暂无任务统计</p>
                )}
              </div>
              <div>
                <h3 className="report-coverage-heading">
                  采集覆盖水位 <CoverageTag state={collection?.state} aggregate />
                </h3>
                {sources.length ? (
                  <ul className="report-coverage-list">
                    {sources.map((item, index) => (
                      <li
                        key={`${item.source}/${item.sensor_id}/${item.campus_id}/${item.access_domain}/${index}`}
                      >
                        <div className="report-coverage-source">
                          <strong>
                            {sourceLabels[item.source ?? ''] ?? item.source ?? '采集来源'}
                          </strong>
                          {[item.sensor_id, item.campus_id, item.access_domain].some(Boolean) && (
                            <span className="report-meta">
                              {[item.sensor_id, item.campus_id, item.access_domain]
                                .filter(Boolean)
                                .join(' · ')}
                            </span>
                          )}
                        </div>
                        <CoverageTag state={item.state} />
                        {formatDateTime(item.covered_to) && (
                          <time className="report-meta" dateTime={item.covered_to ?? undefined}>
                            {formatDateTime(item.covered_to)}
                          </time>
                        )}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="report-meta">暂无采集覆盖记录</p>
                )}
                {formatDateTime(checked_at) && (
                  <p className="report-meta">检查于 {formatDateTime(checked_at)}</p>
                )}
              </div>
            </div>
          </>
        )
      }}
    </ReportPanel>
  )
}
