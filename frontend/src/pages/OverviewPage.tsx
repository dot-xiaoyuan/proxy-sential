import '../styles/pages/overview.css'
import '../styles/pages/reports.css'
import { lazy, Suspense, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  AlertOutlined,
  CheckCircleOutlined,
  CloudServerOutlined,
  CodeOutlined,
  DatabaseOutlined,
  DeploymentUnitOutlined,
  RightOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons'
import { Card, Progress, Select, Tag, Typography } from 'antd'

import { ActiveRiskIps } from './ActiveRiskIps'
import { routerStatusLabels } from './routerLabels'
import {
  RootFilesystemCapacity,
  RootFilesystemWarning,
} from '../entities/system/RootFilesystemCapacity'
import { request } from '../shared/api/client'
import type { components } from '../shared/api/generated'
import {
  useActivityOverview,
  useOrganization,
  useOverview,
  useSession,
  useSystemStatus,
} from '../shared/api/queries'
import type { RiskLevel } from '../shared/api/types'
import { can } from '../shared/auth/permissions'
import {
  AppErrorAlert,
  AppLoadingState,
  AppMetricCard,
  AppPageHeader,
  StatisticsTime,
  type ReportWindow,
} from '../shared/ui'
import { formatBytes } from '../shared/ui/formatBytes'
import { Notice as Alert } from '../shared/ui/Notice'
import { useUrlState } from '../shared/ui/useUrlState'

const SharedTrendChart = lazy(() =>
  import('../features/reports/SharedTrendChart').then((module) => ({
    default: module.SharedTrendChart,
  })),
)

type RouterObservationReport = components['schemas']['RouterObservationReport']
type SharedDecisionTrend = components['schemas']['SharedDecisionTrend']

const levelOrder: RiskLevel[] = ['confirmed', 'high', 'suspicious', 'normal']

const levelNames: Record<RiskLevel, string> = {
  confirmed: '极高风险',
  high: '高风险',
  suspicious: '复核线索',
  normal: '正常终端',
}

const componentNames: Record<string, string> = {
  operations: '运营数据',
  storage: '存储连接',
  collector: '采集链路',
  authentication: '身份认证',
  authentication_oidc: '统一认证',
  identity_ingest: '身份同步',
  statistics_read_model: '统计模型',
  application_read_model: '应用模型',
}

const statusNames: Record<string, string> = {
  ready: '正常',
  file_mode: '文件模式',
  memory_mode: '内存模式',
  disabled: '停用',
  delayed: '延迟',
  stale: '数据滞后',
  idle: '空闲',
  no_data: '无数据',
  unavailable: '异常',
}

function formatDuration(seconds: number) {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  if (days > 0) return `${days} 天 ${hours} 小时`
  if (hours > 0) return `${hours} 小时 ${minutes} 分钟`
  return `${minutes} 分钟`
}

function clampPercent(value: number) {
  return Math.max(0, Math.min(100, value))
}

function progressColor(percent: number) {
  if (percent >= 85) return '#dc2626'
  if (percent >= 70) return '#d97706'
  return '#2257a7'
}

function PanelHeader({ icon, title, meta }: { icon: ReactNode; title: string; meta?: ReactNode }) {
  return (
    <div className="overview-panel-header">
      <div className="overview-panel-heading">
        <span className="overview-panel-icon">{icon}</span>
        <Typography.Title level={4}>{title}</Typography.Title>
      </div>
      {meta && <div className="overview-panel-meta">{meta}</div>}
    </div>
  )
}

function LoadRow({ label, percent, detail }: { label: string; percent: number; detail: string }) {
  const safePercent = clampPercent(percent)
  return (
    <div className="overview-load-row">
      <div className="overview-load-label">
        <span>{label}</span>
        <strong>{detail}</strong>
      </div>
      <Progress percent={safePercent} showInfo={false} strokeColor={progressColor(safePercent)} />
    </div>
  )
}

export function OverviewPage() {
  const [windowValue, setQuickWindow] = useUrlState('window', '1h', [
    '10m',
    '1h',
    '24h',
    '7d',
    '30d',
  ])
  const quickWindow = windowValue as ReportWindow
  const [campusId, setCampusId] = useUrlState('campus_id', '')
  const [sensorId] = useUrlState('sensor_id', '')
  const session = useSession()
  const [healthOpen, setHealthOpen] = useState(false)

  const context = new URLSearchParams({
    window: quickWindow,
    ...(campusId ? { campus_id: campusId } : {}),
    ...(sensorId ? { sensor_id: sensorId } : {}),
  }).toString()

  const canReadIdentity = can(session.data, 'identity:read')
  const canReadPolicies = can(session.data, 'policies:read')
  const canReadCases = can(session.data, 'cases:read')
  const canReadActions = can(session.data, 'actions:read')

  const organization = useOrganization(can(session.data, 'organization:read'))
  const overview = useOverview({
    window: quickWindow,
    sensor_id: sensorId || undefined,
    campus_id: campusId || undefined,
  })
  const activity = useActivityOverview(
    { window: quickWindow, sensor_id: sensorId || undefined, campus_id: campusId || undefined },
    can(session.data, 'dpi:read'),
  )
  const system = useSystemStatus()

  const routerSummary = useQuery({
    queryKey: ['overview-router-summary'],
    queryFn: ({ signal }) =>
      request<RouterObservationReport>('/router-observations/summary', { signal }),
    enabled: canReadIdentity,
    staleTime: 60_000,
  })

  const sharedTrend = useQuery({
    queryKey: ['overview-shared-trend', '1h'],
    queryFn: ({ signal }) =>
      request<SharedDecisionTrend>('/policy-decisions/shared-trend?window=1h', { signal }),
    enabled: canReadPolicies,
    staleTime: 60_000,
  })

  if (overview.isLoading) {
    return <AppLoadingState rows={6} />
  }

  if (overview.isError || !overview.data) {
    return <AppErrorAlert title="运营工作台读取失败" message={overview.error?.message} />
  }

  const levelCounts = overview.data.level_counts
  const totalRiskObjects = levelOrder.reduce((total, level) => total + levelCounts[level], 0)
  const openCases = overview.data.open_case_count ?? overview.data.pending_reviews
  const overdueCases = overview.data.overdue_case_count ?? 0

  const routerTotal = routerSummary.data
    ? routerSummary.data.candidate + routerSummary.data.likely + routerSummary.data.confirmed
    : undefined

  const trendTotals = sharedTrend.data?.buckets.reduce(
    (acc, item) => ({
      matched: acc.matched + item.matched,
      insufficient: acc.insufficient + item.insufficient,
      expired: acc.expired + item.expired,
    }),
    { matched: 0, insufficient: 0, expired: 0 },
  )

  const runtime = system.data?.runtime
  const host = runtime?.host
  const process = runtime?.process
  const hostLoadPercent =
    host?.load_1 === undefined ? undefined : (host.load_1 / Math.max(host.logical_cpus, 1)) * 100
  const healthComponents = Object.entries(system.data?.components ?? {}).filter(([, item]) =>
    Boolean(item.status),
  )
  const degradedComponents = healthComponents.filter(([, item]) =>
    ['unavailable', 'stale', 'delayed'].includes(item.status ?? ''),
  )

  return (
    <main className="page overview-page">
      <AppPageHeader
        onQuickWindowChange={setQuickWindow}
        quickWindow={quickWindow}
        quickWindows={['10m', '1h', '24h', '7d', '30d']}
        extra={
          <>
            <Tag color="blue">观察期 · 仅记录未执行</Tag>
            <Select
              aria-label="校区筛选"
              className="campus-filter"
              value={campusId}
              onChange={setCampusId}
              options={[
                { value: '', label: '全部校区' },
                ...(organization.data?.campuses ?? []).map((item) => ({
                  value: item.campus_id,
                  label: item.name,
                })),
              ]}
            />
          </>
        }
      />

      <StatisticsTime
        freshness={overview.data.data_freshness}
        value={overview.data.statistics_as_of}
      />

      <section className="metric-grid overview-metric-grid" aria-label="防代理核心治理指标">
        <Link className="overview-metric-link" to="/shared-access">
          <AppMetricCard
            icon={<AlertOutlined className="text-danger-color" />}
            statusColor={overdueCases > 0 ? 'red' : 'blue'}
            statusText={overdueCases > 0 ? `超时 ${overdueCases}` : '进入核验'}
            title="待处理案件"
            value={openCases}
          />
        </Link>
        {canReadPolicies ? (
          <Link className="overview-metric-link" to="/actions?tab=decisions">
            <AppMetricCard
              icon={<SafetyCertificateOutlined className="text-primary-color" />}
              statusColor="blue"
              statusText="近 1 小时 · 仅记录"
              title="共享策略命中"
              value={trendTotals ? trendTotals.matched : 0}
            />
          </Link>
        ) : (
          <AppMetricCard
            icon={<SafetyCertificateOutlined className="text-primary-color" />}
            statusColor="blue"
            statusText="证据聚合"
            title="风险证据"
            value={overview.data.throughput.evidence}
          />
        )}
        {canReadIdentity ? (
          <Link className="overview-metric-link" to="/devices?tab=network&routers_view=router">
            <AppMetricCard
              icon={<DeploymentUnitOutlined className="text-primary-color" />}
              statusColor="green"
              statusText={
                routerSummary.data ? `已确认 ${routerSummary.data.confirmed} 台` : '路由器台账'
              }
              title="观测路由器"
              value={routerTotal ?? 0}
            />
          </Link>
        ) : (
          <AppMetricCard
            icon={<CheckCircleOutlined className="text-success-color" />}
            statusColor="green"
            statusText="活跃对象"
            title="风险对象"
            value={overview.data.throughput.risks}
          />
        )}
        <Link className="overview-metric-link" to="/reports">
          <AppMetricCard
            icon={<DatabaseOutlined className="text-primary-color" />}
            statusColor="blue"
            statusText={`窗口 ${overview.data.window ?? quickWindow}`}
            title="标准事件"
            value={overview.data.throughput.events}
          />
        </Link>
      </section>

      {(canReadPolicies || canReadIdentity) && (
        <section className="overview-cockpit-grid" aria-label="防代理治理态势">
          {canReadPolicies && (
            <Card className="surface-card overview-panel" size="small">
              <PanelHeader
                icon={<SafetyCertificateOutlined />}
                title="近 1 小时共享判定趋势"
                meta={
                  <Link className="overview-panel-link" to="/reports">
                    防代理报表 <RightOutlined />
                  </Link>
                }
              />
              {sharedTrend.isPending ? (
                <AppLoadingState rows={3} />
              ) : sharedTrend.isError || !sharedTrend.data ? (
                <Alert type="warning" showIcon title="共享判定趋势暂不可用" />
              ) : (
                <div className="overview-trend-body">
                  <dl className="report-facts">
                    <div>
                      <dt>策略命中</dt>
                      <dd>{(trendTotals?.matched ?? 0).toLocaleString('zh-CN')}</dd>
                    </div>
                    <div>
                      <dt>证据不足</dt>
                      <dd>{(trendTotals?.insufficient ?? 0).toLocaleString('zh-CN')}</dd>
                    </div>
                    <div>
                      <dt>证据过期</dt>
                      <dd>{(trendTotals?.expired ?? 0).toLocaleString('zh-CN')}</dd>
                    </div>
                  </dl>
                  <Suspense fallback={<AppLoadingState rows={3} />}>
                    <SharedTrendChart buckets={sharedTrend.data.buckets} />
                  </Suspense>
                </div>
              )}
            </Card>
          )}

          <Card className="surface-card overview-panel" size="small">
            <PanelHeader
              icon={<AlertOutlined />}
              title="共享研判与路由器态势"
              meta={
                <Link className="overview-panel-link" to="/shared-access">
                  共享发现 <RightOutlined />
                </Link>
              }
            />
            <div className="overview-cockpit-stack">
              {canReadIdentity && routerSummary.data && (
                <div className="report-meters" role="group" aria-label="路由器识别分布">
                  {[
                    {
                      label: routerStatusLabels.confirmed,
                      value: routerSummary.data.confirmed,
                      tone: 'blue',
                    },
                    {
                      label: routerStatusLabels.likely,
                      value: routerSummary.data.likely,
                      tone: 'amber',
                    },
                    {
                      label: routerStatusLabels.candidate,
                      value: routerSummary.data.candidate,
                      tone: 'slate',
                    },
                  ].map((item) => (
                    <div className={`report-meter tone-${item.tone}`} key={item.label}>
                      <div className="report-meter-label">
                        <span>{item.label}</span>
                        <strong>{item.value.toLocaleString('zh-CN')}</strong>
                      </div>
                      <meter min={0} max={Math.max(routerTotal ?? 1, 1)} value={item.value} />
                    </div>
                  ))}
                </div>
              )}

              <div className="overview-quick-links">
                {canReadCases && (
                  <Link className="overview-quick-link" to={`/shared-access?${context}`}>
                    <span>共享行为观察</span>
                    <RightOutlined />
                  </Link>
                )}
                {canReadActions && (
                  <Link className="overview-quick-link" to="/actions?tab=actions">
                    <span>仅记录处置动作</span>
                    <RightOutlined />
                  </Link>
                )}
                {canReadCases && openCases > 0 && (
                  <Link className="overview-quick-link" to={`/cases?${context}`}>
                    <span>
                      待处理案件（{openCases}
                      {overdueCases > 0 ? ` · 超时 ${overdueCases}` : ''}）
                    </span>
                    <RightOutlined />
                  </Link>
                )}
                {canReadIdentity && (
                  <Link className="overview-quick-link" to="/devices?tab=network">
                    <span>路由器台账核验</span>
                    <RightOutlined />
                  </Link>
                )}
              </div>
            </div>
          </Card>
        </section>
      )}

      {activity.data && (activity.data.top_active_risk_ips?.length ?? 0) > 0 && (
        <section className="surface">
          <ActiveRiskIps items={activity.data.top_active_risk_ips} />
        </section>
      )}

      {totalRiskObjects > 0 && (
        <section className="overview-risk-summary">
          <Card className="surface-card overview-panel" size="small">
            <PanelHeader
              icon={<SafetyCertificateOutlined />}
              title="风险等级分布"
              meta={`${totalRiskObjects.toLocaleString()} 个对象`}
            />
            <div className="overview-risk-list">
              {levelOrder.map((level) => {
                const count = levelCounts[level]
                const percent = totalRiskObjects > 0 ? (count / totalRiskObjects) * 100 : 0
                if (count <= 0) return null
                return (
                  <div className={`overview-risk-item overview-risk-item-${level}`} key={level}>
                    <span className="overview-risk-dot" />
                    <span className="overview-risk-name">{levelNames[level]}</span>
                    <strong>{count.toLocaleString()}</strong>
                    <span className="overview-risk-percent">
                      {percent.toFixed(percent > 0 && percent < 1 ? 1 : 0)}%
                    </span>
                  </div>
                )
              })}
            </div>
          </Card>
        </section>
      )}

      <details
        className="surface platform-health"
        open={healthOpen}
        onToggle={(event) => setHealthOpen(event.currentTarget.open)}
      >
        <summary className="overview-health-summary-bar">
          <span className="overview-health-summary-title">
            <CloudServerOutlined /> 平台健康与运行负载
          </span>
          <span className="overview-health-summary-chips">
            {degradedComponents.length > 0 ? (
              <Tag color="orange">{degradedComponents.length} 项组件需关注</Tag>
            ) : healthComponents.length > 0 ? (
              <Tag color="green">全部组件正常</Tag>
            ) : null}
            {host?.memory_used_percent !== undefined && (
              <Tag>内存 {host.memory_used_percent.toFixed(0)}%</Tag>
            )}
            <RootFilesystemWarning
              status={host?.root_filesystem}
              error={host?.root_filesystem_error}
            />
          </span>
        </summary>
        <div className="overview-runtime-grid">
          {host && (
            <Card className="surface-card overview-panel" size="small">
              <PanelHeader
                icon={<CloudServerOutlined />}
                title="服务器资源"
                meta={`${host.logical_cpus} 核`}
              />
              <div className="overview-load-list">
                {hostLoadPercent !== undefined && (
                  <LoadRow
                    label="1 分钟平均负载"
                    percent={hostLoadPercent}
                    detail={[host.load_1, host.load_5, host.load_15]
                      .filter((v): v is number => v !== undefined)
                      .map((v) => v.toFixed(2))
                      .join(' / ')}
                  />
                )}
                {host.memory_used_percent !== undefined && (
                  <LoadRow
                    label="内存使用率"
                    percent={host.memory_used_percent}
                    detail={`${formatBytes(host.memory_used_bytes)} / ${formatBytes(host.memory_total_bytes)}`}
                  />
                )}
              </div>
              <RootFilesystemCapacity
                status={host.root_filesystem}
                error={host.root_filesystem_error}
              />
            </Card>
          )}

          {process && (
            <Card className="surface-card overview-panel" size="small">
              <PanelHeader
                icon={<CodeOutlined />}
                title="服务运行态"
                meta={`已运行 ${formatDuration(process.uptime_seconds)}`}
              />
              <div className="overview-runtime-metrics">
                <div className="overview-runtime-stat">
                  <span>进程 CPU</span>
                  <strong>{process.cpu_percent.toFixed(1)}%</strong>
                </div>
                <div className="overview-runtime-stat">
                  <span>堆内存</span>
                  <strong>{formatBytes(process.heap_alloc_bytes)}</strong>
                </div>
                <div className="overview-runtime-stat">
                  <span>常驻内存</span>
                  <strong>
                    {formatBytes(process.resident_memory_bytes ?? process.heap_in_use_bytes)}
                  </strong>
                </div>
                <div className="overview-runtime-stat">
                  <span>活跃协程 / GC</span>
                  <strong>
                    {process.goroutines} / {process.gc_cycles}
                  </strong>
                </div>
              </div>
            </Card>
          )}

          {(healthComponents.length > 0 || system.isError) && (
            <Card className="surface-card overview-panel" size="small">
              <PanelHeader
                icon={<DatabaseOutlined />}
                title="核心组件健康"
                meta={
                  system.data?.status === 'ready'
                    ? '就绪'
                    : system.data?.status === 'degraded'
                      ? '降级'
                      : ''
                }
              />
              <div className="overview-health-list">
                {healthComponents.map(([key, item]) => (
                  <div className="overview-health-row" key={key}>
                    <span className="overview-health-name">{componentNames[key] ?? key}</span>
                    <span
                      className={`overview-health-state overview-health-state-${item.status ?? 'neutral'}`}
                    >
                      {item.status ? (statusNames[item.status] ?? item.status) : ''}
                    </span>
                  </div>
                ))}
              </div>
              {system.isError && (
                <Alert
                  className="overview-inline-alert"
                  type="warning"
                  showIcon
                  title="平台健康状态读取失败"
                />
              )}
            </Card>
          )}
        </div>
      </details>
    </main>
  )
}
