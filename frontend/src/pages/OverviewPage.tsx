import { ActiveRiskIps } from './ActiveRiskIps'
import { useUrlState } from '../shared/ui/useUrlState'
import { useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
import { type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertOutlined,
  CheckCircleOutlined,
  CloudServerOutlined,
  CodeOutlined,
  DatabaseOutlined,
  DeploymentUnitOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons'
import { Alert, Card, Progress, Select, Typography } from 'antd'

import { RootFilesystemCapacity, RootFilesystemWarning } from '../entities/system/RootFilesystemCapacity'
import { formatBytes } from '../shared/ui/formatBytes'
import { useActivityOverview, useOrganization, useOverview, useSystemStatus } from '../shared/api/queries'
import type { RiskLevel } from '../shared/api/types'
import {
  AppErrorAlert,
  AppLoadingState,
  AppMetricCard,
  AppPageHeader,
  StatisticsTime,
  type ReportWindow,
} from '../shared/ui'

const levelOrder: RiskLevel[] = ['confirmed', 'high', 'suspicious', 'normal']

const levelNames: Record<RiskLevel, string> = {
  confirmed: '极高风险',
  high: '高风险',
  suspicious: '复核线索',
  normal: '正常终端',
}

const evidenceNames: Record<string, string> = {
  ttl_clusters: 'TTL 路径差异',
  multi_ja3_ja4: '多 JA3 / JA4 指纹',
  port_distribution: '端口分布线索',
  dhcp_device_fingerprint: 'DHCP 设备指纹',
  encrypted_tunnel_behavior: '加密传输线索',
  domain_diversity: '域名多样性',
  vpn_proxy_domain_hint: '代理域名线索',
  ua_os_divergence: 'UA 与系统偏差',
  vpn_proxy_rule_hint: '代理规则线索',
  vpn_proxy_rule_match: '代理规则命中',
  known_game_accelerator: '游戏加速器',
  device_fingerprint_conflict: '设备画像差异',
  ai_relay_domain_usage: 'AI 中继域名',
  shared_access_window: '共享接入窗口',
  multi_user_agent: '多用户代理',
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
  return '#0284c7'
}

function PanelHeader({ icon, title, meta }: { icon: ReactNode; title: string; meta?: string }) {
  return (
    <div className="overview-panel-header">
      <div className="overview-panel-heading">
        <span className="overview-panel-icon">{icon}</span>
        <Typography.Title level={4}>{title}</Typography.Title>
      </div>
      {meta && <Typography.Text className="overview-panel-meta">{meta}</Typography.Text>}
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
  const [windowValue,setQuickWindow]=useUrlState('window','1h',['10m','1h','24h','7d','30d']);const quickWindow=windowValue as ReportWindow
  const [campusId,setCampusId]=useUrlState('campus_id','');const session=useSession();
  const [sensorId]=useUrlState('sensor_id','');
  const context=new URLSearchParams({window:quickWindow,...(campusId?{campus_id:campusId}:{}),...(sensorId?{sensor_id:sensorId}:{})}).toString()
  const organization = useOrganization(can(session.data,'organization:read'))
  const overview = useOverview({ window: quickWindow, sensor_id:sensorId||undefined, campus_id: campusId || undefined })
  const activity = useActivityOverview({ window: quickWindow, sensor_id:sensorId||undefined, campus_id: campusId || undefined },can(session.data,'dpi:read'))
  const system = useSystemStatus()

  if (overview.isLoading) {
    return <AppLoadingState rows={6} />
  }

  if (overview.isError || !overview.data) {
    return <AppErrorAlert title="总览控制塔加载失败" message={overview.error?.message} />
  }

  const levelCounts = overview.data.level_counts
  const totalRiskObjects = levelOrder.reduce((total, level) => total + levelCounts[level], 0)
  const maxEvidenceCount = Math.max(...overview.data.top_evidence.map((item) => item.count), 1)
  const runtime = system.data?.runtime
  const host = runtime?.host
  const process = runtime?.process
  const hostLoadPercent = host?.load_1 === undefined ? undefined : (host.load_1 / Math.max(host.logical_cpus, 1)) * 100
  const healthComponents = Object.entries(system.data?.components ?? {})

  return (
    <main className="page overview-page">
      <AppPageHeader
        loading={overview.isFetching || activity.isFetching || system.isFetching}
        onQuickWindowChange={setQuickWindow}
        onRefresh={() => {
          void overview.refetch()
          void activity.refetch()
          void system.refetch()
        }}
        quickWindow={quickWindow}
        quickWindows={['10m', '1h', '24h', '7d', '30d']}
        extra={(
          <Select
            className="campus-filter"
            value={campusId}
            onChange={setCampusId}
            options={[
              { value: '', label: '全部校区' },
              ...(organization.data?.campuses ?? []).map((item) => ({ value: item.campus_id, label: item.name })),
            ]}
          />
        )}
        subtitle="优先处理风险待办、超时案件和证据复核"
        title="高校网络风险运营工作台"
      />

      <StatisticsTime freshness={overview.data.data_freshness} value={overview.data.statistics_as_of} />

      <section className="metric-grid overview-metric-grid">
        <AppMetricCard
          icon={<AlertOutlined className="text-danger-color" />}
          statusColor="red"
          statusText={`超时 ${overview.data.overdue_case_count ?? 0}`}
          title="待处理案件"
          value={overview.data.open_case_count ?? overview.data.pending_reviews}
        />
        <AppMetricCard
          icon={<DatabaseOutlined className="text-primary-color" />}
          statusColor="blue"
          statusText={`窗口 ${overview.data.window ?? quickWindow}`}
          title="标准事件"
          value={overview.data.throughput.events}
        />
        <AppMetricCard
          icon={<SafetyCertificateOutlined className="text-purple-color" />}
          statusColor="purple"
          statusText="证据聚合"
          title="风险证据"
          value={overview.data.throughput.evidence}
        />
        <AppMetricCard
          icon={<CheckCircleOutlined className="text-success-color" />}
          statusColor="green"
          statusText="活跃对象"
          title="风险对象"
          value={overview.data.throughput.risks}
        />
      </section>

      <section className="surface workbench-actions"><Typography.Title level={4}>风险待办</Typography.Title><p>待处理 {overview.data.open_case_count??overview.data.pending_reviews} 件 · 超时 {overview.data.overdue_case_count??0} 件</p><div className="policy-toolbar">
      {can(session.data,'cases:read')&&<><Link to={`/cases?${context}`}>处理风险案件</Link><Link to={`/shared-access?tab=reviews&${context}`}>进入账号复核</Link></>}
      {can(session.data,'actions:read')&&<Link to="/actions?tab=actions">核对处置记录</Link>}
      </div></section>
      {activity.data&&<section className="surface"><ActiveRiskIps items={activity.data.top_active_risk_ips}/></section>}
      <section className="overview-risk-summary">
        <Card className="surface-card overview-panel" size="small">
          <PanelHeader icon={<SafetyCertificateOutlined />} title="风险等级分布" meta={`${totalRiskObjects.toLocaleString()} 个对象`} />
          <div className="overview-risk-list">
            {levelOrder.map((level) => {
              const count = levelCounts[level]
              const percent = totalRiskObjects > 0 ? count / totalRiskObjects * 100 : 0
              return (
                <div className={`overview-risk-item overview-risk-item-${level}`} key={level}>
                  <span className="overview-risk-dot" />
                  <span className="overview-risk-name">{levelNames[level]}</span>
                  <strong>{count.toLocaleString()}</strong>
                  <span className="overview-risk-percent">{percent.toFixed(percent > 0 && percent < 1 ? 1 : 0)}%</span>
                </div>
              )
            })}
          </div>
        </Card>

      </section>

      <section className="overview-focus-grid">
        <Card className="surface-card overview-panel overview-evidence-panel" size="small">
          <PanelHeader
            icon={<DeploymentUnitOutlined />}
            title="历史累计证据"
            meta={`展示前 ${Math.min(8, overview.data.top_evidence.length)} 类`}
          />
          <div className="overview-evidence-grid">
            {overview.data.top_evidence.slice(0, 8).map((item) => (
              <div className="overview-evidence-item" key={item.type}>
                <div className="overview-evidence-label">
                  <span title={item.type}>{evidenceNames[item.type] ?? item.type}</span>
                  <strong>{item.count.toLocaleString()}</strong>
                </div>
                <Progress percent={item.count / maxEvidenceCount * 100} showInfo={false} strokeColor="#64748b" />
              </div>
            ))}
          </div>
          {overview.data.top_evidence.length > 8 && (
            <Typography.Text className="overview-panel-footnote">
              另有 {overview.data.top_evidence.length - 8} 类低贡献证据已收拢
            </Typography.Text>
          )}
        </Card>

      </section>

      <section className="overview-detail-grid">
        <div className="surface overview-activity-summary">
          <div>
            <Typography.Title level={4}>DPI 访问态势</Typography.Title>
            <Typography.Text type="secondary">
              {quickWindow} 内覆盖 {activity.data?.active_ip_count ?? 0} 个活跃 IP 与 {activity.data?.access_object_count ?? 0} 个访问目标
            </Typography.Text>
          </div>
          <div className="overview-activity-metrics">
            <div><span>标准事件</span><strong>{(activity.data?.event_count ?? 0).toLocaleString()}</strong></div>
            <div><span>活跃风险 IP</span><strong>{activity.data?.active_risk_ip_count ?? 0}</strong></div>
            <Link to={`/activity?section=access&${context}`}>进入访问分析</Link>
          </div>
        </div>

      </section>
      <details className="surface platform-health"><summary>平台健康与运行负载 <RootFilesystemWarning status={host?.root_filesystem} error={host?.root_filesystem_error} /></summary><div className="overview-runtime-grid">        <Card className="surface-card overview-panel" size="small">
          <PanelHeader icon={<CloudServerOutlined />} title="服务器负载" meta={host ? `${host.logical_cpus} 核` : undefined} />
          <div className="overview-load-stack">
            {hostLoadPercent !== undefined && host?.load_1 !== undefined && (
              <LoadRow label="1 分钟负载" percent={hostLoadPercent} detail={host.load_1.toFixed(2)} />
            )}
            {host?.memory_used_percent !== undefined && (
              <LoadRow
                label="物理内存"
                percent={host.memory_used_percent}
                detail={`${formatBytes(host.memory_used_bytes)} / ${formatBytes(host.memory_total_bytes)}`}
              />
            )}
          </div>
          <RootFilesystemCapacity status={host?.root_filesystem} error={host?.root_filesystem_error} />
          {host && (host.load_5 !== undefined || host.load_15 !== undefined) && (
            <div className="overview-inline-stats">
              {host.load_5 !== undefined && <div><span>5 分钟负载</span><strong>{host.load_5.toFixed(2)}</strong></div>}
              {host.load_15 !== undefined && <div><span>15 分钟负载</span><strong>{host.load_15.toFixed(2)}</strong></div>}
            </div>
          )}
        </Card>

        <Card className="surface-card overview-panel" size="small">
          <PanelHeader icon={<CodeOutlined />} title="程序负载" meta={process ? `运行 ${formatDuration(process.uptime_seconds)}` : undefined} />
          {process && (
            <>
              <div className="overview-load-stack">
                <LoadRow label="进程 CPU" percent={process.cpu_percent} detail={`${process.cpu_percent.toFixed(1)}%`} />
              </div>
              <div className="overview-inline-stats overview-process-stats">
                {process.resident_memory_bytes !== undefined && <div><span>常驻内存</span><strong>{formatBytes(process.resident_memory_bytes)}</strong></div>}
                <div><span>Go 堆内存</span><strong>{formatBytes(process.heap_alloc_bytes)}</strong></div>
                <div><span>协程</span><strong>{process.goroutines.toLocaleString()}</strong></div>
                <div><span>GC 次数</span><strong>{process.gc_cycles.toLocaleString()}</strong></div>
              </div>
            </>
          )}
          {system.isError && <Alert className="overview-inline-alert" type="warning" showIcon title="运行状态接口加载失败" />}
        </Card>
        <Card className="surface-card overview-panel" size="small">
          <PanelHeader
            icon={<CheckCircleOutlined />}
            title="平台链路健康"
            meta={system.data?.status === 'ready' ? '整体正常' : system.data?.status === 'degraded' ? '存在异常' : undefined}
          />
          <div className="overview-health-list">
            {healthComponents.map(([name, item]) => (
              <div className="overview-health-item" key={name} title={item.error}>
                <span>{componentNames[name] ?? name}</span>
                <span className={`overview-health-state overview-health-state-${item.status ?? 'neutral'}`}>
                  {item.status ? statusNames[item.status] ?? item.status : ''}
                </span>
              </div>
            ))}
          </div>
          {system.isError && <Alert className="overview-inline-alert" type="warning" showIcon title="平台健康状态加载失败" />}
        </Card>
</div></details>
    </main>
  )
}
