import { lazy, Suspense } from 'react'
import { Select } from 'antd'

import { request } from '../../shared/api/client'
import type { components } from '../../shared/api/generated'
import type { Session } from '../../shared/api/types'
import { can } from '../../shared/auth/permissions'
import { AppLoadingState, StatisticsTime, type ReportWindow } from '../../shared/ui'
import { displayField } from '../../shared/ui/status'
import { useUrlState } from '../../shared/ui/useUrlState'
import { ReportFacts, ReportPanel, ReportRows, ReportTime } from './reportUi'
import { useReportQuery } from './useReportQuery'

type Schemas = components['schemas']

const EChartsDualAxisTrend = lazy(() => import('../charts/EChartsDualAxisTrend').then((module) => ({ default: module.EChartsDualAxisTrend })))

const dimensions = [
  { value: 'domain', label: '域名' },
  { value: 'application', label: '应用协议' },
  { value: 'protocol', label: '传输协议' },
  { value: 'ecosystem', label: '生态' },
  { value: 'http_host', label: 'HTTP Host' },
  { value: 'tls_sni', label: 'TLS SNI' },
  { value: 'quic_sni', label: 'QUIC SNI' },
  { value: 'dst_port', label: '目的端口' },
  { value: 'src_ip', label: '来源 IP' },
  { value: 'dst_ip', label: '目的 IP' },
  { value: 'user_agent', label: 'User-Agent' },
]

export function TrafficReports({ session, window }: { session: Session; window: ReportWindow }) {
  const [dimension, setDimension] = useUrlState('dimension', 'domain', dimensions.map((item) => item.value))
  const showDpi = can(session, 'dpi:read')
  const showAi = can(session, 'events:read')
  const showTargets = can(session, 'destination-targets:read')
  const scope = `window=${window}`
  const overview = useReportQuery(`activity-${scope}`, (signal) => request<Schemas['ActivityOverview']>(`/activity/overview?${scope}`, { signal }), showDpi)
  const trends = useReportQuery(`dpi-trend-${scope}`, (signal) => request<{ points: Schemas['DpiTrendPoint'][] }>(`/dpi/trends?${scope}`, { signal }), showDpi)
  const rankings = useReportQuery(`activity-rank-${scope}-${dimension}`, (signal) => request<Schemas['ActivityReport']>(`/activity/reports?${scope}&dimension=${dimension}&limit=10`, { signal }), showDpi)
  const applications = useReportQuery(`applications-${scope}`, (signal) => request<Schemas['ApplicationReport']>(`/application-activity?${scope}`, { signal }), showDpi)
  const ai = useReportQuery('ai-relay-recent', (signal) => request<Schemas['AIRelayUsagePage']>('/ai-relay/usages?limit=5', { signal }), showAi)
  const targets = useReportQuery('target-findings-recent', (signal) => request<Schemas['DestinationTargetFindingPage']>('/destination-targets/findings?limit=5', { signal }), showTargets)
  return (
    <>
      {showDpi && <ReportPanel title="流量概况" query={overview} detail={{ to: `/activity?section=access&${scope}`, label: '查看访问分析' }}>
        {(data) => <>
          <ReportFacts items={[
            ['标准事件', data.event_count], ['活跃 IP', data.active_ip_count],
            ['访问目标', data.access_object_count], ['活跃风险 IP', data.active_risk_ip_count],
          ]} />
          <StatisticsTime value={data.statistics_as_of} freshness={data.data_freshness} />
        </>}
      </ReportPanel>}
      {showDpi && <ReportPanel title="访问排行" query={rankings} extra={
        <Select aria-label="访问排行维度" className="report-select" value={dimension} options={dimensions} onChange={setDimension} />
      }>
        {({ total, classified_count, items }) => <>
          <ReportFacts items={[[ '事件总数', total ], [ '可归类事件', classified_count ]]} />
          <ReportRows empty="当前窗口暂无排行数据" rows={(items ?? []).map((item) => ({
            key: item.key,
            title: displayField(item.label) || '空值分组',
            detail: `${item.count.toLocaleString('zh-CN')} 条 · ${(item.share * 100).toFixed(1)}%`,
            at: item.last_seen,
          }))} />
        </>}
      </ReportPanel>}
      {showDpi && <ReportPanel title="DPI 趋势" query={trends}>
        {({ points }) => points?.length ? (
          <>
            <Suspense fallback={<AppLoadingState rows={2} />}>
              <EChartsDualAxisTrend title="活跃 IP 与吞吐" points={points} />
            </Suspense>
            {points.some((point) => point.estimated) && <p className="report-meta">部分时点含估算值</p>}
          </>
        ) : <p className="report-meta">当前窗口暂无趋势样本</p>}
      </ReportPanel>}
      {showDpi && <ReportPanel title="应用访问" query={applications} disabledCode="applications_disabled" detail={{ to: `/activity?section=applications&${scope}`, label: '查看应用访问' }}>
        {({ items, observation_count, dns_observations, statistics_as_of, as_of }) => <>
          <ReportFacts items={[[ '应用观测', observation_count ], [ 'DNS 观测', dns_observations ]]} />
          <ReportRows empty="当前窗口暂无应用访问记录" rows={(items ?? []).slice(0, 5).flatMap((item) => item.application_id ? [{
            key: item.application_id,
            title: displayField(item.name) || item.application_id,
            detail: [
              item.connection_count === undefined ? undefined : `${item.connection_count.toLocaleString('zh-CN')} 条连接`,
              item.terminal_count === undefined ? undefined : `${item.terminal_count.toLocaleString('zh-CN')} 台终端`,
            ].filter(Boolean).join(' · '),
            at: item.last_seen,
          }] : [])} />
          <ReportTime value={statistics_as_of ?? as_of} />
        </>}
      </ReportPanel>}
      {showAi && <ReportPanel title="近期 AI 中转站观测" query={ai} detail={{ to: '/ai-relay', label: '查看 AI 中转站' }}>
        {({ items }) => <ReportRows rows={(items ?? []).map((item) => ({
          key: `${item.ip}/${item.first_seen}`,
          title: item.account_id || item.ip,
          detail: (item.domains ?? []).slice(0, 3).join(' · '),
          at: item.last_seen,
        }))} />}
      </ReportPanel>}
      {showTargets && <ReportPanel title="近期内网目标访问" query={targets} detail={{ to: '/policies/destination-targets', label: '查看目标访问记录' }}>
        {({ items }) => <ReportRows rows={(items ?? []).map((item) => ({
          key: item.finding_id,
          title: item.account_id || item.subject_ip,
          detail: [item.rule_name, `${item.hit_count.toLocaleString('zh-CN')} 次命中`].filter(Boolean).join(' · '),
          at: item.last_seen,
        }))} />}
      </ReportPanel>}
    </>
  )
}
