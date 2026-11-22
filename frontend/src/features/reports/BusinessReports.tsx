import { detailPath } from '../../app/navigation'
import { api, request } from '../../shared/api/client'
import type { components } from '../../shared/api/generated'
import type { AuditLog, EnforcementAction, Session } from '../../shared/api/types'
import { can } from '../../shared/auth/permissions'
import { StatisticsTime } from '../../shared/ui'
import { displayField } from '../../shared/ui/status'
import { sharedReason, type SharedPolicyDecision } from '../../pages/SharedPolicyRecords'
import { routerStatusLabels } from '../../pages/routerLabels'
import { ReportFacts, ReportPanel, ReportRows, ReportStatus, ReportTime } from './reportUi'
import { useReportQuery } from './useReportQuery'
import { IdentityPipeline, SharingStatus } from './RuntimeReports'

type Schemas = components['schemas']
type Items<T> = { items: T[] }
type Observation = Pick<Schemas['SharedBehaviorAssessment'], 'observation_id' | 'ip' | 'account_id' | 'status' | 'coverage_state' | 'last_seen'>

const observationStates: Record<string, string> = { candidate: '候选待核验', likely: '候选待核验', confirmed: '已确认多终端共享' }
const reportTypeLabels: Record<string, string> = { proxy_behavior: '共享与代理行为', poison_behavior: '网络欺骗事件', ai_relay_audit: 'AI 中转站审计' }

function decisionLabel(item: SharedPolicyDecision) {
  if (item.result === 'insufficient') return '证据不足'
  if (item.result === 'expired') return '已过期'
  if (item.evidence_review_status === 'insufficient_evidence') return '历史证据不足'
  if (item.evidence_review_status === 'pending_review' || item.evidence_review_status === 'unverified') return '历史命中待核验'
  return '已命中'
}

export function SharingReports({ session, returnTo }: { session: Session; returnTo: string }) {
  const enabled = can(session, 'cases:read')
  const observations = useReportQuery('sharing-observations', (signal) => request<Items<Observation>>('/shared-access/observations?view=traffic&limit=5', { signal }), enabled)
  return (
    <>
      <SharingStatus session={session} />
      {enabled && <ReportPanel title="近期镜像观测" query={observations} detail={{ to: '/shared-access', label: '查看共享发现与核验' }}>
        {({ items }) => <ReportRows rows={(items ?? []).map((item) => ({
          key: item.observation_id,
          title: item.account_id || item.ip,
          detail: [item.account_id && item.ip, item.coverage_state === 'partial' && '采集覆盖不足'].filter(Boolean).join(' · '),
          statusLabel: observationStates[item.status],
          at: item.last_seen,
          to: detailPath(`/shared-access/observations/${encodeURIComponent(item.observation_id)}`, returnTo),
        }))} />}
      </ReportPanel>}
    </>
  )
}

export function RiskReports({ session, returnTo }: { session: Session; returnTo: string }) {
  const showRisk = can(session, 'risks:read')
  const showCases = can(session, 'cases:read')
  const showPolicy = can(session, 'policies:read')
  const showActions = can(session, 'actions:read')
  const showReports = can(session, 'behavior-reports:read')
  const risk = useReportQuery('risk-overview', (signal) => request<Schemas['Overview']>('/overview?window=24h', { signal }), showRisk)
  const cases = useReportQuery('risk-cases', (signal) => request<Schemas['RiskCaseListResponse']>('/cases?limit=5', { signal }), showCases)
  const decisions = useReportQuery('policy-decisions', (signal) => request<Items<SharedPolicyDecision>>('/policy-decisions?trigger=shared_access&limit=5', { signal }), showPolicy)
  const actions = useReportQuery('action-history', (signal) => request<Items<EnforcementAction>>('/actions?limit=5&seek=1', { signal }), showActions)
  const reports = useReportQuery('behavior-outbox', (signal) => request<Schemas['BehaviorReportOutboxSeekPage']>('/behavior-reports/outbox?status=recorded&limit=5&seek=1', { signal }), showReports)
  return (
    <>
      {showRisk && <ReportPanel title="风险概况 · 近 24 小时" query={risk} detail={{ to: '/overview?window=24h', label: '查看运营工作台' }}>
        {(data) => <>
          <ReportFacts items={[
            ['极高风险对象', data.level_counts.confirmed],
            ['高风险对象', data.level_counts.high],
            ['复核线索对象', data.level_counts.suspicious],
            ['正常等级对象', data.level_counts.normal],
            ['待处理案件', data.open_case_count ?? data.pending_reviews],
            ['超时案件', data.overdue_case_count],
          ]} />
          <StatisticsTime value={data.statistics_as_of} freshness={data.data_freshness} />
        </>}
      </ReportPanel>}
      {showPolicy && <ReportPanel title="近期策略判定" query={decisions} detail={{ to: '/actions?tab=decisions&decision_result=all', label: '查看全部判定' }}>
        {({ items }) => <ReportRows rows={(items ?? []).map((item) => ({
          key: item.decision_id,
          title: item.account_id || item.ip,
          detail: [item.reasons?.[0] && sharedReason(item.reasons[0]), item.delivery_status === 'record_only' && '仅记录，未执行'].filter(Boolean).join(' · '),
          statusLabel: decisionLabel(item),
          at: item.evaluated_at,
          to: showCases && item.observation_id ? detailPath(`/shared-access/observations/${encodeURIComponent(item.observation_id)}`, returnTo) : undefined,
        }))} />}
      </ReportPanel>}
      {showCases && <ReportPanel title="近期案件" query={cases} detail={{ to: '/cases', label: '查看案件列表' }}>
        {({ items }) => <ReportRows rows={(items ?? []).map((item) => ({
          key: item.case_id,
          title: item.account_id || item.ip || item.subject_id,
          status: item.status,
          at: item.updated_at,
          to: detailPath(`/cases/${encodeURIComponent(item.case_id)}`, returnTo),
        }))} />}
      </ReportPanel>}
      {showActions && <ReportPanel title="近期处置记录" query={actions} detail={{ to: '/actions?tab=actions', label: '查看处置记录' }}>
        {({ items }) => <ReportRows rows={(items ?? []).map((item) => ({
          key: item.action_id,
          title: item.account_id || item.ip || item.subject_id,
          status: item.status,
          statusLabel: item.mode === 'record_only' && item.status === 'recorded' ? '仅记录，未执行' : undefined,
          at: item.created_at,
        }))} />}
      </ReportPanel>}
      {showReports && <ReportPanel title="仅记录上报" query={reports} detail={{ to: '/actions?tab=reports', label: '查看上报记录' }}>
        {({ items }) => <ReportRows empty="暂无仅记录上报" rows={(items ?? []).map((item) => ({
          key: item.report_id,
          title: item.account_id || item.ip || item.subject_id || reportTypeLabels[item.event_type] || item.report_id,
          detail: [reportTypeLabels[item.event_type], item.channel_id].filter(Boolean).join(' · '),
          statusLabel: '仅记录，未发送',
          at: item.created_at,
        }))} />}
      </ReportPanel>}
    </>
  )
}

const coverageLabels: Record<string, string> = {
  brand: '品牌', model: '型号', os: '操作系统', os_family: '操作系统系列', mac: 'MAC',
  device_type: '设备类型', account: '账号', account_id: '账号', hostname: '主机名',
}

export function DeviceReports({ session }: { session: Session }) {
  const enabled = can(session, 'identity:read')
  const inventory = useReportQuery('terminal-inventory', (signal) => api.deviceInventoryMetadata({ view: 'recent', window: '24h' }, signal), enabled)
  const recognition = useReportQuery('device-recognition', api.deviceRecognitionSummary, can(session, 'risks:read') && enabled)
  const routers = useReportQuery('router-observations', (signal) => request<Schemas['RouterAssessmentPage']>('/router-observations?limit=5', { signal }), enabled)
  const discovery = useReportQuery('passive-discovery', (signal) => request<Schemas['DiscoveryCoverage']>('/discovery/coverage', { signal }), enabled)
  const fingerprint = useReportQuery('fingerprint', api.deviceFingerprintLibrary, enabled)
  return (
    <>
      {enabled && <ReportPanel title="终端投影 · 近 24 小时" query={inventory} detail={{ to: '/devices?tab=terminal&window=24h', label: '查看终端列表' }}>
        {({ total, as_of, read_model_state: state }) => <>
          <ReportStatus value={state?.status} label={state?.available === false ? '投影暂不可用' : undefined} />
          <ReportFacts items={[
            ['终端列表索引', state?.available === false || state?.status === 'failed' ? undefined : total],
            ['处理延迟', state?.processing_lag_seconds === undefined ? undefined : `${state.processing_lag_seconds.toLocaleString('zh-CN')} 秒`],
            ['接纳位点', state?.accepted_watermark],
            ['处理位点', state?.processed_watermark],
          ]} />
          {state?.error && <p className="report-meta">终端投影出现异常</p>}
          <ReportTime label="投影水位" value={state?.as_of} />
          <ReportTime label="统计查询时间" value={as_of} />
        </>}
      </ReportPanel>}
      <IdentityPipeline session={session} />
      {enabled && can(session, 'risks:read') && <ReportPanel title="终端识别覆盖" query={recognition} detail={{ to: '/devices?tab=terminal', label: '查看终端识别' }}>
        {(data) => <>
          <ReportFacts items={[
            ['覆盖窗口', data.window],
            ['终端样本', data.total_endpoints],
            ['事件归属率', data.event_count > 0 ? `${(data.event_attribution_rate * 100).toFixed(1)}%` : undefined],
            ['品牌推断冲突', data.brand_inference_conflicts],
            ...Object.entries(data.coverage ?? {}).filter(([key]) => coverageLabels[key]).map(([key, value]) =>
              [`${coverageLabels[key]}覆盖`, data.total_endpoints > 0 ? `${(value.rate * 100).toFixed(1)}%` : undefined] as const),
          ]} />
          <ReportTime value={data.as_of} />
        </>}
      </ReportPanel>}
      {enabled && <ReportPanel title="近期网络设备观测" query={routers} detail={{ to: '/devices?tab=network', label: '查看路由器列表' }}>
        {({ items }) => <ReportRows rows={(items ?? []).map((item) => ({
          key: item.assessment_id,
          title: [displayField(item.brand), displayField(item.model)].filter(Boolean).join(' ') || item.ip || item.mac || item.assessment_id,
          status: item.status,
          statusLabel: routerStatusLabels[item.status],
          at: item.last_seen,
          to: detailPath(`/devices/network/${encodeURIComponent(item.assessment_id)}`, '/reports?section=devices'),
        }))} />}
      </ReportPanel>}
      {enabled && <ReportPanel title="发现采集覆盖" query={discovery} detail={{ to: '/devices?tab=discovery', label: '查看发现设备' }}>
        {({ enabled, items }) => enabled ? (
          <ReportRows rows={(items ?? []).map((item, index) => ({
            key: `${item.sensor_id}/${item.protocol}/${index}`,
            title: item.protocol,
            detail: [item.sensor_id, item.enabled && `接纳 ${item.admitted.toLocaleString('zh-CN')} 条`].filter(Boolean).join(' · '),
            statusLabel: item.enabled ? item.error ? '采集异常' : '已启用' : '已停用',
          }))} />
        ) : <p className="report-meta">发现采集未启用</p>}
      </ReportPanel>}
      {enabled && <ReportPanel title="设备指纹库" query={fingerprint} detail={{ to: '/settings/rules?tab=fingerprints', label: '查看指纹库' }}>
        {(data) => <>
          <ReportStatus value={data.status} />
          <ReportFacts items={[
            ['当前版本', data.version], ['匹配规则', data.rule_count], ['DHCP 规则', data.dhcp_rule_count],
            ['更新方式', data.offline_mode === undefined ? undefined : data.offline_mode ? '离线安装' : '在线配置'],
          ]} />
          <ReportTime label="最近更新" value={data.updated_at} />
        </>}
      </ReportPanel>}
    </>
  )
}

export function AuditReports({ session, returnTo }: { session: Session; returnTo: string }) {
  const enabled = can(session, 'audit:read')
  const audit = useReportQuery('audit-log', (signal) => request<{ logs: AuditLog[] }>('/audit-logs?limit=5&seek=1', { signal }), enabled)
  return enabled && (
    <ReportPanel title="近期操作审计" query={audit} detail={{ to: '/audit', label: '查看审计日志' }}>
      {({ logs }) => <ReportRows rows={(logs ?? []).map((item) => ({
        key: item.audit_id,
        title: item.action,
        detail: [item.actor, item.target].filter(Boolean).join(' · '),
        status: item.outcome,
        at: item.created_at,
        to: detailPath(`/audit/${encodeURIComponent(item.audit_id)}`, returnTo),
      }))} />}
    </ReportPanel>
  )
}
