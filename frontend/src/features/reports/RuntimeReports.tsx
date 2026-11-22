import { api, request } from '../../shared/api/client'
import type { Session, StreamRiskCutoverResponse } from '../../shared/api/types'
import { can } from '../../shared/auth/permissions'
import { formatBytes } from '../../shared/ui/formatBytes'
import { displayField } from '../../shared/ui/status'
import { ReportFacts, ReportPanel, ReportRows, ReportStatus, ReportTime } from './reportUi'
import { useReportQuery } from './useReportQuery'

type SharedSource = {
  source?: string
  sensor_id?: string
  campus_id?: string
  access_domain?: string
  state?: string
  covered_to?: string | null
}

type SharedProgress = {
  source: string
  state?: string
  blocker?: string
  reported_at?: string
  pending_segments?: number
  pending_bytes?: number
  oldest_pending_at?: string
  last_accepted_at?: string
  last_archived_input_at?: string
  last_shared_confirmed_at?: string
  failed_stage?: string
}

type SharedStatus = {
  checked_at?: string
  collection?: { state?: string; sources?: SharedSource[] }
  materialization?: {
    configured?: boolean
    state?: string
    blocker?: string
    pending?: number
    failed?: number
    completed_at?: string | null
    oldest_pending_at?: string | null
    source_progress?: SharedProgress[]
  }
  policy?: { matched?: number; insufficient?: number; expired?: number; coverage_partial?: number }
  attribution?: { insufficient?: number }
}

const sources: Record<string, string> = {
  'packet-sidecar': '报文采集',
  'handshake-sidecar': '握手采集',
  'flow-syn-sidecar': 'TCP SYN 采集',
  zeek: 'Zeek',
}

const sourceBlockers: Record<string, string> = {
  shared_source_binding_mismatch: '采集文件与共享来源的代际不一致',
  stream_progress_stale: '来源进度上报过期',
  shared_source_backlog: '最老待办超过证据新鲜窗口',
  shared_evidence_expired: '共享证据已过期',
  shared_collection_no_data: '等待新采集数据',
  shared_processing_failed: '判定任务处理失败',
  materialization_freshness_not_verified: '判定进度尚未核验',
}

function useSharedStatus(enabled: boolean) {
  return useReportQuery('shared-status', (signal) => request<SharedStatus>('/shared-access/status', { signal }), enabled)
}

export function SharingStatus({ session }: { session: Session }) {
  const query = useSharedStatus(can(session, 'identity:read'))
  return can(session, 'identity:read') && (
    <>
      <ReportPanel title="共享判定结果" query={query} detail={can(session, 'policies:read') ? { to: '/actions?tab=decisions', label: '查看判定记录' } : undefined}>
        {({ policy, materialization, attribution, checked_at }) => (
          <>
            <ReportStatus value={materialization?.state} label={materialization?.state === 'healthy' ? '判定处理正常' : undefined} />
            {!Number.isFinite(policy?.matched) && <p className="report-meta">暂无判定统计</p>}
            <ReportFacts items={[
              ['当前代际有效命中', policy?.matched],
              ['证据不足任务', policy?.insufficient],
              ['过期任务', policy?.expired],
              ['采集覆盖不足任务', policy?.coverage_partial],
              ['身份归因不足任务', attribution?.insufficient],
              ['判定待处理', materialization?.pending],
            ]} />
            <ReportTime label="最近完成" value={materialization?.completed_at} />
            <ReportTime value={checked_at} />
          </>
        )}
      </ReportPanel>
      <ReportPanel title="共享证据覆盖" query={query}>
        {({ collection, checked_at }) => (
          <>
            <ReportStatus value={collection?.state} label={collection?.state === 'healthy' ? '覆盖正常' : undefined} />
            <ReportRows empty="暂无采集覆盖记录" rows={(collection?.sources ?? []).map((item, index) => ({
              key: `${item.source}/${item.sensor_id}/${item.campus_id}/${item.access_domain}/${index}`,
              title: sources[item.source ?? ''] ?? item.source ?? item.sensor_id ?? '采集来源',
              detail: [item.sensor_id, item.campus_id, item.access_domain].filter(Boolean).join(' · '),
              status: item.state,
              statusLabel: item.state === 'healthy' ? '覆盖完整' : undefined,
              at: item.covered_to,
            }))} />
            <ReportTime label="检查时间" value={checked_at} />
          </>
        )}
      </ReportPanel>
    </>
  )
}

export function IdentityPipeline({ session }: { session: Session }) {
  const enabled = can(session, 'actions:read')
  const query = useReportQuery('identity-bridge', api.identityBridge, enabled)
  return enabled && (
    <ReportPanel title="NCU 认证链路" query={query} detail={{ to: '/settings/actions', label: '查看认证接入' }}>
      {({ runtime, checked_at }) => (
        <>
          <ReportStatus value={runtime.state} />
          <ReportFacts items={[
            ['当前在线账号', runtime.accounts],
            ['当前会话', runtime.sessions],
            ['实时接纳待处理', runtime.pipeline?.pending_records],
            ['原始事件待归档', runtime.pipeline?.export_pending_records],
            ['Redis 待接收', runtime.queue_sampled_at && !runtime.queue_sample_stale ? runtime.source_queue : undefined],
            ['Redis 待确认', runtime.queue_sampled_at && !runtime.queue_sample_stale ? runtime.processing_queue : undefined],
          ]} />
          {runtime.queue_sample_stale && <p className="report-meta">Redis 队列采样已过期</p>}
          {runtime.pipeline?.last_error && <p className="report-meta">身份处理出现异常</p>}
          {runtime.pipeline?.export_error && <p className="report-meta">原文归档出现异常</p>}
          <ReportTime label="最老待处理" value={runtime.pipeline?.oldest_pending_at} />
          <ReportTime label="派生水位" value={runtime.pipeline?.derived_cursor_at} />
          <ReportTime label="队列采样" value={runtime.queue_sampled_at} />
          <ReportTime label="检查时间" value={checked_at} />
        </>
      )}
    </ReportPanel>
  )
}

export function PipelineReports({ session }: { session: Session }) {
  const showShared = can(session, 'identity:read')
  const showIngest = can(session, 'ingest:read')
  const showRisk = can(session, 'risks:read')
  const shared = useSharedStatus(showShared)
  const ingest = useReportQuery('ingest', api.ingestStatus, showIngest)
  const risk = useReportQuery('risk-pending', (signal) => request<StreamRiskCutoverResponse>('/risks/stream-cutover', { signal }), showRisk)
  const system = useReportQuery('system', api.systemStatus, showRisk)
  return (
    <>
      {showShared && <ReportPanel title="共享来源处理进度" query={shared} detail={can(session, 'cases:read') ? { to: '/shared-access', label: '查看共享发现' } : undefined}>
        {({ materialization, checked_at }) => (
          <>
            <ReportStatus value={materialization?.state} />
            {materialization?.blocker && <p className="report-meta">{sourceBlockers[materialization.blocker] ?? displayField(materialization.blocker)}</p>}
            <ReportFacts items={[['判定待处理', materialization?.pending], ['判定失败', materialization?.failed]]} />
            <ReportTime label="最老判定待办" value={materialization?.oldest_pending_at} />
            {materialization?.source_progress?.length ? <div className="report-source-list">
              {materialization.source_progress.map((source) => (
                <details key={source.source}>
                  <summary>
                    <span>{sources[source.source] ?? source.source}</span>
                    <ReportStatus value={source.state} />
                    {source.reported_at && source.pending_segments !== undefined && <span className="report-meta">待处理 {source.pending_segments.toLocaleString('zh-CN')} 段</span>}
                  </summary>
                  {source.blocker && <p className="report-meta">{sourceBlockers[source.blocker] ?? displayField(source.blocker)}</p>}
                  <ReportFacts items={[
                    ['待处理字节', source.reported_at && source.pending_bytes !== undefined ? formatBytes(source.pending_bytes) : undefined],
                    ['失败阶段', source.failed_stage],
                  ]} />
                  <ReportTime label="最近接纳" value={source.last_accepted_at} />
                  <ReportTime label="已归档输入至" value={source.last_archived_input_at} />
                  <ReportTime label="最近共享收据" value={source.last_shared_confirmed_at} />
                  <ReportTime label="最老待处理" value={source.oldest_pending_at} />
                  <ReportTime label="进度上报" value={source.reported_at} />
                </details>
              ))}
            </div> : <p className="report-meta">暂无逐来源处理进度</p>}
            <ReportTime label="检查时间" value={checked_at} />
          </>
        )}
      </ReportPanel>}
      {showRisk && <ReportPanel title="实时风险任务" query={risk}>
        {({ active, status }) => active && status ? (
          <>
            <ReportFacts items={[
              ['实时待处理对象', status.pending_subjects],
              ['等待超过 5 秒', status.pending_older_than_5s],
              ['本切点取消的历史对象', status.canceled_subjects],
            ]} />
            <ReportTime label="最老实时待办" value={status.oldest_pending_at} />
            <ReportTime label="固定接收起点" value={status.accepted_after} />
          </>
        ) : <p className="report-meta">暂无实时风险队列统计</p>}
      </ReportPanel>}
      {showIngest && <ReportPanel title="采集与入库" query={ingest} detail={{ to: '/settings/sources?tab=diagnostics', label: '查看入库诊断' }}>
        {(data) => (
          <>
            <ReportStatus value={data.healthy ? 'healthy' : 'degraded'} />
            {displayField(data.summary) && <p className="report-meta">{data.summary}</p>}
            <ReportFacts items={[
              ['批次读取', data.last_counters?.read], ['标准事件产出', data.last_counters?.emitted],
              ['跳过记录', data.last_counters?.skipped], ['格式异常', data.last_counters?.malformed],
            ]} />
            {Object.keys(data.last_event_type_dist ?? {}).length > 0 && <details className="report-source-detail">
              <summary>最近批次事件类型分布</summary>
              <ReportFacts items={Object.entries(data.last_event_type_dist).sort((a, b) => b[1] - a[1])} />
            </details>}
            <ReportTime label="最近批次" value={data.latest_run_at} />
          </>
        )}
      </ReportPanel>}
      <IdentityPipeline session={session} />
      {showRisk && <ReportPanel title="采集信号新鲜度" query={system}>
        {({ components, checked_at }) => (
          <>
            <ReportRows empty="暂无信号新鲜度采样" rows={(components?.signals?.signals ?? []).map((signal) => ({
              key: signal.signal,
              title: signal.signal,
              detail: signal.age_seconds === undefined ? undefined : `距采样 ${signal.age_seconds} 秒 · 阈值 ${signal.max_age_seconds} 秒`,
              status: signal.status,
              statusLabel: signal.status === 'missing' ? '等待信号' : undefined,
              at: signal.last_seen,
            }))} />
            <ReportTime label="检查时间" value={checked_at} />
          </>
        )}
      </ReportPanel>}
    </>
  )
}

const componentLabels: Record<string, string> = {
  storage: '存储连接', authentication: '登录认证', authentication_oidc: '统一认证',
  collector: '采集服务', identity_ingest: '身份接收', inventory_projection: '终端投影',
  statistics_read_model: '统计投影', application_read_model: '应用投影',
  operations: '运营数据', signals: '信号到达', fingerprint_library: '指纹库',
}

export function ResourceReports({ session }: { session: Session }) {
  const enabled = can(session, 'risks:read')
  const system = useReportQuery('system', api.systemStatus, enabled)
  const rules = useReportQuery('rules-status', (signal) => request<{ reload_status?: string }>('/rules/status', { signal }), enabled)
  return enabled && (
    <>
      <ReportPanel title="主机与进程资源" query={system}>
        {({ runtime }) => {
          const host = runtime?.host
          const disk = host?.root_filesystem
          const process = runtime?.process
          if (!runtime) return <p className="report-meta">暂无资源采样</p>
          return <>
            <ReportFacts items={[
              ['可用根盘', disk ? formatBytes(disk.available_bytes) : undefined],
              ['根盘使用率', disk ? `${disk.used_percent.toFixed(1)}%` : undefined],
              ['1 分钟负载', host?.load_1],
              ['CPU 逻辑核数', host?.logical_cpus],
              ['物理内存使用率', host?.memory_used_percent === undefined ? undefined : `${host.memory_used_percent.toFixed(1)}%`],
              ['控制面进程 CPU', process ? `${process.cpu_percent.toFixed(1)}%` : undefined],
              ['控制面常驻内存', process?.resident_memory_bytes === undefined ? undefined : formatBytes(process.resident_memory_bytes)],
            ]} />
            {host?.root_filesystem_error && <p className="report-meta">根盘采样失败</p>}
            <ReportTime label="资源采样" value={runtime.sampled_at} />
          </>
        }}
      </ReportPanel>
      <ReportPanel title="组件健康" query={system}>
        {({ components, checked_at }) => (
          <>
            <ReportRows rows={Object.entries(components ?? {}).map(([key, item]) => ({
              key,
              title: componentLabels[key] ?? key,
              detail: displayField(item.error),
              status: item.status,
              at: item.updated_at,
            }))} />
            <ReportTime label="检查时间" value={checked_at} />
          </>
        )}
      </ReportPanel>
      <ReportPanel title="规则加载" query={rules} detail={{ to: '/settings/rules', label: '查看规则与特征库' }}>
        {({ reload_status }) => <ReportFacts items={[[ '在线重载', reload_status === 'disabled' ? '已关闭' : reload_status ]]} />}
      </ReportPanel>
    </>
  )
}
