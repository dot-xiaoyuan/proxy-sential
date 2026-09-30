import { safeReturnTo } from '../app/navigation'
import { statusText,displayField,severityText } from '../shared/ui/status'
import { ProxyProtocolView } from '../entities/evidence/ProxyProtocolView'
import type { ProxyProtocolEvidence } from '../shared/api/types'
import { Descriptions, Typography } from 'antd'
import { Link, useParams, useSearchParams } from 'react-router-dom'

import { useAuditLog, useEvent, useIngestDiagnostic, useShadowRun } from '../shared/api/queries'
import { AppErrorAlert, AppLoadingState, AppPageHeader } from '../shared/ui'

export function EventDetailsPage() {
  const { eventId = '' } = useParams()
  const query = useEvent(eventId)
  return <RecordPage title="事件详情" back="/events" query={query} identifier={eventId} />
}

export function ShadowRunDetailsPage() {
  const { runId = '' } = useParams()
  const query = useShadowRun(runId)
  return <RecordPage title="影子运行详情" back="/shadow-runs" query={query} identifier={runId} />
}

export function AuditDetailsPage() {
  const { auditId = '' } = useParams()
  const query = useAuditLog(auditId)
  return <RecordPage title="审计详情" back="/audit" query={query} identifier={auditId} />
}

export function IngestDiagnosticDetailsPage() {
  const { diagnosticId = '' } = useParams()
  const query = useIngestDiagnostic(diagnosticId)
  return <RecordPage title="采集诊断详情" back="/settings/sources?tab=diagnostics" query={query} identifier={diagnosticId} />
}

function RecordPage({title,back,identifier,query}:{title:string;back:string;identifier:string;query:{isLoading:boolean;isError:boolean;isFetching:boolean;data?:unknown;error:Error|null;refetch:()=>unknown}}) {
  const [params]=useSearchParams();
  if (query.isLoading) return <AppLoadingState rows={10} />
  if (query.isError || !query.data) return <AppErrorAlert title={`${title}加载失败`} message={query.error?.message} />
  const proxy=(query.data as {proxy_protocol?:ProxyProtocolEvidence}).proxy_protocol
  const record=query.data as Record<string,unknown>
  const fields:Record<string,string>={created_at:'记录时间',timestamp:'发生时间',started_at:'开始时间',finished_at:'结束时间',actor:'操作者',action:'操作',target:'目标',outcome:'结果',summary:'业务说明',stage:'采集阶段',severity:'级别',sensor_id:'传感器',run_id:'运行 ID',evidence_count:'证据数',risk_count:'风险快照数',type:'类型',event_id:'事件 ID',zeek_status:'Zeek 状态',truncated:'输入截断'}
  const summary=Object.entries(record).filter(([key,value])=>fields[key]&&value!=null&&typeof value!=='object').map(([key,value])=>({key,label:fields[key],children:<Typography.Text className="detail-value-wrap">{typeof value==='boolean'?(value?'是':'否'):key==='severity'?severityText(String(value)):['outcome','zeek_status'].includes(key)?statusText(String(value)):key==='sensor_id'?displayField(String(value)):String(value)}</Typography.Text>}))
  const normalized=record.normalized as {read?:number;emitted?:number;malformed?:number}|undefined
  const subject=record.subject as {ip?:string;endpoint_id?:string}|undefined
  const flow=record.flow as {src_ip?:string;dst_ip?:string;app_protocol?:string}|undefined
  return <main className="page"><AppPageHeader title={title} subtitle={identifier} loading={query.isFetching} onRefresh={() => void query.refetch()} extra={<Link to={safeReturnTo(params.get('return_to'),back)}>返回列表</Link>} /><section className="surface detail-stack">
  {proxy&&<ProxyProtocolView evidence={proxy}/>}
  {normalized&&<Typography.Paragraph>读取 {normalized.read??0} 条 · 标准化 {normalized.emitted??0} 条 · 异常 {normalized.malformed??0} 条</Typography.Paragraph>}
  {(subject||flow)&&<Typography.Paragraph>{[subject?.ip,subject?.endpoint_id,flow?.src_ip,flow?.dst_ip,flow?.app_protocol].filter(Boolean).join(' · ')}</Typography.Paragraph>}
  <Descriptions bordered column={{xs:1,sm:2}} size="small" items={summary}/>
  <details><summary>技术详情</summary><pre className="record-json">{JSON.stringify(record,null,2)}</pre></details>
  </section></main>
}
