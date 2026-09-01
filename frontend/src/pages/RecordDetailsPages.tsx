import { Descriptions, Typography } from 'antd'
import { Link, useParams } from 'react-router-dom'

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
  return <RecordPage title="采集诊断详情" back="/ingest" query={query} identifier={diagnosticId} />
}

function RecordPage({title,back,identifier,query}:{title:string;back:string;identifier:string;query:{isLoading:boolean;isError:boolean;isFetching:boolean;data?:unknown;error:Error|null;refetch:()=>unknown}}) {
  if (query.isLoading) return <AppLoadingState rows={10} />
  if (query.isError || !query.data) return <AppErrorAlert title={`${title}加载失败`} message={query.error?.message} />
  const entries = Object.entries(query.data as Record<string, unknown>)
  return <main className="page"><AppPageHeader title={title} subtitle={identifier} loading={query.isFetching} onRefresh={() => void query.refetch()} extra={<Link to={back}>返回列表</Link>} /><section className="surface detail-stack"><Descriptions bordered column={1} size="small" items={entries.filter(([,value]) => typeof value !== 'object').map(([key,value]) => ({key,label:key,children:<Typography.Text className="detail-value-wrap">{String(value ?? '-')}</Typography.Text>}))} />{entries.filter(([,value]) => typeof value === 'object' && value !== null).map(([key,value]) => <div key={key}><Typography.Title level={5}>{key}</Typography.Title><pre className="record-json">{JSON.stringify(value,null,2)}</pre></div>)}</section></main>
}
