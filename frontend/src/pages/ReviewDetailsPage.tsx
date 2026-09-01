import { Alert, App as AntApp, Button, Descriptions, Space, Tag, Typography } from 'antd'
import { Link, useParams, useSearchParams } from 'react-router-dom'

import { ReviewStatusTag } from '../entities/risk/ReviewStatusTag'
import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import { useCreateLabel, useProxyReview, useSession } from '../shared/api/queries'
import type { CreateLabelRequest, LabelKind, ProxyReviewCase } from '../shared/api/types'
import { can } from '../shared/auth/permissions'
import { AppErrorAlert, AppLoadingState, AppPageHeader } from '../shared/ui'

const actions: Array<{label:string; value:LabelKind}> = [
  {label:'确认代理',value:'confirmed_proxy'}, {label:'误报',value:'false_positive'},
  {label:'良性',value:'benign'}, {label:'需要更多数据',value:'needs_more_data'},
]

export function ReviewDetailsPage() {
  const { caseId = '' } = useParams()
  const [params] = useSearchParams()
  const reviewWindow = params.get('window') === '24h' ? '24h' : '7d'
  const review = useProxyReview(caseId, reviewWindow)
  const session = useSession()
  const createLabel = useCreateLabel()
  const { message } = AntApp.useApp()
  if (review.isLoading) return <AppLoadingState rows={10} />
  if (review.isError || !review.data) return <AppErrorAlert title="复核详情加载失败" message={review.error?.message} />
  const item = review.data
  const target = reviewTarget(item)
  return <main className="page">
    <AppPageHeader title="复核详情" subtitle={item.case_id} onRefresh={() => void review.refetch()} loading={review.isFetching} extra={<Link to="/review">返回列表</Link>} />
    <section className="surface detail-stack">
      <Space wrap><RiskLevelTag level={item.risk_level} /><ReviewStatusTag reason={item.review_reason} status={item.review_status} /><Tag>{item.confidence_level} 置信度</Tag><Tag>{item.risk_score} 分</Tag></Space>
      <Descriptions bordered column={{xs:1,md:2}} size="small" items={[
        {key:'ip',label:'IP',children:<Link className="mono list-cell-nowrap" to={`/ips/${encodeURIComponent(item.ip)}`}>{item.ip}</Link>},
        {key:'account',label:'账号',children:item.account_id || '未关联'},
        {key:'endpoint',label:'终端',children:item.endpoint_id ? <Link className="list-cell-nowrap" to={`/devices/${encodeURIComponent(item.endpoint_id)}`}>{item.endpoint_id}</Link> : '未关联'},
        {key:'access',label:'接入位置',children:item.access_ids.join('、') || '未关联'},
        {key:'events',label:'事件',children:`共 ${item.event_count} · TLS ${item.tls_count} · QUIC ${item.quic_count} · Alert ${item.alert_count}`},
        {key:'time',label:'时间范围',children:`${new Date(item.first_seen).toLocaleString()} — ${new Date(item.last_seen).toLocaleString()}`},
      ]} />
      <DetailValues title="目的域名 / SNI" values={item.destination_domains.map(value => `${value.value} (${value.count})`)} />
      <DetailValues title="目的 IP" values={item.destination_ips.map(value => `${value.value} (${value.count})`)} />
      <DetailValues title="JA3 / JA4" values={item.tls_fingerprints.map(value => `${value.value} (${value.count})`)} />
      <div><Typography.Title level={5}>规则命中</Typography.Title>{item.rule_matches.length === 0 ? <Alert showIcon type="info" title="没有明确代理规则，仅能作为行为线索" /> : item.rule_matches.map(rule => <div className="detail-row" key={rule.event_id}><Typography.Text strong>{rule.signature}</Typography.Text><Typography.Text type="secondary">{[rule.category,rule.action,rule.severity ? `severity ${rule.severity}`:''].filter(Boolean).join(' · ')}</Typography.Text></div>)}</div>
      <div className="list-toolbar">{actions.map(action => <Button key={action.value} disabled={!can(session.data,'labels:create') || item.evidence_ids.length === 0} loading={createLabel.isPending} onClick={() => createLabel.mutate({...target,label:action.value,reason:`翻墙监测复核：${action.label}`,evidence_ids:item.evidence_ids},{onSuccess:()=>message.success('复核标注已提交')})}>{action.label}</Button>)}</div>
    </section>
  </main>
}

function DetailValues({title,values}:{title:string;values:string[]}) { return <div><Typography.Title level={5}>{title}</Typography.Title><Typography.Paragraph className="detail-value-wrap">{values.join(' · ') || '无'}</Typography.Paragraph></div> }
function reviewTarget(item:ProxyReviewCase):Pick<CreateLabelRequest,'target_type'|'target_id'>{ if(item.account_id)return{target_type:'account',target_id:item.account_id}; if(item.endpoint_id)return{target_type:'endpoint',target_id:item.endpoint_id}; return{target_type:'ip',target_id:item.ip} }
