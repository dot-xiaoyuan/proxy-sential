import { ReloadOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { Button, Card, Space, Statistic, Tag, Typography } from 'antd'

import { api } from '../../shared/api/client'
import { AppLoadingState } from '../../shared/ui'

const stateLabels: Record<string,string> = { starting:'启动中',healthy:'正常',degraded:'降级',switching:'切换中',switch_failed:'切换失败',failed:'异常',pending:'等待检查',stale:'快照过期',completed:'完成',running:'执行中',building:'构建中' }
const errorLabels: Record<string,string> = { online_inventory_changed:'在线清单持续变化',resource_limit:'数据量超过安全上限',deadline_exceeded:'操作超时',operation_error:'同步操作失败',ingest_error:'实时事件写入失败',malformed_json:'记录格式异常' }

function time(value?:string) { return value ? new Date(value).toLocaleString() : '' }
function stateColor(value:string) { return value === 'healthy' || value === 'completed' ? 'green' : value === 'failed' || value === 'switch_failed' ? 'red' : value === 'degraded' || value === 'stale' ? 'orange' : 'blue' }

export function IdentityBridgePanel() {
  const bridge = useQuery({queryKey:['identity-bridge'],queryFn:api.identityBridge,refetchInterval:false,refetchOnWindowFocus:false,refetchOnReconnect:false,retry:false})
  const refresh = <Button icon={<ReloadOutlined />} aria-label="刷新认证状态" title="刷新认证状态" loading={bridge.isFetching} onClick={()=>void bridge.refetch()}/>
  if (bridge.isLoading) return <AppLoadingState rows={4}/>
  if (!bridge.data) return <Card className="identity-bridge-panel" title="深澜 4K 认证同步" extra={refresh}><p className="actions-inline-error" role="alert">认证同步状态读取失败</p></Card>
  const {config,runtime}=bridge.data
  const statisticsAt = runtime.pipeline?.statistics_at??runtime.projection_at
  const queueSampled = Boolean(runtime.queue_sampled_at)
  const issues = [
    (runtime.snapshot_state==='stale'||runtime.snapshot_state==='failed')&&{text:`在线清单异常${runtime.last_error_type ? `：${errorLabels[runtime.last_error_type]??'同步失败'}` : ''}`,tone:'error'},
    bridge.isError&&{text:'刷新失败，显示上次数据',tone:'error'},
    runtime.queue_sample_stale&&{text:'队列采样过期',tone:'warning'},
    (runtime.quarantine_queue??0)>0&&{text:`隔离消息 ${runtime.quarantine_queue} 条待处理`,tone:'error'},
    runtime.pipeline?.last_error&&{text:'身份处理异常',tone:'error'},
    runtime.pipeline?.export_error&&{text:'原始事件导出异常',tone:'error'},
    runtime.pipeline?.derived_error&&{text:'设备派生处理异常',tone:'error'},
  ].filter((issue): issue is {text:string;tone:string}=>Boolean(issue))
  return <Card className="identity-bridge-panel" title={<Space wrap><span>深澜 4K 认证同步</span><Tag color={stateColor(runtime.state)}>{stateLabels[runtime.state]??runtime.state}</Tag></Space>} extra={refresh}>
    {issues.length>0&&<div className="identity-bridge-issues" role="status">{issues.map(issue=><span className={`identity-bridge-issue is-${issue.tone}`} key={issue.text}>{issue.text}</span>)}</div>}

    <div className="identity-bridge-overview">
      <section className="identity-bridge-current" aria-label="当前在线">
        <div className="identity-bridge-section-heading"><strong>当前在线</strong>{statisticsAt&&<span>统计于 {time(statisticsAt)}</span>}</div>
        <div className="identity-bridge-primary-metrics">
          <Statistic title="当前账号" value={runtime.accounts??''}/>
          <Statistic title="当前会话" value={runtime.sessions??''}/>
        </div>
      </section>
      <section className="identity-bridge-processing" aria-label="事件处理">
        <div className="identity-bridge-section-heading"><strong>事件处理</strong>{runtime.pipeline&&<span>批次 {runtime.pipeline.processed_sequence} / {runtime.pipeline.accepted_sequence}</span>}</div>
        <div className="identity-bridge-queue-metrics">
          <Statistic title="Redis 待接收" value={queueSampled?runtime.source_queue:''}/>
          <Statistic title="Redis 待确认" value={queueSampled?runtime.processing_queue:''}/>
          <Statistic title="服务端待处理" value={runtime.pipeline?.pending_records??''}/>
          <Statistic title="原始事件待导出" value={runtime.pipeline?.export_pending_records??''}/>
        </div>
      </section>
    </div>

    <div className="identity-bridge-channel-list" aria-label="通道状态">
      <div className="identity-bridge-section-heading"><strong>通道状态</strong></div>
      <details>
        <summary><span>权威在线清单</span><Tag color={stateColor(runtime.online_channel_state)}>{stateLabels[runtime.online_channel_state]??runtime.online_channel_state}</Tag></summary>
        <div className="identity-bridge-channel-detail">{runtime.active_online_redis_addr&&<Typography.Text className="identity-bridge-endpoint" copyable>{runtime.active_online_redis_addr}</Typography.Text>}<span>{config.online_list}</span></div>
      </details>
      <details>
        <summary><span>上下线通知</span><Tag color={stateColor(runtime.event_channel_state)}>{stateLabels[runtime.event_channel_state]??runtime.event_channel_state}</Tag></summary>
        <div className="identity-bridge-channel-detail"><Typography.Text className="identity-bridge-endpoint" copyable>{config.event_redis_addr}</Typography.Text><span>{config.event_list}</span></div>
      </details>
      <details>
        <summary><span>可靠处理队列</span><Tag color={runtime.processing_queue?'blue':'green'}>{queueSampled?`${runtime.processing_queue} 条`:''}</Tag></summary>
        <div className="identity-bridge-channel-detail"><Typography.Text className="identity-bridge-endpoint" copyable>{config.event_redis_addr}</Typography.Text><span>{config.processing_list}</span></div>
      </details>
    </div>

    <details className="identity-bridge-diagnostics">
      <summary>更多运行信息</summary>
      <div className="identity-bridge-facts">
        {runtime.pipeline?.oldest_pending_at&&<span>最早待处理 {time(runtime.pipeline.oldest_pending_at)}</span>}
        {runtime.pipeline&&<span>全量校准 {stateLabels[runtime.pipeline.calibration_state]??runtime.pipeline.calibration_state}</span>}
        {runtime.queue_sampled_at&&<span>队列采样 {time(runtime.queue_sampled_at)}</span>}
        {runtime.pipeline?.derived_cursor_at&&<span>设备派生已推进至 {time(runtime.pipeline.derived_cursor_at)}</span>}
        <span>全量校准间隔 {Math.round(config.reconcile_interval_seconds/60)} 分钟</span>
        {runtime.last_event_at&&<span>最近事件 {time(runtime.last_event_at)}</span>}
        {runtime.last_snapshot_at&&<span>最近全量 {time(runtime.last_snapshot_at)}</span>}
      </div>
    </details>
  </Card>
}
