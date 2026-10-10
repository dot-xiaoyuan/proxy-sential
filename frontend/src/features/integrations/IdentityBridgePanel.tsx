import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Card, Space, Statistic, Tag, Typography } from 'antd'

import { api } from '../../shared/api/client'
import { AppErrorAlert, AppLoadingState } from '../../shared/ui'

const stateLabels: Record<string,string> = { starting:'启动中',healthy:'正常',degraded:'降级',switching:'切换中',switch_failed:'切换失败',failed:'异常',pending:'等待检查',stale:'快照过期',completed:'完成',running:'执行中' }
const errorLabels: Record<string,string> = { online_inventory_changed:'在线清单持续变化',resource_limit:'数据量超过安全上限',deadline_exceeded:'操作超时',operation_error:'同步操作失败',ingest_error:'实时事件写入失败',malformed_json:'记录格式异常' }

function time(value?:string) { return value ? new Date(value).toLocaleString() : '' }
function stateColor(value:string) { return value === 'healthy' || value === 'completed' ? 'green' : value === 'failed' || value === 'switch_failed' ? 'red' : value === 'degraded' || value === 'stale' ? 'orange' : 'blue' }

export function IdentityBridgePanel() {
  const bridge = useQuery({queryKey:['identity-bridge'],queryFn:api.identityBridge,refetchInterval:5000})
  if (bridge.isLoading) return <AppLoadingState rows={4}/>
  if (bridge.isError || !bridge.data) return <AppErrorAlert title="4K认证同步状态读取失败"/>
  const {config,runtime}=bridge.data
  return <Card className="identity-bridge-panel" title={<Space wrap><span>深澜 4K 认证同步</span><Tag color={stateColor(runtime.state)}>{stateLabels[runtime.state]??runtime.state}</Tag></Space>} extra={<Button onClick={()=>void bridge.refetch()}>刷新状态</Button>}>
    {runtime.snapshot_state==='stale'||runtime.snapshot_state==='failed'?<Alert className="identity-bridge-alert" type="error" showIcon title="全量在线清单同步异常" description={runtime.last_error_type?errorLabels[runtime.last_error_type]??'请检查认证同步服务':'当前在线会话口径不可作为权威依据'}/>:null}
    <div className="identity-bridge-metrics">
      <Statistic title="在线清单" value={runtime.online_members}/>
      <Statistic title="有效会话" value={runtime.online_sessions}/>
      <Statistic title="认证账号" value={runtime.accounts}/>
      <Statistic title="队列积压" value={runtime.source_queue+runtime.processing_queue}/>
    </div>
    <div className="identity-bridge-channels">
      <article><div className="identity-bridge-channel-heading"><strong>权威在线清单</strong><Tag color={stateColor(runtime.online_channel_state)}>{stateLabels[runtime.online_channel_state]??runtime.online_channel_state}</Tag></div>{runtime.active_online_redis_addr&&<Typography.Text className="identity-bridge-endpoint" copyable>{runtime.active_online_redis_addr}</Typography.Text>}<span>{config.online_list}</span><small>读取4K在线账号、认证IP、MAC与接入信息</small></article>
      <article><div className="identity-bridge-channel-heading"><strong>上下线通知</strong><Tag color={stateColor(runtime.event_channel_state)}>{stateLabels[runtime.event_channel_state]??runtime.event_channel_state}</Tag></div><Typography.Text className="identity-bridge-endpoint" copyable>{config.event_redis_addr}</Typography.Text><span>{config.event_list}</span><small>事件通道未验收前会阻断真实动作</small></article>
      <article><div className="identity-bridge-channel-heading"><strong>可靠处理队列</strong><Tag color={runtime.processing_queue?'blue':'green'}>{runtime.processing_queue} 条</Tag></div><Typography.Text className="identity-bridge-endpoint" copyable>{config.event_redis_addr}</Typography.Text><span>{config.processing_list}</span><small>服务端确认写入后删除，异常退出后继续处理</small></article>
    </div>
    <div className="identity-bridge-facts">
      <span>全量校准 {Math.round(config.reconcile_interval_seconds/60)} 分钟</span>
      {runtime.last_event_at&&<span>最近事件 {time(runtime.last_event_at)}</span>}{runtime.last_snapshot_at&&<span>最近全量 {time(runtime.last_snapshot_at)}</span>}{runtime.projection_at&&<span>身份投影 {time(runtime.projection_at)}</span>}
    </div>
  </Card>
}
