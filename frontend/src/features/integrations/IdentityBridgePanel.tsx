import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Card, Form, Input, Modal, Select, Space, Statistic, Table, Tag, Typography } from 'antd'

import { api } from '../../shared/api/client'
import { useSession } from '../../shared/api/queries'
import type { IdentityBridgeRun } from '../../shared/api/types'
import { can } from '../../shared/auth/permissions'
import { AppErrorAlert, AppLoadingState, AppServerPagination } from '../../shared/ui'

const stateLabels: Record<string,string> = { starting:'启动中',healthy:'正常',degraded:'降级',switching:'切换中',switch_failed:'切换失败',failed:'异常',pending:'等待检查',stale:'快照过期',completed:'完成',running:'执行中' }
const kindLabels: Record<string,string> = { event_batch:'实时事件',snapshot:'全量校准',config_switch:'配置切换' }
const errorLabels: Record<string,string> = { online_inventory_changed:'在线清单持续变化',resource_limit:'数据量超过安全上限',deadline_exceeded:'操作超时',operation_error:'同步操作失败',ingest_error:'实时事件写入失败',malformed_json:'记录格式异常' }

function time(value?:string) { return value ? new Date(value).toLocaleString() : '' }
function duration(value:number) { return value > 0 ? `${(value/1000).toFixed(value < 10000 ? 1 : 0)} 秒` : '' }
function count(value:number) { return value.toLocaleString() }
function stateColor(value:string) { return value === 'healthy' || value === 'completed' ? 'green' : value === 'failed' || value === 'switch_failed' ? 'red' : value === 'degraded' || value === 'stale' ? 'orange' : 'blue' }

export function IdentityBridgePanel() {
  const session = useSession()
  const canManage = can(session.data,'integrations:write')
  const [editing,setEditing] = useState(false)
  const [saving,setSaving] = useState(false)
  const [saveError,setSaveError] = useState('')
  const [form] = Form.useForm<{host:string}>()
  const [page,setPage] = useState(1)
  const [pageSize,setPageSize] = useState(20)
  const [kind,setKind] = useState('')
  const [status,setStatus] = useState('')
  const bridge = useQuery({queryKey:['identity-bridge'],queryFn:api.identityBridge,refetchInterval:5000})
  const runs = useQuery({queryKey:['identity-bridge-runs',page,pageSize,kind,status],queryFn:()=>api.identityBridgeRuns({kind:kind||undefined,status:status||undefined,limit:pageSize,cursor:String((page-1)*pageSize)}),refetchInterval:10000})
  if (bridge.isLoading) return <AppLoadingState rows={4}/>
  if (bridge.isError || !bridge.data) return <AppErrorAlert title="南昌4K认证同步状态读取失败"/>
  const {config,runtime}=bridge.data
  const configPending = runtime.active_config_version !== config.config_version || runtime.active_host !== config.host
  const columns = [
    {title:'类型',dataIndex:'kind',key:'kind',width:110,render:(value:string)=><Tag>{kindLabels[value]??value}</Tag>},
    {title:'状态',dataIndex:'status',key:'status',width:95,render:(value:string)=><Tag color={stateColor(value)}>{stateLabels[value]??value}</Tag>},
    {title:'数据量',key:'counts',render:(_:unknown,item:IdentityBridgeRun)=><span>{count(item.records_read)} 读取 · {count(item.records_emitted)} 写入{item.records_skipped?` · ${count(item.records_skipped)} 跳过`:''}{item.records_malformed?` · ${count(item.records_malformed)} 异常`:''}{item.retry_count?` · ${count(item.retry_count)} 次重试`:''}</span>},
    {title:'耗时',dataIndex:'duration_ms',key:'duration',width:100,render:(value:number)=>duration(value)},
    {title:'时间',dataIndex:'started_at',key:'started',width:175,render:(value:string)=>time(value)},
    {title:'结果',dataIndex:'error_type',key:'error',width:150,render:(value?:string)=>value ? errorLabels[value]??'同步失败' : ''},
  ]
  const save = async () => {
    const value=await form.validateFields();setSaving(true);setSaveError('')
    try { await api.updateIdentityBridge(value.host);setEditing(false);await bridge.refetch() }
    catch(reason){setSaveError(reason instanceof Error?reason.message:'4K地址保存失败')}
    finally{setSaving(false)}
  }
  return <Card className="identity-bridge-panel" title={<Space wrap><span>南昌 4K 认证同步</span><Tag color={stateColor(runtime.state)}>{stateLabels[runtime.state]??runtime.state}</Tag></Space>} extra={<Space wrap><Button onClick={()=>{void bridge.refetch();void runs.refetch()}}>刷新</Button>{canManage&&<Button type="primary" onClick={()=>{form.setFieldsValue({host:config.host});setSaveError('');setEditing(true)}}>修改4K地址</Button>}</Space>}>
    {configPending&&<Alert className="identity-bridge-alert" type={runtime.state==='switch_failed'?'error':'info'} showIcon title={runtime.state==='switch_failed'?'新地址切换失败，当前链路继续运行':'新地址正在校验'} description={`配置地址 ${config.host}${runtime.active_host?`，当前生效 ${runtime.active_host}`:''}`}/>}
    {runtime.snapshot_state==='stale'||runtime.snapshot_state==='failed'?<Alert className="identity-bridge-alert" type="error" showIcon title="全量在线清单同步异常" description={runtime.last_error_type?errorLabels[runtime.last_error_type]??'请检查全量校准记录':'实时事件仍可进入，但当前在线会话口径不可作为权威依据'}/>:null}
    <div className="identity-bridge-metrics">
      <Statistic title="在线清单" value={runtime.online_members}/>
      <Statistic title="有效会话" value={runtime.online_sessions}/>
      <Statistic title="认证账号" value={runtime.accounts}/>
      <Statistic title="队列积压" value={runtime.source_queue+runtime.processing_queue}/>
    </div>
    <div className="identity-bridge-channels">
      <article><div className="identity-bridge-channel-heading"><strong>权威在线清单</strong><Tag color={stateColor(runtime.online_channel_state)}>{stateLabels[runtime.online_channel_state]??runtime.online_channel_state}</Tag></div><Typography.Text className="identity-bridge-endpoint" copyable>{runtime.active_online_redis_addr||config.online_redis_addr}</Typography.Text><span>{config.online_list}</span><small>当前生效通道，读取4K在线账号、认证IP、MAC与接入信息</small></article>
      <article><div className="identity-bridge-channel-heading"><strong>上下线通知</strong><Tag color={stateColor(runtime.event_channel_state)}>{stateLabels[runtime.event_channel_state]??runtime.event_channel_state}</Tag></div><Typography.Text className="identity-bridge-endpoint" copyable>{config.event_redis_addr}</Typography.Text><span>{config.event_list}</span><small>按FIFO接收认证上线与下线事件</small></article>
      <article><div className="identity-bridge-channel-heading"><strong>可靠处理队列</strong><Tag color={runtime.processing_queue?'blue':'green'}>{runtime.processing_queue} 条</Tag></div><Typography.Text className="identity-bridge-endpoint" copyable>{config.event_redis_addr}</Typography.Text><span>{config.processing_list}</span><small>服务端确认写入后删除，异常退出后继续处理</small></article>
    </div>
    <div className="identity-bridge-facts">
      <span>来源 {config.source}</span><span>采集器 {config.sensor_id}</span><span>范围 {config.campus_id} / {config.access_domain}</span><span>每批 {config.batch_size} 条</span><span>全量校准 {Math.round(config.reconcile_interval_seconds/60)} 分钟</span>
      {runtime.last_event_at&&<span>最近事件 {time(runtime.last_event_at)}</span>}{runtime.last_snapshot_at&&<span>最近全量 {time(runtime.last_snapshot_at)}</span>}{runtime.projection_at&&<span>身份投影 {time(runtime.projection_at)}</span>}
    </div>
    <div className="identity-bridge-runs-heading"><strong>同步记录</strong><Space wrap><Select aria-label="同步类型" value={kind} onChange={value=>{setKind(value);setPage(1)}} options={[{value:'',label:'全部类型'},{value:'event_batch',label:'实时事件'},{value:'snapshot',label:'全量校准'},{value:'config_switch',label:'配置切换'}]}/><Select aria-label="同步状态" value={status} onChange={value=>{setStatus(value);setPage(1)}} options={[{value:'',label:'全部状态'},{value:'completed',label:'完成'},{value:'running',label:'执行中'},{value:'failed',label:'失败'}]}/></Space></div>
    {runs.isError?<AppErrorAlert title="同步记录读取失败"/>:runs.isLoading?<AppLoadingState rows={3}/>:<>
      <div className="identity-bridge-run-table"><Table rowKey="run_id" size="small" columns={columns} dataSource={runs.data?.items??[]} pagination={false}/></div>
      <div className="identity-bridge-run-mobile" role="list">{runs.data?.items.map(item=><article key={item.run_id} role="listitem"><div><Tag>{kindLabels[item.kind]??item.kind}</Tag><Tag color={stateColor(item.status)}>{stateLabels[item.status]??item.status}</Tag></div><strong>{count(item.records_read)} 读取 · {count(item.records_emitted)} 写入{item.records_skipped?` · ${count(item.records_skipped)} 跳过`:''}{item.records_malformed?` · ${count(item.records_malformed)} 异常`:''}{item.retry_count?` · ${count(item.retry_count)} 次重试`:''}</strong><span>{time(item.started_at)}{duration(item.duration_ms)?` · ${duration(item.duration_ms)}`:''}</span>{item.error_type&&<span className="identity-bridge-run-error">{errorLabels[item.error_type]??'同步失败'}</span>}</article>)}</div>
      <AppServerPagination disabled={runs.isFetching} page={page} pageSize={pageSize} total={runs.data?.page.total??0} onChange={(next,nextSize)=>{setPage(nextSize===pageSize?next:1);setPageSize(nextSize)}}/>
    </>}
    <Modal title="修改4K地址" open={editing} confirmLoading={saving} onCancel={()=>setEditing(false)} onOk={()=>void save()} okText="保存并平滑切换" destroyOnHidden>
      {saveError&&<Alert className="identity-bridge-alert" type="error" showIcon title={saveError}/>}<Form form={form} layout="vertical"><Form.Item name="host" label="4K 地址" extra="保存后先校验新地址并提交完整在线快照，成功后才切换当前来源。" rules={[{required:true,message:'请输入4K地址'},{pattern:/^[a-zA-Z0-9.:[\]-]+$/,message:'请输入有效的IP或主机名'}]}><Input placeholder="例如 222.204.3.224"/></Form.Item></Form>
    </Modal>
  </Card>
}
