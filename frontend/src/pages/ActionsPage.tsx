import { Alert, Button, Card, List, Space, Switch, Table, Tag, Typography, message } from 'antd'

import { api } from '../shared/api/client'
import { useActionConnectors, useActions, useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
import { AppErrorAlert, AppLoadingState, AppPageHeader } from '../shared/ui'

export function ActionsPage(){
  const connectors=useActionConnectors();const actions=useActions({limit:20});const session=useSession();const canManage=can(session.data,'integrations:write');
  if(connectors.isLoading||actions.isLoading)return <AppLoadingState rows={7}/>;if(connectors.isError||actions.isError||!connectors.data||!actions.data)return <AppErrorAlert title="处置网关加载失败"/>
  return <main className="page"><AppPageHeader title="旁路处置网关" subtitle="通过北向接口执行隔离、限速、踢线与解除；真实动作受硬门槛、冷却和熔断保护" onRefresh={()=>{void connectors.refetch();void actions.refetch()}}/>
    <Alert showIcon type={connectors.data.global_stop?'error':'info'} title={connectors.data.global_stop?'全局紧急停止已启用，所有真实动作均被阻断':'默认影子模式；只有高分、高置信、明确强规则和可定位身份同时满足才允许真实处置'} action={canManage?<Space><Typography.Text>紧急停止</Typography.Text><Switch checked={connectors.data.global_stop} onChange={async value=>{await api.emergencyStop(value);message.success('紧急停止状态已更新');void connectors.refetch()}}/></Space>:undefined}/>
    <section className="details-grid margin-top-md"><Card title="北向连接器"><List locale={{emptyText:'尚未配置北向接口'}} dataSource={connectors.data.items} renderItem={item=><List.Item actions={[<Tag color={item.enabled?'green':'default'} key="enabled">{item.enabled?'启用':'停用'}</Tag>]}><List.Item.Meta title={item.name} description={<span className="nowrap-cell">{item.endpoint_url} · {item.mode==='active'?'真实模式':'影子模式'} · {item.shadow_ready?'影子验收通过':'等待影子验收'}</span>}/></List.Item>}/></Card><Card title="安全门槛"><List dataSource={['风险分 ≥ 90','风险置信度 ≥ 90%','明确代理/隧道强规则','账号与终端会话可定位','无校园例外或良性结论','24 小时对象冷却','校区 5次/10分钟、全局20次/小时熔断']} renderItem={item=><List.Item>{item}</List.Item>}/></Card></section>
    <Card className="margin-top-md" title="最近动作"><Table className="compact-list-table" dataSource={actions.data.items} pagination={false} rowKey="action_id" columns={[{title:'动作',dataIndex:'action_type'},{title:'对象',dataIndex:'subject_id',render:(value:string)=><span className="nowrap-cell">{value}</span>},{title:'模式',dataIndex:'mode',render:(value:string)=><Tag>{value}</Tag>},{title:'状态',dataIndex:'status',render:(value:string)=><Tag color={value==='succeeded'?'green':value==='failed'||value==='blocked'?'red':'blue'}>{value}</Tag>},{title:'阻断原因',dataIndex:'blockers',render:(value?:string[])=><span className="ellipsis-cell" title={value?.join('、')}>{value?.join('、')||'-'}</span>},{title:'时间',dataIndex:'created_at',render:(value:string)=><span className="nowrap-cell">{new Date(value).toLocaleString()}</span>},{title:'操作',render:(_,item)=><Button disabled={!can(session.data,'actions:revoke')||item.status!=='succeeded'} onClick={async()=>{await api.revokeAction(item.action_id);message.success('撤销请求已提交');void actions.refetch()}}>撤销</Button>}]} /></Card>
  </main>
}
