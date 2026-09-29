import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Empty, Spin, Tag } from 'antd'
import { api } from '../../shared/api/client'

const deliveries = { reserved: '已有发送登记，未再次发送', acknowledged: '控制器已接收', uncertain: '发送结果不确定' }
const observations = { unknown: '无法核验会话', online: '目标会话仍在线', absent: '目标会话已不在清单', changed: '会话身份已变化' }

export function NativeObservations({ actionId }: { actionId: string }) {
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined])
  const before = cursors[cursors.length - 1]
  const query = useQuery({ queryKey: ['native-observations', actionId, before], queryFn: () => api.nativeObservations(actionId, before), retry: false })
  return <section className="native-observations" aria-label="原生执行记录">
    <p className="native-observation-id">动作：{actionId}</p>
    <Alert type="info" showIcon title="以下为发送与在线清单核验记录，不代表整个账号已处置成功。记录按入库顺序排列。" />
    <div className="native-observation-controls"><Button onClick={() => { setCursors([undefined]); void query.refetch() }}>刷新记录</Button></div>
    {query.isLoading ? <Spin aria-label="正在加载执行记录" /> : query.isError ? <Alert type="error" showIcon title="执行记录查询失败" description="可能是数据库不可用或权限不足，请稍后刷新。此状态不表示没有执行记录。" /> : <>
      {!query.data?.items.length && <Empty description="暂无原生执行记录" />}
      {query.data?.items.map(item => <article className="native-observation" key={item.id}>
        <div className="native-observation-controls"><strong>记录 {item.id}</strong><Tag color={item.step_failed ? 'red' : 'default'}>{item.step_failed ? '本次步骤发生错误' : '本次步骤已记录'}</Tag></div>
        <p>{deliveries[item.result.delivery] ?? item.result.delivery}</p>
        <p>{observations[item.result.observation] ?? item.result.observation}</p>
        <p>登记时间：{new Date(item.result.reserved_at).toLocaleString()}</p>
        <p>入库时间：{new Date(item.recorded_at).toLocaleString()}</p>
      </article>)}
      <div className="native-observation-controls">
        <Button disabled={cursors.length === 1 || query.isFetching} onClick={() => setCursors(value => value.slice(0, -1))}>较新记录</Button>
        <Button disabled={!query.data?.next_before || query.isFetching} onClick={() => setCursors(value => [...value, query.data?.next_before])}>较早记录</Button>
      </div>
    </>}
  </section>
}
