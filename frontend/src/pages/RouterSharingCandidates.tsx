import { Notice as Alert } from '../shared/ui/Notice'
import { useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Button, Card, Empty, Input, Tabs, Tag } from 'antd'
import { request } from '../shared/api/client'
import type { components } from '../shared/api/generated'
import { AppErrorAlert, AppLoadingState, AppServerPagination, useServerPagination } from '../shared/ui'
import { useUrlState } from '../shared/ui/useUrlState'
import { detailPath } from '../app/navigation'

type Profiles = components['schemas']['SharedDeviceProfilePage']
const time = (value?: string) => value && !value.startsWith('0001-') ? new Date(value).toLocaleString('zh-CN', {hour12:false}) : ''
const identityLabels: Record<string,string> = {confirmed:'路由器身份已确认',likely:'路由器身份较可信',candidate:'路由器身份线索'}

export function RouterSharingCandidates() {
 const location=useLocation()
 const pagination=useServerPagination('router_sharing_')
 const [keyword,setKeyword]=useUrlState('router_keyword','',undefined,['router_sharing_page','router_sharing_cursors'])
 const [accountGroup,setAccountGroup]=useUrlState('router_accounts','linked',['linked','empty'],['router_sharing_page','router_sharing_cursors'])
 const query=new URLSearchParams({role:'router',identity_state:'supported',has_account:String(accountGroup==='linked'),keyword,limit:String(pagination.pageSize),cursor:pagination.cursor})
 const profiles=useQuery({queryKey:['router-sharing-candidates',query.toString()],queryFn:()=>request<Profiles>(`/shared-access/devices?${query}`),refetchInterval:30000})
 useEffect(()=>{if(profiles.data&&!profiles.isFetching&&!profiles.data.items.length&&pagination.page>1)pagination.reset()},[profiles.data,profiles.isFetching,pagination])
 return <Card title="路由器共享核验" extra={<Button onClick={()=>void profiles.refetch()} loading={profiles.isFetching}>刷新</Button>} className="router-sharing-candidates">
  <p className="shared-access-muted">展示身份信息当前有效的路由器记录，包含待核实的身份线索。路由器身份与共享关系分别核验；识别到路由器不等于已确认共享。</p>
  <Tabs className="router-account-tabs" activeKey={accountGroup} onChange={setAccountGroup} items={[{key:'linked',label:'有关联账号'},{key:'empty',label:'无关联账号'}]}/>
  <div className="router-sharing-toolbar"><Input.Search aria-label="搜索路由器" key={keyword} defaultValue={keyword} allowClear placeholder="IP、MAC、账号、品牌或型号" onSearch={value=>setKeyword(value.trim())}/></div>
  {profiles.data?.freshness_state==='stale'&&<Alert type="warning" showIcon title="设备信息处理有延迟" description="以下为最后一次成功生成的设备信息。"/>}
  {profiles.isError?<AppErrorAlert title="路由器记录读取失败"/>:profiles.isLoading?<AppLoadingState rows={4}/>:!profiles.data?.items.length?<Empty description="当前筛选没有身份有效的路由器记录；可在设备档案查看历史信息。"/>:<>
   <div className="router-sharing-columns" aria-hidden="true"><span>路由器身份</span><span>观测地址 / 关联账号</span><span>共享关系</span><span>最近观测</span></div>
   <div className="router-sharing-list" role="list">{profiles.data.items.map(item=>{
    const expired=!item.identity_current||(!!item.identity_expires_at&&new Date(item.identity_expires_at).getTime()<=Date.now())
    return <article className="router-sharing-row" key={item.profile_id} role="listitem">
     <div><strong>{[item.brand,item.model].filter(Boolean).join(' ')||'路由器身份记录'}</strong>{item.mac&&<span className="shared-access-id">MAC：{item.mac}</span>}<Tag>{expired?'身份证据已过期':identityLabels[item.router_status||'']||'路由器身份待核实'}</Tag>{item.identity_conflict&&<Tag color="warning">身份存在冲突</Tag>}</div>
     <div>{item.ip&&<span className="router-sharing-ip" title={item.ip}>{item.ip}</span>}{item.latest_account_id?.trim()?<span className="shared-access-id">关联账号：{item.latest_account_id}</span>:<Tag>无关联账号</Tag>}{item.account_conflict&&<Tag color="warning">账号关联有冲突</Tag>}<span className="shared-access-muted">观测地址不代表已验证的共享出口</span></div>
     <div><Tag>共享关系待核验</Tag><span className="shared-access-muted">尚缺路由转发及下游共享关系证明</span>{item.identity_assessment_id&&<Link to={detailPath(`/discovery/routers/${encodeURIComponent(item.identity_assessment_id)}`,location.pathname+location.search)}>查看身份依据</Link>}</div>
     <div><time>{time(item.last_observed_at)}</time>{item.last_shared_observation_id&&<Link to={detailPath(`/shared-access/observations/${encodeURIComponent(item.last_shared_observation_id)}`,location.pathname+location.search)}>查看关联观察</Link>}</div>
    </article>
   })}</div>
  </>}
  <AppServerPagination page={pagination.page} pageSize={pagination.pageSize} total={profiles.data?.page.total||0} onChange={pagination.update}/>
 </Card>
}
