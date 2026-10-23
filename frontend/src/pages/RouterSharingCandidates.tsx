import { Notice as Alert } from '../shared/ui/Notice'
import { useEffect, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Segmented, Select, Tag } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { request } from '../shared/api/client'
import type { components } from '../shared/api/generated'
import { AppListHeader, AppListSection, AppServerPagination, AppTable, AppTableBar, formatDateTime, useServerPagination } from '../shared/ui'
import { useUrlState } from '../shared/ui/useUrlState'
import { detailPath } from '../app/navigation'
import { routerStatusLabels } from './routerLabels'

type Profiles = components['schemas']['SharedDeviceProfilePage']
type Profile = Profiles['items'][number]
const time = formatDateTime

export function RouterSharingCandidates() {
 const location=useLocation()
 const pagination=useServerPagination('router_sharing_')
 const [keyword,setKeyword]=useUrlState('router_keyword','',undefined,['router_sharing_page','router_sharing_cursors'])
 const [accountGroup,setAccountGroup]=useUrlState('router_accounts','linked',['linked','empty'],['router_sharing_page','router_sharing_cursors'])
 const [routerStatus,setRouterStatus]=useUrlState('router_status','',['','candidate','likely','confirmed'],['router_sharing_page','router_sharing_cursors'])
 const [searchInput,setSearchInput]=useState(keyword)
 useEffect(()=>{const timer=globalThis.setTimeout(()=>{if(searchInput.trim()!==keyword){setKeyword(searchInput.trim());pagination.reset()}},300);return()=>globalThis.clearTimeout(timer)},[searchInput])
 const query=new URLSearchParams({role:'router',router_status:routerStatus,identity_state:'supported',has_account:String(accountGroup==='linked'),keyword,limit:String(pagination.pageSize),cursor:pagination.cursor})
 const profiles=useQuery({queryKey:['router-sharing-candidates',query.toString()],queryFn:()=>request<Profiles>(`/shared-access/devices?${query}`),refetchInterval:30000})
 useEffect(()=>{if(profiles.data&&!profiles.isFetching&&!profiles.data!.items.length&&pagination.page>1)pagination.reset()},[profiles.data,profiles.isFetching,pagination])
 const total=profiles.data?.page.total||0
 const columns: ColumnsType<Profile> = [
  {title:'路由器身份',key:'identity',width:240,render:(_,item)=>{
    const expired=!item.identity_current||(!!item.identity_expires_at&&new Date(item.identity_expires_at).getTime()<=Date.now())
    return <div className="router-sharing-identity"><strong>{[item.brand,item.model].filter(Boolean).join(' ')||'路由器身份记录'}</strong>{item.mac&&<span className="shared-access-id">MAC：{item.mac}</span>}<Tag>{expired?'身份证据已过期':routerStatusLabels[item.router_status||'']||'身份待确认'}</Tag>{item.identity_conflict&&<Tag color="warning">身份存在冲突</Tag>}</div>
  }},
  {title:'观测地址 / 关联账号',key:'account',width:280,render:(_,item)=><div className="router-sharing-account">{item.ip&&<span className="router-sharing-ip" title={item.ip}>{item.ip}</span>}{item.latest_account_id?.trim()?<span className="shared-access-id">关联账号：{item.latest_account_id}</span>:<Tag>无认证账号</Tag>}{item.account_conflict&&<Tag color="warning">账号关联有冲突</Tag>}<span className="shared-access-muted">观测地址不代表已验证的共享出口</span></div>},
  {title:'共享关系',key:'sharing',width:280,render:(_,item)=><div className="router-sharing-relation"><Tag>共享关系待核验</Tag><span className="shared-access-muted">尚缺路由转发及下游共享关系证明</span>{item.identity_assessment_id&&<Link to={detailPath(`/discovery/routers/${encodeURIComponent(item.identity_assessment_id)}`,location.pathname+location.search)}>查看身份依据</Link>}</div>},
  {title:'最近观测',key:'seen',width:160,render:(_,item)=><div className="router-sharing-seen"><time>{time(item.last_observed_at)}</time>{item.last_shared_observation_id&&<Link to={detailPath(`/shared-access/observations/${encodeURIComponent(item.last_shared_observation_id)}`,location.pathname+location.search)}>查看关联观察</Link>}</div>},
 ]
 return <>
  <AppTableBar
    searchPlaceholder="IP、MAC、账号、品牌或型号"
    searchValue={searchInput}
    onSearchChange={setSearchInput}
    filters={<><Segmented aria-label="账号关联范围" value={accountGroup} options={[{label:'有关联账号',value:'linked'},{label:'无关联账号',value:'empty'}]} onChange={value=>{setAccountGroup(String(value));pagination.reset()}} /><Select aria-label="路由身份状态" className="shared-profile-filter" value={routerStatus} onChange={value=>{setRouterStatus(value);pagination.reset()}} options={[{value:'',label:'全部身份状态'},...Object.entries(routerStatusLabels).map(([value,label])=>({value,label}))]} /></>}
  />
  <section className="surface">
    <AppListHeader title="路由器共享核验" count={`${total} 条`} />
    <p className="shared-access-muted router-sharing-note">展示身份证据当前有效的路由器记录，区分身份线索、待确认和已确认。路由器身份及共享转发关系需要分别核验；历史记录可在共享终端档案查看。</p>
    {profiles.data?.freshness_state==='stale'&&<Alert type="warning" showIcon title="设备信息处理有延迟" description="以下为最后一次成功生成的设备信息。"/>}
    <AppListSection isError={profiles.isError} errorTitle="路由器记录读取失败" isLoading={profiles.isLoading} loadingRows={4} isEmpty={!profiles.data?.items.length} emptyText="当前筛选下暂无路由器记录；可切换身份状态或账号范围，历史信息可在共享终端档案查看。">
      <AppTable rowKey="profile_id" columns={columns} dataSource={profiles.data?.items ?? []} scroll={{ x: 960 }} />
    </AppListSection>
    <AppServerPagination page={pagination.page} pageSize={pagination.pageSize} total={total} onChange={pagination.update}/>
  </section>
 </>
}
