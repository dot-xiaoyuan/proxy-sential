import { SharedDeviceProfiles } from './SharedDeviceProfiles'
import { useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
import { Tabs, Typography, Select } from 'antd'
import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { DevicesPage } from './DevicesPage'
import { RouterObservationsPanel } from './RouterObservationsPanel'
import { PassiveDiscoveryPanel, ProtocolOverview, type DiscoverySummary } from './PassiveDiscoveryPanel'
import { request } from '../shared/api/client'

export function DeviceCenterPage(){
 const session=useSession();const identityAllowed=can(session.data,'identity:read');const casesAllowed=can(session.data,'cases:read')
 const [params,setParams]=useSearchParams()
 const tab=['terminal','network','iot'].includes(params.get('tab')||'')?params.get('tab')!:'terminal'
 const auxiliary=params.get('aux')||''
 const change=(key:string,value:string)=>setParams(current=>{const next=new URLSearchParams(current);value?next.set(key,value):next.delete(key);next.delete('page');next.delete('cursor');next.delete('routers_page');next.delete('device');if(key==='tab'){next.delete('aux');next.delete('view')}return next})
 const summary=useQuery({queryKey:['discovery','summary'],queryFn:()=>request<DiscoverySummary>('/discovery/summary'),enabled:tab==='iot'||auxiliary==='records'})
 return <main className="page device-center-page"><header className="center-header"><div><Typography.Title level={3}>设备中心</Typography.Title><Typography.Text type="secondary">按设备身份查看地址、认证关联和发现证据；设备发现不代表当前在线。</Typography.Text></div><Select aria-label="辅助视图" value={auxiliary} onChange={v=>change('aux',v)} options={[{value:'',label:'主要设备列表'},{value:'records',label:'全部发现线索'},{value:'link',label:'仅链路线索'},{value:'history',label:'历史设备'},...(casesAllowed?[{value:'profiles',label:'档案追溯'}]:[])]}/></header><Tabs activeKey={tab} onChange={v=>change('tab',v)} items={[{key:'terminal',label:'终端',disabled:!identityAllowed},{key:'network',label:'网络设备',disabled:!identityAllowed},{key:'iot',label:'哑终端',disabled:!identityAllowed}]}/>{auxiliary==='profiles'&&casesAllowed?<SharedDeviceProfiles/>:!identityAllowed?null:auxiliary==='records'?<><ProtocolOverview summary={summary.data}/><PassiveDiscoveryPanel view="records" addressState="all"/></>:tab==='terminal'?<DevicesPage embedded addressState={auxiliary==='link'?'link':auxiliary==='history'?'history':'current'}/>:tab==='network'?<RouterObservationsPanel addressState={auxiliary==='link'?'link':auxiliary==='history'?'history':'current'}/>:<><ProtocolOverview summary={summary.data}/><PassiveDiscoveryPanel view="iot" addressState={auxiliary==='link'?'link':auxiliary==='history'?'history':'current'}/></>}</main>
}
