import { useQuery } from '@tanstack/react-query'
import { Alert, Tag } from 'antd'
import { Link } from 'react-router-dom'
import { request } from '../shared/api/client'
import { useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
import type { components } from '../shared/api/generated'
import { DeviceHistoryPanel } from './DeviceHistoryPanel'
export type NetworkProfile=components['schemas']['SharedDeviceProfile']
export function useNetworkContexts(ids:string[]){
 const session=useSession();const allowed=can(session.data,'cases:read')
 return useQuery({queryKey:['network-context',ids],enabled:allowed&&ids.length>0,queryFn:()=>request<Record<string,NetworkProfile[]>>(`/shared-access/network-context?ids=${encodeURIComponent(ids.join(','))}`)})
}
export function NetworkSharing({profiles}:{profiles?:NetworkProfile[]}){
 if(!profiles?.length)return null
 if(profiles.length>1)return <Tag color="warning">多份采集范围档案</Tag>
 const p=profiles[0]
 return <div className="center-network-sharing">{p.current_shared?<Tag color="orange">当前共享</Tag>:p.last_shared_at?<span>历史共享</span>:null}{p.last_shared_observation_id&&<Link to={`/shared-access/observations/${encodeURIComponent(p.last_shared_observation_id)}`}>共享证据</Link>}{p.account_conflict&&<Tag color="error">账号冲突</Tag>}</div>
}
export function NetworkProfileDetails({id,history=false}:{id:string;history?:boolean}){
 const context=useNetworkContexts([id]);if(context.isError)return <Alert type="error" title="读取共享档案失败"/>
 return <>{context.data?.[id]?.map(p=><section className="center-network-profile" key={p.profile_id}><h4>设备档案 {p.display_name}</h4><NetworkSharing profiles={[p]}/>{p.latest_account_id&&<p>关联账号：{p.latest_account_id}{p.latest_account_active?'':'（历史关联）'}</p>}{p.sensor_id&&<p>采集范围：{[p.sensor_id,p.campus_id,p.vlan].filter(Boolean).join(' · ')}</p>}{p.address_state==='reassigned'&&<Tag color="error">地址已转移</Tag>}{history&&<DeviceHistoryPanel kind="profile" id={p.profile_id}/>}</section>)}</>
}
