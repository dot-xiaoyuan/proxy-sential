import { useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
import type { ReactNode } from 'react'
import { Navigate,useLocation,useParams } from 'react-router-dom'
export function LegacyRedirect({to,tab}:{to:string;tab?:string}){
 const location=useLocation();const params=new URLSearchParams(location.search)
 if(tab){const old=params.get('tab');if(old)params.set('diagnostic_tab',old);params.set('tab',tab)}
 return <Navigate replace to={`${to}?${params}${location.hash}`}/>
}
export function LegacySettingsEntry({kind,children}:{kind:'actions'|'security';children:ReactNode}){
 const location=useLocation();const tab=new URLSearchParams(location.search).get('tab')
 if(kind==='actions' && ['actions','executions'].includes(tab || ''))return <LegacyRedirect to="/actions"/>
 if(kind==='security' && tab==='exceptions')return <LegacyRedirect to="/policies/exceptions"/>
 return children
}

export function ActivityEntry({children}:{children:ReactNode}){
 const location=useLocation();const params=new URLSearchParams(location.search);const tab=params.get('tab');
 if(!params.has('section') && tab && ['applications','ecosystem','domains','network','matrix','fingerprints','risks'].includes(tab)){
  if(tab==='risks'){params.delete('tab');return <Navigate replace to={`/overview?${params}`}/>}
  params.set('section',['matrix','fingerprints'].includes(tab)?'technical':'access');return <Navigate replace to={`/activity?${params}`}/>
 }
 return children
}

export function DiscoveryEntry(){
 const location=useLocation();const params=new URLSearchParams(location.search);const tab=params.get('tab');if(['sources','scan','tasks'].includes(tab||''))return <Navigate replace to={`/settings/sources?${params}${location.hash}`}/>;params.set('tab',tab==='routers'?'network':'iot');if(tab==='devices')params.set('aux','records');return <Navigate replace to={`/devices?${params}${location.hash}`}/>
}
export function SharedAccessEntry({children}:{children:ReactNode}){
 const session=useSession();
 const location=useLocation();const params=new URLSearchParams(location.search);if(params.get('tab')==='devices'){if(session.isPending)return null;if(!can(session.data,'identity:read'))params.set('aux','profiles');params.set('tab','network');for(const [old,key]of [['device_keyword','router_keyword'],['device_role','router_role'],['device_router_status','router_status']]){if(params.has(old))params.set(key,params.get(old)!)};return <Navigate replace to={`/devices?${params}${location.hash}`}/>};return children
}

export function RouterDetailEntry(){const {assessmentId=''}=useParams();return <LegacyRedirect to={`/devices/network/${encodeURIComponent(assessmentId)}`}/>}
