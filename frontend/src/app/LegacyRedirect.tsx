import type { ReactNode } from 'react'
import { Navigate,useLocation } from 'react-router-dom'
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
