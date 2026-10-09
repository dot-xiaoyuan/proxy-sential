import type { Permission, Session } from '../shared/api/types'
import { can } from '../shared/auth/permissions'

export type NavigationItem = { key: string; title: string; to: string; permission?: Permission; readAlternatives?: {permission: Permission; to: string}[]; owns: (path: string, params: URLSearchParams) => boolean }
export type NavigationGroup = { key: string; title: string; items: NavigationItem[] }
const item = (key: string, title: string, to: string, permission?: Permission, prefix = to.split('?')[0]): NavigationItem => ({ key, title, to, permission, owns: path => path === prefix || path.startsWith(`${prefix}/`) })
export const navigation: NavigationGroup[] = [
  { key: 'workbench', title: '运营工作台', items: [item('overview','运营工作台','/overview','risks:read')] },
  { key: 'risk', title: '风险运营', items: [
    {...item('observations','共享发现','/shared-access?tab=devices','cases:read'), owns: (p,q) => p.startsWith('/shared-access/observations') || p === '/shared-access' && q.get('tab') !== 'reviews'},
    {...item('reviews','账号复核','/shared-access?tab=reviews','cases:read'), owns: (p,q) => p.startsWith('/shared-access/reviews') || p === '/shared-access' && q.get('tab') === 'reviews'},
    item('cases','风险案件','/cases','cases:read'), {...item('actions','处置记录','/actions?tab=actions','actions:read'),readAlternatives:[{permission:'policies:read',to:'/actions?tab=executions'}]},
  ] },
  { key: 'assets', title: '资产与画像', items: [item('devices','终端画像','/devices','identity:read'), item('discovery','网络设备发现','/discovery','identity:read')] },
  { key: 'network', title: '网络分析', items: [
    ...(['applications','access','technical'] as const).map((section,index) => ({...item(section,['应用访问','访问分析','技术指纹'][index],`/activity?section=${section}`,'dpi:read'), owns: (p: string,q: URLSearchParams) => p === '/activity' && (['applications','access','technical'].includes(q.get('section')||'')?q.get('section'):'applications') === section})),
    item('events','事件检索','/events','events:read'),
  ] },
  { key: 'strategy', title: '策略与验证', items: [item('policies','防代理策略','/policies','policies:read'),item('whitelist','白名单','/policies/whitelist','policies:read'),item('exceptions','校园例外','/policies/exceptions','risks:read'),{...item('rules','规则与特征库','/settings/rules','risks:read'),readAlternatives:[{permission:'dpi:read',to:'/settings/rules?tab=application-domains'},{permission:'identity:read',to:'/settings/rules?tab=fingerprints'}]}] },
  { key: 'system', title: '系统管理', items: [{...item('sources','数据源与采集','/settings/sources','ingest:read'),readAlternatives:[{permission:'identity:read',to:'/settings/sources?tab=sources'}]},item('integrations','认证与处置接入','/settings/actions','actions:read'),item('organization','校区与网络区域','/settings/organization','organization:read'),item('users','用户权限','/settings/security','users:manage'),item('audit','审计日志','/audit','audit:read')] },
]

const registeredRoutes=[/^\/(overview|activity|devices|discovery|events|cases|actions|audit|policies|shared-access)$/, /^\/(devices|events|cases|audit|review)\/[^/]+$/, /^\/discovery\/routers\/[^/]+$/, /^\/shared-access\/(observations|reviews)\/[^/]+$/, /^\/policies\/(exceptions|whitelist)$/, /^\/settings\/(sources|rules|organization|actions|security)$/, /^\/(ingest|settings\/sources)\/diagnostics\/[^/]+$/, /^\/ingest$/]
export function safeReturnTo(value: string | null | undefined, fallback = '/events', depth=0): string {
  if (!value || !value.startsWith('/') || value.startsWith('//') || /[\\\u0000-\u001f]/.test(value)) return fallback
  try {
    const url = new URL(value,'https://sentinel.invalid')
    if (url.origin !== 'https://sentinel.invalid' || url.pathname.startsWith('/ips/')) return fallback
    if (!registeredRoutes.some(pattern=>pattern.test(url.pathname))) return fallback
    if(url.searchParams.has('return_to')){if(depth>=2)url.searchParams.delete('return_to');else url.searchParams.set('return_to',safeReturnTo(url.searchParams.get('return_to'),fallback,depth+1))}
    return `${url.pathname}${url.search}${url.hash}`
  } catch { return fallback }
}
export function detailPath(path: string, source: string) {
 const safe=safeReturnTo(source);const query=new URLSearchParams({return_to:safe});const context=new URL(safe,'https://sentinel.invalid').searchParams;
 for(const key of ['window','sensor_id','campus_id','from','to'])if(context.get(key))query.set(key,context.get(key)!);
 return `${path}?${query}`
}
export function routeOwner(path: string, search: string) {
  const params = new URLSearchParams(search)
  if(path.startsWith('/ingest'))return routeOwner('/settings/sources',search)
  if(path.startsWith('/review/'))return routeOwner('/cases',search)
  if (path.startsWith('/ips/')) {
    const source = new URL(safeReturnTo(params.get('return_to')),'https://sentinel.invalid')
    return routeOwner(source.pathname,source.search)
  }
  // Specific children (校园例外) take precedence over their parent path.
  const matches = navigation.flatMap(group => group.items.map(entry => ({group,entry}))).filter(({entry}) => entry.owns(path,params))
  return matches.sort((a,b) => b.entry.to.split('?')[0].length-a.entry.to.split('?')[0].length)[0]
}
export function routePermission(path: string, search: string): Permission | undefined {
  const tab=new URLSearchParams(search).get('tab')
  if(path === '/settings/rules' && tab==='application-domains')return 'dpi:read'
  if(path === '/settings/rules' && tab==='fingerprints')return 'identity:read'
  if(path === '/settings/security' && tab==='exceptions')return 'risks:read'
  if(path === '/settings/actions' && tab==='executions')return 'policies:read'
  if(path.startsWith('/ips/')) return 'risks:read'
  if(path.startsWith('/ingest')) return 'ingest:read'
  if(path === '/settings/sources' && ['sources','scan','tasks'].includes(new URLSearchParams(search).get('tab') || '')) return 'identity:read'
  if(path === '/actions' && new URLSearchParams(search).get('tab') !== 'actions') return 'policies:read'
  return routeOwner(path,search)?.entry.permission
}
export function visibleNavigation(session: Session) {
 return navigation.map(group => ({...group,items:group.items.flatMap(entry => {
  if(!entry.permission || can(session,entry.permission))return [entry]
  const alternative=entry.readAlternatives?.find(option=>can(session,option.permission))
  return alternative?[{...entry,...alternative}]:[]
 })})).filter(group => group.items.length)
}
