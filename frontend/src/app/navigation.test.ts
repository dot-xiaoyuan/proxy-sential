import { describe,it,expect } from 'vitest'
import { navigation,routeOwner,routePermission,safeReturnTo,visibleNavigation } from './navigation'
import type { Session } from '../shared/api/types'

describe('menu and investigation navigation',()=>{
 it('has six nonempty groups with stable detail ownership',()=>{
 expect(navigation.map(g=>g.title)).toEqual(['运营工作台','风险运营','资产与画像','网络分析','策略与验证','系统管理'])
 expect(routeOwner('/policies/exceptions','')?.entry.key).toBe('exceptions')
 expect(routeOwner('/shared-access/reviews/review-1','')?.entry.key).toBe('reviews')
 expect(routeOwner('/ips/10.0.0.1','')?.entry.key).toBe('events')
 expect(routeOwner('/ips/10.0.0.1','?return_to='+encodeURIComponent('/activity?section=technical&window=7d'))?.entry.key).toBe('technical')
 })
 it('accepts only registered site routes and restores conditions',()=>{
 for(const path of ['https://evil.test','//evil.test','/events/arbitrary/route','/ips/10.0.0.1?return_to=/ips/10.0.0.1','/settings/security/unregistered','/events\\evil'])expect(safeReturnTo(path)).toBe('/events')
 const source='/events?window=30d&app_protocol=http2&cursor=40'
 expect(safeReturnTo(source)).toBe(source)
 expect(safeReturnTo('/cases/case-1?return_to='+encodeURIComponent('/cases?campus_id=east&page=2'))).toContain('return_to=')
 })
 it('hides empty groups and preserves protected read permissions',()=>{
 const session={user:{id:'viewer',name:'viewer'},role:'viewer',permissions:['events:read']} as Session
 expect(visibleNavigation(session).map(g=>g.key)).toEqual(['network'])
 const policyOnly={...session,permissions:['policies:read']} as Session
 expect(visibleNavigation(policyOnly).find(g=>g.key==='risk')?.items[0].to).toBe('/actions?tab=executions')
 const identityOnly={...session,permissions:['identity:read']} as Session
 expect(visibleNavigation(identityOnly).find(g=>g.key==='system')?.items[0].to).toBe('/settings/sources?tab=sources')
 expect(routePermission('/policies/exceptions','')).toBe('risks:read')
 expect(routePermission('/settings/security','?tab=exceptions')).toBe('risks:read')
 expect(routePermission('/settings/security','')).toBe('users:manage')
 expect(routePermission('/actions','?tab=actions')).toBe('actions:read')
 })
})
