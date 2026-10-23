import { describe,it,expect } from 'vitest'
import { navigation,routeOwner,routePermission,safeReturnTo,visibleNavigation } from './navigation'
import type { Session } from '../shared/api/types'

describe('menu and investigation navigation',()=>{
 it('has six nonempty groups with stable detail ownership',()=>{
 expect(navigation.map(g=>g.title)).toEqual(['运营工作台','AI 中转站','风险运营','设备中心','网络分析','策略与验证','系统管理'])
 expect(navigation.find(g=>g.key==='assets')?.items.map(item=>item.title)).toEqual(['终端列表','路由器'])
 expect(navigation.find(g=>g.key==='risk')?.items.map(item=>item.title)).toEqual(['共享发现与核验','策略与处置记录'])
 expect(routeOwner('/discovery','')?.entry.key).toBe('devices')
 expect(routeOwner('/devices','')?.entry.key).toBe('devices')
 expect(routeOwner('/devices','?tab=network')?.entry.key).toBe('routers')
 expect(routeOwner('/devices','?tab=iot')?.entry.key).toBe('devices')
 expect(routeOwner('/devices/mac:aa:bb','')?.entry.key).toBe('devices')
 expect(routeOwner('/devices/network/assessment-1','')?.entry.key).toBe('routers')
 expect(routeOwner('/discovery/routers/assessment-1','')?.entry.key).toBe('routers')
 expect(routeOwner('/accounts/student-1','')).toBeUndefined()
 expect(routeOwner('/policies/exceptions','')?.entry.key).toBe('exceptions')
 expect(routeOwner('/shared-access/reviews/review-1','')?.entry.key).toBe('observations')
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
 expect(visibleNavigation(session).map(g=>g.key)).toEqual(['ai-relay'])
 expect(routePermission('/ai-relay','')).toBe('events:read')
 expect(safeReturnTo('/ai-relay')).toBe('/ai-relay')
 expect(navigation.find(g=>g.key==='network')).toBeTruthy()
 const policyOnly={...session,permissions:['policies:read']} as Session
 expect(visibleNavigation(policyOnly).find(g=>g.key==='risk')?.items[0].to).toBe('/actions?tab=decisions')
 const identityOnly={...session,permissions:['identity:read']} as Session
 expect(visibleNavigation(identityOnly).find(g=>g.key==='system')?.items[0].to).toBe('/settings/sources?tab=sources')
 expect(routePermission('/policies/exceptions','')).toBe('risks:read')
 expect(routePermission('/settings/security','?tab=exceptions')).toBe('risks:read')
 expect(routePermission('/settings/security','')).toBe('users:manage')
 expect(routePermission('/actions','?tab=actions')).toBe('actions:read')
 })
})
