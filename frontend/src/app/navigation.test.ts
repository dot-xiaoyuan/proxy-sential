import { describe, expect, it } from 'vitest'
import {
  navigation,
  routeOwner,
  routePermission,
  safeReturnTo,
  visibleNavigation,
} from './navigation'
import type { Session } from '../shared/api/types'

describe('五大域菜单与溯源导航', () => {
  it('按五大域组织主导航并正确归属详情路由', () => {
    expect(navigation.map((g) => g.title)).toEqual([
      '态势总览',
      '共享研判',
      '资产台账',
      '策略治理',
      '系统运维',
    ])
    expect(navigation.find((g) => g.key === 'situation')?.items.map((item) => item.title)).toEqual([
      '运营工作台',
      '防代理报表',
    ])
    expect(navigation.find((g) => g.key === 'risk')?.items.map((item) => item.title)).toEqual([
      '共享发现与核验',
      '策略与处置记录',
      'AI 中转站',
    ])
    expect(
      visibleNavigation({
        user: { id: 'admin', name: 'admin' },
        role: 'admin',
        permissions: ['identity:read', 'events:read'],
      } as Session)
        .find((g) => g.key === 'assets')
        ?.items.map((item) => item.title),
    ).toEqual(['终端列表', '路由器', '发现设备'])
    expect(
      visibleNavigation({
        user: { id: 'admin', name: 'admin' },
        role: 'admin',
        permissions: ['identity:read', 'events:read'],
        device_discovery_menu_hidden: true,
      } as Session)
        .find((g) => g.key === 'assets')
        ?.items.map((item) => item.title),
    ).toEqual(['终端列表', '路由器'])

    expect(routeOwner('/discovery', '')?.entry.key).toBe('discovered-devices')
    expect(routeOwner('/devices', '')?.entry.key).toBe('devices')
    expect(routeOwner('/devices', '?tab=network')?.entry.key).toBe('routers')
    expect(routeOwner('/devices', '?tab=iot')?.entry.key).toBe('discovered-devices')
    expect(routeOwner('/devices', '?tab=ip')?.entry.key).toBe('devices')
    expect(routePermission('/devices', '?tab=discovery')).toBe('identity:read')
    expect(routeOwner('/devices', '?tab=discovery')?.entry.key).toBe('discovered-devices')
    expect(routeOwner('/devices/mac:aa:bb', '')?.entry.key).toBe('devices')
    expect(routeOwner('/devices/network/assessment-1', '')?.entry.key).toBe('routers')
    expect(routeOwner('/discovery/routers/assessment-1', '')?.entry.key).toBe('routers')
    expect(routeOwner('/accounts/student-1', '')).toBeUndefined()
    expect(routeOwner('/policies/exceptions', '')?.entry.key).toBe('exceptions')
    expect(routeOwner('/shared-access/reviews/review-1', '')?.entry.key).toBe('observations')
    expect(routeOwner('/cases/case-1', '')?.entry.key).toBe('observations')
    expect(routeOwner('/ips/10.0.0.1', '')?.entry.key).toBe('overview')
    expect(
      routeOwner('/ips/10.0.0.1', '?return_to=' + encodeURIComponent('/devices?tab=terminal'))
        ?.entry.key,
    ).toBe('devices')
    expect(
      routeOwner('/events/event-1', '?return_to=' + encodeURIComponent('/shared-access'))?.entry
        .key,
    ).toBe('observations')
  })

  it('发现服务关闭时隐藏发现设备菜单', () => {
    const session: Session = {
      user: { id: 'operator', name: 'operator' },
      role: 'operator',
      permissions: ['identity:read'],
      device_discovery_menu_hidden: true,
    }
    expect(
      visibleNavigation(session)
        .find((g) => g.key === 'assets')
        ?.items.map((item) => item.title),
    ).toEqual(['终端列表', '路由器'])
  })

  it('仅接受已注册站内返回路径并保留筛选条件', () => {
    for (const path of [
      'https://evil.test',
      '//evil.test',
      '/events/arbitrary/route',
      '/ips/10.0.0.1?return_to=/ips/10.0.0.1',
      '/settings/security/unregistered',
      '/events\\evil',
    ]) {
      expect(safeReturnTo(path)).toBe('/overview')
    }
    const source = '/shared-access?tab=associations&keyword=test'
    expect(safeReturnTo(source)).toBe(source)
    expect(
      safeReturnTo('/cases/case-1?return_to=' + encodeURIComponent('/cases?campus_id=east&page=2')),
    ).toContain('return_to=')
  })

  it('隐藏无权限分组并保持只读权限校验准确', () => {
    const session = {
      user: { id: 'viewer', name: 'viewer' },
      role: 'viewer',
      permissions: ['events:read'],
    } as Session
    expect(visibleNavigation(session).map((g) => g.key)).toEqual(['risk'])
    expect(visibleNavigation(session)[0].items.map((i) => i.key)).toEqual(['ai-relay-usages'])
    expect(routeOwner('/reports', '?window=15m')?.entry.key).toBe('reports')
    expect(safeReturnTo('/reports?window=15m')).toBe('/reports?window=15m')
    expect(routePermission('/ai-relay', '')).toBe('events:read')
    expect(routePermission('/events/event-1', '')).toBe('events:read')
    expect(safeReturnTo('/ai-relay')).toBe('/ai-relay')
    const policyOnly = { ...session, permissions: ['policies:read'] } as Session
    expect(visibleNavigation(policyOnly).find((g) => g.key === 'risk')?.items[0].to).toBe(
      '/actions?tab=decisions',
    )
    const identityOnly = { ...session, permissions: ['identity:read'] } as Session
    expect(visibleNavigation(identityOnly).find((g) => g.key === 'system')?.items[0].to).toBe(
      '/settings/sources?tab=sources',
    )
    expect(routePermission('/policies/exceptions', '')).toBe('risks:read')
    expect(routePermission('/settings/security', '?tab=exceptions')).toBe('risks:read')
    expect(routePermission('/settings/security', '')).toBe('users:manage')
    expect(routePermission('/actions', '?tab=actions')).toBe('actions:read')
  })
})
