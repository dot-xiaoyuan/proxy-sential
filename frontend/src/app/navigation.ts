import type { Permission, Session } from '../shared/api/types'
import { can } from '../shared/auth/permissions'

export type NavigationItem = {
  key: string
  title: string
  to: string
  permission?: Permission
  hidden?: boolean
  readAlternatives?: { permission: Permission; to: string }[]
  owns: (path: string, params: URLSearchParams) => boolean
}
export type NavigationGroup = {
  key: string
  title: string
  items: NavigationItem[]
  hidden?: boolean
}

export const deviceCenterTabs = ['terminal', 'network', 'discovery'] as const
export type DeviceCenterTab = (typeof deviceCenterTabs)[number]
export const deviceCenterTab = (params: URLSearchParams): DeviceCenterTab =>
  params.get('tab') === 'network'
    ? 'network'
    : ['discovery', 'records', 'iot'].includes(params.get('tab') || '')
      ? 'discovery'
      : 'terminal'

const item = (
  key: string,
  title: string,
  to: string,
  permission?: Permission,
  prefix = to.split('?')[0],
): NavigationItem => ({
  key,
  title,
  to,
  permission,
  owns: (path) => path === prefix || path.startsWith(`${prefix}/`),
})

// 五大业务域主导航：态势总览 / 共享研判 / 资产台账 / 策略治理 / 系统运维。
export const navigation: NavigationGroup[] = [
  {
    key: 'situation',
    title: '态势总览',
    items: [
      item('overview', '运营工作台', '/overview', 'risks:read'),
      {
        ...item('reports', '防代理报表', '/reports', 'identity:read'),
        readAlternatives: [
          { permission: 'cases:read', to: '/reports' },
          { permission: 'policies:read', to: '/reports' },
        ],
      },
    ],
  },
  {
    key: 'risk',
    title: '共享研判',
    items: [
      {
        ...item('observations', '共享发现与核验', '/shared-access', 'cases:read'),
        owns: (p) =>
          p === '/shared-access' ||
          p.startsWith('/shared-access/') ||
          p === '/cases' ||
          p.startsWith('/cases/'),
      },
      {
        ...item('actions', '策略与处置记录', '/actions?tab=decisions', 'policies:read'),
        readAlternatives: [
          { permission: 'actions:read', to: '/actions?tab=actions' },
          { permission: 'behavior-reports:read', to: '/actions?tab=reports' },
        ],
      },
      item('ai-relay-usages', 'AI 中转站', '/ai-relay', 'events:read'),
    ],
  },
  {
    key: 'assets',
    title: '资产台账',
    items: [
      {
        ...item('devices', '终端列表', '/devices?tab=terminal', 'identity:read'),
        owns: (p, q) =>
          (p === '/devices' && deviceCenterTab(q) === 'terminal') ||
          (p.startsWith('/devices/') && !p.startsWith('/devices/network/')),
      },
      {
        ...item('routers', '路由器', '/devices?tab=network', 'identity:read'),
        owns: (p, q) =>
          (p === '/devices' && deviceCenterTab(q) === 'network') ||
          p.startsWith('/devices/network/') ||
          p.startsWith('/discovery/routers/'),
      },
      {
        ...item('discovered-devices', '发现设备', '/devices?tab=discovery', 'identity:read'),
        owns: (p, q) =>
          (p === '/devices' && deviceCenterTab(q) === 'discovery') || p === '/discovery',
      },
    ],
  },
  {
    key: 'strategy',
    title: '策略治理',
    items: [
      item('policies', '防代理策略', '/policies', 'policies:read'),
      item('whitelist', '白名单', '/policies/whitelist', 'policies:read'),
      item('blacklist', '黑名单', '/policies/blacklist', 'policies:read'),
      {
        ...item(
          'destination-targets',
          '内网目标访问',
          '/policies/destination-targets',
          'destination-targets:read',
        ),
        readAlternatives: [
          { permission: 'destination-targets:manage', to: '/policies/destination-targets' },
        ],
      },
      item('exceptions', '校园例外', '/policies/exceptions', 'risks:read'),
      {
        ...item('rules', '规则与特征库', '/settings/rules', 'risks:read'),
        readAlternatives: [
          { permission: 'dpi:read', to: '/settings/rules?tab=application-domains' },
          { permission: 'identity:read', to: '/settings/rules?tab=fingerprints' },
        ],
      },
    ],
  },
  {
    key: 'system',
    title: '系统运维',
    items: [
      {
        ...item('sources', '数据源与采集', '/settings/sources', 'ingest:read'),
        readAlternatives: [{ permission: 'identity:read', to: '/settings/sources?tab=sources' }],
      },
      item('integrations', '认证与处置接入', '/settings/actions', 'actions:read'),
      item('notifications', '通知模板与通道', '/settings/notifications', 'notifications:read'),
      {
        ...item(
          'behavior-reports',
          '上报通道配置',
          '/settings/behavior-reports',
          'behavior-reports:read',
        ),
        readAlternatives: [
          { permission: 'behavior-reports:manage', to: '/settings/behavior-reports' },
        ],
      },
      item('organization', '校区与网络区域', '/settings/organization', 'organization:read'),
      item('users', '用户权限', '/settings/security', 'users:manage'),
      item('audit', '审计日志', '/audit', 'audit:read'),
    ],
  },
]

const registeredRoutes = [
  /^\/(overview|reports|ai-relay|devices|discovery|cases|actions|audit|policies|shared-access|violation-observations|behavior-report-proposals)$/,
  /^\/(devices|events|cases|audit|review)\/[^/]+$/,
  /^\/discovery\/routers\/[^/]+$/,
  /^\/shared-access\/(observations|reviews)\/[^/]+$/,
  /^\/policies\/(exceptions|whitelist|blacklist|destination-targets)$/,
  /^\/settings\/(sources|rules|organization|actions|security|notifications|behavior-reports)$/,
  /^\/(ingest|settings\/sources)\/diagnostics\/[^/]+$/,
  /^\/ingest$/,
]

function hasControlChars(value: string) {
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) <= 0x1f) return true
  }
  return false
}

export function safeReturnTo(
  value: string | null | undefined,
  fallback = '/overview',
  depth = 0,
): string {
  if (
    !value ||
    !value.startsWith('/') ||
    value.startsWith('//') ||
    value.includes('\\') ||
    hasControlChars(value)
  ) {
    return fallback
  }
  try {
    const url = new URL(value, 'https://sentinel.invalid')
    if (url.origin !== 'https://sentinel.invalid' || url.pathname.startsWith('/ips/')) {
      return fallback
    }
    if (!registeredRoutes.some((pattern) => pattern.test(url.pathname))) return fallback
    if (url.searchParams.has('return_to')) {
      if (depth >= 2) url.searchParams.delete('return_to')
      else
        url.searchParams.set(
          'return_to',
          safeReturnTo(url.searchParams.get('return_to'), fallback, depth + 1),
        )
    }
    return `${url.pathname}${url.search}${url.hash}`
  } catch {
    return fallback
  }
}

export function detailPath(path: string, source: string) {
  const safe = safeReturnTo(source)
  const query = new URLSearchParams({ return_to: safe })
  const context = new URL(safe, 'https://sentinel.invalid').searchParams
  for (const key of ['window', 'sensor_id', 'campus_id', 'from', 'to']) {
    if (context.get(key)) query.set(key, context.get(key)!)
  }
  return `${path}?${query}`
}

export function routeOwner(path: string, search: string) {
  const params = new URLSearchParams(search)
  if (path.startsWith('/ingest')) return routeOwner('/settings/sources', search)
  if (path.startsWith('/review/')) return routeOwner('/cases', search)
  if (path.startsWith('/ips/') || path.startsWith('/events/')) {
    const source = new URL(
      safeReturnTo(params.get('return_to'), '/overview'),
      'https://sentinel.invalid',
    )
    return routeOwner(source.pathname, source.search)
  }
  // 具体子路径（如校园例外）优先于父路径匹配。
  const matches = navigation
    .flatMap((group) => group.items.map((entry) => ({ group, entry })))
    .filter(({ entry }) => entry.owns(path, params))
  return matches.sort(
    (a, b) => b.entry.to.split('?')[0].length - a.entry.to.split('?')[0].length,
  )[0]
}

export function routePermission(path: string, search: string): Permission | undefined {
  const tab = new URLSearchParams(search).get('tab')
  if (path === '/settings/rules' && tab === 'application-domains') return 'dpi:read'
  if (path === '/settings/rules' && tab === 'fingerprints') return 'identity:read'
  if (path === '/settings/security' && tab === 'exceptions') return 'risks:read'
  if (path === '/settings/actions' && tab === 'executions') return 'policies:read'
  if (path.startsWith('/ips/')) return 'risks:read'
  if (path.startsWith('/events/')) return 'events:read'
  if (path.startsWith('/ingest')) return 'ingest:read'
  if (
    path === '/settings/sources' &&
    ['sources', 'scan', 'tasks'].includes(new URLSearchParams(search).get('tab') || '')
  ) {
    return 'identity:read'
  }
  if (path === '/actions') {
    return tab === 'actions'
      ? 'actions:read'
      : tab === 'reports'
        ? 'behavior-reports:read'
        : 'policies:read'
  }
  const entry = routeOwner(path, search)?.entry
  // 防代理报表页内部按区块分别校验各数据源权限。
  return entry?.key === 'reports' ? undefined : entry?.permission
}

export function visibleNavigation(session: Session) {
  return navigation
    .map((group) => ({
      ...group,
      items: group.items.flatMap((entry) => {
        if (
          entry.hidden ||
          (entry.key === 'discovered-devices' && session.device_discovery_menu_hidden)
        ) {
          return []
        }
        if (!entry.permission || can(session, entry.permission)) return [entry]
        const alternative = entry.readAlternatives?.find((option) =>
          can(session, option.permission),
        )
        return alternative ? [{ ...entry, ...alternative }] : []
      }),
    }))
    .filter((group) => group.items.length && !group.hidden)
}
