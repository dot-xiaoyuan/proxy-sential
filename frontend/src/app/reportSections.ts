import type { Permission } from '../shared/api/types'

export const reportSections: ReadonlyArray<{ key: string; label: string; permissions: Permission[] }> = [
  { key: 'sharing', label: '共享识别', permissions: ['identity:read', 'cases:read'] },
  { key: 'risk', label: '风险与处置', permissions: ['risks:read', 'cases:read', 'policies:read', 'actions:read', 'behavior-reports:read'] },
  { key: 'devices', label: '终端与认证', permissions: ['identity:read', 'actions:read'] },
  { key: 'traffic', label: '流量与访问', permissions: ['dpi:read', 'events:read', 'destination-targets:read'] },
  { key: 'pipeline', label: '链路与积压', permissions: ['identity:read', 'risks:read', 'ingest:read', 'actions:read'] },
  { key: 'operations', label: '资源与审计', permissions: ['risks:read', 'audit:read'] },
]

export const reportPermissions = [...new Set(reportSections.flatMap((section) => section.permissions))]
