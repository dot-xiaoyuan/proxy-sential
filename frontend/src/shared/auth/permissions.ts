import type { Permission, Session } from '../api/types'

export function can(session: Session | undefined, permission: Permission) {
  return session?.permissions.includes(permission) ?? false
}
