import type { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
export function LegacyRedirect({ to, tab }: { to: string; tab?: string }) {
  const location = useLocation()
  const params = new URLSearchParams(location.search)
  if (tab) {
    const old = params.get('tab')
    if (old) params.set('diagnostic_tab', old)
    params.set('tab', tab)
  }
  return <Navigate replace to={`${to}?${params}${location.hash}`} />
}
export function LegacySettingsEntry({
  kind,
  children,
}: {
  kind: 'actions' | 'security'
  children: ReactNode
}) {
  const location = useLocation()
  const tab = new URLSearchParams(location.search).get('tab')
  if (kind === 'actions' && ['actions', 'executions'].includes(tab || ''))
    return <LegacyRedirect to="/actions" />
  if (kind === 'security' && tab === 'exceptions') return <Navigate replace to="/policies" />
  return children
}

export function LegacyDiscoveryRedirect() {
  const location = useLocation()
  const params = new URLSearchParams(location.search)
  const tab = params.get('tab')
  params.set(
    'tab',
    ['routers', 'network', 'infrastructure'].includes(tab || '') ? 'network' : 'terminal',
  )
  params.delete('page')
  params.delete('cursor')
  params.delete('offset')
  return <Navigate replace to={`/devices?${params}${location.hash}`} />
}
