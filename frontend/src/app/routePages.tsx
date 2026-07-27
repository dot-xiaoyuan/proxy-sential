import { lazy, Suspense, type ReactNode } from 'react'
import { Spin } from 'antd'

const AuditPage = lazy(() => import('../pages/AuditPage').then((module) => ({ default: module.AuditPage })))
const IpDetailsPage = lazy(() =>
  import('../pages/IpDetailsPage').then((module) => ({ default: module.IpDetailsPage })),
)
const OverviewPage = lazy(() =>
  import('../pages/OverviewPage').then((module) => ({ default: module.OverviewPage })),
)
const ReviewPage = lazy(() => import('../pages/ReviewPage').then((module) => ({ default: module.ReviewPage })))
const RisksPage = lazy(() => import('../pages/RisksPage').then((module) => ({ default: module.RisksPage })))
const RulesPage = lazy(() => import('../pages/RulesPage').then((module) => ({ default: module.RulesPage })))
const ShadowRunsPage = lazy(() =>
  import('../pages/ShadowRunsPage').then((module) => ({ default: module.ShadowRunsPage })),
)

function RouteSuspense({ children }: { children: ReactNode }) {
  return (
    <Suspense
      fallback={
        <div className="surface">
          <Spin />
        </div>
      }
    >
      {children}
    </Suspense>
  )
}

export function AuditRoute() {
  return (
    <RouteSuspense>
      <AuditPage />
    </RouteSuspense>
  )
}

export function IpDetailsRoute() {
  return (
    <RouteSuspense>
      <IpDetailsPage />
    </RouteSuspense>
  )
}

export function OverviewRoute() {
  return (
    <RouteSuspense>
      <OverviewPage />
    </RouteSuspense>
  )
}

export function ReviewRoute() {
  return (
    <RouteSuspense>
      <ReviewPage />
    </RouteSuspense>
  )
}

export function RisksRoute() {
  return (
    <RouteSuspense>
      <RisksPage />
    </RouteSuspense>
  )
}

export function RulesRoute() {
  return (
    <RouteSuspense>
      <RulesPage />
    </RouteSuspense>
  )
}

export function ShadowRunsRoute() {
  return (
    <RouteSuspense>
      <ShadowRunsPage />
    </RouteSuspense>
  )
}
