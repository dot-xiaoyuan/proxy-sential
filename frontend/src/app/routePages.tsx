import { lazy, Suspense, type ReactNode } from 'react'

import { AppPageSkeleton } from '../shared/ui'

const loaders = {
  overview: () => import('../pages/OverviewPage'),
  reports: () => import('../pages/ReportsPage'),
  sharedAccess: () => import('../pages/SharedAccessPage'),
  actionRecords: () => import('../pages/ActionRecordsPage'),
  aiRelay: () => import('../pages/AIRelayPage'),
  devices: () => import('../pages/DeviceCenterPage'),
  endpointDetails: () => import('../pages/EndpointDetailsPage'),
  ipDetails: () => import('../pages/IpDetailsPage'),
  routerDetails: () => import('../pages/RouterObservationDetailsPage'),
  cases: () => import('../pages/CasesPage'),
  caseDetails: () => import('../pages/CaseDetailsPage'),
  reviewDetails: () => import('../pages/ReviewDetailsPage'),
  recordDetails: () => import('../pages/RecordDetailsPages'),
  policies: () => import('../pages/PoliciesPage'),
  whitelist: () => import('../pages/WhitelistPage'),
  blacklist: () => import('../pages/BlacklistPage'),
  destinationTargets: () => import('../pages/DestinationTargetsPage'),
  campusExceptions: () => import('../pages/CampusExceptionsPage'),
  rules: () => import('../pages/RulesPage'),
  sources: () => import('../pages/SourcesPage'),
  actions: () => import('../pages/ActionsPage'),
  notifications: () => import('../pages/NotificationsPage'),
  behaviorReports: () => import('../pages/BehaviorReportsPage'),
  organization: () => import('../pages/OrganizationPage'),
  security: () => import('../pages/SecuritySettingsPage'),
  audit: () => import('../pages/AuditPage'),
  ingest: () => import('../pages/IngestPage'),
  discovery: () => import('../pages/DiscoveryPage'),
} as const

const prefetched = new Set<string>()

// 根据路由前缀预加载对应页面模块，提升侧边栏切换响应速度。
export function prefetchRoute(to: string) {
  const path = to.split('?')[0]
  const key: keyof typeof loaders | undefined =
    path === '/overview'
      ? 'overview'
      : path === '/reports'
        ? 'reports'
        : path === '/shared-access'
          ? 'sharedAccess'
          : path === '/actions'
            ? 'actionRecords'
            : path === '/ai-relay'
              ? 'aiRelay'
              : path === '/devices'
                ? 'devices'
                : path === '/policies'
                  ? 'policies'
                  : path === '/policies/whitelist'
                    ? 'whitelist'
                    : path === '/policies/blacklist'
                      ? 'blacklist'
                      : path === '/policies/destination-targets'
                        ? 'destinationTargets'
                        : path === '/policies/exceptions'
                          ? 'campusExceptions'
                          : path === '/settings/rules'
                            ? 'rules'
                            : path === '/settings/sources'
                              ? 'sources'
                              : path === '/settings/actions'
                                ? 'actions'
                                : path === '/settings/notifications'
                                  ? 'notifications'
                                  : path === '/settings/behavior-reports'
                                    ? 'behaviorReports'
                                    : path === '/settings/organization'
                                      ? 'organization'
                                      : path === '/settings/security'
                                        ? 'security'
                                        : path === '/audit'
                                          ? 'audit'
                                          : undefined
  if (!key || prefetched.has(key)) return
  prefetched.add(key)
  void loaders[key]()
}

const AuditPage = lazy(() => loaders.audit().then((m) => ({ default: m.AuditPage })))
const DevicesPage = lazy(() => loaders.devices().then((m) => ({ default: m.DeviceCenterPage })))
const EndpointDetailsPage = lazy(() =>
  loaders.endpointDetails().then((m) => ({ default: m.EndpointDetailsPage })),
)
const IpDetailsPage = lazy(() => loaders.ipDetails().then((m) => ({ default: m.IpDetailsPage })))
const IngestPage = lazy(() => loaders.ingest().then((m) => ({ default: m.IngestPage })))
const OverviewPage = lazy(() => loaders.overview().then((m) => ({ default: m.OverviewPage })))
const ReportsPage = lazy(() => loaders.reports().then((m) => ({ default: m.ReportsPage })))
const ReviewDetailsPage = lazy(() =>
  loaders.reviewDetails().then((m) => ({ default: m.ReviewDetailsPage })),
)
const EventDetailsPage = lazy(() =>
  loaders.recordDetails().then((m) => ({ default: m.EventDetailsPage })),
)
const AuditDetailsPage = lazy(() =>
  loaders.recordDetails().then((m) => ({ default: m.AuditDetailsPage })),
)
const IngestDiagnosticDetailsPage = lazy(() =>
  loaders.recordDetails().then((m) => ({ default: m.IngestDiagnosticDetailsPage })),
)
const RulesPage = lazy(() => loaders.rules().then((m) => ({ default: m.RulesPage })))
const CasesPage = lazy(() => loaders.cases().then((m) => ({ default: m.CasesPage })))
const CaseDetailsPage = lazy(() =>
  loaders.caseDetails().then((m) => ({ default: m.CaseDetailsPage })),
)
const OrganizationPage = lazy(() =>
  loaders.organization().then((m) => ({ default: m.OrganizationPage })),
)
const ActionsPage = lazy(() => loaders.actions().then((m) => ({ default: m.ActionsPage })))
const SecuritySettingsPage = lazy(() =>
  loaders.security().then((m) => ({ default: m.SecuritySettingsPage })),
)
const PoliciesPage = lazy(() => loaders.policies().then((m) => ({ default: m.PoliciesPage })))
const SharedAccessPage = lazy(() =>
  loaders.sharedAccess().then((m) => ({ default: m.SharedAccessPage })),
)
const SharedBehaviorDetailsPage = lazy(() =>
  loaders.sharedAccess().then((m) => ({ default: m.SharedBehaviorDetailsPage })),
)
const SharedReviewDetailsPage = lazy(() =>
  loaders.sharedAccess().then((m) => ({ default: m.SharedReviewDetailsPage })),
)
const DiscoveryPage = lazy(() => loaders.discovery().then((m) => ({ default: m.DiscoveryPage })))
const RouterObservationDetailsPage = lazy(() =>
  loaders.routerDetails().then((m) => ({ default: m.RouterObservationDetailsPage })),
)
const ActionRecordsPage = lazy(() =>
  loaders.actionRecords().then((m) => ({ default: m.ActionRecordsPage })),
)
const CampusExceptionsPage = lazy(() =>
  loaders.campusExceptions().then((m) => ({ default: m.CampusExceptionsPage })),
)
const SourcesPage = lazy(() => loaders.sources().then((m) => ({ default: m.SourcesPage })))
const WhitelistPage = lazy(() => loaders.whitelist().then((m) => ({ default: m.WhitelistPage })))
const NotificationsPage = lazy(() =>
  loaders.notifications().then((m) => ({ default: m.NotificationsPage })),
)
const BlacklistPage = lazy(() => loaders.blacklist().then((m) => ({ default: m.BlacklistPage })))
const DestinationTargetsPage = lazy(() =>
  loaders.destinationTargets().then((m) => ({ default: m.DestinationTargetsPage })),
)
const BehaviorReportsPage = lazy(() =>
  loaders.behaviorReports().then((m) => ({ default: m.BehaviorReportsPage })),
)
const AIRelayPage = lazy(() => loaders.aiRelay().then((m) => ({ default: m.AIRelayPage })))

function RouteSuspense({ children }: { children: ReactNode }) {
  return <Suspense fallback={<AppPageSkeleton />}>{children}</Suspense>
}

export function AuditRoute() {
  return (
    <RouteSuspense>
      <AuditPage />
    </RouteSuspense>
  )
}
export function DevicesRoute() {
  return (
    <RouteSuspense>
      <DevicesPage />
    </RouteSuspense>
  )
}
export function EndpointDetailsRoute() {
  return (
    <RouteSuspense>
      <EndpointDetailsPage />
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
export function IngestRoute() {
  return (
    <RouteSuspense>
      <IngestPage />
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
export function ReportsRoute() {
  return (
    <RouteSuspense>
      <ReportsPage />
    </RouteSuspense>
  )
}
export function ReviewDetailsRoute() {
  return (
    <RouteSuspense>
      <ReviewDetailsPage />
    </RouteSuspense>
  )
}
export function EventDetailsRoute() {
  return (
    <RouteSuspense>
      <EventDetailsPage />
    </RouteSuspense>
  )
}
export function AuditDetailsRoute() {
  return (
    <RouteSuspense>
      <AuditDetailsPage />
    </RouteSuspense>
  )
}
export function IngestDiagnosticDetailsRoute() {
  return (
    <RouteSuspense>
      <IngestDiagnosticDetailsPage />
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
export function CasesRoute() {
  return (
    <RouteSuspense>
      <CasesPage />
    </RouteSuspense>
  )
}
export function CaseDetailsRoute() {
  return (
    <RouteSuspense>
      <CaseDetailsPage />
    </RouteSuspense>
  )
}
export function OrganizationRoute() {
  return (
    <RouteSuspense>
      <OrganizationPage />
    </RouteSuspense>
  )
}
export function ActionsRoute() {
  return (
    <RouteSuspense>
      <ActionsPage />
    </RouteSuspense>
  )
}
export function SecuritySettingsRoute() {
  return (
    <RouteSuspense>
      <SecuritySettingsPage />
    </RouteSuspense>
  )
}
export function PoliciesRoute() {
  return (
    <RouteSuspense>
      <PoliciesPage />
    </RouteSuspense>
  )
}
export function SharedAccessRoute() {
  return (
    <RouteSuspense>
      <SharedAccessPage />
    </RouteSuspense>
  )
}
export function SharedBehaviorDetailsRoute() {
  return (
    <RouteSuspense>
      <SharedBehaviorDetailsPage />
    </RouteSuspense>
  )
}
export function SharedReviewDetailsRoute() {
  return (
    <RouteSuspense>
      <SharedReviewDetailsPage />
    </RouteSuspense>
  )
}
export function DiscoveryRoute() {
  return (
    <RouteSuspense>
      <DiscoveryPage />
    </RouteSuspense>
  )
}
export function RouterObservationDetailsRoute() {
  return (
    <RouteSuspense>
      <RouterObservationDetailsPage />
    </RouteSuspense>
  )
}
export function ActionRecordsRoute() {
  return (
    <RouteSuspense>
      <ActionRecordsPage />
    </RouteSuspense>
  )
}
export function CampusExceptionsRoute() {
  return (
    <RouteSuspense>
      <CampusExceptionsPage />
    </RouteSuspense>
  )
}
export function SourcesRoute() {
  return (
    <RouteSuspense>
      <SourcesPage />
    </RouteSuspense>
  )
}
export function WhitelistRoute() {
  return (
    <RouteSuspense>
      <WhitelistPage />
    </RouteSuspense>
  )
}
export function NotificationsRoute() {
  return (
    <RouteSuspense>
      <NotificationsPage />
    </RouteSuspense>
  )
}
export function BlacklistRoute() {
  return (
    <RouteSuspense>
      <BlacklistPage />
    </RouteSuspense>
  )
}
export function DestinationTargetsRoute() {
  return (
    <RouteSuspense>
      <DestinationTargetsPage />
    </RouteSuspense>
  )
}
export function BehaviorReportsRoute() {
  return (
    <RouteSuspense>
      <BehaviorReportsPage />
    </RouteSuspense>
  )
}
export function AIRelayRoute() {
  return (
    <RouteSuspense>
      <AIRelayPage />
    </RouteSuspense>
  )
}
