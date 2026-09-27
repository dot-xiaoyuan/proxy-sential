import { lazy, Suspense, type ReactNode } from 'react'
import { Spin } from 'antd'

const AuditPage = lazy(() => import('../pages/AuditPage').then((module) => ({ default: module.AuditPage })))
const ActivityPage = lazy(() =>
  import('../pages/ActivityPage').then((module) => ({ default: module.ActivityPage })),
)
const EventsPage = lazy(() => import('../pages/EventsPage').then((module) => ({ default: module.EventsPage })))
const DevicesPage = lazy(() => import('../pages/DevicesPage').then((module) => ({ default: module.DevicesPage })))
const AttributionDiagnosticsPage = lazy(() => import('../pages/AttributionDiagnosticsPage').then((module) => ({ default: module.AttributionDiagnosticsPage })))
const EndpointDetailsPage = lazy(() =>
  import('../pages/EndpointDetailsPage').then((module) => ({ default: module.EndpointDetailsPage })),
)
const IpDetailsPage = lazy(() =>
  import('../pages/IpDetailsPage').then((module) => ({ default: module.IpDetailsPage })),
)
const IngestPage = lazy(() => import('../pages/IngestPage').then((module) => ({ default: module.IngestPage })))
const OverviewPage = lazy(() =>
  import('../pages/OverviewPage').then((module) => ({ default: module.OverviewPage })),
)
const ReviewPage = lazy(() => import('../pages/ReviewPage').then((module) => ({ default: module.ReviewPage })))
const ReviewDetailsPage = lazy(() => import('../pages/ReviewDetailsPage').then((module) => ({ default: module.ReviewDetailsPage })))
const EventDetailsPage = lazy(() => import('../pages/RecordDetailsPages').then((module) => ({ default: module.EventDetailsPage })))
const ShadowRunDetailsPage = lazy(() => import('../pages/RecordDetailsPages').then((module) => ({ default: module.ShadowRunDetailsPage })))
const AuditDetailsPage = lazy(() => import('../pages/RecordDetailsPages').then((module) => ({ default: module.AuditDetailsPage })))
const IngestDiagnosticDetailsPage = lazy(() => import('../pages/RecordDetailsPages').then((module) => ({ default: module.IngestDiagnosticDetailsPage })))
const RisksPage = lazy(() => import('../pages/RisksPage').then((module) => ({ default: module.RisksPage })))
const RulesPage = lazy(() => import('../pages/RulesPage').then((module) => ({ default: module.RulesPage })))
const ShadowRunsPage = lazy(() =>
  import('../pages/ShadowRunsPage').then((module) => ({ default: module.ShadowRunsPage })),
)
const CasesPage = lazy(() => import('../pages/CasesPage').then(module=>({default:module.CasesPage})))
const CaseDetailsPage = lazy(() => import('../pages/CaseDetailsPage').then(module=>({default:module.CaseDetailsPage})))
const OrganizationPage = lazy(() => import('../pages/OrganizationPage').then(module=>({default:module.OrganizationPage})))
const ActionsPage = lazy(() => import('../pages/ActionsPage').then(module=>({default:module.ActionsPage})))
const SecuritySettingsPage = lazy(() => import('../pages/SecuritySettingsPage').then(module=>({default:module.SecuritySettingsPage})))

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

export function ActivityRoute() {
  return (
    <RouteSuspense>
      <ActivityPage />
    </RouteSuspense>
  )
}

export function EventsRoute() {
  return (
    <RouteSuspense>
      <EventsPage />
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

export function AttributionDiagnosticsRoute() {
  return <RouteSuspense><AttributionDiagnosticsPage /></RouteSuspense>
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

export function ReviewRoute() {
  return (
    <RouteSuspense>
      <ReviewPage />
    </RouteSuspense>
  )
}

export function ReviewDetailsRoute() { return <RouteSuspense><ReviewDetailsPage /></RouteSuspense> }
export function EventDetailsRoute() { return <RouteSuspense><EventDetailsPage /></RouteSuspense> }
export function ShadowRunDetailsRoute() { return <RouteSuspense><ShadowRunDetailsPage /></RouteSuspense> }
export function AuditDetailsRoute() { return <RouteSuspense><AuditDetailsPage /></RouteSuspense> }
export function IngestDiagnosticDetailsRoute() { return <RouteSuspense><IngestDiagnosticDetailsPage /></RouteSuspense> }

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
export function CasesRoute(){return <RouteSuspense><CasesPage/></RouteSuspense>}
export function CaseDetailsRoute(){return <RouteSuspense><CaseDetailsPage/></RouteSuspense>}
export function OrganizationRoute(){return <RouteSuspense><OrganizationPage/></RouteSuspense>}
export function ActionsRoute(){return <RouteSuspense><ActionsPage/></RouteSuspense>}
export function SecuritySettingsRoute(){return <RouteSuspense><SecuritySettingsPage/></RouteSuspense>}
