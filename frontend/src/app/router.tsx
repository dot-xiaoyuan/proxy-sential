import { Navigate, createBrowserRouter } from 'react-router-dom'

import { AppShell } from './AppShell'
import {
  ActivityRoute,
  AuditRoute,
  DevicesRoute,
  EndpointDetailsRoute,
  EventsRoute,
  IngestRoute,
  IpDetailsRoute,
  OverviewRoute,
  ReviewRoute,
  RisksRoute,
  RulesRoute,
  ShadowRunsRoute,
} from './routePages'

export const router = createBrowserRouter([
  {
    path: '/',
    element: <AppShell />,
    children: [
      { index: true, element: <Navigate replace to="/overview" /> },
      { path: 'overview', element: <OverviewRoute /> },
      { path: 'activity', element: <ActivityRoute /> },
      { path: 'devices', element: <DevicesRoute /> },
      { path: 'devices/:endpointId', element: <EndpointDetailsRoute /> },
      { path: 'events', element: <EventsRoute /> },
      { path: 'ingest', element: <IngestRoute /> },
      { path: 'risks', element: <RisksRoute /> },
      { path: 'ips/:ip', element: <IpDetailsRoute /> },
      { path: 'review', element: <ReviewRoute /> },
      { path: 'shadow-runs', element: <ShadowRunsRoute /> },
      { path: 'audit', element: <AuditRoute /> },
      { path: 'settings/rules', element: <RulesRoute /> },
    ],
  },
])
