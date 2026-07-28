import { Navigate, createBrowserRouter } from 'react-router-dom'

import { AppShell } from './AppShell'
import {
  ActivityRoute,
  AuditRoute,
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
