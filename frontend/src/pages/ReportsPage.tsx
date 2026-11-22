import { ReloadOutlined } from '@ant-design/icons'
import { useIsFetching, useQueryClient } from '@tanstack/react-query'
import { Button } from 'antd'

import { RouterReport, SharedBehaviorReport, SharingCoverageReport, SharingTrendReport } from '../features/reports/DefenseReports'
import { useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
import { Notice } from '../shared/ui/Notice'

export function ReportsPage() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  const fetching = useIsFetching({ queryKey: ['reports'] }) > 0
  const identity = can(session, 'identity:read')
  const policies = can(session, 'policies:read')
  const cases = can(session, 'cases:read')
  if (!identity && !policies && !cases) {
    return <main className="page"><Notice showIcon type="warning" title="没有报表访问权限" /></main>
  }

  return (
    <main className="page reports-page">
      <div className="report-toolbar">
        <Button className="report-refresh" icon={<ReloadOutlined />} loading={fetching}
          onClick={() => void queryClient.invalidateQueries({ queryKey: ['reports'], refetchType: 'active' })}>
          刷新报表
        </Button>
      </div>
      <div className="report-panels">
        {policies && <SharingTrendReport />}
        {identity && <RouterReport />}
      </div>
      <div className="report-panels report-diagnostics">
        {cases && <SharedBehaviorReport />}
        {identity && <SharingCoverageReport />}
      </div>
    </main>
  )
}
