import { ReloadOutlined } from '@ant-design/icons'
import { useIsFetching, useQueryClient } from '@tanstack/react-query'
import { Button, Select } from 'antd'
import { Link, useLocation, useSearchParams } from 'react-router-dom'

import { reportSections } from '../app/reportSections'
import { AuditReports, DeviceReports, RiskReports, SharingReports } from '../features/reports/BusinessReports'
import { PipelineReports, ResourceReports } from '../features/reports/RuntimeReports'
import { TrafficReports } from '../features/reports/TrafficReports'
import { useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
import type { ReportWindow } from '../shared/ui'
import { Notice } from '../shared/ui/Notice'
import { useUrlState } from '../shared/ui/useUrlState'

const reportWindows: { value: ReportWindow; label: string }[] = [
  { value: '10m', label: '近 10 分钟' }, { value: '1h', label: '近 1 小时' }, { value: '24h', label: '近 24 小时' },
  { value: '7d', label: '近 7 天' }, { value: '30d', label: '近 30 天' },
]

export function ReportsPage() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  const fetching = useIsFetching({ queryKey: ['reports'] }) > 0
  const location = useLocation()
  const [params] = useSearchParams()
  const [window, setWindow] = useUrlState('window', '1h', reportWindows.map((option) => option.value))
  const sections = reportSections.filter(({ permissions }) => permissions.some((permission) => can(session, permission)))
  const current = sections.find((section) => section.key === params.get('section')) ?? sections[0]
  if (!session || !current) {
    return <main className="page"><Notice showIcon type="warning" title="没有报表访问权限" /></main>
  }

  const returnTo = location.pathname + location.search
  return (
    <main className="page reports-page">
      <div className="report-toolbar">
        <nav className="report-nav" aria-label="报表分类">
          {sections.map((section) => <Link key={section.key} to={`/reports?section=${section.key}`}
            aria-current={section.key === current.key ? 'page' : undefined}>{section.label}</Link>)}
        </nav>
        <Button className="report-refresh" icon={<ReloadOutlined />} loading={fetching}
          onClick={() => void queryClient.invalidateQueries({ queryKey: ['reports'], refetchType: 'active' })}>
          刷新报表
        </Button>
      </div>
      {current.key === 'traffic' && can(session, 'dpi:read') && <div className="report-filter">
        <label htmlFor="report-window">流量统计窗口</label>
        <Select id="report-window" className="report-select" value={window} onChange={setWindow} options={reportWindows} />
      </div>}
      <div className="report-panels" aria-label={current.label}>
        {current.key === 'sharing' && <SharingReports session={session} returnTo={returnTo} />}
        {current.key === 'risk' && <RiskReports session={session} returnTo={returnTo} />}
        {current.key === 'devices' && <DeviceReports session={session} />}
        {current.key === 'traffic' && <TrafficReports session={session} window={window as ReportWindow} />}
        {current.key === 'pipeline' && <PipelineReports session={session} />}
        {current.key === 'operations' && <>
          <ResourceReports session={session} />
          <AuditReports session={session} returnTo={returnTo} />
        </>}
      </div>
    </main>
  )
}
