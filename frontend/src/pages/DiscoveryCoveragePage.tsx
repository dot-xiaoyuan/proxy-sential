import { useQuery } from '@tanstack/react-query'
import { Button, Select, Typography } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { useSearchParams } from 'react-router-dom'
import { request } from '../shared/api/client'
import type { components } from '../shared/api/generated'
import { DiscoveryCoverageReport } from './DiscoveryCoverageReport'
import { DiscoveryCoverageDiagnostics } from './DiscoveryCoverageDiagnostics'
import { CensusPanel } from './CensusPanel'

const windows = [
  { value: '15m', label: '近 15 分钟' },
  { value: '24h', label: '近 24 小时' },
  { value: '168h', label: '近 7 天' },
  { value: '720h', label: '近 30 天' },
]

export function DiscoveryCoveragePage() {
  const [params, setParams] = useSearchParams()
  const requested = params.get('window') || '24h'
  const window = windows.some(item => item.value === requested) ? requested : '24h'
  const coverage = useQuery({
    queryKey: ['discovery-coverage-report', window],
    queryFn: ({signal}) => request<components['schemas']['DiscoveryCoverageReport']>(`/discovery/devices/coverage-report?window=${window}`, {signal}),
    staleTime: 60_000,
  })
  return <main className="page device-center-page discovery-coverage-page">
    <header className="discovery-report-page-header">
      <div><Typography.Title level={3}>设备发现覆盖报表</Typography.Title><Typography.Text type="secondary">镜像流量发现范围与设备事实对照</Typography.Text></div>
      <div className="discovery-report-page-actions">
        <Select aria-label="统计时间范围" value={window} options={windows} onChange={value => setParams({window:value})}/>
        <Button icon={<ReloadOutlined aria-hidden="true"/>} onClick={() => void coverage.refetch()} loading={coverage.isFetching}>刷新</Button>
      </div>
    </header>
    <DiscoveryCoverageReport report={coverage.data} loading={coverage.isPending} error={coverage.isError}/>
    <details className="discovery-coverage-advanced"><summary>查看原因分析与镜像明细</summary>
      <DiscoveryCoverageDiagnostics/>
      <CensusPanel/>
    </details>
  </main>
}
