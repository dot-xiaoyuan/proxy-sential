import { useState } from 'react'

import { useRisks } from '../shared/api/queries'
import type { RiskLevel } from '../shared/api/types'
import {
  AppErrorAlert,
  AppLoadingState,
  AppMetricCard,
  AppPageHeader,
  AppTableBar,
  type QuickWindow,
} from '../shared/ui'
import { RiskTable } from '../widgets/RiskTable'

export function RisksPage() {
  const [quickWindow, setQuickWindow] = useState<QuickWindow>('1h')
  const [level, setLevel] = useState<RiskLevel | 'all'>('all')
  const [ipQuery, setIpQuery] = useState('')

  const risks = useRisks({
    level: level === 'all' ? undefined : level,
    limit: 100,
  })

  if (risks.isLoading) {
    return <AppLoadingState rows={6} />
  }

  const rawItems = risks.data?.items ?? []
  const items = rawItems.filter((i) => (!ipQuery ? true : i.ip.includes(ipQuery) || i.summary.includes(ipQuery)))

  const confirmedCount = rawItems.filter((i) => i.level === 'confirmed').length
  const highCount = rawItems.filter((i) => i.level === 'high').length
  const normalCount = rawItems.filter((i) => i.level === 'normal').length

  const filterOptions = [
    { key: 'confirmed', label: '确认代理 (Confirmed)', active: level === 'confirmed' },
    { key: 'high', label: '高风险 (High)', active: level === 'high' },
    { key: 'suspicious', label: '疑点 (Suspicious)', active: level === 'suspicious' },
    { key: 'normal', label: '正常终端 (Normal)', active: level === 'normal' },
  ]

  return (
    <main className="page">
      <AppPageHeader
        loading={risks.isFetching}
        onQuickWindowChange={setQuickWindow}
        onRefresh={() => void risks.refetch()}
        quickWindow={quickWindow}
        subtitle="展示网络环境中 Sensor 实时识别的所有设备 IP 风险快照、综合评分与处置建议"
        title="全网络识别设备与风险 IP 监控"
      />

      <section className="metric-grid">
        <AppMetricCard
          statusColor="blue"
          statusText="观测快照"
          title="识别终端 IP 总数"
          value={rawItems.length}
        />
        <AppMetricCard
          statusColor="red"
          statusText="需要判定"
          title="确认代理终端 (Confirmed)"
          value={confirmedCount}
        />
        <AppMetricCard
          statusColor="orange"
          statusText="疑似共享"
          title="高风险设备 (High)"
          value={highCount}
        />
        <AppMetricCard
          statusColor="green"
          statusText="极低风险"
          title="正常终端 (Normal)"
          value={normalCount}
        />
      </section>

      {risks.isError && <AppErrorAlert title="加载设备风险快照失败" />}

      <AppTableBar
        filterOptions={filterOptions}
        onClearFilters={() => {
          setLevel('all')
          setIpQuery('')
        }}
        onFilterToggle={(key) => setLevel(level === key ? 'all' : (key as RiskLevel))}
        onSearchChange={setIpQuery}
        searchPlaceholder="搜索 IP 或摘要 (如 10.255.0.59 / multi_ja3)..."
        searchValue={ipQuery}
        totalCount={items.length}
      />

      <section className="surface">
        <RiskTable data={items} loading={risks.isFetching} />
      </section>
    </main>
  )
}
