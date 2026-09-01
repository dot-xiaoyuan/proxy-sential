import { useEffect, useState } from 'react'
import { Pagination } from 'antd'

import { useRisks } from '../shared/api/queries'
import type { RiskLevel } from '../shared/api/types'
import { AppErrorAlert, AppLoadingState, AppPageHeader, AppTableBar, type QuickWindow } from '../shared/ui'
import { RiskTable } from '../widgets/RiskTable'

export function RisksPage() {
  const [quickWindow, setQuickWindow] = useState<QuickWindow>('1h')
  const [level, setLevel] = useState<RiskLevel | 'all'>('all')
  const [searchInput, setSearchInput] = useState('')
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  useEffect(() => { const timer = globalThis.setTimeout(() => { setQuery(searchInput.trim()); setPage(1) }, 300); return () => globalThis.clearTimeout(timer) }, [searchInput])
  const risks = useRisks({ level: level === 'all' ? undefined : level, q: query, limit: pageSize, cursor: String((page - 1) * pageSize) })
  const filterOptions = [
    { key:'confirmed',label:'确认代理',active:level==='confirmed' }, { key:'high',label:'高风险',active:level==='high' },
    { key:'suspicious',label:'疑点',active:level==='suspicious' }, { key:'normal',label:'正常',active:level==='normal' },
  ]
  if (risks.isLoading) return <AppLoadingState rows={8} />
  return <main className="page">
    <AppPageHeader title="风险 IP 监控" subtitle="单行展示风险摘要，点击 IP 查看设备、证据与事件详情。" quickWindow={quickWindow} onQuickWindowChange={setQuickWindow} loading={risks.isFetching} onRefresh={() => void risks.refetch()} />
    {risks.isError && <AppErrorAlert title="加载风险快照失败" message={risks.error.message} />}
    <AppTableBar filterOptions={filterOptions} onClearFilters={() => {setLevel('all');setSearchInput('');setPage(1)}} onFilterToggle={(key) => {setLevel(level===key?'all':key as RiskLevel);setPage(1)}} onSearchChange={setSearchInput} searchPlaceholder="搜索 IP 或风险摘要" searchValue={searchInput} totalCount={risks.data?.page.total ?? 0} />
    <section className="surface"><RiskTable data={risks.data?.items ?? []} loading={risks.isFetching} /><Pagination className="list-pagination" current={page} pageSize={pageSize} total={risks.data?.page.total ?? 0} showSizeChanger pageSizeOptions={[20,50]} onChange={(next,size)=>{setPageSize(size);setPage(next)}} /></section>
  </main>
}
