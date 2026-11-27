import '../styles/pages/system.css'
import '../styles/pages/devices.css'
import { Tabs } from 'antd'
import { useSearchParams } from 'react-router-dom'
import { useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
import { useUrlState } from '../shared/ui/useUrlState'
import { ActionsPage } from './ActionsPage'
import { IngestPage } from './IngestPage'
import { DiscoveryPage } from './DiscoveryPage'

// 采集与接入整合页：合并原“数据源与采集”与“认证与处置接入”。
export function SourcesPage() {
  const session = useSession()
  const [params] = useSearchParams()
  const canReadIngest = can(session.data, 'ingest:read')
  const canReadIdentity = can(session.data, 'identity:read')
  const canReadSources = canReadIngest || canReadIdentity
  const canReadActions = can(session.data, 'actions:read')
  const defaultSection = canReadSources ? 'sources' : 'actions'
  const [tab, setTab] = useUrlState('tab', defaultSection, ['sources', 'actions'])
  const legacySubTab = ['scan', 'tasks'].includes(params.get('tab') || '')
    ? (params.get('tab') as 'scan' | 'tasks')
    : undefined
  const defaultSourceTab = canReadIngest ? 'diagnostics' : 'sources'
  const [sourceTab, setSourceTab] = useUrlState('source_tab', legacySubTab ?? defaultSourceTab, [
    'diagnostics',
    'sources',
    'scan',
    'tasks',
  ])

  const sectionItems = [
    ...(canReadSources ? [{ key: 'sources', label: '数据源与采集' }] : []),
    ...(canReadActions ? [{ key: 'actions', label: '认证与处置接入' }] : []),
  ]
  const activeSection = sectionItems.some((item) => item.key === tab)
    ? tab
    : (sectionItems[0]?.key ?? 'sources')

  const sourceSubItems = [
    ...(canReadIngest ? [{ key: 'diagnostics', label: '采集诊断' }] : []),
    ...(canReadIdentity
      ? [
          { key: 'sources', label: '基础设施接入' },
          { key: 'scan', label: '主动发现' },
          { key: 'tasks', label: '发现任务' },
        ]
      : []),
  ]
  const activeSourceTab = sourceSubItems.some((item) => item.key === sourceTab)
    ? sourceTab
    : (sourceSubItems[0]?.key ?? 'diagnostics')

  return (
    <main className="page sources-page">
      <section className="surface">
        <Tabs activeKey={activeSection} onChange={setTab} items={sectionItems} />
      </section>
      {activeSection === 'actions' ? (
        <ActionsPage embedded />
      ) : (
        <>
          {sourceSubItems.length > 1 && (
            <section className="surface">
              <Tabs activeKey={activeSourceTab} onChange={setSourceTab} items={sourceSubItems} />
            </section>
          )}
          {activeSourceTab === 'diagnostics' ? (
            <IngestPage embedded />
          ) : (
            <DiscoveryPage configuration embedded tabParamKey="source_tab" />
          )}
        </>
      )}
    </main>
  )
}
