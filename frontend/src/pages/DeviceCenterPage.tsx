import '../styles/pages/devices.css'
import '../styles/pages/shared-access.css'
import { Tabs } from 'antd'
import { Navigate, useSearchParams } from 'react-router-dom'
import { deviceCenterTab } from '../app/navigation'
import { useUrlState } from '../shared/ui/useUrlState'
import { DevicesPage } from './DevicesPage'
import { RouterObservationsPanel } from './RouterObservationsPanel'
import { RouterSharingCandidates } from './RouterSharingCandidates'
import { SharedDeviceProfiles } from './SharedDeviceProfiles'

const legacyDiscoveryTabs = new Set(['discovery', 'iot', 'records'])

// 设备中心的每个子菜单是独立页面：终端列表与路由器各自展示。
// 路由器视图下提供单层切换：路由器台账、路由器核验与涉共享设备档案。
export function DeviceCenterPage() {
  const [params] = useSearchParams()
  const [networkView, setNetworkView] = useUrlState(
    'network_view',
    'observations',
    ['observations', 'candidates', 'profiles'],
    [
      'router_sharing_page',
      'router_sharing_cursors',
      'shared_devices_page',
      'shared_devices_cursors',
    ],
  )
  const rawTab = params.get('tab') || ''
  if (legacyDiscoveryTabs.has(rawTab)) {
    return <Navigate replace to="/devices?tab=terminal" />
  }
  const tab = deviceCenterTab(params)
  return (
    <main className="page device-center-page">
      {tab === 'network' ? (
        <section className="device-center-network">
          <div className="page-tabs-row">
            <Tabs
              className="page-section-tabs"
              activeKey={networkView}
              onChange={setNetworkView}
              items={[
                { key: 'observations', label: '路由器台账' },
                { key: 'candidates', label: '路由器核验' },
                { key: 'profiles', label: '涉共享设备档案' },
              ]}
            />
          </div>
          {networkView === 'candidates' ? (
            <RouterSharingCandidates />
          ) : networkView === 'profiles' ? (
            <SharedDeviceProfiles />
          ) : (
            <RouterObservationsPanel />
          )}
        </section>
      ) : (
        <DevicesPage embedded />
      )}
    </main>
  )
}
