import { useSearchParams } from 'react-router-dom'
import { deviceCenterTab } from '../app/navigation'
import { PassiveDiscoveryPanel } from './PassiveDiscoveryPanel'
import { DevicesPage } from './DevicesPage'
import { RouterObservationsPanel } from './RouterObservationsPanel'

// 设备中心的每个子菜单是独立页面：终端列表、路由器与发现设备各自展示。
// 页面标题由顶部栏按菜单项显示，这里直接进入列表内容。
export function DeviceCenterPage() {
  const [params] = useSearchParams()
  const tab = deviceCenterTab(params)
  return <main className="page device-center-page">
    {tab === 'network' ? <section className="device-center-network"><RouterObservationsPanel /></section> : tab === 'discovery' ? <PassiveDiscoveryPanel view={params.get('tab') === 'iot' ? 'iot' : 'records'} /> : <DevicesPage embedded />}
  </main>
}
