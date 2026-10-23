import { useSearchParams } from 'react-router-dom'
import { deviceCenterTab } from '../app/navigation'
import { DevicesPage } from './DevicesPage'
import { RouterObservationsPanel } from './RouterObservationsPanel'

// 设备中心的每个子菜单是独立页面：终端列表与路由器各自展示。
// 页面标题由顶部栏按菜单项显示，这里直接进入列表内容。
export function DeviceCenterPage() {
  const [params] = useSearchParams()
  const tab = deviceCenterTab(params)
  return <main className="page device-center-page">
    {tab === 'network' ? <section className="device-center-network"><RouterObservationsPanel /></section> : <DevicesPage embedded />}
  </main>
}
