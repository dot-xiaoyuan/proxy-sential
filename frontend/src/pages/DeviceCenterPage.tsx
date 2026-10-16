import { InfoCircleOutlined } from '@ant-design/icons'
import { Tooltip, Typography } from 'antd'
import { useSearchParams } from 'react-router-dom'
import { deviceCenterTab } from '../app/navigation'
import { DevicesPage } from './DevicesPage'
import { RouterObservationsPanel } from './RouterObservationsPanel'

// 设备中心的每个子菜单是独立页面：终端列表与路由器各自开发、各自展示。
// 哑终端与发现线索随采集侧 ARP 一并暂停，旧链接（tab=iot/records）回落到终端列表。
const views = {
  terminal: { title: '终端列表', hint: '按终端身份查看在线终端与最近归属；最近观测不代表当前在线。' },
  network: { title: '路由器', hint: '按网络设备身份查看疑似路由器、共享接入证据与归属账号。' },
} as const

export function DeviceCenterPage() {
  const [params] = useSearchParams()
  const tab = deviceCenterTab(params)
  const view = views[tab]
  return <main className="page device-center-page">
    <header className="center-header"><div className="center-header-title">
      <Typography.Title level={3}>{view.title}</Typography.Title>
      <Tooltip title={view.hint}><InfoCircleOutlined className="center-title-hint" aria-label={`${view.title}说明`} /></Tooltip>
    </div></header>
    {tab === 'terminal' && <DevicesPage embedded />}
    {tab === 'network' && <section className="device-center-network"><RouterObservationsPanel /></section>}
  </main>
}
