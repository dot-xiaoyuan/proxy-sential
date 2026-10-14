import { InfoCircleOutlined } from '@ant-design/icons'
import { Tabs, Tooltip, Typography } from 'antd'
import { useSearchParams } from 'react-router-dom'
import { DevicesPage } from './DevicesPage'
import { RouterObservationsPanel } from './RouterObservationsPanel'
import { PassiveDiscoveryPanel } from './PassiveDiscoveryPanel'

const tabs = [{ key: 'terminal', label: '终端' }, { key: 'network', label: '网络设备' }, { key: 'iot', label: '哑终端' }, { key: 'records', label: '发现线索' }]

export function DeviceCenterPage() {
  const [params, setParams] = useSearchParams()
  const requested = params.get('tab')
  const tab = tabs.some(item => item.key === requested) ? requested! : 'terminal'
  const selectTab = (value: string) => setParams(current => {
    const next = new URLSearchParams(current)
    next.set('tab', value)
    for (const key of ['page', 'cursor', 'routers_page', 'discovery_page', 'device']) next.delete(key)
    return next
  }, { replace: true })
  return <main className="page device-center-page">
    <header className="center-header"><div className="center-header-title">
      <Typography.Title level={3}>设备中心</Typography.Title>
      <Tooltip title="按设备身份查看终端、网络设备和发现证据；最近观测和服务公告不代表当前在线。"><InfoCircleOutlined className="center-title-hint" aria-label="设备中心说明" /></Tooltip>
    </div></header>
    <Tabs activeKey={tab} onChange={selectTab} items={tabs} />
    {tab === 'terminal' && <DevicesPage embedded />}
    {tab === 'network' && <section className="surface device-center-network"><RouterObservationsPanel /></section>}
    {(tab === 'iot' || tab === 'records') && <PassiveDiscoveryPanel key={tab} view={tab} />}
  </main>
}
