import { Tag, Tooltip, Typography } from 'antd'
import { Link } from 'react-router-dom'
import type { EndpointDeviceInventory } from '../../shared/api/types'
import { BrandLogo } from './BrandLogo'
import { OperatingSystemLabel } from './OperatingSystemLabel'

export function deviceDetailsURL(device: EndpointDeviceInventory) {
  return `/devices/${encodeURIComponent(device.endpoint_id)}`
}

export function DeviceMAC({ device, href }: { device: EndpointDeviceInventory; href?:string }) {
  const vendor = (device.vendor_confidence ?? 0) >= .8 && device.vendor?.toLowerCase() !== 'unknown' ? device.vendor : ''
  return <div className="device-mac-identity"><div className="device-mac-cell">
    <Link className="mono device-mac-link" to={href || deviceDetailsURL(device)} title={vendor ? `MAC 注册厂商：${vendor}；不代表整机品牌` : device.primary_mac || '查看终端详情'}>{device.primary_mac || ''}</Link>
    {device.primary_mac && <Typography.Text className="device-copy-control" copyable={{ text: device.primary_mac }} />}
  </div></div>

}

export function DeviceBrandSummary({ device }: { device: EndpointDeviceInventory }) {
  const safe = !device.recognition_conflict
  const brand = safe && (device.brand_confidence ?? 0) >= 0.8 ? device.brand : ''
  const inference = device.brand_inference
  const inferred = !brand && inference?.status === 'inferred'
  const model = safe && (device.model_confidence ?? 0) >= 0.8 ? device.model : ''
  const reference = safe && !brand && inference?.status !== 'conflict' && (!inferred || device.brand_reference?.brand.toLowerCase() === inference.brand?.toLowerCase()) ? device.brand_reference : undefined
  const platform = virtualPlatform(device)
  const label = brand || (inferred ? inference.brand : reference?.brand || '')
  const os = safe && device.os_family?.toLowerCase() !== 'unknown' ? device.os_family : ''
  const conflict = device.recognition_conflict || inference?.status === 'conflict'
  return <div className="device-brand-summary">
    <div className={`device-brand-heading${!brand ? ' device-brand-tentative' : ''}`}>
      {label ? <BrandLogo brandKey={label} /> : <Typography.Text type="secondary"></Typography.Text>}
      {inferred && !reference && <Tooltip title={`推测 ${inference.brand} · 域名证据评分 ${Math.round(inference.confidence * 100)}%，不确认硬件品牌；查看详情了解依据。`}><Tag className="device-inference-tag">域名推测</Tag></Tooltip>}
      {reference && <Tooltip title={`${reference.explanation} · 来源：${reference.vendor} · 参考评分 ${Math.round(reference.confidence * 100)}%${inferred ? `；域名推测 ${inference.brand}，证据评分 ${Math.round(inference.confidence*100)}%` : ''}`}><Tag className="device-inference-tag">{inferred?'品牌线索':'MAC 厂商线索'}</Tag></Tooltip>}
      {conflict && <Tooltip title="识别线索存在冲突，查看详情核对证据"><Tag className="device-conflict-tag">线索冲突</Tag></Tooltip>}
    </div>
    {platform && <Tooltip title="MAC 注册厂商为 VMware，提示虚拟网卡/虚拟化平台；不确认宿主机品牌，也不作为代理或共享上网的判定依据。"><div className="device-platform-clue"><BrandLogo brandKey="VMware" /><Tag className="device-inference-tag">虚拟机线索</Tag></div></Tooltip>}
    {os && <div className="device-os-summary"><OperatingSystemLabel family={os} confirmed={(device.os_family_confidence ?? 0) >= .8} />{(device.os_family_confidence ?? 0) < .8 && <Tooltip title={`操作系统线索置信度 ${Math.round((device.os_family_confidence ?? 0) * 100)}%，查看详情核对识别证据。`}><Tag className="device-inference-tag">系统推测</Tag></Tooltip>}</div>}
    {device.discovery?.conflict && <Tag className="device-conflict-tag">发现线索冲突</Tag>}
    {!!device.discovery?.capabilities?.length && <Typography.Text type="secondary" className="device-model">{device.discovery.capabilities.map(c=>({printing:'打印服务',scanning:'扫描服务',casting:'投屏服务',network_video:'网络视频'}[c]??c)).join(' · ')}</Typography.Text>}
    {model && <Typography.Text type="secondary" className="list-cell-nowrap device-model" title={model}>{model}</Typography.Text>}
    {device.router_observation && <Link className={`router-device-summary router-device-summary-${device.router_observation.status}`} to={`/discovery/routers/${encodeURIComponent(device.router_observation.assessment_id)}`}>
      路由观察 · {routerStatusLabel(device.router_observation.status)} · {device.router_observation.confidence}
    </Link>}
  </div>
}

function routerStatusLabel(status: string) {
  return ({ candidate: '候选', likely: '较可信', confirmed: '已确认' } as Record<string, string>)[status] || status
}

// Virtual-interface vendors are shown independently, never promoted to hardware brand.
export function virtualPlatform(device: EndpointDeviceInventory): string | undefined {
  const mac = device.primary_mac || ''
  if (!/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(mac) || (parseInt(mac.slice(0, 2), 16) & 3) !== 0 || device.randomized_mac || (device.vendor_confidence ?? 0) < .8) return undefined
  if (/^vmware(?:[\s,.]|$)/i.test(device.vendor?.trim() || '')) return 'VMware'
  return undefined
}
