import { Tag, Tooltip, Typography } from 'antd'
import { Link } from 'react-router-dom'
import { CloudServerOutlined, DeploymentUnitOutlined, DesktopOutlined, HddOutlined, LaptopOutlined, MobileOutlined, PrinterOutlined, TabletOutlined } from '@ant-design/icons'
import type { DeviceInventoryListItem, EndpointDeviceInventory } from '../../shared/api/types'
import { BrandLogo } from './BrandLogo'
import { DeviceNameView } from './DeviceNameView'
import { OperatingSystemLabel } from './OperatingSystemLabel'
import { resolveDeviceBrand } from './brandMatcher'

type DeviceDisplayItem = EndpointDeviceInventory | DeviceInventoryListItem

export function deviceDetailsURL(device: DeviceDisplayItem) {
  return `/devices/${encodeURIComponent(device.endpoint_id)}`
}

export function DeviceMAC({ device, href }: { device: DeviceDisplayItem; href?:string }) {
  const vendor = (device.vendor_confidence ?? 0) >= .8 && device.vendor?.toLowerCase() !== 'unknown' ? device.vendor : ''
  return <div className="device-mac-identity"><div className="device-mac-cell">
    <Link className="mono device-mac-link" to={href || deviceDetailsURL(device)} title={vendor ? `MAC 注册厂商：${vendor}；不代表整机品牌` : device.primary_mac || '查看终端详情'}>{device.primary_mac || ''}</Link>
    {device.primary_mac && <Typography.Text className="device-copy-control" copyable={{ text: device.primary_mac }} />}
  </div></div>

}

export function DeviceBrandSummary({ device }: { device: DeviceDisplayItem }) {
  const safe = !device.recognition_conflict
  const brand = safe && (device.brand_confidence ?? 0) >= 0.8 ? device.brand : ''
  const inference = device.brand_inference
  const inferred = !brand && inference?.status === 'inferred'
  const model = safe && (device.model_confidence ?? 0) >= 0.8 ? device.model : ''
  const reference = safe && !brand && inference?.status !== 'conflict' && (!inferred || device.brand_reference?.brand.toLowerCase() === inference.brand?.toLowerCase()) ? device.brand_reference : undefined
  const platform = virtualPlatform(device) || (safe && (device.brand_confidence ?? 0) >= .8 && /^vmware(?:[\s,.]|$)/i.test(device.brand?.trim() || '') ? 'VMware' : undefined)
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

export function DeviceIdentityCell({ device, showName = true }: { device: DeviceDisplayItem; showName?: boolean }) {
  const safe = !device.recognition_conflict
  const platform = virtualPlatform(device)
  const type = safe && (device.device_type_confidence ?? 0) >= .8 && !isEmptyRecognition(device.device_type) ? device.device_type : ''
  const brandValue = safe && !platform && (device.brand_confidence ?? 0) >= .8 && !isEmptyRecognition(device.brand) ? device.brand : ''
  const brand = brandValue ? resolveDeviceBrand({ brand: brandValue }) : undefined
  const model = safe && (device.model_confidence ?? 0) >= .8 && !isEmptyRecognition(device.model) ? device.model : ''
  const os = safe && (device.os_family_confidence ?? 0) >= .8 && !isEmptyRecognition(device.os_family) ? device.os_family : ''
  const inference = device.brand_inference
  const inferred = !brandValue && inference?.status === 'inferred' ? inference : undefined
  const reference = !brandValue && inference?.status !== 'conflict' ? device.brand_reference : undefined
  const primaryFallback = type ? deviceTypeLabel(type) : brand?.name || ''
  return <div className="device-identity-cell">
    <DeviceSemanticIcon device={device} />
    <div className="device-identity-content">
      <div className="device-identity-primary">
        {showName && device.device_name?.value ? <DeviceNameView name={device.device_name} compact /> : primaryFallback && <Typography.Text strong>{primaryFallback}</Typography.Text>}
        {showName && device.device_name?.value && type && <Typography.Text type="secondary" className="device-type-label">{deviceTypeLabel(type)}</Typography.Text>}
      </div>
      {(brand || model) && <Typography.Text className="device-brand-model" title={[brand?.name, model].filter(Boolean).join(' ')}>{[brand?.name, model].filter(Boolean).join(' · ')}</Typography.Text>}
      {os && <div className="device-os-summary"><OperatingSystemLabel family={os} confirmed /></div>}
      <div className="device-identity-clues">
        {inferred && <Tooltip title={`域名证据评分 ${Math.round(inferred.confidence * 100)}%，不确认硬件品牌。`}><Tag className="device-inference-tag">{resolveDeviceBrand({ brand: inferred.brand }).name || inferred.brand} · 品牌推测</Tag></Tooltip>}
        {reference && (!inferred || reference.brand.toLowerCase() !== inferred.brand?.toLowerCase()) && <Tooltip title={`${reference.explanation} · 参考评分 ${Math.round(reference.confidence * 100)}%`}><Tag className="device-inference-tag">{resolveDeviceBrand({ brand: reference.brand }).name || reference.brand} · MAC 厂商线索</Tag></Tooltip>}
        {safe && !os && !isEmptyRecognition(device.os_family) && <Tooltip title={`置信度 ${Math.round((device.os_family_confidence ?? 0) * 100)}%`}><Tag className="device-inference-tag">{device.os_family} · 系统线索</Tag></Tooltip>}
        {platform && <Tooltip title="VMware 注册厂商仅提示虚拟网卡或虚拟化平台，不确认宿主机品牌。"><Tag className="device-platform-tag"><CloudServerOutlined />VMware 虚拟平台线索</Tag></Tooltip>}
        {(device.recognition_conflict || inference?.status === 'conflict') && <Tooltip title="识别线索存在冲突，查看详情核对证据"><Tag className="device-conflict-tag">线索冲突</Tag></Tooltip>}
        {device.discovery?.conflict && <Tag className="device-conflict-tag">发现线索冲突</Tag>}
      </div>
      {device.router_observation && <Link className={`router-device-summary router-device-summary-${device.router_observation.status}`} to={`/discovery/routers/${encodeURIComponent(device.router_observation.assessment_id)}`}>路由观察 · {routerStatusLabel(device.router_observation.status)} · {device.router_observation.confidence}</Link>}
    </div>
  </div>
}

export function DeviceSemanticIcon({ device }: { device: DeviceDisplayItem }) {
  const confidentType = !device.recognition_conflict && (device.device_type_confidence ?? 0) >= .8 ? (device.device_type || '').toLowerCase() : ''
  const confidentOS = !device.recognition_conflict && (device.os_family_confidence ?? 0) >= .8 ? (device.os_family || '').toLowerCase() : ''
  const Icon = /printer|打印/.test(confidentType) ? PrinterOutlined
    : /phone|mobile|手机/.test(confidentType) ? MobileOutlined
    : /tablet|平板/.test(confidentType) ? TabletOutlined
    : /laptop|notebook|笔记本/.test(confidentType) ? LaptopOutlined
    : /server|服务器/.test(confidentType) ? HddOutlined
    : /virtual|vm|虚拟/.test(confidentType) ? CloudServerOutlined
    : /desktop|workstation|computer|pc|终端|电脑/.test(confidentType) ? DesktopOutlined
    : /android|ios/.test(confidentOS) ? MobileOutlined
    : /windows|macos|linux/.test(confidentOS) ? DesktopOutlined : DeploymentUnitOutlined
  return <span className="device-semantic-icon" aria-hidden="true"><Icon /></span>
}

export function DeviceLedgerIdentity({device,href,showName=true}:{device:DeviceDisplayItem;href:string;showName?:boolean}) {
 const name=showName?device.device_name?.value:undefined
 const primary=name||device.current_ip||device.primary_mac||device.endpoint_id
 return <div className="device-identity-cell">
  <DeviceSemanticIcon device={device}/>
  <div className="device-identity-content">
   <div className="device-ledger-ip"><Link className={`device-ledger-primary${!name?' mono':''}`} to={href} title={name?[primary,device.device_name?.manual?'人工备注':'观测名称',device.device_name?.status==='historical'?'历史观测，尚未重新确认':'',device.device_name?.multiple_names?'其他名称可在详情查看':''].filter(Boolean).join(' · '):primary}>{primary}</Link>{name&&device.device_name?.status==='historical'&&<span className="device-name-caption">历史名称</span>}{!name&&device.current_ip&&<Typography.Text className="device-copy-control" copyable={{text:device.current_ip}}/>}</div>
   {name&&device.current_ip&&<Typography.Text className="mono device-ledger-address" copyable={{text:device.current_ip}}>{device.current_ip}</Typography.Text>}
   {device.primary_mac&&<DeviceMAC device={device} href={href}/>}
   {device.ip_match&&<Typography.Text className="device-match-caption" title={`${device.ip_match.ip} · ${device.ip_match.matched_at} · ${device.ip_match.source==='account_session'?'账号会话':'IP 观测'}`}>{device.ip_match.is_recent_ip?'最近 IP 命中':'历史 IP 命中'}</Typography.Text>}
  </div>
 </div>
}

export function DeviceLedgerRecognition({device}:{device:DeviceDisplayItem}) {
 const safe=!device.recognition_conflict
 const platform=virtualPlatform(device)||(/^vmware(?:[\s,.]|$)/i.test(device.brand||'')?'VMware':undefined)
 const type=safe&&(device.device_type_confidence??0)>=.8&&!isEmptyRecognition(device.device_type)?deviceTypeLabel(device.device_type!):''
 const brand=safe&&!platform&&(device.brand_confidence??0)>=.8&&!isEmptyRecognition(device.brand)?resolveDeviceBrand({brand:device.brand}).name:''
 const model=safe&&(device.model_confidence??0)>=.8&&!isEmptyRecognition(device.model)?device.model:''
 const clues=[
  device.brand_inference?.status==='inferred'&&!isEmptyRecognition(device.brand_inference.brand)?`${device.brand_inference.brand} · 品牌推测（${Math.round(device.brand_inference.confidence*100)}%）`:'',
  device.brand_reference&&!isEmptyRecognition(device.brand_reference.brand)?`${device.brand_reference.brand} · MAC 厂商线索：${device.brand_reference.explanation}`:'',
  safe&&(device.os_family_confidence??0)<.8&&!isEmptyRecognition(device.os_family)?`${device.os_family} · 系统线索（${Math.round((device.os_family_confidence??0)*100)}%）`:'',
  safe&&(device.device_type_confidence??0)<.8&&!isEmptyRecognition(device.device_type)?`${deviceTypeLabel(device.device_type!)} · 类型线索`:'',
 ].filter(Boolean)
 return <div className="device-ledger-recognition">
  {type&&<Typography.Text>{type}</Typography.Text>}
  {(brand||model)&&<Typography.Text className="device-brand-model">{[brand,model].filter(Boolean).join(' · ')}</Typography.Text>}
  <div className="device-identity-clues">
   {platform&&<Tooltip title="虚拟网卡或虚拟化平台线索，不确认宿主机品牌。"><Tag className="device-platform-tag"><CloudServerOutlined/>VMware 虚拟平台线索</Tag></Tooltip>}
   {(device.recognition_conflict||device.brand_inference?.status==='conflict')&&<Tag className="device-conflict-tag">线索冲突</Tag>}
   {device.discovery?.conflict&&<Tag className="device-conflict-tag">发现线索冲突</Tag>}
   {clues.length>0&&<Tooltip title={<div>{clues.map(clue=><div key={clue}>{clue}</div>)}</div>}><Typography.Text className="device-ledger-clues" tabIndex={0}>识别依据</Typography.Text></Tooltip>}
  </div>
  {device.router_observation&&<Link className="router-device-summary" to={`/discovery/routers/${encodeURIComponent(device.router_observation.assessment_id)}`}>路由观察 · {routerStatusLabel(device.router_observation.status)}</Link>}
 </div>
}

export function DeviceLedgerOS({device}:{device:DeviceDisplayItem}) {
 return !device.recognition_conflict&&(device.os_family_confidence??0)>=.8&&!isEmptyRecognition(device.os_family)?<OperatingSystemLabel family={device.os_family!} confirmed/>:null
}

function isEmptyRecognition(value?: string) {
  return !value || /^(unknown|未知|未识别)$/i.test(value.trim())
}

function deviceTypeLabel(value: string) {
  const normalized = value.toLowerCase()
  if (/printer/.test(normalized)) return '打印机'
  if (/phone|mobile/.test(normalized)) return '手机'
  if (/tablet/.test(normalized)) return '平板设备'
  if (/laptop|notebook/.test(normalized)) return '笔记本电脑'
  if (/desktop|workstation|computer|pc/.test(normalized)) return '桌面终端'
  if (/server/.test(normalized)) return '服务器'
  if (/virtual|\bvm\b/.test(normalized)) return '虚拟终端'
  return value
}

function routerStatusLabel(status: string) {
  return ({ candidate: '候选', likely: '较可信', confirmed: '已确认' } as Record<string, string>)[status] || status
}

// Virtual-interface vendors are shown independently, never promoted to hardware brand.
export function virtualPlatform(device: DeviceDisplayItem): string | undefined {
  const mac = device.primary_mac || ''
  if (!/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(mac) || (parseInt(mac.slice(0, 2), 16) & 3) !== 0 || device.randomized_mac || (device.vendor_confidence ?? 0) < .8) return undefined
  if (/^vmware(?:[\s,.]|$)/i.test(device.vendor?.trim() || '')) return 'VMware'
  return undefined
}
