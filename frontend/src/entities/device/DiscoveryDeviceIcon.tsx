import {ApartmentOutlined,ApiOutlined,CloudServerOutlined,ClusterOutlined,DesktopOutlined,HddOutlined,LaptopOutlined,MobileOutlined,PhoneOutlined,PrinterOutlined,ScanOutlined,TabletOutlined,VideoCameraOutlined,WifiOutlined,PlaySquareOutlined,IdcardOutlined,DeploymentUnitOutlined} from '@ant-design/icons'

const kinds = {
  printer:[PrinterOutlined,'打印机'], scanner:[ScanOutlined,'扫描仪'], camera:[VideoCameraOutlined,'摄像机'], recorder:[HddOutlined,'录像设备'],
  access_point:[WifiOutlined,'无线接入点'],router:[ApartmentOutlined,'路由器'],gateway:[ApartmentOutlined,'网关'],switch:[ClusterOutlined,'交换机'],
  mobile:[MobileOutlined,'手机'],tablet:[TabletOutlined,'平板'],laptop:[LaptopOutlined,'笔记本'],desktop:[DesktopOutlined,'桌面终端'],server:[HddOutlined,'服务器'],
  media_device:[PlaySquareOutlined,'媒体设备'],display:[PlaySquareOutlined,'显示设备'],access_control:[IdcardOutlined,'门禁'],iot:[ApiOutlined,'物联网设备'],virtual:[CloudServerOutlined,'虚拟终端'],voip_phone:[PhoneOutlined,'VoIP 话机'],tv:[PlaySquareOutlined,'电视'],wireless_controller:[WifiOutlined,'无线控制器'],generic:[DeploymentUnitOutlined,'设备地址'],
} as const

export function DiscoveryDeviceIcon({type,capabilities=[]}:{type?:string;capabilities?:string[]}) {
  const aliases:Record<string,string>={phone:'mobile',smartphone:'mobile',computer:'desktop',workstation:'desktop',pc:'desktop',notebook:'laptop',media_player:'media_device',iot_gateway:'gateway',attendance:'access_control',sensor:'iot',building_controller:'iot',building_device:'iot',virtual_machine:'virtual'}
  const normalized=aliases[type??'']??type??''
  const kind=(normalized in kinds?normalized:capabilities.includes('printing')?'printer':capabilities.includes('scanning')?'scanner':capabilities.includes('network_video')?'camera':capabilities.some(x=>['casting','media_rendering'].includes(x))?'media_device':capabilities.includes('routing')?'gateway':'generic') as keyof typeof kinds
  const [Icon,label]=kinds[kind]
  return <span className={`terminal-device-icon terminal-device-icon-${kind}`} data-device-kind={kind} role="img" aria-label={label}><Icon aria-hidden="true" /></span>
}
