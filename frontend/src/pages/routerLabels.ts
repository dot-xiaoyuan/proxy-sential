export const routerStatusLabels: Record<string, string> = { candidate: '候选', likely: '较可信', confirmed: '已确认' }

export const routerRoleLabels: Record<string, string> = {
  router: '路由器',
  ap: '接入点',
  access_point: '接入点',
  switch: '交换机',
  firewall: '防火墙',
  gateway: '网关',
  shared_gateway: '共享网关',
  endpoint: '普通终端',
  camera: '摄像头',
  media_device: '媒体设备',
}

export const routerSourceLabels: Record<string, string> = {
  oui: 'MAC 厂商',
  dhcp: 'DHCP',
  software: '软件识别',
  lldp: 'LLDP',
  cdp: 'CDP',
  ssdp: 'SSDP',
  snmp_management: 'SNMP 管理面',
  first_hop_redundancy: 'VRRP / HSRP',
  shared_gateway_behavior: '共享网关行为',
  http_management: 'HTTP 管理面',
  tls_management: 'TLS 管理面',
  weak_stack: '弱栈特征',
}

// Open-source library names shown as secondary labels: "<library> 命中" means that library
// recognised part of the device. Copyleft libraries are internal-only display.
export const routerLibraryLabels: Record<string, string> = {
  recog: 'Recog 命中',
  satori: 'Satori 命中',
  whatweb: 'WhatWeb 命中',
  librenms: 'LibreNMS 命中',
  openwrt: 'OpenWrt ToH 命中',
  'fingerbank-current': 'Fingerbank 命中',
}

export const routerStrengthLabels: Record<string, string> = { strong: '强证据', medium: '中等证据', weak: '弱证据' }

export const routerAssociationLabels: Record<string, string> = {
  endpoint: '终端标识关联',
  mac: 'MAC 关联',
  event_window_mac: '事件时间窗口 MAC 关联',
  dhcp_lease: 'DHCP 租约关联',
  ip_vlan_window: 'IP 与 VLAN 窗口推测',
  shared_gateway_window: '共享窗口推测',
}

export const routerConflictLabels: Record<string, string> = {
  ordinary_endpoint: '普通终端特征冲突',
  infrastructure_ap: '接入点排除',
  infrastructure_switch: '交换机排除',
  infrastructure_firewall: '防火墙排除',
  infrastructure_role: '基础设施角色',
  ambiguous_association: '关联不唯一',
  brand_reference_only: '仅品牌参考',
  strong_evidence_required: '缺少强证据',
  shared_gateway_window_retired: '支持窗口已失效',
}
