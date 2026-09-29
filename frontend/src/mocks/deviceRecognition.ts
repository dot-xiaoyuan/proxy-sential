import type { EndpointDeviceInventory, EndpointIdentityProfile } from '../shared/api/types'

const seen = new Date().toISOString()

// Separate OS evidence and an interface manufacturer; neither establishes brand.
export const macOSDevice: EndpointDeviceInventory = {
  device_name: {value:'office-mac41.local',source:'dhcp_hostname',manual:false,status:'current',multiple_names:false},
  endpoint_id: 'mac:00:1b:21:00:00:41', primary_mac: '00:1b:21:00:00:41', entity_role: 'endpoint', registration_status: 'unregistered', merge_status: 'active',
  accounts: [], ips: ['198.18.90.41'], access_ids: [], current_ip: '198.18.90.41', identity_confidence: .9, recognition_confidence: .9,
  brand: '', brand_confidence: 0, vendor: 'Intel Corporation', vendor_confidence: .9,
  os_family: 'macOS', os_family_confidence: .65, recognition_source: 'dhcp_hostname_hint',
  recognition_evidence: ['macOS 推测: DHCP vendor class darwin + Mac 主机名 office-mac41.local'],
  randomized_mac: false, summary: 'macOS 系统线索', last_seen: seen,
}

export const macOSProfile: EndpointIdentityProfile = {
 device_name: macOSDevice.device_name,
  endpoint_id: macOSDevice.endpoint_id, summary: macOSDevice.summary, accounts: [], sessions: [], ip_history: [], access_history: [],
  endpoint: { endpoint_id: macOSDevice.endpoint_id, primary_mac: macOSDevice.primary_mac, entity_role: 'endpoint', identity_confidence: .9, attributes: { hostname: 'office-mac41.local', vendor_class: 'darwin' }, first_seen: seen, last_seen: seen, registration_status: 'unregistered', merge_status: 'active' },
  recognition: macOSDevice,
}

export const manufacturerReferenceDevices: EndpointDeviceInventory[] = [
  ['Huawei', 'Huawei Technologies Co.,Ltd.', '00:10:20:00:00:01', '198.18.90.51'],
  ['Vivo', 'vivo Mobile Communication Co., Ltd.', '00:10:20:00:00:02', '198.18.90.52'],
].map(([brand, vendor, mac, ip]) => ({
  ...macOSDevice, endpoint_id: `mac:${mac}`, primary_mac: mac, current_ip: ip, ips: [ip],
  os_family: '', os_family_confidence: 0, recognition_source: 'ieee_oui', recognition_evidence: [`IEEE OUI: ${vendor}`],
  vendor, brand_reference: { brand, vendor, source: 'mac_vendor', confidence: .6, explanation: 'MAC 注册厂商对应的品牌参考，不确认整机品牌、型号或操作系统' },
}))
