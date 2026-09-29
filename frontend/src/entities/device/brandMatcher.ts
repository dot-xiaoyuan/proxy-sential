export interface BrandInfo {
  key: string
  name: string
  nameEn: string
}

// Match the supplied brand only. OS, endpoint IDs and service visits do not establish hardware brands.
const brands: [string, string, string, string[]][] = [
  ['vmware', 'VMware', 'VMware', ['vmware']],
  ['apple', '苹果', 'Apple', ['apple', '苹果']],
  ['xiaomi', '小米', 'Xiaomi', ['xiaomi', 'redmi', '小米', '红米']],
  ['honor', '荣耀', 'Honor', ['honor', '荣耀']],
  ['huawei', '华为', 'Huawei', ['huawei', '华为']],
  ['microsoft', '微软', 'Microsoft', ['microsoft', '微软']],
  ['lenovo', '联想', 'Lenovo', ['lenovo', '联想']],
  ['dell', '戴尔', 'Dell', ['dell', '戴尔']],
  ['hp', '惠普', 'HP', ['hp', 'hewlett packard', '惠普']],
  ['samsung', '三星', 'Samsung', ['samsung', '三星']],
  ['cisco', '思科', 'Cisco', ['cisco', '思科']],
  ['asus', '华硕', 'ASUS', ['asus', 'asustek', '华硕']],
  ['oppo', 'OPPO', 'OPPO', ['oppo']],
  ['vivo', 'vivo', 'vivo', ['vivo']],
  ['realme', '真我', 'realme', ['realme', '真我']],
  ['amazon', '亚马逊', 'Amazon', ['amazon', '亚马逊']],
  ['roku', 'Roku', 'Roku', ['roku']],
  ['sonos', 'Sonos', 'Sonos', ['sonos']],
  ['google', '谷歌', 'Google', ['google', '谷歌']],
  ['acer', '宏碁', 'Acer', ['acer', '宏碁']],
  ['tplink', 'TP-Link', 'TP-Link', ['tp link', 'tplink', '普联']],
  ['ubiquiti', 'Ubiquiti', 'Ubiquiti', ['ubiquiti']],
  ['nokia', '诺基亚', 'Nokia', ['nokia', '诺基亚']],
  ['sony', '索尼', 'Sony', ['sony', '索尼']],
  ['android', 'Android', 'Android', ['android']],
  ['linux', 'Linux', 'Linux', ['linux']],
]

export function resolveDeviceBrand(device: {
  brand?: string
  vendor?: string
  summary?: string
  endpoint_id?: string
  model?: string
}): BrandInfo {
  const label = (device.brand || '').trim()
  const normalized = label.toLowerCase().replace(/[-_.,]+/g, ' ').replace(/\s+/g, ' ')
  const match = brands.find(([, , , aliases]) => aliases.some(alias => normalized === alias || normalized.startsWith(`${alias} `)))
  if (match) return { key: match[0], name: match[1], nameEn: match[2] }
  return { key: 'unknown', name: label && !/^(unknown|未知|未知设备)$/i.test(label) ? label : '', nameEn: label || 'Unknown' }
}
