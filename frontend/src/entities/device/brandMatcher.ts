export interface BrandInfo {
  key: string
  name: string
  nameEn: string
  color: string
  bgColor: string
  borderColor: string
}

const BRAND_MAP: Record<string, BrandInfo> = {
  apple: {
    key: 'apple',
    name: '苹果',
    nameEn: 'Apple',
    color: '#333333',
    bgColor: '#f5f5f7',
    borderColor: '#e5e5e7',
  },
  xiaomi: {
    key: 'xiaomi',
    name: '小米',
    nameEn: 'Xiaomi',
    color: '#ff6900',
    bgColor: '#fff7f0',
    borderColor: '#ffd8be',
  },
  huawei: {
    key: 'huawei',
    name: '华为',
    nameEn: 'Huawei',
    color: '#cf0a2c',
    bgColor: '#fdf2f4',
    borderColor: '#f9d2d8',
  },
  microsoft: {
    key: 'microsoft',
    name: '微软',
    nameEn: 'Microsoft',
    color: '#00a4ef',
    bgColor: '#f0f9ff',
    borderColor: '#bae6fd',
  },
  lenovo: {
    key: 'lenovo',
    name: '联想',
    nameEn: 'Lenovo',
    color: '#e2231a',
    bgColor: '#fef2f2',
    borderColor: '#fecaca',
  },
  dell: {
    key: 'dell',
    name: '戴尔',
    nameEn: 'Dell',
    color: '#0076ce',
    bgColor: '#f0f7ff',
    borderColor: '#bfdbfe',
  },
  hp: {
    key: 'hp',
    name: '惠普',
    nameEn: 'HP',
    color: '#0096d6',
    bgColor: '#f0f9ff',
    borderColor: '#bae6fd',
  },
  samsung: {
    key: 'samsung',
    name: '三星',
    nameEn: 'Samsung',
    color: '#1428a0',
    bgColor: '#eff2fe',
    borderColor: '#c7d2fe',
  },
  cisco: {
    key: 'cisco',
    name: '思科',
    nameEn: 'Cisco',
    color: '#049fd9',
    bgColor: '#f0f9ff',
    borderColor: '#bae6fd',
  },
  asus: {
    key: 'asus',
    name: '华硕',
    nameEn: 'Asus',
    color: '#00539b',
    bgColor: '#f0f7ff',
    borderColor: '#bfdbfe',
  },
  android: {
    key: 'android',
    name: '安卓终端',
    nameEn: 'Android',
    color: '#3ddc84',
    bgColor: '#f0fdf4',
    borderColor: '#bbf7d0',
  },
  linux: {
    key: 'linux',
    name: 'Linux 服务器',
    nameEn: 'Linux',
    color: '#fcc624',
    bgColor: '#fefce8',
    borderColor: '#fef08a',
  },
  unknown: {
    key: 'unknown',
    name: '未知设备',
    nameEn: 'Unknown',
    color: '#64748b',
    bgColor: '#f8fafc',
    borderColor: '#e2e8f0',
  },
}

export function resolveDeviceBrand(device: {
  brand?: string
  vendor?: string
  summary?: string
  endpoint_id?: string
  model?: string
}): BrandInfo {
  const brandRaw = (device.brand || device.vendor || '').toLowerCase()
  const textRaw = `${device.endpoint_id || ''} ${device.summary || ''} ${device.model || ''} ${brandRaw}`.toLowerCase()

  if (brandRaw.includes('apple') || textRaw.includes('iphone') || textRaw.includes('macbook') || textRaw.includes('ipad') || textRaw.includes('apple') || textRaw.includes('macos') || textRaw.includes('ios')) {
    return BRAND_MAP.apple
  }
  if (brandRaw.includes('xiaomi') || brandRaw.includes('redmi') || textRaw.includes('xiaomi') || textRaw.includes('redmi') || textRaw.includes('mi 13') || textRaw.includes('mi 14') || textRaw.includes('mi 12')) {
    return BRAND_MAP.xiaomi
  }
  if (brandRaw.includes('huawei') || brandRaw.includes('honor') || textRaw.includes('huawei') || textRaw.includes('mate60') || textRaw.includes('mate50') || textRaw.includes('p60') || textRaw.includes('p50') || textRaw.includes('harmonyos')) {
    return BRAND_MAP.huawei
  }
  if (brandRaw.includes('microsoft') || textRaw.includes('surface') || textRaw.includes('windows') || textRaw.includes('microsoft') || textRaw.includes('desktop-ops')) {
    return BRAND_MAP.microsoft
  }
  if (brandRaw.includes('lenovo') || textRaw.includes('thinkpad') || textRaw.includes('lenovo') || textRaw.includes('ideapad')) {
    return BRAND_MAP.lenovo
  }
  if (brandRaw.includes('dell') || textRaw.includes('dell') || textRaw.includes('latitude') || textRaw.includes('xps') || textRaw.includes('optiplex')) {
    return BRAND_MAP.dell
  }
  if (brandRaw.includes('hp') || brandRaw.includes('hewlett') || textRaw.includes('hp ') || textRaw.includes('probook') || textRaw.includes('elitebook')) {
    return BRAND_MAP.hp
  }
  if (brandRaw.includes('samsung') || textRaw.includes('galaxy') || textRaw.includes('samsung')) {
    return BRAND_MAP.samsung
  }
  if (brandRaw.includes('cisco') || textRaw.includes('cisco') || textRaw.includes('catalyst')) {
    return BRAND_MAP.cisco
  }
  if (brandRaw.includes('asus') || textRaw.includes('asus') || textRaw.includes('rog')) {
    return BRAND_MAP.asus
  }
  if (brandRaw.includes('android') || textRaw.includes('android')) {
    return BRAND_MAP.android
  }
  if (brandRaw.includes('linux') || textRaw.includes('ubuntu') || textRaw.includes('debian') || textRaw.includes('centos')) {
    return BRAND_MAP.linux
  }

  return BRAND_MAP.unknown
}
