import type { components } from '../shared/api/generated'

type Device = components['schemas']['DiscoveryDevice']

// A user-controlled hostname is descriptive evidence, never a classification.
// Avoid generic vendor names: Huawei, for example, also names APs and routers.
export function discoveryNameClue(name?: string) {
  const value = name?.trim()
  if (!value) return undefined
  const rules: Array<[RegExp, string, string]> = [
    [/^(?:desktop|laptop)[-_][a-z0-9]+$|^win[-_](?!server(?:$|[-_]))[a-z0-9]+$|(?:^|[-_. ])(?:macbook|imac)(?:$|[-_. 0-9])/i, '电脑名称线索', '电脑名称特征'],
    [/(?:^|[-_. ])(?:iphone|ipad|redmi|realme|oneplus|iqoo)(?:$|[-_. 0-9])/i, '移动设备名称线索', '移动设备产品名称'],
    [/^(?:printer|laserjet|officejet)(?:$|[-_. 0-9])/i, '打印设备名称线索', '打印设备名称特征'],
    [/^(?:camera|cam|nvr)(?:$|[-_. 0-9])/i, '视频设备名称线索', '视频设备名称特征'],
    [/^(?:ap|switch|router)(?:$|[-_. 0-9])/i, '网络设备名称线索', '网络设备名称特征'],
  ]
  const rule = rules.find(([pattern]) => pattern.test(value))
  if (!rule) return undefined
  return { label: rule[1], detail: `名称“${value}”含${rule[2]}；名称可自行设置，不能据此确认设备类型、操作系统或用途。` }
}

export function discoveryClassificationExplanation(item: Partial<Pick<Device, 'classification_status' | 'protocols' | 'device_type'>> & { recognition?: { device_type?: string; confidence?: number } }) {
  if (item.classification_status === 'conflict') return '当前类型证据互相冲突，需核对各条证据，不能据此确认设备类型。'
  if (item.classification_status === 'expired') return '分类证据已过期；历史类型不代表当前有效分类。'
  if (item.device_type || (item.recognition?.device_type && (item.recognition.confidence ?? 0) >= .8)) return ''
  const protocols = item.protocols ?? []
  if (protocols.length > 0 && protocols.every(protocol => protocol === 'arp' || protocol === 'ndp')) return '仅有地址活动证据，可以确认发现了设备地址，不能据此确定设备类型。'
  return '已发现设备，现有分类证据不足以确定设备类型；名称和服务能力保留为线索。'
}
