import type { HardwareView } from './discoveryHardware'
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

export function discoveryClassificationExplanation(item: Partial<Pick<Device, 'classification_status' | 'protocols' | 'device_type'>> & HardwareView & { recognition?: { device_type?: string; confidence?: number } }) {
  if (item.hardware_type_status === 'identified') return '硬件类型来自已归属的产品证据；服务公告到期不清除类型，活动与地址绑定单独判断。'
  if (item.hardware_type_status === 'revoked') return '支撑硬件类型的证据已撤销或失效，旧画像不再作为类型结论。'
  if (item.hardware_type_status === 'conflict') return '同一可信身份存在互斥的硬件类型证据，需核对原文与归属。'
  if (item.hardware_type_status === 'candidate') return '现有证据不足以确认硬件主类型；服务能力与厂商信息保留为线索。'
  if (item.classification_status === 'conflict') return '当前类型证据互相冲突，需核对各条证据，不能据此确认设备类型。'
  if (item.classification_status === 'expired') return '分类证据已过期；历史类型不代表当前有效分类。'
  if (item.device_type || (item.recognition?.device_type && (item.recognition.confidence ?? 0) >= .8)) return ''
  const protocols = item.protocols ?? []
  if (protocols.length > 0 && protocols.every(protocol => protocol === 'arp' || protocol === 'ndp')) return '仅有地址活动证据，可以确认发现了设备地址，不能据此确定设备类型。'
  return '已发现设备，现有分类证据不足以确定设备类型；名称和服务能力保留为线索。'
}
