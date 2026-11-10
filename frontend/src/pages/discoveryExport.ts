type ExportableDevice = {
  id?: string
  name?: string
  mac?: string
  primary_ip?: string
  current_addresses?: string[]
  device_type?: string
  manufacturer?: string
  model_name?: string
  domain?: string
  vlan?: string
  sensor_id?: string
  classification_status?: string
  first_seen?: string
  last_seen?: string
  evidence_count?: number
  recognition?: { device_type?: string; brand?: string; os_family?: string; confidence?: number; rule_version?: string }
}

const statusLabels: Record<string, string> = { identified: '证据有效', candidate: '发现线索', conflict: '类型证据冲突', expired: '证据已过期' }

export function csvCell(value: unknown): string {
  const text = value === undefined || value === null ? '' : String(value)
  return /[",\r\n]/.test(text) ? '"' + text.replaceAll('"', '""') + '"' : text
}

function deviceType(item: ExportableDevice, types: Record<string, string>): string {
  if (item.classification_status === 'conflict') return '类型证据冲突'
  const observed = item.device_type ?? ''
  if (observed) return types[observed] ?? observed
  const recognized = (item.recognition?.confidence ?? 0) >= 0.8 ? item.recognition?.device_type ?? '' : ''
  return recognized ? types[recognized] ?? recognized : ''
}

export function discoveryCSV(items: ExportableDevice[], types: Record<string, string>): string {
  const rows: string[][] = [['标识', '名称', 'MAC', '当前地址', '设备类型', '品牌', '型号', '操作系统', '网络域', 'VLAN', '采集传感器', '证据状态', '识别置信度', '识别规则', '首次观测', '最近观测', '证据数']]
  for (const item of items) {
    rows.push([
      item.id ?? '',
      item.name ?? '',
      item.mac ?? '',
      (item.current_addresses?.length ? item.current_addresses.join(';') : item.primary_ip) ?? '',
      deviceType(item, types),
      item.manufacturer ?? item.recognition?.brand ?? '',
      item.model_name ?? '',
      item.recognition?.os_family ?? '',
      item.domain ?? '',
      item.vlan ?? '',
      item.sensor_id ?? '',
      statusLabels[item.classification_status ?? ''] ?? item.classification_status ?? '',
      item.recognition?.confidence === undefined ? '' : `${Math.round(item.recognition.confidence * 100)}%`,
      item.recognition?.rule_version ?? '',
      item.first_seen ?? '',
      item.last_seen ?? '',
      item.evidence_count === undefined ? '' : String(item.evidence_count),
    ])
  }
  return rows.map(row => row.map(csvCell).join(',')).join('\r\n') + '\r\n'
}
