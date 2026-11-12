import { getApiBase } from '../shared/api/client'
import { activityStates, confirmedDeviceType, hardwareStates, type HardwareView } from './discoveryHardware'

type ExportableDevice = HardwareView & {
  id?: string
  name?: string
  mac?: string
  primary_ip?: string
  current_addresses?: string[]
  device_type?: string
  last_product_type?: string
  last_product_at?: string
  manufacturer?: string
  model_name?: string
  domain?: string
  vlan?: string
  sensor_id?: string
  classification_status?: string
  review_reason?: string
  review_observed_at?: string
  first_seen?: string
  last_seen?: string
  evidence_count?: number
  recognition?: { device_type?: string; brand?: string; os_family?: string; confidence?: number; rule_version?: string }
}

export type DiscoveryExportResult<T> = { items: T[]; total: number; snapshotAt: string }

// A download is valid only after the server's end record confirms the entire
// read-only snapshot. Network interruption or a server error yields no CSV.
export async function readDiscoveryExport<T>(response: Response, onProgress?: (count: number, total: number) => void, rowKey?: (item: T) => string): Promise<DiscoveryExportResult<T>> {
  if (!response.ok) throw new Error(`完整导出请求失败（HTTP ${response.status}）`)
  if (!response.body) throw new Error('浏览器无法读取导出数据流')
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  const items: T[] = []
  const seen = new Set<string>()
  let buffer = ''
  let total = -1
  let snapshotAt = ''
  let ended = false
  const consume = (line: string) => {
    if (!line.trim()) return
    const record = JSON.parse(line) as {record?:string;total?:number;snapshot_at?:string;item?:T;count?:number;complete?:boolean;message?:string}
    if (ended) throw new Error('导出结束后仍收到设备记录')
    if (record.record === 'manifest' && total < 0 && Number.isSafeInteger(record.total) && record.total! >= 0 && record.total! <= 200_000) {
      total = record.total!
      snapshotAt = record.snapshot_at ?? ''
      return
    }
    if (total < 0) throw new Error('导出缺少快照清单')
    if (record.record === 'error') throw new Error(record.message || '导出过程中断')
    if (record.record === 'item' && record.item) {
      if (rowKey) {
        const key = rowKey(record.item)
        if (seen.has(key)) throw new Error('导出存在重复设备，请重试')
        seen.add(key)
      }
      items.push(record.item)
      if (items.length > total) throw new Error('导出数量超过快照统计')
      if (items.length % 200 === 0) onProgress?.(items.length, total)
      return
    }
    if (record.record === 'end' && record.complete === true && record.count === items.length && items.length === total) {
      ended = true
      onProgress?.(items.length, total)
      return
    }
    throw new Error('导出数据流校验失败')
  }
  try {
    for (;;) {
      const {value, done} = await reader.read()
      if (done) break
      buffer += decoder.decode(value, {stream:true})
      for (;;) {
        const newline = buffer.indexOf('\n')
        if (newline < 0) break
        consume(buffer.slice(0,newline))
        buffer = buffer.slice(newline+1)
      }
    }
    buffer += decoder.decode()
    if (buffer.trim()) consume(buffer)
    if (!ended) throw new Error('导出未收到完成校验，未生成文件')
    return {items,total,snapshotAt}
  } finally {
    reader.releaseLock()
  }
}

export async function fetchDiscoveryExport<T>(query: URLSearchParams, onProgress?: (count: number, total: number) => void, rowKey?: (item: T) => string): Promise<DiscoveryExportResult<T>> {
  const scope = new URLSearchParams(query)
  scope.delete('cursor')
  scope.delete('limit')
  scope.delete('offset')
  const response = await fetch(`${getApiBase()}/discovery/devices/export?${scope.toString()}`, {credentials:'include',headers:{Accept:'application/x-ndjson'}})
  return readDiscoveryExport(response,onProgress,rowKey)
}

const statusLabels: Record<string, string> = { identified: '证据有效', candidate: '发现线索', conflict: '类型证据冲突', expired: '证据已过期' }
const reviewLabels: Record<string, string> = { new_priority: '近 7 天新出现重点品类', type_change: '待核实类型变化线索', conflict: '类型证据冲突', address_only: '长期只有地址线索' }

export function csvCell(value: unknown): string {
  const text = value === undefined || value === null ? '' : String(value)
  return /[",\r\n]/.test(text) ? '"' + text.replaceAll('"', '""') + '"' : text
}

function deviceType(item: ExportableDevice, types: Record<string, string>): string {
  const observed = confirmedDeviceType(item)
  return observed ? types[observed] ?? observed : ''
}

export function discoveryCSV(items: ExportableDevice[], types: Record<string, string>): string {
  const rows: string[][] = [['标识', '名称', 'MAC', '当前地址', '设备类型', '历史型号类型', '型号自报时间', '品牌', '型号', '操作系统', '网络域', 'VLAN', '采集传感器', '证据状态', '识别置信度', '识别规则', '窗口内首次观测', '最近观测', '证据数', '待核实原因', '核实线索时间', '硬件类型状态', '类型依据时间', '活动状态', '硬件规则版本', '硬件来源引用', '人工核实类型', '人工核实型号', '实物或台账依据', '镜像覆盖核对', '核实时间', '核实人']]
  for (const item of items) {
    rows.push([
      item.id ?? '',
      item.name ?? '',
      item.mac ?? '',
      (item.current_addresses?.length ? item.current_addresses.join(';') : item.primary_ip) ?? '',
      deviceType(item, types),
      item.last_product_type ? types[item.last_product_type] ?? item.last_product_type : '',
      item.last_product_at ?? '',
      item.manufacturer ?? item.recognition?.brand ?? '',
      item.hardware_type_status ? item.hardware_model ?? '' : item.model_name ?? '',
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
      reviewLabels[item.review_reason ?? ''] ?? '',
      item.review_observed_at ?? '',
      hardwareStates[item.hardware_type_status ?? ''] ?? '',
      item.type_evidence_at ?? '',
      activityStates[item.activity_status ?? ''] ?? '',
      item.type_rule_version ?? '',
      (item.type_sources ?? []).map(source => [source.source, source.rule_id, source.rule_version, source.evidence_id, source.observed_at].join('|')).join(';'),
      '', '', '', '', '', '',
    ])
  }
  return rows.map(row => row.map(csvCell).join(',')).join('\r\n') + '\r\n'
}
