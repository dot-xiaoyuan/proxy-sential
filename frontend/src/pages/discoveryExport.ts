import { getApiBase } from '../shared/api/client'

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
  const rows: string[][] = [['标识', '名称', 'MAC', '当前地址', '设备类型', '品牌', '型号', '操作系统', '网络域', 'VLAN', '采集传感器', '证据状态', '识别置信度', '识别规则', '窗口内首次观测', '最近观测', '证据数']]
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
