export type CensusRow = {
  kind: 'ip'|'mac'|'binding'|'terminal'
  scope_key: string
  sensor_id?: string
  campus_id?: string
  access_domain?: string
  vlan?: string
  vrf?: string
  value: string
  ip_family?: number
  ip?: string
  mac?: string

  hardware_type?: string
  hardware_type_status?: string
  type_evidence_at?: string
  activity_status?: string
  random_mac?: boolean
  effective_type?: string
  classification_status?: string
  device_key?: string
  first_seen?: string
  last_seen?: string
}

export type CSVTable = { headers: string[]; rows: string[][] }
export type ColumnMapping = { ip: number; mac: number; scope: number; type: number }
export type Difference = { result: 'shared'|'local_only'|'external_only'|'type_difference'|'address_rebind'|'scope_review'|'input_review'; scope: string; ip: string; mac: string; local_type: string; external_type: string; reason: string }

const maxCSVBytes = 50 * 1024 * 1024
const maxCSVRows = 200_000

export async function readComparisonCSV(file: File): Promise<CSVTable> {
  if (file.size > maxCSVBytes) throw new Error('CSV 超过 50 MB，请缩小文件后重试')
  const text = (await file.text()).replace(/^\uFEFF/, '')
  const rows: string[][] = []
  let row: string[] = [], field = '', quoted = false
  for (let i = 0; i < text.length; i++) {
    const char = text[i]
    if (quoted) {
      if (char === '"' && text[i+1] === '"') { field += '"'; i++ }
      else if (char === '"') quoted = false
      else field += char
    } else if (char === '"' && field === '') quoted = true
    else if (char === ',') { row.push(field); field = '' }
    else if (char === '\n' || char === '\r') {
      if (char === '\r' && text[i+1] === '\n') i++
      row.push(field); field = ''
      if (row.some(Boolean)) rows.push(row)
      row = []
      if (rows.length > maxCSVRows + 1) throw new Error('CSV 超过 200,000 行，请缩小文件后重试')
    } else field += char
  }
  if (quoted) throw new Error('CSV 引号未闭合')
  row.push(field)
  if (row.some(Boolean)) rows.push(row)
  const headers = rows.shift()?.map(v => v.trim()) ?? []
  if (!headers.length) throw new Error('CSV 缺少表头')
  if (rows.length > maxCSVRows) throw new Error('CSV 超过 200,000 行，请缩小文件后重试')
  return { headers, rows }
}

export function normalizeMAC(raw: string): string {
  const compact = raw.toLowerCase().replace(/[-:.\s]/g, '')
  if (!/^[0-9a-f]{12}$/.test(compact) || parseInt(compact.slice(0,2),16)&1 || compact === '000000000000') return ''
  return compact.match(/.{2}/g)!.join(':')
}

export function normalizeIP(raw: string): string {
  const value = raw.trim()
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) {
    const parts = value.split('.').map(Number)
    return parts.every(n => n >= 0 && n <= 255) ? parts.join('.') : ''
  }
  if (value.includes(':')) {
    try { return new URL(`http://[${value}]/`).hostname.replace(/^\[|\]$/g,'').toLowerCase() } catch { return '' }
  }
  return ''
}

export function scopeLabel(row: CensusRow): string {
  return [row.sensor_id, row.campus_id, row.access_domain, row.vlan, row.vrf].map(v=>v?.trim() ?? '').join('|')
}

function normalizeType(value:string):string {
  const text=value.trim().toLowerCase().replace(/[\s_-]/g,'')
  const aliases:Record<string,string>={environmentmonitor:'environment_monitor',环境监测设备:'environment_monitor',环境监测:'environment_monitor',ups:'ups',不间断电源:'ups',pdu:'pdu',电源分配单元:'pdu',printer:'printer',打印机:'printer',打印设备:'printer',camera:'camera',摄像机:'camera',摄像头:'camera',recorder:'recorder',nvr:'recorder',录像机:'recorder',录像设备:'recorder',accesscontrol:'access_control',门禁:'access_control',门禁设备:'access_control',voipphone:'voip_phone',ipphone:'voip_phone',voip话机:'voip_phone',网络电话:'voip_phone'}
  return aliases[text]??text
}

function completeScope(value: string): boolean {
  const parts = value.split('|')
  return parts.length === 5 && Boolean(parts[0] && parts[1] && parts[2] && parts[3])
}

function terminalMAC(row: CensusRow): string {
  const projected = normalizeMAC(row.mac ?? '')
  if (projected) return projected
  try {
    const identity = JSON.parse(row.value) as string[]
    return identity[0] === 'identity' && identity[6] === 'mac' ? normalizeMAC(identity[7]) : ''
  } catch { return '' }
}

export function compareCensus(local: CensusRow[], external: CSVTable, mapping: ColumnMapping): Difference[] {
  if (mapping.scope < 0 || mapping.scope >= external.headers.length || mapping.ip < 0 && mapping.mac < 0) throw new Error('请选择网络作用域及至少一个 IP 或 MAC 列')
  const ipsByMAC = new Map<string, Set<string>>()
  const macsByIP = new Map<string, Set<string>>()
  const terminalTypes = new Map<string,string>()
  const localRows = new Map<string, Difference>()
  const scopeKeys = new Map<string, Set<string>>()
  const remember = (identifier:string, scope:string) => { const scopes=scopeKeys.get(identifier)??new Set<string>();scopes.add(scope);scopeKeys.set(identifier,scopes) }
  for (const row of local) {
    if (row.kind !== 'binding') continue
    const scope = scopeLabel(row), ip = normalizeIP(row.ip ?? ''), mac = normalizeMAC(row.mac ?? '')
    if (ip && mac && completeScope(scope)) {
      const macKey=`${scope}|${mac}`,ipKey=`${scope}|${ip}`
      const ips=ipsByMAC.get(macKey)??new Set<string>();ips.add(ip);ipsByMAC.set(macKey,ips)
      const macs=macsByIP.get(ipKey)??new Set<string>();macs.add(mac);macsByIP.set(ipKey,macs)
    }
  }
  for (const row of local) {
    if (row.kind !== 'terminal' || row.classification_status !== 'identified') continue
    const scope=scopeLabel(row), mac=terminalMAC(row)
    if (mac) terminalTypes.set(`${scope}|${mac}`,row.effective_type ?? '')
  }
  for (const row of local) {
    if (row.kind !== 'ip' && row.kind !== 'mac') continue
    const scope=scopeLabel(row), ip=row.kind==='ip'?normalizeIP(row.value):'', mac=row.kind==='mac'?normalizeMAC(row.value):''
    if (ip) remember(`ip:${ip}`,scope)
    if (mac) remember(`mac:${mac}`,scope)
    const linkedMAC=ip?[...(macsByIP.get(`${scope}|${ip}`)??[])][0]:''
    const linkedIP=mac?[...(ipsByMAC.get(`${scope}|${mac}`)??[])][0]:''
    const key=`${scope}|${row.kind}|${ip || mac}`
    localRows.set(key,{result:completeScope(scope)?'local_only':'scope_review',scope,ip:ip || linkedIP || '',mac:mac || linkedMAC || '',local_type:terminalTypes.get(`${scope}|${mac || linkedMAC}`) || '',external_type:'',reason:completeScope(scope)?'仅镜像侧存在':'镜像侧作用域字段不完整'})
  }
  for(const row of local){
    if(row.kind==='terminal' && row.classification_status==='identified' && !terminalMAC(row)) {
      const scope=scopeLabel(row)
      localRows.set(`${scope}|terminal|${row.value}`,{result:completeScope(scope)?'local_only':'scope_review',scope,ip:'',mac:'',local_type:row.effective_type ?? '',external_type:'',reason:'终端身份没有可直接比对的 MAC'})
    }
  }
  const differences: Difference[]=[]
  const seenExternal=new Set<string>()
  for (const fields of external.rows) {
    const get=(index:number)=>index>=0?(fields[index]??'').trim():''
    const rawIP=get(mapping.ip),rawMAC=get(mapping.mac)
    const ip=normalizeIP(rawIP), mac=normalizeMAC(rawMAC), scope=get(mapping.scope), externalType=get(mapping.type)
    if ((!ip&&!mac)||(rawIP&&!ip)||(rawMAC&&!mac)) {
      differences.push({result:'input_review',scope,ip:rawIP,mac:rawMAC,local_type:'',external_type:externalType,reason:'对方记录缺少可比对标识或 IP/MAC 格式不合法'})
      continue
    }
    const dedupe=`${scope}|${ip}|${mac}`
    if (seenExternal.has(dedupe)) {
      differences.push({result:'input_review',scope,ip,mac,local_type:'',external_type:externalType,reason:'对方表格中同作用域标识重复'})
      continue
    }
    seenExternal.add(dedupe)
    const macRow=mac?localRows.get(`${scope}|mac|${mac}`):undefined
    const ipRow=ip?localRows.get(`${scope}|ip|${ip}`):undefined
    const related=macRow??ipRow
    if (!completeScope(scope) || related && !completeScope(related.scope)) {
      differences.push({result:'scope_review',scope,ip,mac,local_type:'',external_type:externalType,reason:'网络作用域需补齐传感器、校区、接入域和 VLAN'})
      continue
    }
    const knownMACIPs=mac?ipsByMAC.get(`${scope}|${mac}`):undefined
    const knownIPMACs=ip?macsByIP.get(`${scope}|${ip}`):undefined
    if (macRow && ipRow && mac && ip && (knownMACIPs?.size || knownIPMACs?.size) && !knownMACIPs?.has(ip)) {
      differences.push({result:'address_rebind',scope,ip,mac,local_type:macRow.local_type,external_type:externalType,reason:'相同 IP 对应不同 MAC'})
    } else if (macRow && ip && knownMACIPs?.size && !knownMACIPs.has(ip) || ipRow && mac && knownIPMACs?.size && !knownIPMACs.has(mac)) {
      differences.push({result:'address_rebind',scope,ip,mac,local_type:related?.local_type ?? '',external_type:externalType,reason:'有效 IP–MAC 绑定不同'})
    } else if (related) {
      const localType=related.local_type
      differences.push({result:macRow && externalType && localType && normalizeType(externalType)!==normalizeType(localType)?'type_difference':'shared',scope,ip,mac,local_type:localType,external_type:externalType,reason:macRow?'同作用域 MAC 一致':'同作用域 IP 标识一致，设备身份仍需 MAC 核实'})
    } else {
      const elsewhere=(mac && scopeKeys.get(`mac:${mac}`)?.size || 0)+(ip && scopeKeys.get(`ip:${ip}`)?.size || 0)
      differences.push({result:elsewhere?'scope_review':'external_only',scope,ip,mac,local_type:'',external_type:externalType,reason:elsewhere?'标识出现在其他网络作用域':'仅对方系统存在'})
    }
    if (macRow) localRows.delete(`${scope}|mac|${mac}`)
    if (ipRow) localRows.delete(`${scope}|ip|${ip}`)
  }
  return [...differences,...localRows.values()]
}

export function differencesCSV(rows: Difference[]): string {
  const columns: (keyof Difference)[]=['result','scope','ip','mac','local_type','external_type','reason']
  const escape=(value:string)=>{const safe=/^[=+@\-\t\r]/.test(value)?`'${value}`:value;return `"${safe.replace(/"/g,'""')}"`}
  return [columns.join(','),...rows.map(row=>columns.map(key=>escape(row[key])).join(','))].join('\r\n')+'\r\n'
}
