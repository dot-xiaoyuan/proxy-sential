import { http, HttpResponse } from 'msw'
import type { components } from '../shared/api/generated'

type Registration = components['schemas']['EndpointRegistrationRecord']
type Update = components['schemas']['UpdateEndpointRegistrationRequest']
const statuses = ['registered', 'unregistered', 'ignored', 'retired']
const ownerships = ['unknown', 'byod', 'school_asset', 'public_terminal', 'infrastructure']

function initialRecords(): Registration[] {
  const now = new Date().toISOString()
  const base = {
    owner_account: '', owner_name: '', owner_department: '', asset_tag: '', registration_note: '',
    registration_updated_at: now, registration_updated_by: '演示管理员', registered_at: now, last_seen: '', source: 'local' as const,
    merge_status: 'active' as const, merged_into_endpoint_id: '', split_from_endpoint_id: '',
  }
  return [
    {
      ...base, endpoint_id: 'mac:00:11:22:33:44:55', primary_mac: '00:11:22:33:44:55', registration_status: 'registered',
      owner_account: 'library-office', owner_name: '图书馆服务台', owner_department: '图书馆', asset_tag: 'DEMO-PRINTER-001', ownership_class: 'school_asset',
      registration_note: '本地演示样例：核对设备铭牌后登记。', last_seen: now,
      registration_details: { name: '图书馆服务台打印机', device_type: 'printer', manufacturer: 'HP', model: 'LaserJet Pro MFP', serial_number: 'DEMO-PRINT-001', registered_ip: '192.0.2.10', location: '图书馆一层服务台' },
    },
    {
      ...base, endpoint_id: 'mac:02:20:40:00:00:02', primary_mac: '02:20:40:00:00:02', registration_status: 'registered',
      owner_account: 'network-center', owner_name: '网络值班组', owner_department: '信息中心', asset_tag: 'DEMO-AP-002', ownership_class: 'infrastructure',
      registration_note: '本地演示样例：依据无线设备资产清单登记。',
      registration_details: { name: '教学楼二层无线 AP', device_type: 'access_point', manufacturer: 'H3C', model: 'WA6520', serial_number: 'DEMO-AP-002', registered_ip: '192.0.2.21', location: '第一教学楼二层走廊' },
    },
    {
      ...base, endpoint_id: 'mac:02:20:40:00:00:03', primary_mac: '02:20:40:00:00:03', registration_status: 'unregistered',
      owner_name: '安防值班组', owner_department: '保卫处', ownership_class: 'public_terminal', registered_at: '',
      registration_note: '本地演示样例：已记录安装位置，资产编号待核实。',
      registration_details: { name: '图书馆南门摄像机', device_type: 'camera', manufacturer: 'Hikvision', model: 'DS-2CD', registered_ip: '192.0.2.31', location: '图书馆南门' },
    },
  ]
}

function text(value: unknown) { return typeof value === 'string' ? value.trim() : '' }
function fail(message: string, code = 'bad_registration_query') { return HttpResponse.json({ code, message }, { status: 400 }) }

// Browser-local demo state only; creating a fresh handler set resets all edits.
export function createTerminalRegistrationHandlers() {
  const records = new Map(initialRecords().map(row => [row.endpoint_id, row]))
  const read = (request: Request, metadata: boolean, position=false) => {
    const params = new URL(request.url).searchParams
    const search = text(params.get('search')).toLowerCase()
    const status = text(params.get('status'))
    const type = text(params.get('type'))
    const ownership = text(params.get('ownership_class'))
    const mac = text(params.get('mac')).toLowerCase().replaceAll('-', ':')
    const limit = params.has('limit') ? Number(params.get('limit')) : 20
    if (params.has('offset') || !Number.isInteger(limit) || limit < 1 || limit > 200) return fail('登记台账使用游标分页，分页数量须为 1 至 200')
    if (status && !statuses.includes(status)) return fail('登记状态无效')
    if (ownership && !ownerships.includes(ownership)) return fail('终端归属无效')
    if (mac && !/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac)) return fail('设备 MAC 无效')
    const signature = JSON.stringify([search, status, type, ownership, mac])
    let after = ''
    if (!metadata && !position && params.get('cursor')) {
      try {
        const cursor = JSON.parse(decodeURIComponent(atob(params.get('cursor')!))) as { id: string; scope: string }
        if (!cursor.id || cursor.scope !== signature) return fail('登记游标与查询条件不匹配')
        after = cursor.id
      } catch { return fail('登记游标无效') }
    }
    const matched = [...records.values()].filter(row => {
      const details = row.registration_details
      const haystack = [row.primary_mac, row.owner_account, row.owner_name, row.owner_department, row.asset_tag, details.name, details.registered_ip, details.serial_number, details.location].filter(Boolean).join(' ').toLowerCase()
      return (!search || haystack.includes(search)) && (!status || row.registration_status === status) && (!type || details.device_type === type) && (!ownership || row.ownership_class === ownership) && (!mac || row.primary_mac === mac)
    }).sort((left, right) => left.endpoint_id.localeCompare(right.endpoint_id))
    const as_of = new Date().toISOString()
    if (metadata) return HttpResponse.json({ total: matched.length, as_of })
    if(position) {
      const page=Number(params.get('page')??1),offset=(page-1)*limit
      if(!Number.isInteger(page)||page<1||(page>1&&offset>=matched.length))return fail('目标页已不存在，请刷新列表','page_out_of_range')
      const cursor=page===1?'':btoa(encodeURIComponent(JSON.stringify({id:matched[offset-1].endpoint_id,scope:signature})))
      return HttpResponse.json({page,limit,cursor,as_of})
    }
    const remaining = matched.filter(row => !after || row.endpoint_id > after)
    const items = remaining.slice(0, limit)
    const has_more = remaining.length > items.length
    const next_cursor = has_more ? btoa(encodeURIComponent(JSON.stringify({ id: items.at(-1)!.endpoint_id, scope: signature }))) : ''
    return HttpResponse.json({ items, next_cursor, has_more, limit, as_of } satisfies components['schemas']['EndpointRegistrationPage'])
  }

  return [
    http.get('/api/v1/endpoints/registrations', ({ request }) => read(request, false)),
    http.get('/api/v1/endpoints/registrations/metadata', ({ request }) => read(request, true)),
    http.get('/api/v1/endpoints/registrations/position', ({ request }) => read(request, false, true)),
    http.post('/api/v1/endpoints/:endpointId/registration', async ({ params, request }) => {
      let body: Update
      try { body = await request.json() as Update } catch { return fail('登记内容不是有效 JSON', 'bad_endpoint_registration_request') }
      const endpointID = String(params.endpointId)
      const previous = records.get(endpointID)
      const mac = endpointID.startsWith('mac:') ? endpointID.slice(4) : previous?.primary_mac ?? ''
      if (!endpointID || (endpointID.startsWith('mac:') && (!/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac) || mac === '00:00:00:00:00:00' || (parseInt(mac.slice(0, 2), 16) & 1) !== 0))) return fail('请提供有效设备 MAC', 'bad_endpoint_registration_request')
      if (!body || !statuses.includes(body.registration_status)) return fail('登记状态无效', 'bad_endpoint_registration_request')
      if (body.ownership_class && !ownerships.includes(body.ownership_class)) return fail('终端归属无效', 'bad_endpoint_registration_request')
      if (body.registration_status === 'registered' && ![body.owner_account, body.owner_name, body.asset_tag].some(value => text(value))) return fail('已登记设备需要责任人、责任人账号或资产编号', 'bad_endpoint_registration_request')
      const now = new Date().toISOString()
      const row: Registration = {
        endpoint_id: endpointID, primary_mac: mac, registration_status: body.registration_status,
        owner_account: text(body.owner_account), owner_name: text(body.owner_name), owner_department: text(body.owner_department),
        asset_tag: text(body.asset_tag), ownership_class: body.ownership_class || 'unknown', registration_note: text(body.registration_note),
        registration_updated_at: now, registration_updated_by: '演示管理员', registered_at: previous?.registered_at || now,
        last_seen: previous?.last_seen ?? '', source: 'local',
        merge_status: body.merge_status || 'active', merged_into_endpoint_id: text(body.merged_into_endpoint_id), split_from_endpoint_id: text(body.split_from_endpoint_id),
        registration_details: body.registration_details ? Object.fromEntries(Object.entries(body.registration_details).map(([key, value]) => [key, text(value)])) : previous?.registration_details ?? {},
      }
      records.set(endpointID, row)
      return HttpResponse.json({
        endpoint_id: endpointID, primary_mac: mac, entity_role: 'endpoint', first_seen: '', last_seen: row.last_seen, identity_confidence: 0,
        attributes: { manual_registration: row.registration_details }, registration_status: row.registration_status,
        owner_account: row.owner_account, owner_name: row.owner_name, owner_department: row.owner_department, asset_tag: row.asset_tag,
        ownership_class: row.ownership_class, registered_by: row.registration_updated_by, registered_at: row.registered_at,
        registration_note: row.registration_note, registration_updated_at: now, registration_update_by_id: row.registration_updated_by,
        merge_status: row.merge_status, merged_into_endpoint_id: row.merged_into_endpoint_id, split_from_endpoint_id: row.split_from_endpoint_id,
      } satisfies components['schemas']['EndpointEntity'])
    }),
  ]
}

export const terminalRegistrationHandlers = createTerminalRegistrationHandlers()
