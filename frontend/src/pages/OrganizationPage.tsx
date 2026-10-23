import { useRef, useState } from 'react'
import { Button, Card, Form, Input, Modal, Select, Space, Tabs, Tag, Typography, message } from 'antd'
import { can } from '../shared/auth/permissions'
import { useOrganization, useOrganizationList, useOrganizationMutation, useSession } from '../shared/api/queries'
import { AppErrorAlert, AppListHeader, AppListSection, AppLoadingState, AppPageHeader, AppServerPagination, AppTable, useServerPagination } from '../shared/ui'
import type { ColumnsType } from 'antd/es/table'
import { useUrlState } from '../shared/ui/useUrlState'

type OrganizationKind = 'campuses' | 'buildings' | 'network-zones' | 'access-points'
const identifiers = { campuses: 'campus_id', buildings: 'building_id', 'network-zones': 'network_zone_id', 'access-points': 'access_point_id' }
const names = { campuses: '校区', buildings: '楼宇', 'network-zones': '网段映射', 'access-points': '接入点' }
const splitValues = (value = '') => value.split(/[,，\n]+/).map(item => item.trim()).filter(Boolean)
function saveError(error: unknown) {
  if (!(error instanceof Error)) return '请稍后重试'
  try {
    const body = JSON.parse(error.message)
    return body.error?.message || body.message || error.message
  } catch { return error.message }
}

export function OrganizationPage() {
  const [messageApi, messageContext] = message.useMessage()
  const [activeTab, setActiveTab] = useUrlState('tab', 'campuses', ['campuses', 'zones'])
  const campusPage = useServerPagination('campuses_')
  const zonePage = useServerPagination('zones_')
  const query = useOrganization()
  const campusList = useOrganizationList('campuses', { limit: campusPage.pageSize, cursor: campusPage.cursor })
  const zoneList = useOrganizationList('network_zones', { limit: zonePage.pageSize, cursor: zonePage.cursor })
  const session = useSession()
  const mutation = useOrganizationMutation()
  const [kind, setKind] = useState<OrganizationKind | null>(null)
  const [editing, setEditing] = useState(false)
  const [error, setError] = useState('')
  const saving = useRef(false)
  const [form] = Form.useForm<Record<string, string>>()
  const selectedCampus = Form.useWatch('campus_id', {form, preserve:true})
  const selectedBuilding = Form.useWatch('building_id', {form, preserve:true})
  if (query.isLoading) return <AppLoadingState rows={6} />
  if (query.isError || !query.data) return <AppErrorAlert title="校园组织与网络区域读取失败" />
  const data = query.data
  const writable = !!session.data && can(session.data, 'organization:write')
  const qianhu = data.campuses.find(item => item.campus_id === 'ncu' || item.code === 'NCU-QH' || item.name.includes('前湖'))
  const defaultCampus = qianhu?.campus_id ?? (data.campuses.length === 1 ? data.campuses[0].campus_id : undefined)
  const open = (value: OrganizationKind, item?: object, defaults?: Record<string, unknown>) => {
    form.resetFields()
    setError('')
    setEditing(!!item)
    setKind(value)
    const id = `${value}-${Array.from(crypto.getRandomValues(new Uint8Array(12)), byte => byte.toString(16).padStart(2, '0')).join('')}`
    const values: Record<string, unknown> = item ? { ...item } : { [identifiers[value]]: id, code: id, campus_id: value === 'campuses' ? id : defaultCampus, kind: 'ap', ...defaults }
    for (const key of ['cidrs', 'ssids', 'vlans']) if (Array.isArray(values[key])) values[key] = values[key].join('，')
    form.setFieldsValue(values as Record<string, string>)
  }
  const submit = async () => {
    if (!kind || saving.current) return
    let values: Record<string, string>
    try { values = await form.validateFields() } catch { return }
    saving.current = true
    setError('')
    // Only send fields belonging to this form; Ant Design retains unmounted values.
    const fields = kind === 'campuses' ? ['campus_id', 'code', 'name'] : kind === 'buildings' ? ['building_id', 'campus_id', 'code', 'name'] : kind === 'network-zones' ? ['network_zone_id', 'campus_id', 'building_id', 'name'] : ['access_point_id', 'campus_id', 'building_id', 'network_zone_id', 'kind', 'name', 'management_ip']
    const payload: Record<string, unknown> = Object.fromEntries(fields.map(key => [key, values[key]?.trim() ?? '']))
    if (kind === 'network-zones') {
      for (const key of ['cidrs', 'ssids', 'vlans']) payload[key] = splitValues(values[key])
      payload.name = values.name?.trim() || data.buildings.find(item => item.building_id === values.building_id)?.name || ''
    }
    try {
      await mutation.mutateAsync({ kind, payload })
      if (kind === 'campuses') campusPage.update(1, campusPage.pageSize)
      if (kind === 'network-zones') zonePage.update(1, zonePage.pageSize)
      setKind(null)
      messageApi.success('组织与网络位置映射已保存')
    } catch (reason) { setError(`保存失败：${saveError(reason)}`) }
    finally { saving.current = false }
  }
  const buildings = data.buildings.filter(item => item.campus_id === selectedCampus)
  const zones = data.network_zones.filter(item => item.campus_id === selectedCampus && (!selectedBuilding || !item.building_id || item.building_id === selectedBuilding))
  const editButton = (value: OrganizationKind, item: object, label: string) => writable && <Button size="small" onClick={() => open(value, item)}>{label}</Button>
  const campusColumns: ColumnsType<NonNullable<typeof campusList.data>['items'][number]> = [
    { title: '校区', dataIndex: 'name', render: (value: string) => <Typography.Text strong>{value}</Typography.Text> },
    { title: '楼宇', key: 'buildings', width: 100, render: (_, campus) => `${data.buildings.filter(item => item.campus_id === campus.campus_id).length} 栋` },
    { title: '网段', key: 'zones', width: 100, render: (_, campus) => `${data.network_zones.filter(zone => zone.campus_id === campus.campus_id).length} 个` },
    { title: '操作', key: 'action', width: 120, render: (_, campus) => editButton('campuses', campus, '编辑校区') },
  ]
  const zoneColumns: ColumnsType<NonNullable<typeof zoneList.data>['items'][number]> = [
    { title: '名称', dataIndex: 'name', width: 170, render: (value: string) => <Typography.Text strong>{value}</Typography.Text> },
    { title: '校区 / 楼宇', key: 'location', width: 190, render: (_, zone) => [data.campuses.find(item => item.campus_id === zone.campus_id)?.name, data.buildings.find(item => item.building_id === zone.building_id)?.name].filter(Boolean).join(' · ') },
    { title: 'IP 网段', key: 'cidrs', width: 220, render: (_, zone) => <div className="organization-mappings">{(zone.cidrs ?? []).map(cidr => <span key={cidr}>{cidr}</span>)}</div> },
    { title: 'SSID', key: 'ssids', width: 140, render: (_, zone) => (zone.ssids ?? []).join('、') },
    { title: 'VLAN', key: 'vlans', width: 120, render: (_, zone) => (zone.vlans ?? []).join('、') },
    { title: '操作', key: 'action', width: 110, render: (_, zone) => editButton('network-zones', zone, '编辑映射') },
  ]
  return <main className="page organization-page">
    {messageContext}
    <AppPageHeader extra={writable && <Space wrap>
      <Button onClick={() => open('campuses')}>新增校区</Button>
      <Button disabled={!data.campuses.length} onClick={() => open('buildings')}>新增楼宇</Button>
      <Button type="primary" disabled={!data.campuses.length} onClick={() => open('network-zones')}>新增网段映射</Button>
      <Button disabled={!data.campuses.length} onClick={() => open('access-points')}>新增接入点</Button>
    </Space>} />
    {qianhu && <Card className="organization-preset">
      <div className="organization-row"><div><Typography.Title level={4}>南昌大学（前湖校区）</Typography.Title><Typography.Text type="secondary">江西省南昌市红谷滩区学府大道999号 · 康健社区位于学府大道1299号</Typography.Text></div><Tag>前湖基础资料</Tag></div>
      <p>校区、社区及楼宇资料来源于学校官网。在楼宇旁配置 IP 网段即可关联位置，一个楼宇可配置多个网段，无需填写 VLAN 或创建接入点。</p>
      <div className="organization-row"><Typography.Text type="secondary">{data.campuses.length} 个校区 · {data.buildings.length} 栋楼宇 · {data.network_zones.length} 个区域 · {data.access_points.length} 个接入点</Typography.Text><a href="https://iec.ncu.edu.cn/info/1551/14706.htm" target="_blank" rel="noreferrer">查看学校资料来源</a></div>
    </Card>}
    <Card className="surface-card margin-top-md operations-tabs-surface">
      <Tabs activeKey={activeTab} onChange={setActiveTab} destroyOnHidden items={[
        { key: 'campuses', label: '校区与楼宇', children: <>
          <AppListHeader title="校区与楼宇" count={`${campusList.data?.page.total ?? 0} 个校区`} />
          <AppListSection isError={campusList.isError} errorTitle="校区列表读取失败" isLoading={campusList.isLoading} loadingRows={3} isEmpty={!campusList.data?.items.length} emptyText="尚未配置校区">
            <AppTable rowKey="campus_id" columns={campusColumns} dataSource={campusList.data?.items ?? []} scroll={{x:640}} expandable={{rowExpandable: campus => data.buildings.some(item => item.campus_id === campus.campus_id), expandedRowRender: campus => <div className="organization-building-grid">{data.buildings.filter(item => item.campus_id === campus.campus_id).map(item => <div className="organization-building" key={item.building_id}>
              <div className="organization-row"><Typography.Text strong>{item.name}</Typography.Text>{editButton('buildings', item, '编辑楼宇')}</div>
              {data.network_zones.filter(zone => zone.building_id === item.building_id).map(zone => <div className="organization-building-mapping" key={zone.network_zone_id}>
                <div className="organization-mappings">{(zone.cidrs ?? []).map(cidr => <span key={cidr}>{cidr}</span>)}{!zone.cidrs?.length && <span>{zone.name}</span>}</div>
                {editButton('network-zones', zone, '编辑网段')}
              </div>)}
              {writable && <Button size="small" onClick={() => open('network-zones', undefined, {campus_id:item.campus_id,building_id:item.building_id})}>配置网段</Button>}
            </div>)}</div>}} />
          </AppListSection>
          <AppServerPagination page={campusPage.page} pageSize={campusPage.pageSize} total={campusList.data?.page.total ?? 0} onChange={campusPage.update} />
        </> },
        { key: 'zones', label: '网段与位置映射', children: <>
          <p className="organization-guidance">用 IP 网段关联楼宇或区域，例如 222.204.88.0/23 对应行政楼。VLAN、SSID 与接入点均为可选信息。</p>
          <AppListHeader title="网段与位置映射" count={`${zoneList.data?.page.total ?? 0} 个映射`} />
          <AppListSection isError={zoneList.isError} errorTitle="网络区域列表读取失败" isLoading={zoneList.isLoading} loadingRows={3} isEmpty={!zoneList.data?.items.length} emptyText="尚未配置网络区域">
            <AppTable rowKey="network_zone_id" columns={zoneColumns} dataSource={zoneList.data?.items ?? []} scroll={{x:900}} />
          </AppListSection>
          <AppServerPagination page={zonePage.page} pageSize={zonePage.pageSize} total={zoneList.data?.page.total ?? 0} onChange={zonePage.update} />
          {data.access_points.length > 0 && <details className="organization-buildings"><summary>接入点 / NAS（{data.access_points.length}）</summary><div className="organization-list">{data.access_points.map(item => <div key={item.access_point_id} className="organization-row organization-item"><span>{[item.name, item.management_ip].filter(Boolean).join(' · ')}</span>{editButton('access-points', item, '编辑接入点')}</div>)}</div></details>}
        </> },
      ]} />
    </Card>
    <Modal title={kind ? `${editing ? '编辑' : '新增'}${names[kind]}` : ''} open={kind !== null} confirmLoading={mutation.isPending} closable={!mutation.isPending} mask={{closable:!mutation.isPending}} keyboard={!mutation.isPending} cancelButtonProps={{disabled: mutation.isPending}} onCancel={() => setKind(null)} onOk={() => void submit()} okText="保存" cancelText="取消" forceRender>
      {error && <AppErrorAlert className="margin-bottom-md" title={error} />}
      <Form form={form} layout="vertical" onFinish={() => void submit()} disabled={mutation.isPending}>
        {kind && <Form.Item name={identifiers[kind]} hidden><Input /></Form.Item>}
        {(kind === 'campuses' || kind === 'buildings') && <Form.Item name="code" hidden><Input /></Form.Item>}
        {kind !== 'campuses' && <Form.Item name="campus_id" label="所属校区" rules={[{required:true,message:'请选择所属校区'}]}><Select onChange={() => form.setFieldsValue({building_id:undefined,network_zone_id:undefined})} options={data.campuses.map(item => ({value:item.campus_id,label:item.name}))} /></Form.Item>}
        {kind !== 'network-zones' && <Form.Item name="name" label={kind === 'campuses' ? '校区名称' : kind === 'buildings' ? '楼宇名称' : '名称'} rules={[{required:true,whitespace:true,message:'请填写名称'}]}><Input maxLength={120} /></Form.Item>}
        {(kind === 'network-zones' || kind === 'access-points') && <Form.Item name="building_id" label="楼宇（选填）"><Select allowClear showSearch optionFilterProp="label" onChange={() => form.setFieldValue('network_zone_id', undefined)} options={buildings.map(item => ({value:item.building_id,label:item.name}))} /></Form.Item>}
        {kind === 'network-zones' && <>
          <Form.Item name="cidrs" label="IP 网段" extra="支持 IPv4 / IPv6 CIDR，多个网段用逗号或换行分隔。" rules={[{validator:(_, value:string) => !editing && !splitValues(value).length ? Promise.reject(new Error('请填写 IP 网段')) : Promise.resolve()}]}><Input.TextArea rows={3} placeholder="例如：222.204.88.0/23" /></Form.Item>
          <Form.Item name="name" label={selectedBuilding ? '映射名称（选填）' : '位置名称'} extra={selectedBuilding ? '留空时使用楼宇名称。' : '没有对应楼宇时，可填写社区或其他位置名称。'} dependencies={['building_id']} rules={[({getFieldValue}) => ({validator:(_, value:string) => getFieldValue('building_id') || value?.trim() ? Promise.resolve() : Promise.reject(new Error('请选择楼宇或填写位置名称'))})]}><Input maxLength={120} placeholder={buildings.find(item => item.building_id === selectedBuilding)?.name} /></Form.Item>
          <details className="organization-advanced"><summary>高级设置：SSID / VLAN（选填）</summary><Typography.Paragraph type="secondary">按 IP 网段配置位置时可直接留空，无需创建接入点。</Typography.Paragraph><Form.Item name="ssids" label="SSID（选填）"><Input /></Form.Item><Form.Item name="vlans" label="VLAN（选填）"><Input /></Form.Item></details>
        </>}
        {kind === 'access-points' && <><Form.Item name="network_zone_id" label="网络区域（选填）"><Select allowClear options={zones.map(item => ({value:item.network_zone_id,label:item.name}))} /></Form.Item><Form.Item name="kind" label="类型" rules={[{required:true,message:'请选择类型'}]}><Select options={[{value:'ap',label:'无线 AP'},{value:'nas',label:'NAS'},{value:'switch',label:'交换机'}]} /></Form.Item><Form.Item name="management_ip" label="管理 IP（选填）"><Input /></Form.Item></>}
      </Form>
    </Modal>
  </main>
}
