import { Input, Select } from 'antd'

import { useOrganization } from '../api/queries'

export type UniversityDimensions = {
  campus_id?: string
  department?: string
  person_type?: string
  ssid?: string
  vlan?: string
  ap?: string
  nas_ip?: string
}

export function UniversityDimensionFilters({ value, onChange }: { value: UniversityDimensions; onChange: (next: UniversityDimensions) => void }) {
  const organization = useOrganization()
  const update = (field: keyof UniversityDimensions, fieldValue?: string) => onChange({ ...value, [field]: fieldValue || undefined })
  return <div className="university-filter-grid">
    <Select allowClear loading={organization.isLoading} placeholder="全部校区" value={value.campus_id} onChange={(item) => update('campus_id', item)} options={(organization.data?.campuses ?? []).map((item) => ({ value: item.campus_id, label: item.name }))} />
    <Input allowClear placeholder="院系" value={value.department} onChange={(event) => update('department', event.target.value)} />
    <Select allowClear placeholder="人员类型" value={value.person_type} onChange={(item) => update('person_type', item)} options={[{ value: 'student', label: '学生' }, { value: 'faculty', label: '教职工' }, { value: 'visitor', label: '访客' }, { value: 'service', label: '服务账号' }]} />
    <Input allowClear placeholder="SSID" value={value.ssid} onChange={(event) => update('ssid', event.target.value)} />
    <Input allowClear placeholder="VLAN" value={value.vlan} onChange={(event) => update('vlan', event.target.value)} />
    <Input allowClear placeholder="AP / 接入点" value={value.ap} onChange={(event) => update('ap', event.target.value)} />
    <Input allowClear placeholder="NAS IP" value={value.nas_ip} onChange={(event) => update('nas_ip', event.target.value)} />
  </div>
}
