import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { OrganizationPage } from './OrganizationPage'

const state = vi.hoisted(() => ({
  save: vi.fn(),
  data: { campuses: [{campus_id:'ncu',code:'NCU-QH',name:'南昌大学（前湖校区）',enabled:true}], buildings: [{building_id:'admin-building',campus_id:'ncu',code:'ADMIN',name:'行政楼',enabled:true}], network_zones: [], access_points: [] },
}))
vi.mock('../shared/api/queries', () => ({
  useOrganization: () => ({data:state.data,refetch:vi.fn()}),
  useOrganizationList: (kind:keyof typeof state.data) => ({data:{items:state.data[kind],page:{total:state.data[kind].length}}}),
  useSession: () => ({data:{role:'admin',permissions:['organization:write']}}),
  useOrganizationMutation: () => ({mutateAsync:state.save,isPending:false}),
}))
afterEach(() => { cleanup(); vi.resetAllMocks() })
function setup() { render(<MemoryRouter><OrganizationPage /></MemoryRouter>) }
it('adds a campus using only its name and generates stable identifiers', async () => {
  setup(); fireEvent.click(screen.getByRole('button',{name:'新增校区'}))
  fireEvent.change(screen.getByLabelText('校区名称'),{target:{value:'测试校区'}})
  fireEvent.click(screen.getByRole('button',{name:/保\s*存/}))
  await waitFor(() => expect(state.save).toHaveBeenCalledWith({kind:'campuses',payload:expect.objectContaining({name:'测试校区',campus_id:expect.any(String),code:expect.any(String)})}))
})
it('retains input and displays a visible save error, then allows retry', async () => {
  state.save.mockRejectedValueOnce(new Error('校区编码重复')).mockResolvedValueOnce({})
  setup(); fireEvent.click(screen.getByRole('button',{name:'新增校区'}))
  fireEvent.change(screen.getByLabelText('校区名称'),{target:{value:'测试校区'}})
  fireEvent.click(screen.getByRole('button',{name:/保\s*存/}))
  await screen.findByText(/保存失败.*校区编码重复/)
  expect(screen.getByLabelText('校区名称')).toHaveValue('测试校区')
  fireEvent.click(screen.getByRole('button',{name:/保\s*存/}))
  await waitFor(() => expect(state.save).toHaveBeenCalledTimes(2))
  expect(state.save.mock.calls[0][0]).toEqual(state.save.mock.calls[1][0])
})
it('selects the existing Qianhu campus automatically for a network zone', async () => {
  setup(); fireEvent.click(screen.getByRole('button',{name:'新增网段映射'}))
  fireEvent.change(screen.getByLabelText('位置名称'),{target:{value:'测试区域'}})
  fireEvent.change(screen.getByLabelText('IP 网段'),{target:{value:'222.204.88.0/23'}})
  fireEvent.click(screen.getByRole('button',{name:/保\s*存/}))
  await waitFor(() => expect(state.save).toHaveBeenCalledWith({kind:'network-zones',payload:expect.objectContaining({campus_id:'ncu',name:'测试区域',cidrs:['222.204.88.0/23'],ssids:[],vlans:[]})}))
})

it('configures the administration building by CIDR without VLAN, SSID or access points', async () => {
  setup(); fireEvent.click(screen.getByRole('button',{name:'新增网段映射'}))
  fireEvent.mouseDown(screen.getByLabelText('楼宇（选填）'))
  fireEvent.click(await screen.findByText('行政楼'))
  fireEvent.change(screen.getByLabelText('IP 网段'), {target:{value:'222.204.88.0/23'}})
  fireEvent.click(screen.getByRole('button', {name:/保\s*存/}))
  await waitFor(() => expect(state.save).toHaveBeenCalledWith({kind:'network-zones',payload:expect.objectContaining({campus_id:'ncu',building_id:'admin-building',name:'行政楼',cidrs:['222.204.88.0/23'],ssids:[],vlans:[]})}))
})
