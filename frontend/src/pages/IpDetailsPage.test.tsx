import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import type { IpDeviceInventory, RiskSnapshot } from '../shared/api/types'
import { IpDetailsPage } from './IpDetailsPage'

const data = vi.hoisted(() => ({ risk: {} as RiskSnapshot, inventory: {} as IpDeviceInventory }))
vi.mock('../shared/api/queries', () => ({
  useSession: () => ({ data: { permissions: ['identity:read'] } }),
  useIpRisk: () => ({ data: data.risk }),
  useIpDevices: () => ({ data: data.inventory }),
  useIpEvidence: () => ({}), useIpEvents: () => ({}), useIpActivity: () => ({}),
  useCreateLabel: () => ({ isPending: false, mutate: vi.fn() }),
}))
vi.mock('../features/applications/ApplicationActivity', () => ({ ApplicationActivity: () => null }))
afterEach(cleanup)
const risk: RiskSnapshot = { ip: '192.0.2.82', score: 59, level: 'suspicious', confidence: .79, window: '10m', evidence_ids: ['proof-fixture'], summary: '客户端协议线索，需要复核', recommended_action: 'shadow_watch', updated_at: '2026-10-01T00:00:00Z', suspected_device_count: 0, device_confidence: 0 }
const inventory: IpDeviceInventory = { ip: risk.ip, window: '24h', suspected_device_count: 1, confidence: .82, status: 'single_candidate', summary: '单个设备候选', signals: [], conflicts: [], devices: [{ device_id: 'fixture-device', ip: risk.ip, label: '设备候选', brand: 'unknown', vendor: '未获取厂商', os_family: 'Linux', device_type: 'desktop', model: '', confidence: .82, signal_count: 1, strong_signal_count: 1, medium_signal_count: 0, weak_signal_count: 0, signals: [], fingerprints: [], summary: '原始设备线索保留' }] }
function setup(value = risk, devices = inventory) {
  data.risk = value; data.inventory = devices
  render(<MemoryRouter initialEntries={['/ips/192.0.2.82']}><Routes><Route path="/ips/:ip" element={<IpDetailsPage />} /></Routes></MemoryRouter>)
}
it('可访问的 IP 详情隐藏设备缺省字段并保留真实系统', () => {
  setup()
  expect(screen.queryByText('unknown')).toBeNull()
  expect(screen.queryByText('未获取厂商')).toBeNull()
  expect(screen.getByText('Linux')).toBeInTheDocument()
  expect(screen.getByText('原始设备线索保留')).toBeInTheDocument()
})
it('影子建议动作展示中文且风险置信度保留', () => {
  setup()
  expect(screen.getByText('影子观察')).toBeInTheDocument()
  expect(screen.queryByText('shadow_watch')).toBeNull()
  expect(screen.getByText('79%')).toBeInTheDocument()
})
it('没有有效风险窗口不能展示正常零分或请求时刻为评估时刻', () => {
  setup({ ...risk, window: 'none', score: 0, level: 'normal', confidence: 0, evidence_ids: [], summary: '未发现该 IP 的有效风险证据', recommended_action: 'record' })
  expect(screen.queryByText('正常')).toBeNull()
  expect(screen.queryByText('0%')).toBeNull()
  expect(screen.queryByText('none')).toBeNull()
  expect(screen.queryByText(new Date(risk.updated_at).toLocaleString())).toBeNull()
  expect(screen.getByText('未发现该 IP 的有效风险证据')).toBeInTheDocument()
  expect(screen.queryByRole('textbox', { name: '复核原因' })).toBeNull()
  expect(screen.queryByRole('button', { name: '提交标注' })).toBeNull()
  expect(screen.getByText('当前对象没有可关联证据 ID，暂不能提交复核标注')).toBeInTheDocument()
})
it('有效高风险保留等级分数、影子复核和原始证据追溯', () => {
  setup({ ...risk, level: 'high', score: 97, confidence: .85, recommended_action: 'shadow_manual_review', detection_basis: 'explicit_tunnel', independent_signal_groups: ['protocol_rule'] })
  expect(screen.getByText('高风险')).toBeInTheDocument()
  expect(screen.getByRole('progressbar', { name: '风险分 97' })).toBeInTheDocument()
  expect(screen.getByText('85%')).toBeInTheDocument()
  expect(screen.getByText('人工复核（影子）')).toBeInTheDocument()
  expect(screen.getByTitle('protocol_rule')).toHaveTextContent('协议规则')
  expect(screen.getByText('proof-fixture')).toBeInTheDocument()
  expect(screen.getByRole('textbox', { name: '复核原因' })).toBeInTheDocument()
})
it('缺省设备名称隐藏但候选 ID 与实际来源保留', () => {
  setup(risk, { ...inventory, devices: [{ ...inventory.devices[0], label: '未知设备候选' }] })
  expect(screen.queryByText('未知设备候选')).toBeNull()
  expect(screen.getByText('fixture-device')).toBeInTheDocument()
  expect(screen.getByText('原始设备线索保留')).toBeInTheDocument()
})
it('协议线索不显示为设备候选零或成功识别', () => {
  const { container } = renderProtocolOnly()
  expect(screen.queryByText('设备候选数')).toBeNull()
  expect(screen.getByText('仅有协议或基础设施线索')).toBeInTheDocument()
  expect(container.querySelector('.ant-alert-success')).toBeNull()
})
function renderProtocolOnly() {
  data.risk = risk
  data.inventory = { ...inventory, status: 'non_endpoint_or_weak', suspected_device_count: 0, confidence: 0, devices: [] }
  return render(<MemoryRouter initialEntries={['/ips/192.0.2.82']}><Routes><Route path="/ips/:ip" element={<IpDetailsPage />} /></Routes></MemoryRouter>)
}

it('撤销的历史系统推测弱化展示，原始值和 MAC 身份可追溯', () => {
  const baseSignal = { signal_id: 'legacy-os', ip: risk.ip, source: 'dhcp', kind: 'os_family', value: 'Linux', normalized_value: 'linux', strength: 'strong' as const, confidence: .82, weight: 70, event_ids: ['legacy-os-proof'] }
  const macSignal = { ...baseSignal, signal_id: 'mac-signal', kind: 'mac', value: '02:00:00:00:00:82', event_ids: ['mac-proof'] }
  setup(risk, { ...inventory, signals: [baseSignal, macSignal], devices: [{ ...inventory.devices[0], os_family: 'unknown', device_type: 'unknown', signals: [baseSignal, macSignal], strong_signal_count: 2 }] })
  expect(screen.getByText('历史推测')).toBeInTheDocument()
  const legacy = screen.getByTitle('legacy-os-proof')
  expect(legacy).toHaveTextContent('os_family: Linux')
  expect(legacy).toHaveClass('ant-typography-secondary')
  expect(legacy.closest('.device-signal-token')?.querySelector('.ant-tag-green')).toBeNull()
  expect(screen.getByTitle('mac-proof').closest('.device-signal-token')?.querySelector('.ant-tag-green')).toBeInTheDocument()
})
