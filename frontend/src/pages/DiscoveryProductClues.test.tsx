import { render, screen, cleanup } from '@testing-library/react'
import { afterEach, expect, it } from 'vitest'
import { DiscoveryProductClues } from './DiscoveryProductClues'
import type { components } from '../shared/api/generated'

const clue: components['schemas']['DiscoveryProductClue'] = {
  ip: '192.0.2.4', sensor_id: 'sensor', site: 'campus', domain: 'mirror', vlan: '4005',
  type: 'switch', manufacturer: 'Ruijie', model: 'S2910-24GT4SFP-UP-H',
  product_status: 'identified', attribution: 'response_ip', observed_at: '2026-11-15T06:00:00Z',
  event_id: 'source-snmp', rule_version: 'reviewed-v1', sources: [{ source: 'verified_snmp', rule_id: 'ruijie-switch', rule_version: 'reviewed-v1', evidence_id: 'source-snmp', observed_at: '2026-11-15T06:00:00Z' }],
}
afterEach(cleanup)

it('shows scoped response provenance separately from physical identity', () => {
  render(<DiscoveryProductClues clues={[clue]} />)
  expect(screen.getByText(/交换机 · Ruijie · S2910/)).toBeInTheDocument()
  expect(screen.getByText(/192.0.2.4 · mirror · VLAN 4005/)).toBeInTheDocument()
  expect(screen.getByText('source-snmp')).toBeInTheDocument()
  expect(screen.getByText(/物理设备归属按独立的地址绑定证据核实/)).toBeInTheDocument()
})

it('retains the matching failure rather than showing an empty type placeholder', () => {
  render(<DiscoveryProductClues clues={[{ ...clue, type: '', model: '', product_status: 'no_type_match' }]} />)
  expect(screen.getByText('现有产品字段尚无类型规则命中')).toBeInTheDocument()
  expect(screen.getByText('Ruijie')).toBeInTheDocument()
})

it('distinguishes a phone requester self-report from a server response', () => {
  render(<DiscoveryProductClues clues={[{ ...clue, type: 'voip_phone', manufacturer: 'Huawei', model: 'eSpace 7910', attribution: 'request_ip' }]} />)
  expect(screen.getByText('来源：请求端自报')).toBeInTheDocument()
  expect(screen.queryByText('来源：响应端自报')).not.toBeInTheDocument()
  expect(screen.getByText(/物理设备归属按独立的地址绑定证据核实/)).toBeInTheDocument()
})
