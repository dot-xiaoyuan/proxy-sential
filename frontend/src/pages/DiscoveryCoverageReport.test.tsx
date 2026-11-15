import { render, screen } from '@testing-library/react'
import { it, expect } from 'vitest'
import { DiscoveryCoverageReport } from './DiscoveryCoverageReport'

it('shows only live address and identity counts in the current observation section', () => {
  render(<DiscoveryCoverageReport report={{as_of:'2026-11-15T11:00:00Z',identity_as_of:'2026-11-15T10:38:00Z',diagnostic_as_of:'2026-11-15T10:37:00Z',window:'24h',subnet24:1070,ipv4:15390,ipv6:12,mac:5144,scoped_mac:5200,ip_mac_pairs:4300,identified:329,dumb_terminals:76,identity_total:6285,typed_ipv4:300,identity_no_type_ipv4:1000,no_identity_ipv4:14090,untyped_network_only_ipv4:200,untyped_dhcp_only_ipv4:600,untyped_application_ipv4:190,untyped_other_ipv4:10}} loading={false} error={false} />)
  const report = screen.getByLabelText('设备发现覆盖报表')
  expect(report).toHaveTextContent('15,390')
  expect(report).toHaveTextContent('4,300')
  expect(report).toHaveTextContent('设备发现水位')
  expect(report).toHaveTextContent('已确认设备类型329')
  expect(report).toHaveTextContent('哑终端类型76')
  expect(report).toHaveTextContent('有身份，缺类型结论1,000')
  expect(report).toHaveTextContent('有 DHCP、无应用协议观测600')
  expect(report).toHaveTextContent('落后约 22 分钟')
})
