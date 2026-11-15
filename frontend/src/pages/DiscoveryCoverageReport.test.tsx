import { render, screen } from '@testing-library/react'
import { it, expect } from 'vitest'
import { DiscoveryCoverageReport } from './DiscoveryCoverageReport'

it('keeps live address counts separate from the frozen fact-table comparison', () => {
  render(<DiscoveryCoverageReport report={{as_of:'2026-11-15T11:00:00Z',identity_as_of:'2026-11-15T10:38:00Z',window:'24h',subnet24:1070,ipv4:15390,ipv6:12,mac:5144,scoped_mac:5200,ip_mac_pairs:4300,identified:329,dumb_terminals:76,identity_total:6285}} loading={false} error={false} />)
  const report = screen.getByLabelText('设备发现覆盖报表')
  expect(report).toHaveTextContent('15,390')
  expect(report).toHaveTextContent('4,300')
  expect(report).toHaveTextContent('设备发现水位')
  expect(report).toHaveTextContent('冻结核查：2026-11-15 09:35:11 +08:00')
  expect(report).toHaveTextContent('镜像覆盖39')
  expect(report).toHaveTextContent('已有类型识别13')
  expect(report).toHaveTextContent('有流量待识别26')
  expect(report).toHaveTextContent('未见镜像 IP7')
})
