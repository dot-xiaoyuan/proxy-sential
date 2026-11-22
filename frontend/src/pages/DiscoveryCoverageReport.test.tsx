import { fireEvent, render, screen, within } from '@testing-library/react'
import { it, expect } from 'vitest'
import { DiscoveryCoverageReport, DiscoveryMirrorCoverage, type CoverageReport } from './DiscoveryCoverageReport'

const report: CoverageReport = {as_of:'2026-11-15T11:00:00Z',identity_as_of:'2026-11-15T10:38:00Z',diagnostic_as_of:'2026-11-15T10:37:00Z',window:'24h',subnet24:1070,ipv4:15390,ipv6:12,mac:5144,scoped_mac:5200,ip_mac_pairs:4300,ipv4_with_mac:2500,ip_mac_unique_pairs:3100,ip_mac_valid_scoped_pairs:1400,multi_mac_ipv4:590,multi_scope_ip_mac_pairs:1380,blank_and_filled_vlan_pairs:1360,identified:329,dumb_terminals:76,identity_total:6285,typed_ipv4:300,identity_no_type_ipv4:1000,no_identity_ipv4:14090,untyped_network_only_ipv4:200,untyped_dhcp_only_ipv4:600,untyped_application_ipv4:190,untyped_other_ipv4:10,mirror_funnel:{status:'ready',evaluated_at:'2026-11-15T11:01:00Z',as_of:'2026-11-15T11:00:00Z',ipv4_total:5835,ipv4_only:3938,mac_total:3472,mac_only:767,ip_mac_pairs:4034,scoped_pairs:5483,trusted_identities:2867,identified_pairs:3559,typed_pairs:703,oui_matched:1111,locally_administered_mac:2359,no_oui_global_mac:2,oui_library_version:'test-oui'}}

it('uses one address denominator for the three IPv4 stages and a separate denominator for the gap breakdown', () => {
  render(<DiscoveryCoverageReport report={report} />)
  const coverage = screen.getByRole('region', {name:'设备发现覆盖报表'})
  const progress = within(coverage).getByRole('region', {name:'IPv4 识别进度'})
  expect(progress).toHaveTextContent('15,390 个有设备观测的 IPv4')
  expect(progress).toHaveTextContent('1.9%')
  expect(within(progress).getByRole('img', {name:/IPv4 地址类型确认构成/})).toHaveAttribute('aria-label','IPv4 地址类型确认构成 · 15,390 个 IPv4 地址')
  const gaps = within(coverage).getByRole('region', {name:'类型待确认的证据'})
  expect(gaps).toHaveTextContent('1,000 个已关联设备')
  const dhcp = within(gaps).getByRole('progressbar', {name:'有 DHCP · 缺应用或设备公告'})
  expect(dhcp).toHaveAttribute('value','600')
  expect(dhcp).toHaveAttribute('max','1000')
  expect(coverage).not.toHaveTextContent('4,034')
  expect(coverage).toHaveTextContent('滞后约 22 分钟')
})

it('displays the mirror ratio using valid pair counts and shows OUI only on demand', () => {
  render(<DiscoveryMirrorCoverage funnel={report.mirror_funnel} />)
  const pairs = screen.getByRole('region', {name:'有效 IP–MAC 配对'})
  expect(pairs).toHaveTextContent('17.4%')
  expect(within(pairs).getByRole('img',{name:'有效配对的身份与类型构成 · 4,034 种有效配对'})).toBeVisible()
  expect(within(pairs).getByText('身份待关联')).toBeVisible()
  expect(screen.getByText('全局管理 · 匹配 OUI')).not.toBeVisible()
  fireEvent.click(screen.getByText('查看 MAC 管理位和厂商前缀'))
  expect(screen.getByText('全局管理 · 匹配 OUI')).toBeVisible()
  expect(screen.getByText('3,938 个无有效 MAC 配对')).toBeVisible()
})

it('keeps zero and absent breakdowns distinct', () => {
  const view=render(<DiscoveryCoverageReport report={{...report, typed_ipv4:0, identity_no_type_ipv4:0, no_identity_ipv4:0}} />)
  expect(screen.getByText('选定范围内暂无设备侧 IPv4 观测。')).toBeVisible()
  expect(screen.queryByRole('progressbar')).not.toBeInTheDocument()
  view.rerender(<DiscoveryCoverageReport report={{...report, typed_ipv4:undefined}} />)
  expect(screen.queryByRole('region',{name:'IPv4 识别进度'})).not.toBeInTheDocument()
  expect(screen.getByText('15,390')).toBeVisible()
})

it('keeps address coverage visible when identity totals time out', () => {
  render(<DiscoveryCoverageReport report={{
    ...report,
    identity_status: 'timeout',
    identity_as_of: undefined,
    identity_total: undefined,
    identified: undefined,
    dumb_terminals: undefined,
  }} />)
  expect(screen.getByRole('status')).toHaveTextContent('身份统计读取超时')
  expect(screen.getByRole('region', { name: 'IPv4 识别进度' })).toHaveTextContent('15,390')
  expect(screen.queryByText('发现处理水位', { exact: false })).not.toBeInTheDocument()
  expect(screen.queryByText('个发现身份', { exact: true })).not.toBeInTheDocument()
})

it('shows revoked type conclusions as a subset of addresses still awaiting confirmation', () => {
  render(<DiscoveryCoverageReport report={{...report, revoked_type_ipv4: 25}} />)
  expect(screen.getByText('25 个')).toBeVisible()
  expect(screen.getByText(/现有统计未区分具体原因/)).toBeVisible()
  expect(screen.getByRole('region', {name:'类型待确认的证据'})).toHaveTextContent('1,000 个已关联设备')
})
