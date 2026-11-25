import { fireEvent, render, screen, within } from '@testing-library/react'
import { it, expect } from 'vitest'
import { DiscoveryCoverageReport, DiscoveryMirrorCoverage, type CoverageReport } from './DiscoveryCoverageReport'

const report: CoverageReport = {as_of:'2026-11-15T11:00:00Z',identity_as_of:'2026-11-15T10:38:00Z',diagnostic_as_of:'2026-11-15T10:37:00Z',window:'24h',subnet24:1070,ipv4:15390,ipv6:12,mac:5144,scoped_mac:5200,ip_mac_pairs:4300,ipv4_with_mac:2500,ip_mac_unique_pairs:3100,ip_mac_valid_scoped_pairs:1400,multi_mac_ipv4:590,multi_scope_ip_mac_pairs:1380,blank_and_filled_vlan_pairs:1360,identified:329,dumb_terminals:76,identity_total:6285,typed_ipv4:300,identity_no_type_ipv4:1000,no_identity_ipv4:14090,untyped_network_only_ipv4:200,untyped_dhcp_only_ipv4:600,untyped_application_ipv4:190,untyped_other_ipv4:10,mirror_funnel:{status:'ready',evaluated_at:'2026-11-15T11:01:00Z',as_of:'2026-11-15T11:00:00Z',ipv4_total:5835,ipv4_only:3938,mac_total:3472,mac_only:767,ip_mac_pairs:4034,scoped_pairs:5483,trusted_identities:2867,identified_pairs:3559,typed_pairs:703,oui_matched:1111,locally_administered_mac:2359,no_oui_global_mac:2,oui_library_version:'test-oui'}}

it('uses one address denominator for the three IPv4 stages and a separate denominator for the gap breakdown', () => {
  render(<DiscoveryCoverageReport report={report} />)
  const coverage = screen.getByRole('region', {name:'设备发现覆盖报表'})
  const progress = within(coverage).getByRole('region', {name:'观测 IPv4 的硬件类型确认覆盖'})
  expect(progress).toHaveTextContent('15,390 个有设备观测的 IPv4')
  expect(progress).toHaveTextContent('1.9%')
  expect(within(progress).getByRole('img', {name:/IPv4 地址类型确认构成/})).toHaveAttribute('aria-label','IPv4 地址类型确认构成 · 15,390 个 IPv4 地址')
  const gaps = within(coverage).getByRole('region', {name:'类型待确认的证据'})
  expect(gaps).toHaveTextContent('1,000 个已关联设备')
  const dhcp = within(gaps).getByRole('progressbar', {name:'有 DHCP · 缺设备协议证据'})
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
  expect(within(screen.getByRole('region', {name:'类型待确认的证据'})).queryByRole('progressbar')).not.toBeInTheDocument()
  view.rerender(<DiscoveryCoverageReport report={{...report, typed_ipv4:undefined}} />)
  expect(screen.queryByRole('region',{name:'观测 IPv4 的硬件类型确认覆盖'})).not.toBeInTheDocument()
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
  expect(screen.getByRole('region', { name: '观测 IPv4 的硬件类型确认覆盖' })).toHaveTextContent('15,390')
  expect(screen.queryByText('发现处理水位', { exact: false })).not.toBeInTheDocument()
  expect(screen.queryByText('个发现身份', { exact: true })).not.toBeInTheDocument()
})

it('splits prior confirmations and conflicts from other pending addresses without losing inactive confirmed types', () => {
  render(<DiscoveryCoverageReport report={{...report, revoked_type_ipv4: 25, profile_candidate_identities: 120,
    ipv4_type_review: { withdrawn_confirmation: 4, conflict: 3, confirmed_inactive: 12 }}} />)
  expect(screen.getByText('25 个')).toBeVisible()
  expect(screen.getByText('120 个发现身份')).toBeVisible()
  const chart = screen.getByRole('region', {name:'观测 IPv4 的硬件类型确认覆盖'})
  expect(within(chart).getByText('曾确认，现已撤回').closest('li')).toHaveTextContent('4')
  expect(within(chart).getByText('类型证据冲突').closest('li')).toHaveTextContent('3')
  expect(within(chart).getByText('已关联，尚待确认').closest('li')).toHaveTextContent('993')
  expect(within(chart).getByText('12 个')).toBeVisible()
  expect(chart).toHaveTextContent('1.9%')
})

it('shows the window evidence matrix and labels the protocol replay as a fixed snapshot', () => {
  render(<DiscoveryCoverageReport report={{...report, ipv4_pending:[
    { status:'with_profile', network_only:10, dhcp_only:40, device_protocol:5, other:0 },
    { status:'without_profile', network_only:600, dhcp_only:200, device_protocol:145, other:0 },
    { status:'unlinked', network_only:14090, dhcp_only:0, device_protocol:0, other:0 },
  ]}} />)
  const table = screen.getByRole('table', {name:'待确认 IPv4 的画像及协议证据'})
  const row = within(table).getByRole('row', {name:/已有画像类型线索/})
  expect(within(row).getAllByRole('cell').map(cell => cell.textContent)).toEqual(['10','40','5','0','55'])
  fireEvent.click(screen.getByText('设备协议回放明细 · 11 月 23 日 18:54'))
  expect(screen.getByText(/固定 24 小时快照/)).toBeVisible()
  expect(screen.getByText('协议响应缺可信 MAC')).toBeVisible()
})

it('shows recorded identity changes and leaves gaps visible in a partial month', () => {
  render(<DiscoveryCoverageReport report={{...report, window:'720h', hardware_trend:{
    as_of:report.as_of, window_days:30, observation_from:'2026-11-12T00:00:00Z',
    first_seen:3, previous_only:1,
  }}}/>)
  const trend = screen.getByRole('region', {name:'近 30 天硬件身份变化'})
  expect(trend).toHaveTextContent('首次观测')
  expect(trend).toHaveTextContent('此前连续覆盖待核查')
  expect(trend).not.toHaveTextContent('0 个')
})

it('shows the published deduplicated denominator separately from planning labels and the global count', () => {
  const { rerender } = render(<DiscoveryCoverageReport report={report} />)
  expect(screen.queryByRole('region',{name:'规划设备网段的可见 IPv4'})).toBeNull()
  rerender(<DiscoveryCoverageReport report={{...report,planned_ipv4:{
    status:'partial', version:'version-1', as_of:report.as_of, available_from:report.as_of,
    visible_ipv4:2, ranges:[{range:'192.0.2.0/24',device_type:'摄像头',visible_ipv4:2},
      {range:'192.0.2.1',device_type:'监控设备',visible_ipv4:1}],
  }}}/>)
  const panel = screen.getByRole('region',{name:'规划设备网段的可见 IPv4'})
  expect(within(panel).getAllByRole('listitem')).toHaveLength(2)
  expect(panel.querySelector('header strong')).toHaveTextContent('2 个地址')
  expect(panel).toHaveTextContent('192.0.2.1 · 监控设备')
  expect(panel).toHaveTextContent('可用起点')
  expect(panel).toHaveTextContent('范围版本 version-1')
  expect(within(panel).getByRole('status')).toHaveTextContent('部分时间')
  rerender(<DiscoveryCoverageReport report={{...report,planned_ipv4:{status:'unavailable'}}}/>)
  expect(within(panel).getByRole('status')).toHaveTextContent('读取失败')
  expect(panel).not.toHaveTextContent('0 个地址')
})
