import { fireEvent, render, screen, within } from '@testing-library/react'
import { it, expect } from 'vitest'
import { DiscoveryCoverageReport, DiscoveryMirrorCoverage, type CoverageReport } from './DiscoveryCoverageReport'
import { buildCoverageSummary } from './discoveryCoverageSummary'

const report: CoverageReport = { as_of: '2026-11-15T11:00:00Z', identity_as_of: '2026-11-15T10:38:00Z', diagnostic_as_of: '2026-11-15T10:37:00Z', window: '24h', subnet24: 1070, ipv4: 15390, ipv6: 12, mac: 5144, scoped_mac: 5200, ip_mac_pairs: 4300, ipv4_with_mac: 2500, ip_mac_unique_pairs: 3100, ip_mac_valid_scoped_pairs: 1400, multi_mac_ipv4: 590, multi_scope_ip_mac_pairs: 1380, blank_and_filled_vlan_pairs: 1360, identified: 329, dumb_terminals: 76, identity_total: 6285, typed_ipv4: 300, identity_no_type_ipv4: 1000, no_identity_ipv4: 14090, untyped_network_only_ipv4: 200, untyped_dhcp_only_ipv4: 600, untyped_application_ipv4: 190, untyped_other_ipv4: 10, mirror_funnel: { status: 'ready', evaluated_at: '2026-11-15T11:01:00Z', as_of: '2026-11-15T11:00:00Z', ipv4_total: 5835, ipv4_only: 3938, mac_total: 3472, mac_only: 767, ip_mac_pairs: 4034, scoped_pairs: 5483, trusted_identities: 2867, identified_pairs: 3559, typed_pairs: 703, oui_matched: 1111, locally_administered_mac: 2359, no_oui_global_mac: 2, oui_library_version: 'test-oui' } }

// Same numbers as the 204 report published for the last 24 hours on 2026-11-25.
const field: CoverageReport = {
  ...report, ipv4: 3438, ipv6: 3022, typed_ipv4: 347, identity_no_type_ipv4: 2430, no_identity_ipv4: 661,
  untyped_network_only_ipv4: 763, untyped_dhcp_only_ipv4: 1460, untyped_application_ipv4: 207, untyped_other_ipv4: 0,
  ipv4_type_review: { withdrawn_confirmation: 1, conflict: 1, confirmed_inactive: 73 },
  ipv4_pending: [
    { status: 'with_profile', network_only: 35, dhcp_only: 1316, device_protocol: 57, other: 0 },
    { status: 'without_profile', network_only: 728, dhcp_only: 144, device_protocol: 148, other: 0 },
    { status: 'withdrawn_confirmation', network_only: 0, dhcp_only: 0, device_protocol: 1, other: 0 },
    { status: 'conflict', network_only: 0, dhcp_only: 0, device_protocol: 1, other: 0 },
    { status: 'unlinked', network_only: 534, dhcp_only: 0, device_protocol: 127, other: 0 },
  ],
  mirror_funnel: { ...report.mirror_funnel, ipv4_total: 6053 }, ipv4_mirror_overlap: 1916
}

it('partitions device-observed IPv4 and joins the mirror census only through the overlap', () => {
  const summary = buildCoverageSummary(field)
  expect(summary).toMatchObject({ device: 3438, confirmed: 347, inferred: 1408, pending: 1683, mirror: 6053, total: 7575, mirrorOnly: 4137, deviceOutsideMirror: 1522 })
  expect(summary.reasons.map(reason => [reason.key, reason.value])).toEqual([
    ['network', 728], ['unlinked', 661], ['protocol', 148], ['dhcp', 144], ['conflict', 2],
  ])
  expect(summary.reasons.reduce((sum, reason) => sum + reason.value, 0)).toBe(3438 - 347 - 1408)
})

it('leads with one funnel whose layers are subsets of the previous one', () => {
  render(<DiscoveryCoverageReport report={field} />)
  const lead = screen.getByText(/共发现/, { selector: 'p' })
  expect(lead).toHaveTextContent('近 24 小时共发现 7,575 个 IPv4 地址，其中 3,438 个有设备层报文。其中 1,755 个已有类型判断，占设备层地址的 51.0%（硬件规则确认 347 个，画像识别 1,408 个）。')
  const funnel = screen.getByRole('region', { name: '发现与识别' })
  const steps = within(funnel).getAllByRole('listitem').filter(item => item.classList.contains('coverage-funnel-step'))
  expect(steps.map(step => step.querySelector('.coverage-funnel-label strong')?.textContent)).toEqual(['共发现 IPv4 地址', '有设备层报文', '已有类型判断'])
  expect(steps[0]).toHaveTextContent('7,575')
  expect(steps[1]).toHaveTextContent('3,438占 45.4%')
  expect(steps[2]).toHaveTextContent('1,755占设备层 51.0%')
  expect(steps[2]).toHaveTextContent('硬件规则确认 34710.1%')
  expect(steps[2]).toHaveTextContent('画像识别 1,40841.0%')
  expect(funnel).toHaveTextContent('4,137 个只在流量中出现，没有设备层报文，无法判断类型')
  expect(funnel).toHaveTextContent('1,683 个有设备层报文，尚无类型判断')
  expect(within(funnel).getByRole('img', { name: '已有类型判断 1,755 个，其中硬件规则确认 347 个，画像识别 1,408 个' })).toBeVisible()
  expect(screen.getByRole('list', { name: '统计口径' })).toHaveTextContent('有 1,522 个有设备层报文的地址未出现在本窗口的镜像统计中')
  expect(screen.getByRole('list', { name: '统计口径' })).toHaveTextContent('另有 IPv6 地址 3,022 个，未计入以上数字')
  expect(document.body).not.toHaveTextContent('未识别')
})

it.each([
  ['15m0s', '近 15 分钟'], ['24h0m0s', '近 24 小时'],
  ['168h0m0s', '近 7 天'], ['720h0m0s', '近 30 天'],
])('labels published duration %s in the overview', (window, label) => {
  render(<DiscoveryCoverageReport report={{ ...field, window }} />)
  expect(screen.getByText(/共发现/, { selector: 'p' })).toHaveTextContent(label + '共发现')
})

it('explains every unconfirmed address with mutually exclusive reasons', () => {
  render(<DiscoveryCoverageReport report={field} />)
  const reasons = screen.getByRole('region', { name: '尚无类型判断的原因' })
  expect(reasons).toHaveTextContent('1,683 个有设备层报文的地址尚无类型判断')
  const rows = within(reasons).getAllByRole('listitem')
  expect(rows.map(row => row.querySelector('.coverage-reason-head')?.textContent)).toEqual([
    '只有 ARP 等地址层报文72843.3%',
    'IP 地址的设备归属待核实66139.3%',
    '有设备协议报文，证据不足1488.8%',
    '有 DHCP 报文，特征不足1448.6%',
    '证据冲突或确认被撤回20.1%',
  ])
})

it.each([3437, 3439])('keeps separate address counts when the published device partition differs from %i', ipv4 => {
  render(<DiscoveryCoverageReport report={{ ...field, ipv4 }} />)
  const funnel = screen.getByRole('region', { name: '发现与识别' })
  expect(funnel).toHaveTextContent('合并总数暂不可用')
  expect(within(funnel).getByRole('img', { name: '有设备层报文 3,438 个' })).toBeVisible()
  expect(funnel).not.toHaveTextContent('共发现 IPv4 地址')
  expect(funnel).not.toHaveTextContent('个只在流量中出现')
  expect(screen.getByRole('list', { name: '统计口径' })).not.toHaveTextContent('未出现在本窗口的镜像统计中')
})

it('falls back to device counts when the overlap or profile evidence is unavailable', () => {
  render(<DiscoveryCoverageReport report={report} />)
  const funnel = screen.getByRole('region', { name: '发现与识别' })
  expect(funnel).not.toHaveTextContent('共发现 IPv4 地址')
  expect(funnel).toHaveTextContent('镜像流量另见 5,835 个站点网段地址，与上面的地址部分重叠，合并总数暂不可用。')
  expect(funnel).toHaveTextContent('硬件规则确认画像识别统计暂不可用')
  expect(screen.getByText(/有设备层报文的 IPv4 地址/, { selector: 'p' })).toHaveTextContent('15,390')
  const reasons = screen.getByRole('region', { name: '尚无类型判断的原因' })
  expect(reasons).toHaveTextContent('本次报表缺少画像识别明细')
  expect(within(reasons).queryAllByRole('listitem')).toHaveLength(0)
})

it('ignores an overlap that cannot belong to both address sets', () => {
  expect(buildCoverageSummary({ ...field, ipv4_mirror_overlap: 9999 }).total).toBeUndefined()
  expect(buildCoverageSummary({ ...field, mirror_funnel: { ...field.mirror_funnel, status: 'initializing' } }).total).toBeUndefined()
})

it('groups confirmed and inferred types by business category in visual cards', () => {
  render(<DiscoveryCoverageReport report={field} composition={{
    ip_product_types: [{ device_type: 'switch', count: 6 }],
    types: [{ device_type: 'access_point', count: 240 }, { device_type: 'camera', count: 34 }, { device_type: 'printer', count: 33 },
    { device_type: 'laptop', count: 11 }, { device_type: 'router', count: 10 }, { device_type: 'access_control', count: 5 },
    { device_type: 'recorder', count: 4 }, { device_type: 'media_player', count: 3 }, { device_type: 'switch', count: 3 },
    { device_type: 'voip_phone', count: 2 }, { device_type: 'desktop', count: 1 }],
    candidate_types: [{ device_type: 'mobile', count: 1098 }, { device_type: 'desktop', count: 286 }, { device_type: 'tablet', count: 148 },
    { device_type: 'router', count: 99 }, { device_type: 'access_point', count: 17 }, { device_type: 'printer', count: 17 }],
    dumb_terminals: 118,
  }} />)
  const types = screen.getByRole('region', { name: '识别出了什么' })
  expect(within(types).queryByRole('table')).not.toBeInTheDocument()
  const confirmed = within(types).getByRole('region', { name: '硬件规则确认' })
  expect(confirmed.querySelector('h5')).toHaveTextContent('硬件规则确认346')
  const groups = [...confirmed.querySelectorAll('.coverage-type-group-head')].map(head => head.textContent)
  expect(groups).toEqual(['网络设备253', '哑终端81', '电脑与移动终端12'])
  expect(confirmed).toHaveTextContent('无线接入点 240')
  expect(confirmed).toHaveTextContent('媒体播放器 3')
  expect(types).not.toHaveTextContent('其中哑终端')
  expect(within(types).getByRole('region', { name: 'IP 自报的产品类型' })).toHaveTextContent('归属待核实')
  const inferred = within(types).getByRole('region', { name: '画像识别' })
  expect([...inferred.querySelectorAll('.coverage-type-group-head')].map(head => head.textContent)).toEqual(['电脑与移动终端1,532', '网络设备116', '哑终端17'])
})

it('shows the processing lag, partial mirror window and identity timeout plainly', () => {
  render(<DiscoveryCoverageReport report={{ ...field, identity_status: 'timeout', mirror_funnel: { ...field.mirror_funnel, status: 'partial', available_from: '2026-11-12T04:33:01Z' } }} />)
  expect(screen.getByText(/发现处理滞后约 22 分钟/)).toHaveClass('coverage-warning')
  expect(screen.getByText(/镜像统计窗口覆盖不完整/)).toBeVisible()
  expect(screen.getByRole('status')).toHaveTextContent('身份统计读取超时')
})

it('keeps technical breakdowns available but folded below the summary', () => {
  render(<DiscoveryCoverageReport report={{
    ...field, ipv4_binding_freshness: { current: 1370, expired: 943, uncertain: 465, no_binding: 660 }, planned_ipv4: {
      status: 'partial', version: 'version-1', as_of: report.as_of, available_from: report.as_of,
      visible_ipv4: 2, ranges: [{ range: '192.0.2.0/24', device_type: '摄像头', visible_ipv4: 2 }]
    }
  }} />)
  const details = screen.getByText('查看技术明细')
  expect(screen.getByText('硬件规则未确认的地址明细')).not.toBeVisible()
  fireEvent.click(details)
  const table = screen.getByRole('table', { name: '硬件规则未确认 IPv4 的画像及协议证据' })
  expect(within(within(table).getByRole('row', { name: /画像已识别类型/ })).getAllByRole('cell').map(cell => cell.textContent)).toEqual(['35', '1,316', '57', '0', '1,408'])
  expect(screen.getByRole('region', { name: 'IPv4 绑定时效' })).toBeVisible()
  expect(screen.getByRole('region', { name: '规划设备网段的可见 IPv4' })).toHaveTextContent('192.0.2.0/24 · 摄像头')
})

it('shows recorded identity changes and leaves gaps visible in a partial month', () => {
  render(<DiscoveryCoverageReport report={{
    ...report, window: '720h', hardware_trend: {
      as_of: report.as_of, window_days: 30, observation_from: '2026-11-12T00:00:00Z',
      first_seen: 3, previous_only: 1,
    }
  }} />)
  const trend = screen.getByRole('region', { name: '近 30 天硬件身份变化' })
  expect(trend).toHaveTextContent('首次观测')
  expect(trend).toHaveTextContent('此前连续覆盖待核查')
  expect(trend).not.toHaveTextContent('0 个')
  expect(screen.getByText(/有设备层报文的 IPv4 地址/, { selector: 'p' })).toHaveTextContent('近 30 天')
})

it('keeps an empty window distinct from missing statistics', () => {
  const empty = {
    ...report, ipv4: 0, typed_ipv4: 0, identity_no_type_ipv4: 0, no_identity_ipv4: 0,
    untyped_network_only_ipv4: 0, untyped_dhcp_only_ipv4: 0, untyped_application_ipv4: 0, untyped_other_ipv4: 0
  }
  const view = render(<DiscoveryCoverageReport report={empty} />)
  expect(screen.getByRole('region', { name: '尚无类型判断的原因' })).toHaveTextContent('选定范围内暂无有设备层报文的地址。')
  view.rerender(<DiscoveryCoverageReport report={{ ...empty, ipv4: 5, typed_ipv4: 5 }} />)
  expect(screen.getByRole('region', { name: '尚无类型判断的原因' })).toHaveTextContent('有设备层报文的地址均已有类型判断。')
  view.rerender(<DiscoveryCoverageReport report={{ ...report, typed_ipv4: undefined }} />)
  expect(screen.getByRole('region', { name: '发现与识别' })).not.toHaveTextContent('已确认类型')
})

it('displays the mirror ratio using valid pair counts and shows OUI only on demand', () => {
  render(<DiscoveryMirrorCoverage funnel={report.mirror_funnel} />)
  const pairs = screen.getByRole('region', { name: '有效 IP–MAC 配对' })
  expect(pairs).toHaveTextContent('17.4%')
  expect(within(pairs).getByRole('img', { name: '有效配对的身份与类型构成 · 4,034 种有效配对' })).toBeVisible()
  expect(within(pairs).getByText('身份待关联')).toBeVisible()
  expect(screen.getByText('全局管理 · 匹配 OUI')).not.toBeVisible()
  fireEvent.click(screen.getByText('查看 MAC 管理位和厂商前缀'))
  expect(screen.getByText('全局管理 · 匹配 OUI')).toBeVisible()
  expect(screen.getByText('3,938 个无有效 MAC 配对')).toBeVisible()
})

it('renders drill-down KPI cards, type chips, 7-day trend, brands and network hotspots', () => {
  render(
    <DiscoveryCoverageReport
      report={{
        ...field,
        planned_ipv4: {
          status: 'ready',
          visible_ipv4: 42,
          ranges: [{ range: '10.126.254.0/24', device_type: '摄像机', visible_ipv4: 42 }],
        },
      }}
      composition={{
        count_unit: 'cross_vlan_discovery_identity',
        total: 4490,
        identified: 348,
        profile_typed: 1321,
        types: [{ device_type: 'access_point', count: 240 }, { device_type: 'printer', count: 35 }],
        candidate_types: [{ device_type: 'mobile', count: 573 }],
        ip_product_types: [{ device_type: 'switch', count: 68 }],
        dumb_terminals: 79,
        vlans: [{ vlan: '3112', count: 420 }],
        overview: {
          active: 1280,
          previous_active: 1210,
          dumb_terminals: 79,
          new_seven_days: 156,
          new_by_day: [
            { date: '2026-11-20', count: 18 },
            { date: '2026-11-21', count: 24 },
          ],
          brands: [
            { brand: 'Huawei', device_type: 'access_point', count: 180 },
            { brand: 'HP', device_type: 'printer', count: 25 },
          ],
          subnets: [{ subnet: '10.126.254.0/24', count: 160 }],
        },
      }}
      windowKey="24h"
    />,
  )
  const kpis = screen.getByLabelText('核心资产指标')
  expect(kpis).toHaveTextContent('4,490')
  expect(kpis).toHaveTextContent('348')
  expect(kpis).toHaveTextContent('79')
  expect(kpis).toHaveTextContent('1,280')
  expect(kpis).toHaveTextContent('较昨日同期 +70')
  expect(screen.getByRole('link', { name: '查看重点哑终端明细' })).toHaveAttribute('href', '/devices?tab=discovery&discovery_window=24h&discovery_capability=dumb')
  expect(screen.getByRole('link', { name: '无线接入点 240' })).toHaveAttribute('href', '/devices?tab=discovery&discovery_window=24h&discovery_state=identified&discovery_type=access_point')
  expect(screen.getByRole('link', { name: '手机 573' })).toHaveAttribute('href', '/devices?tab=discovery&discovery_window=24h&discovery_state=profile_typed&discovery_type=mobile')
  expect(screen.getByRole('region', { name: '近 7 天每日新发现' })).toHaveTextContent('合计 156 个')
  expect(screen.getByRole('region', { name: '已确认设备品牌分布' })).toHaveTextContent('Huawei')
  const hotspots = screen.getByRole('region', { name: '网段与 VLAN 热点' })
  expect(hotspots).toHaveTextContent('10.126.254.0/24')
  fireEvent.click(within(hotspots).getByText('VLAN'))
  expect(hotspots).toHaveTextContent('VLAN 3112')
  fireEvent.click(within(hotspots).getByText('规划网段'))
  expect(hotspots).toHaveTextContent('摄像机')
})
