import type { components } from '../shared/api/generated'

type CoverageReport = components['schemas']['DiscoveryCoverageReport']
type PendingRow = NonNullable<CoverageReport['ipv4_pending']>[number]

export type Tone = 'teal' | 'blue' | 'slate' | 'amber' | 'purple'
export type Reason = { key: string; label: string; detail: string; value: number; tone: Tone }

export type CoverageSummary = {
  device?: number
  confirmed?: number
  inferred?: number
  pending?: number
  mirror?: number
  total?: number
  mirrorOnly?: number
  deviceOutsideMirror?: number
  reasons: Reason[]
}

const sumRow = (row?: PendingRow) => row ? row.network_only + row.dhcp_only + row.device_protocol + row.other : 0

// One denominator for the whole overview. Device-observed IPv4 is partitioned
// into confirmed, inferred and pending. The mirror census uses another scope,
// so it joins the funnel only through the published overlap.
export function buildCoverageSummary(report: CoverageReport): CoverageSummary {
  const { typed_ipv4: typed, identity_no_type_ipv4: needsType, no_identity_ipv4: unlinked } = report
  const partitioned = typed !== undefined && needsType !== undefined && unlinked !== undefined
  const device = partitioned ? typed + needsType + unlinked : report.ipv4
  const rows = report.ipv4_pending
  const byStatus = (status: PendingRow['status']) => rows?.find(row => row.status === status)
  const inferred = rows ? sumRow(byStatus('with_profile')) : undefined
  const pending = typed !== undefined ? device - typed - (inferred ?? 0) : undefined
  const funnel = report.mirror_funnel
  const mirror = funnel && funnel.status !== 'initializing' && funnel.as_of ? funnel.ipv4_total : undefined
  const overlap = report.ipv4_mirror_overlap
  // Older published snapshots may count the address rows and their type
  // partition at different moments. Only combine counts with one denominator.
  const overlapValid = device === report.ipv4 && mirror !== undefined && overlap !== undefined
    && overlap >= 0 && overlap <= mirror && overlap <= device
  const total = overlapValid ? device + mirror - overlap : undefined
  let reasons: Reason[] = []
  if (rows) {
    const open = [byStatus('without_profile'), byStatus('unlinked')]
    const pick = (key: keyof Omit<PendingRow, 'status'>) => open.reduce((sum, row) => sum + (row?.[key] ?? 0), 0)
    reasons = [
      { key: 'inferred', label: '已推测出类型，待证据确认', detail: '依据 DHCP 等画像线索，多为手机、电脑和平板', value: inferred ?? 0, tone: 'blue' },
      { key: 'network', label: '只有 ARP 等地址层报文', detail: '能看到地址，但没有可用于判断类型的设备特征', value: pick('network_only'), tone: 'slate' },
      { key: 'protocol', label: '有设备协议报文，证据不足', detail: '设备自报未归属到可信 MAC，或缺少型号等字段', value: pick('device_protocol'), tone: 'slate' },
      { key: 'dhcp', label: '有 DHCP 报文，特征不足', detail: 'DHCP 特征未能对应到具体设备类型', value: pick('dhcp_only'), tone: 'slate' },
      { key: 'other', label: '其他证据', detail: '证据类型不在以上分组中', value: pick('other'), tone: 'slate' },
      { key: 'conflict', label: '证据冲突或确认被撤回', detail: '多项证据指向不同类型，或原确认已撤回，需人工核实', value: sumRow(byStatus('conflict')) + sumRow(byStatus('withdrawn_confirmation')), tone: 'amber' },
    ]
  } else if (needsType !== undefined && unlinked !== undefined) {
    reasons = [
      { key: 'unlinked', label: '设备归属待核实', detail: '地址还没有对应到可信的设备记录', value: unlinked, tone: 'slate' },
      { key: 'network', label: '只有 ARP 等地址层报文', detail: '能看到地址，但没有可用于判断类型的设备特征', value: report.untyped_network_only_ipv4 ?? 0, tone: 'slate' },
      { key: 'protocol', label: '有设备协议报文，证据不足', detail: '设备自报缺少型号等字段，或规则未能确认', value: report.untyped_application_ipv4 ?? 0, tone: 'slate' },
      { key: 'dhcp', label: '有 DHCP 报文，特征不足', detail: 'DHCP 特征未能对应到具体设备类型', value: report.untyped_dhcp_only_ipv4 ?? 0, tone: 'slate' },
      { key: 'other', label: '其他证据', detail: '证据类型不在以上分组中', value: report.untyped_other_ipv4 ?? 0, tone: 'slate' },
    ]
  }
  return {
    device, confirmed: typed, inferred, pending, mirror, total,
    mirrorOnly: total !== undefined && mirror !== undefined ? mirror - overlap! : undefined,
    deviceOutsideMirror: total !== undefined ? report.ipv4 - overlap! : undefined,
    reasons: reasons.filter(reason => reason.value > 0),
  }
}
