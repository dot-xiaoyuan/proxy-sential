import type { components } from '../shared/api/generated'

type CoverageReport = components['schemas']['DiscoveryCoverageReport']
type PendingRow = NonNullable<CoverageReport['ipv4_pending']>[number]

export type Tone = 'teal' | 'blue' | 'slate' | 'amber' | 'purple'
export type Reason = { key: string; label: string; detail: string; value: number; tone: Tone }

export type CoverageSummary = {
  device?: number
  confirmed?: number
  inferred?: number
  judged?: number
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
  const judged = typed !== undefined && inferred !== undefined ? typed + inferred : undefined
  const pending = judged !== undefined ? device - judged : device === typed ? 0 : undefined
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
    const open = byStatus('without_profile')
    reasons = [
      { key: 'network', label: '只有 ARP 等地址层报文', detail: '能看到地址，但没有可用于判断类型的设备特征', value: open?.network_only ?? 0, tone: 'slate' },
      { key: 'unlinked', label: 'IP 地址的设备归属待核实', detail: '地址还未与可信设备关联。即使 IP 自报了产品或型号，也只能作为该地址的线索。', value: sumRow(byStatus('unlinked')), tone: 'slate' },
      { key: 'protocol', label: '有设备协议报文，证据不足', detail: '设备协议缺少可用于判断类型的产品或型号等字段。', value: open?.device_protocol ?? 0, tone: 'slate' },
      { key: 'dhcp', label: '有 DHCP 报文，特征不足', detail: 'DHCP 特征未能对应到具体设备类型', value: open?.dhcp_only ?? 0, tone: 'slate' },
      { key: 'other', label: '其他证据', detail: '证据类型不在以上分组中', value: open?.other ?? 0, tone: 'slate' },
      { key: 'conflict', label: '证据冲突或确认被撤回', detail: '多项证据指向不同类型，或原确认已撤回，需人工核实', value: sumRow(byStatus('conflict')) + sumRow(byStatus('withdrawn_confirmation')), tone: 'amber' },
    ]
  }
  return {
    device, confirmed: typed, inferred, judged, pending, mirror, total,
    mirrorOnly: total !== undefined && mirror !== undefined ? mirror - overlap! : undefined,
    deviceOutsideMirror: total !== undefined ? report.ipv4 - overlap! : undefined,
    reasons: reasons.filter(reason => reason.value > 0),
  }
}
