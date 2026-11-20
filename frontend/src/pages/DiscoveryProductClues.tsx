import { Typography } from 'antd'
import type { components } from '../shared/api/generated'
import { deviceTypeLabel } from '../entities/device/DeviceInventoryCells'
import { observedTimeTitle } from '../shared/ui/observedTime'

type Clue = components['schemas']['DiscoveryProductClue']

function productClueLabel(clue: Clue) {
  return [clue.type ? deviceTypeLabel(clue.type) : '', clue.manufacturer, clue.model].filter(Boolean).join(' · ')
}

export function DiscoveryProductClues({ clues }: { clues?: Clue[] }) {
  if (!clues?.length) return null
  const ordered = [...clues].sort((a, b) => b.observed_at.localeCompare(a.observed_at))
  return <section className="discovery-product-clues" aria-label="IP 产品证据">
    <Typography.Title level={5}>IP 产品证据</Typography.Title>
    <Typography.Paragraph type="secondary">产品来自该作用域内设备端点的自报；物理设备归属按独立的地址绑定证据核实。</Typography.Paragraph>
    {ordered.map(clue => <article key={`${clue.event_id}:${clue.rule_version}`}>
      {productClueLabel(clue) && <strong>{productClueLabel(clue)}</strong>}
      <span>{[clue.ip, clue.domain, clue.vlan ? `VLAN ${clue.vlan}` : '', clue.vrf ? `VRF ${clue.vrf}` : ''].filter(Boolean).join(' · ')}</span>
      <time>{observedTimeTitle(clue.observed_at)}</time>
      <span>{clue.attribution === 'request_ip' ? '来源：请求端自报' : '来源：响应端自报'}</span>
      {clue.product_status === 'conflict' && <Typography.Text type="warning">产品证据冲突：{[...(clue.conflicting_types ?? []).map(deviceTypeLabel), ...(clue.conflicting_models ?? [])].join('、')}</Typography.Text>}
      {clue.product_status === 'no_type_match' && <Typography.Text type="secondary">现有产品字段尚无类型规则命中</Typography.Text>}
      {clue.product_status === 'missing_product_fields' && <Typography.Text type="secondary">自报缺少产品字段：{clue.missing_fields?.join('、')}</Typography.Text>}
      {clue.evaluation_error && <Typography.Text type="danger">产品匹配失败：{clue.evaluation_error}</Typography.Text>}
      <span>{clue.event_id}</span>
      {clue.sources?.map(source => <Typography.Text type="secondary" key={`${source.source}:${source.rule_id}`}>{source.source} · {source.rule_id} · {source.rule_version}</Typography.Text>)}
    </article>)}
  </section>
}
