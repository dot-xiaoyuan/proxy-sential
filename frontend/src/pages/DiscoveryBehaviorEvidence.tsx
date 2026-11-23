import { useQuery } from '@tanstack/react-query'
import { Typography } from 'antd'
import { request } from '../shared/api/client'
import type { components } from '../shared/api/generated'
import { AppErrorAlert } from '../shared/ui'
import { observedTimeTitle } from '../shared/ui/observedTime'
import { deviceTypeLabel } from '../entities/device/DeviceInventoryCells'

const evidenceLabels: Record<string, string> = {
  vendor_domain: '厂商服务域名',
  device_sni: '设备服务 SNI',
  port_attempt: '目标端口',
  port_response: '设备侧连接响应',
  port_reply_seen: '连接尝试见到反向响应',
  ntp: 'NTP 目标',
  tcp_stack: 'TCP 握手指纹',
  tcp_os_clue: '系统线索',
}

export function DiscoveryBehaviorEvidence({evidenceKey}: {evidenceKey: string}) {
  const result = useQuery({
    queryKey: ['discovery-behavior', evidenceKey],
    queryFn: ({signal}) => request<components['schemas']['DiscoveryBehavior']>(
      `/discovery/behavior?${new URLSearchParams({key:evidenceKey})}`, {signal}),
    staleTime: 60_000,
  })
  if (result.isError) return <AppErrorAlert title="读取流量行为线索失败" />
  if (!result.data) return null
  const data = result.data
  if (!data.items.length && data.status === 'ready') return null
  return <section className="discovery-client-clues" aria-label={data.attribution === 'device' ? '被动流量行为线索' : '当前 IP 的行为线索'}>
    <Typography.Title level={5}>{data.attribution === 'device' ? '被动流量行为线索' : '当前 IP 的行为线索'}</Typography.Title>
    {data.attribution === 'ip' && <Typography.Text type="secondary">地址复用或换绑时需核对证据时间。</Typography.Text>}
    {data.status === 'partial' && <Typography.Text type="secondary">行为证据覆盖有缺口，显示当前可用样本。</Typography.Text>}
    {data.candidate_type && <Typography.Text>候选类型 · {data.candidate_type==='video_device'?'视频设备':deviceTypeLabel(data.candidate_type)}</Typography.Text>}
    {data.sni_brand_hint && <Typography.Text strong>品牌线索 · {data.sni_brand_hint}（SNI）</Typography.Text>}
    {data.sni_brand_conflict && <Typography.Text type="warning">SNI 品牌线索存在冲突</Typography.Text>}
    {data.os_hint && <Typography.Text>系统线索 · {data.os_hint}</Typography.Text>}
    {data.cadence_minutes && <Typography.Text>观测分桶间隔 · {data.cadence_minutes} 分钟</Typography.Text>}
    {data.ntp_target && <Typography.Text>NTP 多次访问 · {data.ntp_target}</Typography.Text>}
    <Typography.Text type="secondary">{data.rule_version} · {observedTimeTitle(data.as_of)}</Typography.Text>
    <details>
      <summary>查看行为证据（{data.items.length}）</summary>
      {data.items.map(item=><article key={`${item.event_id}:${item.kind}:${item.value}`}>
        <strong>{evidenceLabels[item.kind] ?? item.kind}</strong>
        <span>{item.value}</span>
        <Typography.Text type="secondary">{item.event_id} · {observedTimeTitle(item.observed_at)}</Typography.Text>
      </article>)}
    </details>
  </section>
}
