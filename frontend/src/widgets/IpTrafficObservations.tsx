import { useState, type FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Input, Typography } from 'antd'
import { Link, useLocation } from 'react-router-dom'
import { api } from '../shared/api/client'
import type { IpTrafficObservationQuery, NormalizedEventSummary, StreamEventIndexItem } from '../shared/api/types'
import { AppErrorAlert, formatDateTime } from '../shared/ui'

const protocolLabels: Record<string, string> = { handshake: '握手观测', ttl: 'TTL 观测', hop_limit: 'IPv6 Hop Limit 观测' }
const sourceLabels = { 'handshake-sidecar': '握手采集', 'packet-sidecar': '数据包采集' }

function recentQuery(): IpTrafficObservationQuery {
  const to = new Date()
  return { source_owner: 'handshake-sidecar', from: new Date(to.getTime() - 15 * 60_000).toISOString(), to: to.toISOString(), limit: 20 }
}
function localTime(value: string) {
  const date = new Date(value)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

export function IpTrafficObservations({ ip, sensorId, identityLastSeen, contextMac }: { ip: string; sensorId?: string; identityLastSeen?: string; contextMac?: string }) {
  const location = useLocation()
  const [initial] = useState(recentQuery)
  const [query, setQuery] = useState(initial)
  const [from, setFrom] = useState(localTime(initial.from))
  const [to, setTo] = useState(localTime(initial.to))
  const [owner, setOwner] = useState(initial.source_owner)
  const [protocol, setProtocol] = useState<NonNullable<IpTrafficObservationQuery['protocol']> | ''>('')
  const [validation, setValidation] = useState('')
  const [previous, setPrevious] = useState<string[]>([])
  const [selected, setSelected] = useState<StreamEventIndexItem | null>(null)
  const index = useQuery({ queryKey: ['ip-traffic-observations', ip, sensorId, query],
    queryFn: () => api.ipTrafficObservations(ip, { ...query, sensor_id: sensorId }), retry: false, staleTime: 0, gcTime: 30_000, refetchOnWindowFocus: false })
  const body = useQuery({ queryKey: ['ip-traffic-observation-body', selected?.body_ref],
    queryFn: () => api.streamEventBody(selected!.body_ref), enabled: selected !== null, retry: false, refetchOnWindowFocus: false })
  const page = !index.isFetching && !index.isError ? index.data : undefined

  function submit(event: FormEvent) {
    event.preventDefault()
    const start = new Date(from).getTime(), end = new Date(to).getTime()
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start || end - start > 15 * 60_000) {
      setValidation('请选择不超过 15 分钟的有效时间范围。'); return
    }
    setValidation(''); setPrevious([]); setSelected(null)
    setQuery({ source_owner: owner, protocol: protocol || undefined, from: new Date(start).toISOString(), to: new Date(end).toISOString(), limit: 20 })
  }
  function refresh() {
    const latest = { ...recentQuery(), source_owner: owner, protocol: protocol || undefined }
    setFrom(localTime(latest.from)); setTo(localTime(latest.to)); setValidation(''); setPrevious([]); setSelected(null); setQuery(latest)
  }
  return <section className="surface ip-traffic-observations" aria-label="IP 流量观察">
    <Typography.Title level={4}>IP 流量观察</Typography.Title>
    <p className="ip-traffic-description">查看该 IP 已入库的握手、TTL 和 IPv6 Hop Limit 摘要。SNI、Host、UA 可能来自共享出口后的客户端，需结合归属证据判断设备身份。</p>
    <form className="ip-traffic-form" onSubmit={submit}>
      <label>采集来源<select aria-label="观测采集来源" value={owner} onChange={event => setOwner(event.target.value as typeof owner)}>
        <option value="handshake-sidecar">握手采集</option><option value="packet-sidecar">数据包采集</option>
      </select></label>
      <label>观测类型<select aria-label="观测类型" value={protocol ?? ''} onChange={event => setProtocol(event.target.value as typeof protocol)}>
        <option value="">全部类型</option><option value="handshake">握手</option><option value="ttl">TTL</option><option value="hop_limit">IPv6 Hop Limit</option>
      </select></label>
      <label>开始时间<Input type="datetime-local" step="1" aria-label="观测开始时间" value={from} onChange={event => setFrom(event.target.value)} /></label>
      <label>结束时间<Input type="datetime-local" step="1" aria-label="观测结束时间" value={to} onChange={event => setTo(event.target.value)} /></label>
      <div className="ip-traffic-actions"><Button type="primary" htmlType="submit">查询观测</Button><Button onClick={refresh}>刷新最近 15 分钟</Button></div>
    </form>
    {validation && <p role="alert" className="stream-events-validation">{validation}</p>}
    {index.isFetching && <p role="status">正在读取流量观测…</p>}
    {index.isError && <AppErrorAlert title="流量观察读取失败" message={index.error.message} />}
    {page && <>
      <div className="ip-traffic-coverage">
        <p>{sourceLabels[page.source_owner]} · 查询范围 {formatDateTime(page.from)} 至 {formatDateTime(page.to)}</p>
        {page.source && <>
          <p>来源接续起点：{formatDateTime(page.source.cutoff_at)}。本次仅查看这一接续批次，更早及审计取消的历史未包含在内。</p>
          {page.source.state !== 'active' && <p role="status">来源登记状态：{({ paused: '已暂停', closed: '已关闭', prepared: '准备中' } as Record<string, string>)[page.source.state]}。现存记录不能证明采集仍在持续。</p>}
          {identityLastSeen && Date.parse(identityLastSeen) < Date.parse(page.source.cutoff_at) && <p>设备识别摘要早于本来源的接续起点；摘要最后观测于 {formatDateTime(identityLastSeen)}。</p>}
        </>}
        <p>查询完成：{formatDateTime(page.queried_at)}。记录数量按摘要计，采集完整性需结合来源运行状态核对。</p>
      </div>
      {page.status === 'source_unavailable' && <p role="status">该来源尚未登记新存查接续起点。</p>}
      {page.status === 'before_cutover' && <p role="status">所选时间早于本来源的接续起点，请选择之后的时间。</p>}
      {page.status === 'ready' && <>
        {page.events.length === 0 ? <p>该范围内没有已入库的观测摘要。</p> : <p className="ip-traffic-page-count">本页 {page.events.length} 条观测摘要</p>}
        <div className="ip-traffic-list">
          {page.events.map(item => {
            const expanded = selected?.event_key === item.event_key && selected.body_ref.sha256 === item.body_ref.sha256
            const matchingMac = Boolean(contextMac && item.subject_mac && contextMac.toLowerCase() === item.subject_mac.toLowerCase())
            const candidateURL = item.subject_mac && /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(item.subject_mac)
              ? `/devices/${encodeURIComponent(`mac:${item.subject_mac.toLowerCase()}`)}?${new URLSearchParams({tab:'signals',ip,return_to:`${location.pathname}${location.search}`})}`
              : ''
            return <article className="ip-traffic-card" key={item.event_key + item.body_ref.sha256}>
              <div className="ip-traffic-card-heading"><strong>{protocolLabels[item.protocol] ?? item.protocol}</strong><time dateTime={item.observed_at}>{formatDateTime(item.observed_at)}</time><Button size="small" aria-expanded={expanded} onClick={() => setSelected(expanded ? null : item)}>{expanded ? '收起观测内容' : '查看观测内容'}</Button></div>
              {item.subject_mac && <p className="ip-traffic-mac"><span className="mono">MAC {item.subject_mac}</span>{matchingMac && item.protocol === 'handshake' && <span className="ip-traffic-match-note">握手 MAC 与本终端一致</span>}{candidateURL && <Link to={candidateURL}>查看该 MAC 的终端详情</Link>}</p>}
              {expanded && <div className="ip-traffic-detail">
                {body.isFetching && <p role="status">正在读取观测内容…</p>}
                {body.isError && <AppErrorAlert title="观测内容读取失败" message={body.error.message} />}
                {!body.isFetching && !body.isError && body.data && <TrafficObservationDetail event={body.data} />}
              </div>}
            </article>
          })}
        </div>
        <div className="ip-traffic-actions ip-traffic-pagination">
          <Button disabled={previous.length === 0} onClick={() => { setQuery({ ...query, cursor: previous[previous.length - 1] || undefined }); setPrevious(previous.slice(0, -1)); setSelected(null) }}>上一页</Button>
          <Button disabled={!page.next_cursor} onClick={() => { setPrevious([...previous, query.cursor ?? '']); setQuery({ ...query, cursor: page.next_cursor }); setSelected(null) }}>下一页</Button>
        </div>
      </>}
    </>}
  </section>
}

function scalar(value: unknown): string { return typeof value === 'string' || typeof value === 'number' ? String(value) : '' }
function TrafficObservationDetail({ event }: { event: NormalizedEventSummary }) {
  const payload = event.payload ?? {}, flow = event.flow ?? {}
  const miwifiDomain = ['snis','hosts','sni','host'].some(key => {
    const value = payload[key]
    return (Array.isArray(value) ? value : [value]).some(item => typeof item === 'string' && item.trim().toLowerCase().replace(/\.$/, '') === 'api.miwifi.com')
  })
  const fields = [
    ['摘要累计观测数', scalar(payload.observed_count)], ['MAC', scalar(payload.mac ?? event.subject?.mac)],
    ['TTL', scalar(payload.ttl ?? flow.ttl)], ['IPv6 Hop Limit', scalar(payload.hop_limit ?? flow.hop_limit)],
    ['方向', ({ outbound: '出站', inbound: '入站', ingress: '入站', egress: '出站' } as Record<string, string>)[scalar(payload.direction)] ?? ''],
  ].filter(([, value]) => value)
  return <>
    <dl className="ip-traffic-facts">{fields.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
    {miwifiDomain && <p className="ip-traffic-router-clue">访问 api.miwifi.com：MiWiFi 服务访问是小米路由器候选线索，需结合 MAC 厂商与共享或设备角色证据核实；单次访问不能确认设备类型。</p>}
    {payload.neighbor_role === 'unverified' && <p>链路邻居归属尚未核实，TTL 仅作为路径观测。</p>}
    {(['snis', 'hosts', 'user_agents'] as const).map(key => {
      const values = Array.isArray(payload[key]) ? (payload[key] as unknown[]).map(scalar).filter(Boolean) : []
      return values.length > 0 && <div className="ip-traffic-values" key={key}><strong>{{ snis: 'TLS SNI', hosts: 'HTTP Host', user_agents: 'User-Agent' }[key]}</strong><ul>{values.slice(0, 8).map((value, i) => <li key={i}>{value}</li>)}</ul>{values.length > 8 && <p>显示前 8 项，其余可展开标准事件正文查看。</p>}</div>
    })}
    <details className="ip-traffic-raw"><summary>标准事件正文</summary><pre>{JSON.stringify(event, null, 2)}</pre></details>
  </>
}
