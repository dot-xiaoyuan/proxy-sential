import { useEffect, useState, type FormEvent } from 'react'
import { Button, Input, Typography } from 'antd'
import { Link, useSearchParams } from 'react-router-dom'
import { can } from '../shared/auth/permissions'
import { useSession } from '../shared/api/queries'
import { isIPAddress } from '../shared/ipAddress'
import { IpTrafficObservations } from '../widgets/IpTrafficObservations'

export function IpTrafficLookupPanel() {
  const [params, setParams] = useSearchParams()
  const [input, setInput] = useState(params.get('ip') ?? '')
  const [error, setError] = useState('')
  const session = useSession()
  const ip = (params.get('ip') ?? '').trim()
  const selectedIP = isIPAddress(ip) ? ip : ''

  useEffect(() => setInput(ip), [ip])

  function submit(event: FormEvent) {
    event.preventDefault()
    const value = input.trim()
    if (!isIPAddress(value)) {
      setError('请输入完整有效的 IPv4 或 IPv6 地址。')
      return
    }
    setError('')
    setParams(current => {
      const next = new URLSearchParams(current)
      next.set('tab', 'ip')
      next.set('ip', value)
      return next
    })
  }

  return <section className="ip-observation-lookup">
    <div className="surface ip-observation-lookup-header">
      <Typography.Title level={4}>按 IP 查看流量观测</Typography.Title>
      <p>按 IP 查询已入库的握手、TTL 和 IPv6 Hop Limit 摘要。终端列表只检索已生成的终端身份与地址关联，流量观测可在这里独立查看。</p>
      <form className="ip-observation-lookup-form" onSubmit={submit}>
        <Input aria-label="IP 地址" placeholder="输入完整 IPv4 或 IPv6 地址" value={input} onChange={event => setInput(event.target.value)} />
        <Button type="primary" htmlType="submit">查询 IP</Button>
      </form>
      {error && <p role="alert" className="ip-observation-lookup-error">{error}</p>}
      {selectedIP && can(session.data, 'risks:read') && <Link to={`/ips/${encodeURIComponent(selectedIP)}?tab=devices&return_to=${encodeURIComponent(`/devices?tab=ip&ip=${selectedIP}`)}`}>查看完整 IP 详情</Link>}
    </div>
    {selectedIP && <IpTrafficObservations key={selectedIP} ip={selectedIP} />}
  </section>
}
