import { useEffect, useState, type FormEvent } from 'react'
import { Button, Input, Typography } from 'antd'
import { useSearchParams } from 'react-router-dom'
import { isIPAddress } from '../shared/ipAddress'
import { IpTrafficObservations } from '../widgets/IpTrafficObservations'

export function EndpointTrafficPanel({ recentIP, primaryMac, identityLastSeen }: { recentIP?: string; primaryMac?: string; identityLastSeen?: string }) {
  const [params, setParams] = useSearchParams()
  const explicitIP = (params.get('ip') ?? '').trim()
  const selectedIP = isIPAddress(explicitIP) ? explicitIP : isIPAddress(recentIP ?? '') ? recentIP! : ''
  const [input, setInput] = useState(explicitIP || recentIP || '')
  const [error, setError] = useState('')

  useEffect(() => setInput(explicitIP || recentIP || ''), [explicitIP, recentIP])

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
      next.set('tab', 'signals')
      next.set('ip', value)
      return next
    }, { replace: true })
  }

  return <>
    <section className="surface endpoint-traffic-lookup">
      <Typography.Title level={4}>按 IP 核查流量观测</Typography.Title>
      <p>握手、TTL 和 IPv6 Hop Limit 属于 IP 观测。握手记录中的 MAC 可作为终端候选线索，SNI、Host、UA 也可能来自共享出口后的客户端。</p>
      <form className="endpoint-traffic-lookup-form" onSubmit={submit}>
        <Input aria-label="流量观测 IP" placeholder="输入完整 IPv4 或 IPv6 地址" value={input} onChange={event => setInput(event.target.value)} />
        <Button type="primary" htmlType="submit">查询此 IP</Button>
      </form>
      {error && <p role="alert" className="endpoint-traffic-lookup-error">{error}</p>}
      {selectedIP && recentIP !== selectedIP && <p className="endpoint-traffic-ownership-note">身份摘要中没有该 IP 的地址关联；此处按指定 IP 核查流量，需结合 MAC、地址租约和接入证据核实归属。</p>}
    </section>
    {selectedIP && <IpTrafficObservations key={selectedIP} ip={selectedIP} contextMac={primaryMac} identityLastSeen={identityLastSeen} />}
  </>
}
