import { useState } from 'react'
import { Button, Input, Typography } from 'antd'

const beijingOffset = 8 * 60 * 60_000
const retention = 30 * 24 * 60 * 60_000
const displayTime = (at: string) => {
  const parsed = Date.parse(at)
  return Number.isFinite(parsed) ? new Date(parsed + beijingOffset).toISOString().slice(0, 16) : ''
}
const parseTime = (value: string) => Date.parse(value + ':00+08:00')

export function DiscoveryObservationRange({from, to, apply}: {
  from: string
  to: string
  apply: (from: string, to: string) => void
}) {
  const [start, setStart] = useState(displayTime(from))
  const [end, setEnd] = useState(displayTime(to))
  const first = parseTime(start)
  const last = parseTime(end)
  const valid = first < last && first >= Date.now() - retention && last <= Date.now()

  return <fieldset className="discovery-date-range">
    <legend>自定义观测时间 · 北京时间</legend>
    <Input aria-label="观测开始" type="datetime-local" value={start} onChange={event => setStart(event.target.value)} />
    <Input aria-label="观测截止" type="datetime-local" value={end} onChange={event => setEnd(event.target.value)} />
    <Button size="small" disabled={!valid} onClick={() => apply(new Date(first).toISOString(), new Date(last).toISOString())}>应用时间</Button>
    {start && end && !valid && <Typography.Text type="secondary">请选择最近 30 天内的有效起止时间。</Typography.Text>}
  </fieldset>
}
