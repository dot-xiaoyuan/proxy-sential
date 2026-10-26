import { useState, type FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Input } from 'antd'

import { api } from '../shared/api/client'
import type { StreamEventIndexItem, StreamEventIndexQuery } from '../shared/api/types'
import { AppErrorAlert, formatDateTime } from '../shared/ui'

function localMinute(value: Date) {
  const pad = (part: number) => String(part).padStart(2, '0')
  return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}T${pad(value.getHours())}:${pad(value.getMinutes())}`
}

function initialRange() {
  const end = new Date()
  end.setSeconds(0, 0)
  return { from: localMinute(new Date(end.getTime() - 15 * 60_000)), to: localMinute(end) }
}

export function StreamEventsPanel() {
  const [range] = useState(initialRange)
  const [scope, setScope] = useState('')
  const [protocol, setProtocol] = useState('')
  const [from, setFrom] = useState(range.from)
  const [to, setTo] = useState(range.to)
  const [validation, setValidation] = useState('')
  const [submitted, setSubmitted] = useState<Omit<StreamEventIndexQuery, 'cursor'> | null>(null)
  const [cursor, setCursor] = useState('')
  const [previous, setPrevious] = useState<string[]>([])
  const [selected, setSelected] = useState<StreamEventIndexItem | null>(null)
  const query: StreamEventIndexQuery | null = submitted ? { ...submitted, cursor: cursor || undefined } : null
  const index = useQuery({
    queryKey: ['stream-events', query],
    queryFn: () => api.streamEventIndex(query!),
    enabled: query !== null,
  })
  const body = useQuery({
    queryKey: ['stream-event-body', selected?.body_ref],
    queryFn: () => api.streamEventBody(selected!.body_ref),
    enabled: selected !== null,
  })

  function search(event: FormEvent) {
    event.preventDefault()
    const start = new Date(from).getTime()
    const end = new Date(to).getTime()
    if (!scope.trim() || !Number.isFinite(start) || !Number.isFinite(end) ||
        end <= start || end - start > 15 * 60_000) {
      setValidation('填写捕获域，并选择不超过 15 分钟的有效时间范围。')
      return
    }
    setValidation('')
    setCursor('')
    setPrevious([])
    setSelected(null)
    setSubmitted({ scope_id: scope.trim(), protocol: protocol.trim() || undefined,
      from: new Date(start).toISOString(), to: new Date(end).toISOString(), limit: 50 })
  }

  return <section className="stream-events-panel" aria-label="新流事件检索">
    <p className="stream-events-explanation">按捕获域和时间查看已归档的标准事件。每次最多检索 15 分钟，正文按需读取。</p>
    <form className="stream-events-form" onSubmit={search}>
      <label>捕获域<Input aria-label="捕获域" value={scope} onChange={event => setScope(event.target.value)} placeholder="输入捕获域 ID" /></label>
      <label>开始时间<Input aria-label="开始时间" type="datetime-local" value={from} onChange={event => setFrom(event.target.value)} /></label>
      <label>结束时间<Input aria-label="结束时间" type="datetime-local" value={to} onChange={event => setTo(event.target.value)} /></label>
      <label>协议<Input aria-label="协议" value={protocol} onChange={event => setProtocol(event.target.value)} placeholder="可选" /></label>
      <Button htmlType="submit" type="primary">查询事件</Button>
    </form>
    {validation && <p className="stream-events-validation" role="alert">{validation}</p>}
    {index.isError && <AppErrorAlert title="新流事件检索失败" message={index.error.message} />}
    {index.isLoading && <p>正在查询事件…</p>}
    {index.data && <>
      {index.data.events.length === 0 && <p>该范围内没有事件。</p>}
      <div className="stream-event-list">
        {index.data.events.map(item => <article className="stream-event-card" key={item.event_key + item.body_ref.sha256}>
          <div className="stream-event-main">
            <strong>{item.protocol || item.event_type}</strong>
            <span>{formatDateTime(item.observed_at)}</span>
            <span>{item.subject_ip || item.src_ip}</span>
            <span>{item.dst_ip}</span>
            <Button size="small" onClick={() => setSelected(selected?.event_key === item.event_key && selected.body_ref.sha256 === item.body_ref.sha256 ? null : item)}>查看正文</Button>
          </div>
          <div className="stream-event-key mono" title={item.event_key}>{item.event_key}</div>
          {selected?.event_key === item.event_key && selected.body_ref.sha256 === item.body_ref.sha256 && <div className="stream-event-detail">
            {body.isLoading && <p>正在读取正文…</p>}
            {body.isError && <AppErrorAlert title="事件正文读取失败" message={body.error.message} />}
            {body.data && <pre>{JSON.stringify(body.data, null, 2)}</pre>}
          </div>}
        </article>)}
      </div>
      <div className="stream-events-pagination">
        <Button disabled={previous.length === 0} onClick={() => { setCursor(previous[previous.length - 1]); setPrevious(previous.slice(0, -1)); setSelected(null) }}>上一页</Button>
        <Button disabled={!index.data.next_cursor} onClick={() => { setPrevious([...previous, cursor]); setCursor(index.data!.next_cursor!); setSelected(null) }}>下一页</Button>
      </div>
    </>}
  </section>
}
