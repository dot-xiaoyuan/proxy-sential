import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Select } from 'antd'

import { api } from '../shared/api/client'
import type { RiskLevel, StreamRiskCurrentQuery } from '../shared/api/types'
import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import { AppErrorAlert, formatDateTime } from '../shared/ui'

export function StreamRiskCurrentPanel() {
  const [subjectType, setSubjectType] = useState<'ip' | 'account'>('ip')
  const [level, setLevel] = useState<RiskLevel | ''>('')
  const [cursor, setCursor] = useState('')
  const [previous, setPrevious] = useState<string[]>([])
  const query: StreamRiskCurrentQuery = {
    subject_type: subjectType, level: level || undefined, cursor: cursor || undefined, limit: 20,
  }
  const current = useQuery({ queryKey: ['stream-risk-current', query], queryFn: () => api.streamRiskCurrent(query) })
  const changeFilter = () => { setCursor(''); setPrevious([]) }

  return <section className="stream-risk-panel" aria-label="新流风险结果">
    <p>只展示新鲜起点之后已处理且仍在有效窗口内的结果。上方缺口卡片显示当前待处理数量。</p>
    <div className="stream-risk-controls">
      <label>对象类型<Select aria-label="对象类型" value={subjectType} onChange={value => { setSubjectType(value); changeFilter() }} options={[{ value: 'ip', label: 'IP' }, { value: 'account', label: '账号' }]} /></label>
      <label>风险等级<Select aria-label="风险等级" value={level} onChange={value => { setLevel(value); changeFilter() }} options={[{ value: '', label: '全部等级' }, { value: 'confirmed', label: '确认代理' }, { value: 'high', label: '高风险' }, { value: 'suspicious', label: '疑点' }, { value: 'normal', label: '正常' }]} /></label>
      <Button onClick={() => void current.refetch()} loading={current.isFetching}>刷新结果</Button>
    </div>
    {current.isError && <AppErrorAlert title="新流风险结果读取失败" message={current.error.message} />}
    {current.isFetching && <p>正在查询风险结果…</p>}
    {!current.isFetching && current.data && <>
      <p className="stream-risk-cutoff">新鲜起点：{formatDateTime(current.data.accepted_after)}</p>
      {current.data.items.length === 0 && <p>当前筛选没有风险结果。</p>}
      <div className="stream-risk-cards">
        {current.data.items.map(item => <article className="stream-risk-card" key={`${subjectType}:${item.subject_id || item.ip}`}>
          <div className="stream-risk-card-head"><strong className="mono">{item.subject_id || item.ip}</strong><RiskLevelTag level={item.level} /><span>评分 {item.score}</span></div>
          <p>{item.summary}</p>
          <div className="stream-risk-card-meta"><span>置信度 {Math.round(item.confidence * 100)}%</span><span>证据 {item.evidence_ids.length} 条</span><span>{formatDateTime(item.updated_at)}</span></div>
        </article>)}
      </div>
      <div className="stream-events-pagination">
        <Button disabled={previous.length === 0} onClick={() => { setCursor(previous[previous.length - 1]); setPrevious(previous.slice(0, -1)) }}>上一页</Button>
        <span>第 {previous.length + 1} 页</span>
        <Button disabled={!current.data.next_cursor} onClick={() => { setPrevious([...previous, cursor]); setCursor(current.data!.next_cursor!) }}>下一页</Button>
      </div>
    </>}
  </section>
}
