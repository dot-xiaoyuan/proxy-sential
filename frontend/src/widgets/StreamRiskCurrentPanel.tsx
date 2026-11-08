import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Drawer, Select } from 'antd'

import { api } from '../shared/api/client'
import type { RiskLevel, StreamRiskCurrentQuery } from '../shared/api/types'
import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import { AppErrorAlert, AppServerPagination, useCursorPagePosition, usePaginationMetadata, formatDateTime } from '../shared/ui'

export function StreamRiskCurrentPanel() {
  const queryClient=useQueryClient()
  const [selectedEvidence, setSelectedEvidence] = useState<{ kind: 'ip' | 'account'; subject: string; id: string; number: number } | null>(null)
  const [subjectType, setSubjectType] = useState<'ip' | 'account'>('ip')
  const [level, setLevel] = useState<RiskLevel | ''>('')
  const [pageNumber,setPageNumber]=useState(1)
  const [pageSize,setPageSize]=useState(20)
  const query: StreamRiskCurrentQuery = {
    subject_type: subjectType, level: level || undefined, limit: pageSize,
  }
  const position=useCursorPagePosition({path:'/risks/stream-current/position',query,page:pageNumber,pageSize})
  const metadata=usePaginationMetadata('/risks/stream-current/metadata',query)
  query.cursor=position.cursor
  const current = useQuery({
    queryKey: ['stream-risk-current', query],
    queryFn: () => api.streamRiskCurrent(query),
    enabled:position.ready,
    staleTime: 0,
    refetchIntervalInBackground: false,
  })
  const fact = useQuery({
    queryKey: ['stream-risk-evidence', selectedEvidence],
    queryFn: () => api.streamRiskEvidence(selectedEvidence!.kind, selectedEvidence!.subject, selectedEvidence!.id),
    enabled: selectedEvidence !== null,
  })
  const refresh=()=>{setPageNumber(1);void position.invalidate();void metadata.refetch();const first={...query,cursor:undefined};void queryClient.invalidateQueries({queryKey:['stream-risk-current'],refetchType:'none'});void queryClient.refetchQueries({queryKey:['stream-risk-current',first],exact:true})}
  const changeFilter = () => { setPageNumber(1) }

  return <section className="stream-risk-panel" aria-label="新流风险结果">
    <p>只展示新鲜起点之后已处理且仍在有效窗口内的结果。上方缺口卡片显示当前待处理数量。</p>
    <div className="stream-risk-controls">
      <label>对象类型<Select aria-label="对象类型" value={subjectType} onChange={value => { setSubjectType(value); changeFilter() }} options={[{ value: 'ip', label: 'IP' }, { value: 'account', label: '账号' }]} /></label>
      <label>风险等级<Select aria-label="风险等级" value={level} onChange={value => { setLevel(value); changeFilter() }} options={[{ value: '', label: '全部等级' }, { value: 'confirmed', label: '确认代理' }, { value: 'high', label: '高风险' }, { value: 'suspicious', label: '疑点' }, { value: 'normal', label: '正常' }]} /></label>
      <Button onClick={refresh}>刷新结果</Button>
    </div>
    {metadata.data&&<p className="stream-risk-cutoff">统计时间：{formatDateTime(metadata.data.as_of)}</p>}
    {current.isError && <AppErrorAlert title="新流风险结果读取失败" message={current.error.message} />}
    {(current.isPending||position.isLocating) && <p>正在查询风险结果…</p>}
    {position.ready && !current.isError && current.data && <>
      <p className="stream-risk-cutoff">新鲜起点：{formatDateTime(current.data.accepted_after)}</p>
      {current.data.items.length === 0 && <p>当前筛选没有风险结果。</p>}
      <div className="stream-risk-cards">
        {current.data.items.map(item => <article className="stream-risk-card" key={`${subjectType}:${item.subject_id || item.ip}`}>
          <div className="stream-risk-card-head"><strong className="mono">{item.subject_id || item.ip}</strong><RiskLevelTag level={item.level} /><span>评分 {item.score}</span></div>
          <p>{item.summary}</p>
          <div className="stream-risk-card-meta"><span>置信度 {Math.round(item.confidence * 100)}%</span><span>证据 {item.evidence_ids.length} 条</span><span>{formatDateTime(item.updated_at)}</span></div>
          {item.evidence_ids.length > 0 && <div className="stream-risk-card-evidence" aria-label={`${item.subject_id || item.ip} 的证据`}>
            {item.evidence_ids.map((id, index) => <Button key={id} size="small" onClick={() => setSelectedEvidence({ kind: subjectType, subject: item.subject_id || item.ip, id, number: index + 1 })} title={id}>查看证据 {index + 1}</Button>)}
          </div>}
        </article>)}
      </div>

    </>}
      {position.isError&&<AppErrorAlert title="页码定位失败" message={position.error.message}/>}
      <AppServerPagination disabled={current.isFetching||position.isLocating} page={pageNumber} pageSize={pageSize} total={metadata.data?.total} totalText={metadata.isError?'数量读取失败':undefined} onChange={(next,size)=>{setPageNumber(next);setPageSize(size);}}/>
    <Drawer title={selectedEvidence ? `风险证据 ${selectedEvidence.number}` : '风险证据'} open={selectedEvidence !== null} onClose={() => setSelectedEvidence(null)} rootClassName="stream-risk-evidence-drawer">
      {fact.isPending && <p>正在读取证据…</p>}
      {fact.isError && <AppErrorAlert title="当前证据读取失败" message={fact.error.message} />}
      {fact.data && !fact.isError && <><p className="stream-risk-evidence-id">{fact.data.evidence_id}</p><p>{fact.data.reason}</p><pre className="stream-risk-evidence-json">{JSON.stringify(fact.data, null, 2)}</pre></>}
    </Drawer>
  </section>
}
