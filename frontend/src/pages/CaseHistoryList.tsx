import { AppErrorAlert, formatDateTime } from '../shared/ui'
import { useState } from 'react';
import { Button, Typography } from 'antd';
import { useCaseHistory } from '../shared/api/queries';
import type { CaseHistoryKind, CaseHistoryRow } from '../shared/api/types';

const names = { evidence: '证据历史', comments: '调查记录', timeline: '活动历史' };
function recordKey(row: CaseHistoryRow) {
  return 'snapshot_id' in row ? row.snapshot_id : 'comment_id' in row ? row.comment_id : row.event_id;
}
export function CaseHistoryList({ caseId, kind, total }: { caseId: string; kind: CaseHistoryKind; total?: number }) {
  const [expanded, setExpanded] = useState(false);
  const query = useCaseHistory(caseId, kind, expanded);
  return <section className="case-history-section">
    <Button onClick={() => setExpanded(!expanded)}>{expanded ? '收起' : '查看'}{names[kind]}{total !== undefined ? `（${total}）` : ''}</Button>
    {expanded && <>
      {query.isError && <AppErrorAlert title="历史读取失败" action={<Button onClick={() => query.refetch()}>重试</Button>} />}
      <div className="case-history-list">
        {query.data?.pages.flatMap(page => page.items).map(row => <article className="case-history-record" key={recordKey(row)}>
          <div className="case-history-meta"><Typography.Text className="case-history-id">{recordKey(row)}</Typography.Text><Typography.Text type="secondary" className="case-history-time">{formatDateTime(row.created_at)}</Typography.Text></div>
          {'snapshot_id' in row ? <>
            {row.evidence.shared_access ? <>
              <Typography.Paragraph>
                已确认共享 · {row.evidence.shared_access.confidence}% · 当前设备下界 {row.evidence.shared_access.device_lower_bound} 台
              </Typography.Paragraph>
              <Typography.Paragraph type="secondary">
                {formatDateTime(row.evidence.shared_access.window_start)} 至 {formatDateTime(row.evidence.shared_access.window_end)} · {row.ruleset_version || ''}
              </Typography.Paragraph>
            </> : row.evidence.router_observation ? <>
              <Typography.Paragraph>
                {row.evidence.router_observation.status === 'confirmed' ? '已确认路由器' : '较可信路由器观察'} · {row.evidence.router_observation.confidence}% · 独立证据源 {row.evidence.router_observation.independent_sources} 类
              </Typography.Paragraph>
              <Typography.Paragraph type="secondary">
                {formatDateTime(row.evidence.router_observation.first_seen)} 至 {formatDateTime(row.evidence.router_observation.expires_at)} · {row.ruleset_version || ''}
              </Typography.Paragraph>
            </> : <Typography.Paragraph>{row.evidence.event_count ?? 0} 条事件 · {row.ruleset_version || ''}</Typography.Paragraph>}
            <details><summary>查看该快照证据</summary><pre className="case-history-json">{JSON.stringify(row.evidence, null, 2)}</pre></details>
          </> : 'comment_id' in row ? <Typography.Paragraph>{row.author_id} · {row.body}</Typography.Paragraph> : <Typography.Paragraph>{row.actor_id} · {row.type}</Typography.Paragraph>}
        </article>)}
      </div>
      {query.isPending ? <Typography.Text type="secondary">正在加载历史…</Typography.Text> : query.data?.pages.every(page => page.items.length === 0) ? <Typography.Text type="secondary">暂无记录</Typography.Text> : null}
      {query.hasNextPage && <Button loading={query.isFetchingNextPage} onClick={() => query.fetchNextPage()}>加载更早记录</Button>}
    </>}
  </section>;
}
