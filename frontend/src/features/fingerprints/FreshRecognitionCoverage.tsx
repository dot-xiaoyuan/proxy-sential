import { Tag, Typography } from 'antd'
import type { components } from '../../shared/api/generated'
import { AppEmptyState, AppFactBar, AppListHeader, formatCount, formatDateTime } from '../../shared/ui'

type Fresh = components['schemas']['FreshRecognitionCoverage']
type Protocol = components['schemas']['FreshRecognitionProtocol']
const issues: { key: keyof Protocol; label: string }[] = [
  { key: 'processing', label: '处理中' }, { key: 'unattributed', label: '无法归属' },
  { key: 'insufficient', label: '证据不足' }, { key: 'conflict', label: '证据冲突' },
  { key: 'errors', label: '已记录错误' }, { key: 'overdue', label: '超过 5 秒' },
]

export function FreshRecognitionCoverage({ data }: { data?: Fresh }) {
  if (!data) return <AppEmptyState description="新鲜输入统计正在准备" />
  const active = data.items.filter(item => item.inputs > 0)
  const absent = data.items.filter(item => item.inputs === 0)
  return <section className="fresh-recognition-coverage" aria-label="新鲜输入协议覆盖">
    <AppListHeader title="新鲜输入链路" count={`${formatCount(data.items.reduce((n, item) => n + item.inputs, 0))} 条标准事件`} />
    <AppFactBar label="新鲜输入范围" items={[
      `起点 ${formatDateTime(data.since)}，统计最近 24 小时`,
      '历史输入不参与，不启动回填', '每分钟异步更新',
    ]} />
    <Typography.Paragraph type="secondary">
      仅统计已接收的标准发现事件，不代表原始报文采集完整率。归属与结论按有效特征核对，候选和结论只计算该事件贡献的证据。
      处理耗时是完成时间的保守上界；接口可见时间需另行逐事件验证。
    </Typography.Paragraph>
    <Typography.Paragraph type="secondary">统计时间 {formatDateTime(data.as_of)}{data.status === 'stale' ? ' · 统计已过期，等待后台刷新' : ''}</Typography.Paragraph>
    <div className="fresh-recognition-grid">
      {active.map(item => <article className="fresh-recognition-card" key={item.protocol}>
        <div className="fresh-recognition-title"><Typography.Title level={5}>{item.protocol.toUpperCase()}</Typography.Title>
          {item.purpose === 'association' && <Tag>用于关联</Tag>}{item.purpose === 'fields_pending' && <Tag>字段待接入</Tag>}
        </div>
        <dl className="fresh-recognition-counts">
          {([['接收', item.inputs], ['解析', item.parsed], ['归属', item.attributed], ['有效特征', item.features], ['候选命中', item.candidates], ['结论', item.conclusions]] as const).map(([name, count]) => <div key={name}><dt>{name}</dt><dd>{formatCount(count)}</dd></div>)}
        </dl>
        <div className="fresh-recognition-issues">{issues.filter(issue => Number(item[issue.key]) > 0).map(issue => <Tag key={issue.key}>{issue.label} {formatCount(Number(item[issue.key]))}</Tag>)}</div>
        {!!item.timed && <details className="fresh-recognition-timings"><summary>处理耗时 · {formatCount(item.timed)} 条样本</summary>
          <p>平均取数与准备 {item.read_and_prepare_ms?.toFixed(1)} ms · 查表 {item.lookup_ms?.toFixed(1)} ms · 规则 {item.rules_ms?.toFixed(1)} ms · 写入 {item.write_ms?.toFixed(1)} ms</p>
          <p>处理完成上界 P95 {item.processing_upper_p95_ms?.toFixed(1)} ms</p>
        </details>}
      </article>)}
    </div>
    {active.length === 0 && <AppEmptyState description="起点之后暂无新标准发现事件" />}
    {absent.length > 0 && <div className="fresh-recognition-absent"><Typography.Title level={5}>没有新输入的协议</Typography.Title>
      <div className="fresh-recognition-issues">{absent.map(item => <Tag key={item.protocol}>{item.protocol.toUpperCase()}{item.purpose === 'association' ? ' · 用于关联' : item.purpose === 'fields_pending' ? ' · 字段待接入' : ''}</Tag>)}</div>
      <Typography.Paragraph type="secondary">这些协议保留接入接口，当前没有新样本可验证，不计为现场已覆盖。</Typography.Paragraph>
    </div>}
  </section>
}
