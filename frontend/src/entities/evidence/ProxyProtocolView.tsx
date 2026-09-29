import { Tag, Typography } from 'antd'
import { Link } from 'react-router-dom'
import type { ProxyProtocolEvidence } from '../../shared/api/types'
const outcomes:Record<string,string>={success:'成功连接',failed:'连接失败',incomplete:'事务不完整',unsupported:'暂不支持',conflict:'记录冲突'}
const protocols:Record<string,string>={http_connect:'HTTP CONNECT',socks5:'SOCKS5'}
const timeLabel=(s:string)=>!s||s.startsWith('0001-')?'未提供':s
export function ProxyProtocolView({evidence:e}:{evidence:ProxyProtocolEvidence}){
 return <section className="proxy-protocol-evidence" aria-label="代理协议识别依据">
 <div className="proxy-protocol-tags"><Tag>{protocols[e.protocol]??e.protocol}</Tag><Tag color={e.outcome==='success'&&e.trusted?'blue':'default'}>{outcomes[e.outcome]}</Tag><Tag>{e.trusted?'来源已校验':'未通过来源校验'}</Tag><Tag>仅观测或人工确认</Tag></div>
 <Typography.Title level={5}>{e.trusted?e.reason:'代理协议线索，来源尚未通过校验'}</Typography.Title>
 <dl className="proxy-protocol-fields"><div><dt>事件发生时的账号</dt><dd>{e.attribution.state==='resolved'?e.attribution.account_id:e.attribution.state==='conflict'?'身份冲突':'未知，无法归责'}</dd></div><div><dt>请求时间</dt><dd>{timeLabel(e.request_at)}</dd></div><div><dt>响应时间</dt><dd>{timeLabel(e.response_at)}</dd></div><div><dt>采集来源</dt><dd>{e.source} / {e.parser_id||'未登记'} / {e.parser_version||'未登记'}</dd></div><div><dt>识别规则</dt><dd>{e.rule_version}</dd></div><div><dt>连接与事务</dt><dd>{e.connection_id||'缺失'} / {e.transaction_id||'缺失'}</dd></div></dl>
 <div className="proxy-protocol-links">{e.event_ids.slice(0,10).map(id=><Link key={id} to={`/events/${encodeURIComponent(id)}`}>查看原始事件 {id}</Link>)}</div>
 <Typography.Text type="secondary">协议识别不等于违规，是否允许使用由组织策略和人工复核决定。</Typography.Text>
 </section>
}
