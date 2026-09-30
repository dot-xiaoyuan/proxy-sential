import { Alert,Descriptions,Table,Tag,Typography } from 'antd'
import { Link } from 'react-router-dom'
import { ApiError } from '../shared/api/client'
import { useShadowEvaluation } from '../shared/api/queries'
import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import type { RiskLevel } from '../shared/api/types'
import { AppLoadingState } from '../shared/ui'
export function ShadowEvaluationPanel(){
 const evaluation=useShadowEvaluation()
 if(evaluation.isLoading)return <AppLoadingState rows={4}/>
 if(evaluation.isError)return evaluation.error instanceof ApiError&&evaluation.error.status===404?
 <Alert type="info" showIcon title="评估报告尚未生成" description="完成影子回放与样本复核后生成评估报告。当前没有准入结论。"/>:
 <Alert type="error" showIcon title="评估报告读取失败" description={evaluation.error.message}/>
 const report=evaluation.data;if(!report)return null
 const percent=(value?:number)=>value===undefined?'':`${(value*100).toFixed(1)}%`
 return <div className="detail-stack">
 <Alert showIcon type={report.ready?'success':'warning'} title={report.ready?'评估报告满足准入条件':'评估报告存在准入阻断'} description={`报告时间：${new Date(report.generated_at).toLocaleString()}；连接器与处置仍需通过各自准入检查。`}/>
 <Descriptions bordered column={{xs:1,sm:2,lg:3}} items={[
 {key:'days',label:'连续观测',children:`${report.longest_continuous_days} / ${report.required_days} 天`},
 {key:'coverage',label:'复核覆盖',children:`${report.reviewed_snapshot_count} / ${report.evaluated_sample_count} · ${percent(report.review_coverage)}`},
 {key:'reviewdays',label:'有复核的观测天数',children:report.days_with_reviews},
 {key:'precision',label:'候选精确率',children:report.candidate_reviewed?`${percent(report.candidate_precision)} · 复核 ${report.candidate_reviewed} 个`:''},
 {key:'normal',label:'正常样本复核',children:report.normal_reviewed},
 {key:'window',label:'评估范围',children:[report.window_from,report.window_to].filter(Boolean).join(' 至 ')},
 ]}/>
 <Typography.Title level={4}>分层复核统计</Typography.Title>
 <Table className="compact-list-table" rowKey="level" pagination={false} dataSource={Object.entries(report.level_stats??{}).map(([level,stats])=>({level,...stats}))} columns={[
 {title:'风险等级',dataIndex:'level',render:(level:string)=><RiskLevelTag level={level as RiskLevel}/>},
 {title:'样本',dataIndex:'total'},{title:'已复核',dataIndex:'reviewed'},{title:'确认代理',dataIndex:'confirmed'},
 {title:'误报',dataIndex:'false_positive'},{title:'良性',dataIndex:'benign'},{title:'需补数据',dataIndex:'needs_more_data'},
 {title:'精确率',dataIndex:'precision',render:(value:number,row)=>row.reviewed?percent(value):''},
 ]}/>
 <section><Typography.Title level={4}>准入阻断原因</Typography.Title>{report.blockers.length?report.blockers.map((text,index)=><Alert className="margin-bottom-sm" key={index} type="warning" title={text}/>):<Typography.Text>报告无阻断项</Typography.Text>}</section>
 <section><Typography.Title level={4}>缺失复核样本</Typography.Title>{report.missing_review_buckets.length?report.missing_review_buckets.map(bucket=><Tag key={bucket}>{bucket}</Tag>):<Typography.Text>各分层已有复核记录</Typography.Text>}<p><Link to="/review-samples">进入样本复核</Link></p></section>
 {(report.false_positive_reasons?.length||report.false_positive_evidence?.length)?<section><Typography.Title level={4}>误报归因</Typography.Title>{report.false_positive_reasons?.map(item=><p key={item.value}>{item.value} · {item.count} 次</p>)}{report.false_positive_evidence?.map(item=><p key={item.value}>{item.value} · {item.count} 次</p>)}</section>:null}
 {report.collection_warnings?.map((warning,index)=><Alert key={index} type="warning" title={warning}/>)}
 {report.recommended_adjustments.map((text,index)=><p key={index}>{text}</p>)}
 <details><summary>技术详情</summary><pre className="record-json">{JSON.stringify(report,null,2)}</pre></details>
 </div>
}
