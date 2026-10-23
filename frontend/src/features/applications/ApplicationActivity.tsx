import {
  Notice as Alert } from '../../shared/ui/Notice'
import { useUrlState } from '../../shared/ui/useUrlState'
import { detailPath } from '../../app/navigation'
import { useLocation } from 'react-router-dom'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button,
  Drawer,
  Input,
  Select,
  Tag,
  Typography,
} from 'antd'
import { Link } from 'react-router-dom'
import { useSession } from '../../shared/api/queries'
import { can } from '../../shared/auth/permissions'
import { applicationAPI, type AppItem } from './api'
import { formatBytes } from '../../shared/ui/formatBytes'
import { AppCursorPagination, AppErrorAlert, AppFactBar, AppListHeader, AppTable, formatDateTime } from '../../shared/ui'
export function ApplicationActivity({ip,window='24h'}:{ip?:string;window?:string}) {
 const session=useSession();const location=useLocation();const [sensor,setSensor]=useUrlState('sensor_id','');const [campus,setCampus]=useUrlState('campus_id','');const [filterIP,setFilterIP]=useUrlState('ip',ip||'');const [app,setApp]=useUrlState('application_id','');const [inspect,setInspect]=useState<string>();const [page,setPage]=useState(1);const [exportError,setExportError]=useState('')
 const [reportPage,setReportPage]=useUrlState('application_page','1');
 const [exportId,setExportId]=useState<string>();const [exportSubmitting,setExportSubmitting]=useState(false)
 const exportJob=useQuery({queryKey:['application-export',exportId],queryFn:()=>applicationAPI.exportStatus(exportId!),enabled:!!exportId,refetchInterval:q=>['completed','failed','cancelled'].includes(q.state.data?.status||'')?false:1000})
 const [detailBase,setDetailBase]=useState('');const [cursors,setCursors]=useState<string[]>([''])
 const status=useQuery({queryKey:['application-library'],queryFn:applicationAPI.status,refetchInterval:10000})
 const query=new URLSearchParams({window,...(sensor?{sensor_id:sensor}:{}),...(campus?{campus_id:campus}:{}),...((ip||filterIP)?{ip:ip||filterIP}:{})});if(app)query.set('application_id',app)
 const report=useQuery({queryKey:['application-report',query.toString()],queryFn:()=>applicationAPI.report(query.toString()),enabled:status.data?.enabled===true,refetchInterval:15000})
 const detailQuery=new URLSearchParams(detailBase);if(inspect)detailQuery.set('application_id',inspect);detailQuery.set('limit','20');if(cursors[page-1])detailQuery.set('cursor',cursors[page-1])
 const details=useQuery({queryKey:['application-observations',detailQuery.toString()],queryFn:()=>applicationAPI.observations(detailQuery.toString()),enabled:!!inspect})
 if(status.isError) return <AppErrorAlert title="应用观测状态读取失败" />
 if(status.isPending) return <Typography.Text>加载应用观测…</Typography.Text>
 if(!status.data.enabled) return <AppFactBar items={['应用观测尚未启用','应用协议报表仍可使用','启用应用观测并导入离线特征包后，此处展示具体应用访问']}/>
 const openInspection=(id:string)=>{const pinned=new URLSearchParams(query);pinned.set('to',new Date().toISOString());setDetailBase(pinned.toString());setCursors(['']);setInspect(id);setPage(1)}
 const data=report.data;const reportAsOf=data?.statistics_as_of||data?.as_of;const reportLag=reportAsOf?Math.max(0,(Date.now()-new Date(reportAsOf).getTime())/1000):0;const columns=[{title:'应用',dataIndex:'name',render:(_:string,row:AppItem)=><Button type="link" onClick={()=>openInspection(row.application_id)}>{row.name}</Button>},{title:'识别观测',dataIndex:'observation_count'},{title:'关联 IP',dataIndex:'terminal_count'},{title:'已识别连接',dataIndex:'connection_count'},{title:'上行累计',dataIndex:'upload_bytes',render:formatBytes},{title:'下行累计',dataIndex:'download_bytes',render:formatBytes},{title:'计量缺失连接',dataIndex:'missing_meter_connections'},{title:'最近观测',dataIndex:'last_seen',render:(v:string)=>formatDateTime(v)}]
 return <section className="application-content">
 <Typography.Paragraph type="secondary">关联 IP 按园区内地址去重。域名观测不证明用户打开了客户端。</Typography.Paragraph>
 <div className="application-toolbar">
 <Input aria-label="传感器筛选" placeholder="传感器 ID" value={sensor} onChange={e=>setSensor(e.target.value)} allowClear />
 <Input aria-label="园区筛选" placeholder="园区 ID" value={campus} onChange={e=>setCampus(e.target.value)} allowClear />
 {!ip&&<Input aria-label="IP 筛选" placeholder="终端 IP" value={filterIP} onChange={e=>setFilterIP(e.target.value)} allowClear />}
 <Select aria-label="应用筛选" placeholder="全部应用" allowClear value={app||undefined} onChange={value=>setApp(value||'')} options={data?.items.map(i=>({label:i.name,value:i.application_id}))}/>

 <Button loading={exportSubmitting} disabled={!can(session.data,'exports:read')||['queued','running'].includes(exportJob.data?.status||'')} onClick={()=>{setExportError('');setExportSubmitting(true);void applicationAPI.export(query.toString()).then(job=>setExportId(job.export_id)).catch(e=>setExportError(String(e))).finally(()=>setExportSubmitting(false))}}>导出待补特征域名</Button>
 </div>
 {report.isError&&<AppErrorAlert title="应用统计读取失败" message={report.error.message} />}
 {data&&reportLag>60&&(
  <Alert type={reportLag>300?'error':'warning'} title={reportLag>300?'当前展示最近成功快照':'应用统计数据延迟'} description={`快照时间：${formatDateTime(reportAsOf)}，后台正在追赶积压。`}/>
 )}
 {exportId&&<div className="application-toolbar"><Typography.Text>导出任务：{exportJob.data?.status==='completed'?`已完成 · ${exportJob.data.row_count} 条`:exportJob.data?.status==='cancelled'?'已取消':exportJob.data?.status==='failed'?'失败':exportJob.data?.status==='running'?'正在生成文件':'等待执行'}</Typography.Text>{['queued','running'].includes(exportJob.data?.status||'')&&<Button onClick={()=>{void applicationAPI.cancelExport(exportId).then(()=>exportJob.refetch()).catch(e=>setExportError(String(e)))}}>取消导出</Button>}{exportJob.data?.status==='completed'&&<Button onClick={()=>{void applicationAPI.downloadExport(exportId).catch(e=>setExportError(String(e)))}}>下载文件</Button>}{(exportJob.isError||exportJob.data?.error)&&<Typography.Text type="danger">{exportJob.error?.message||exportJob.data?.error}</Typography.Text>}</div>}
 {data&&(data.statistics_as_of||data.as_of)&&<Typography.Paragraph type="secondary">统计时间：{formatDateTime(data.statistics_as_of||data.as_of)}</Typography.Paragraph>}
 {exportError&&<AppErrorAlert title={exportError} />}
 {status.data.error&&<Alert type="warning" title="后台观测更新异常" description={status.data.error}/>}
 <Typography.Text type="secondary">最近成功处理：{status.data.last_scan?formatDateTime(status.data.last_scan):'等待首轮同步'}</Typography.Text>
 {data&&<>
 <dl className="application-metrics"><div><dt>待补特征观测</dt><dd>{data.unknown_observations}</dd></div><div><dt>多应用连接</dt><dd>{data.multi_application.connection_count}</dd></div><div><dt>缺少连接标识</dt><dd>{data.missing_connection_observations}</dd></div><div><dt>DNS 观测</dt><dd>{data.dns_observations}</dd></div></dl>
 <AppFactBar label="流量统计口径" items={[data.traffic_basis]}/>
 <div className="application-toolbar"><Typography.Text>识别版本：</Typography.Text>{Object.entries(data.versions).map(([v,n])=><Tag key={v}>{v} · {n}</Tag>)}</div>
 <AppListHeader title="应用访问" count={`${data.items.length} 个应用`} />
 <AppTable rowKey="application_id" columns={columns} dataSource={data.items} pagination={{current:Math.max(1,Number(reportPage)||1),pageSize:10,showSizeChanger:false,onChange:value=>setReportPage(String(value))}} loading={report.isFetching} scroll={{x:960}}/>
 <Typography.Paragraph type="secondary">待补特征连接 {data.unknown.connection_count}，上行 {formatBytes(data.unknown.upload_bytes)} / 下行 {formatBytes(data.unknown.download_bytes)}；多应用连接上行 {formatBytes(data.multi_application.upload_bytes)} / 下行 {formatBytes(data.multi_application.download_bytes)}，不重复分配至应用。</Typography.Paragraph>
 </>}
 <Drawer title="应用观测依据" open={!!inspect} onClose={()=>setInspect(undefined)} size="large" className="application-drawer">
 {details.isError&&<AppErrorAlert title="观测明细读取失败" />}{details.isPending&&<Typography.Text>加载明细…</Typography.Text>}
 {details.data?.items.map(o=><article className="application-card" key={`${o.sensor_id}-${o.event_id}`}><Typography.Title level={5}>{o.match.name||''}</Typography.Title><dl><div><dt>终端</dt><dd><Link to={detailPath(`/ips/${encodeURIComponent(o.ip)}`,location.pathname+location.search)}>{o.ip||''}</Link></dd></div><div><dt>观测域名</dt><dd>{o.domain||''}</dd></div><div><dt>来源 / 置信度</dt><dd>{o.source_field} / {o.match.confidence===0?'未评估':`${Math.round(o.match.confidence*100)}%`}</dd></div><div><dt>规则 / 版本</dt><dd>{o.match.rule_id||'未命中'} / {o.bundle_version}</dd></div><div><dt>特征来源</dt><dd>{o.match.source} / {o.match.source_version}</dd></div><div><dt>连接</dt><dd>{o.connection_id||''}</dd></div><div><dt>观测时间</dt><dd>{formatDateTime(o.timestamp)}</dd></div></dl></article>)}
 <AppCursorPagination disabled={details.isFetching} previous={page!==1} next={Boolean(details.data?.next_cursor)} label={`第 ${page} 页 · ${details.data?.total||0} 条观测`} onPrevious={()=>setPage(page-1)} onNext={()=>{const next=details.data?.next_cursor;if(next){setCursors([...cursors.slice(0,page),next]);setPage(page+1)}}} />
 </Drawer>
 </section>
}
