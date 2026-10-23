import { AppErrorAlert, AppListHeader, AppTable, formatDateTime } from '../../shared/ui'
import { Notice as Alert } from '../../shared/ui/Notice'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Input, InputNumber, Select, Switch, Typography, Upload } from 'antd'
import { UploadOutlined } from '@ant-design/icons'
import { useSession } from '../../shared/api/queries'
import { can } from '../../shared/auth/permissions'
import type { ColumnsType } from 'antd/es/table'
import { applicationAPI, type ApplicationJob } from './api'
function jobState(job: ApplicationJob) {
 if(job.requested_control) return job.requested_control==='pause'?'已请求暂停，等待批次提交':'已请求取消，等待批次提交'
 return ({running:'处理中',paused:'已暂停',cancelled:'已取消',completed:'已完成',failed:'失败'} as Record<string,string>)[job.status]||'尚未开始'
}
export function ApplicationLibrary() {
 const session = useSession(); const cache = useQueryClient()
 const status = useQuery({queryKey:['application-library'],queryFn:applicationAPI.status,refetchInterval:10000})
 const [historyInterval,setHistoryInterval]=useState<number>()
 const [enabled,setEnabled] = useState<boolean>(); const [url,setURL] = useState<string>(); const [token,setToken] = useState('')
 const runtime = useMutation({mutationFn:async(action:'save'|'pull')=>{
  if(action==='save') return applicationAPI.configure(enabled??status.data?.enabled??false,url??status.data?.config?.update_url??'',token,historyInterval==null?undefined:historyInterval*1000)
  const result=await applicationAPI.pull(token)
  if(result.enabled && result.job?.status!=='running') await applicationAPI.reclassify()
  return result
 },onSuccess:()=>{setToken('');void cache.invalidateQueries({queryKey:['application-library']});void cache.invalidateQueries({queryKey:['application-report']})}})
 const [version,setVersion] = useState<string>(); const [file,setFile] = useState<File>()
 const update = useMutation({mutationFn: async (operation: 'import'|'rollback'|'reclassify') => {if(operation==='import' && file) return applicationAPI.import(file); if(operation==='rollback' && version) return applicationAPI.rollback(version); if(operation==='reclassify') return applicationAPI.reclassify(); throw new Error('请先选择文件或版本')},onSuccess:()=>{setFile(undefined);void cache.invalidateQueries({queryKey:['application-library']});void cache.invalidateQueries({queryKey:['application-report']})}})
 const control=useMutation({mutationFn:applicationAPI.control,onSuccess:()=>{void cache.invalidateQueries({queryKey:['application-library']})}})
 if(status.isPending) return <Typography.Text>加载应用特征库…</Typography.Text>
 if(status.isError) return <AppErrorAlert title="应用特征库状态读取失败" />
 const allowed = can(session.data,'device-fingerprint-library:update');const data=status.data;const busy=runtime.isPending||update.isPending||['running','paused'].includes(data.job?.status)||!!data.job?.requested_control
 const taskJobs = ([['实时处理',data.processing?.realtime],['历史重分类',data.processing?.history],['迟到事件补扫',data.processing?.reconcile]] as const).filter(([,job])=>job) as [string, NonNullable<typeof data.processing>['realtime']][]
 const taskRows = taskJobs.map(([taskName, job]) => ({ ...job, taskName }))
 const jobColumns: ColumnsType<(typeof taskRows)[number]> = [
  {title:'任务',dataIndex:'taskName',width:110},
  {title:'状态',key:'state',width:150,render:(_,job)=>jobState(job)},
  {title:'任务特征版本',key:'version',width:130,render:(_,job)=>job.version||'尚未分配'},
  {title:'本轮已处理',key:'processed',width:100,render:(_,job)=>`${job.processed||0} 条`},
  {title:'最近成功',key:'success',width:160,render:(_,job)=>formatDateTime(job.last_success)||'尚无成功记录'},
  {title:'游标距当前',key:'lag',width:110,render:(_,job)=>job.lag_seconds==null?'尚未统计':`${Math.round(job.lag_seconds)} 秒`},
  {title:'批次耗时 / 重试',key:'batch',width:140,render:(_,job)=>`${job.batch_millis||0} ms / ${job.retries||0} 次`},
 ]
 return <section className="application-content">
 <Typography.Paragraph type="secondary">配置运行开关和特征库服务地址，保存后即时生效。拉取时校验包内容，启用后自动回填最近七天；失败保留当前规则。</Typography.Paragraph>
 <div className="application-runtime-config">
 <label><span>启用应用识别</span><Switch aria-label="启用应用识别" checked={enabled??data.enabled} onChange={setEnabled} disabled={!allowed||runtime.isPending} /></label>
 <label htmlFor="application-update-url">特征库服务地址</label>
 <Input id="application-update-url" value={url??data.config?.update_url??''} onChange={event=>setURL(event.target.value)} disabled={!allowed||busy} placeholder="http://192.168.0.30:8081" />
 <label htmlFor="application-pull-token">服务下载凭证</label>
 <Input.Password id="application-pull-token" autoComplete="off" value={token} onChange={event=>setToken(event.target.value)} disabled={!allowed||busy} placeholder={data.config?.credential_configured ? "已保存；留空保留现有凭证" : "从特征库“发布”页面创建下载凭证"} />
 <label htmlFor="application-history-interval">历史批次间隔（秒）</label>
 <InputNumber id="application-history-interval" min={1} max={60} precision={0} value={historyInterval??((data.config?.history_interval_ms||1000)/1000)} onChange={value=>setHistoryInterval(value??undefined)} disabled={!allowed||runtime.isPending}/>
 <div className="application-toolbar">
 <Button disabled={!allowed||runtime.isPending} onClick={()=>runtime.mutate('save')}>保存运行配置</Button>
 <Button type="primary" disabled={!allowed||busy||!data.config?.update_url} loading={runtime.isPending} onClick={()=>runtime.mutate('pull')}>拉取并回填</Button>
 </div>
 {!data.enabled&&<Alert type="info" title="应用识别已关闭，可配置或导入规则，启用后开始处理" />}
 {data.config?.last_pull_at&&<Typography.Text type="secondary">最近拉取：{formatDateTime(data.config.last_pull_at)}</Typography.Text>}
 {(runtime.error||data.config?.last_pull_error)&&<Alert type="error" title="配置或拉取失败" description={runtime.error?.message||data.config?.last_pull_error} />}
 {runtime.isSuccess&&<Alert type="success" title="操作成功，配置已保存或规则已加载" />}
 </div>
 <dl className="application-metrics"><div><dt>当前版本</dt><dd>{data.library.version || '尚未导入'}</dd></div><div><dt>有效规则</dt><dd>{data.library.rule_count}</dd></div><div><dt>重分类进度</dt><dd className="application-job-summary">{jobState(data.job)} · <span>{data.job?.processed || 0} 条</span></dd></div></dl>
 {data.processing&&<>
 <AppListHeader title="应用处理任务" count={`${taskRows.length} 项`} />
 <AppTable
  rowKey="taskName"
  columns={jobColumns}
  dataSource={taskRows}
  scroll={{x:900}}
  expandable={taskRows.some(job=>job.available_from||job.error)?{expandedRowRender:(job)=><div className="application-task-detail">
    {job.available_from&&<p>本轮已观测范围：{formatDateTime(job.available_from)} 至 {job.available_to?formatDateTime(job.available_to):'处理中'}</p>}
    {job.error&&<AppErrorAlert title="批次处理失败" message={job.error} />}
  </div>}:undefined}
 />
 <Typography.Paragraph type="secondary">游标时间差用于判断处理进度，不等于精确积压条数；未产生新事件时也会增大。最近统计查询耗时 {data.processing.query_millis} ms。</Typography.Paragraph>
 </>}
 <div className="application-toolbar" aria-label="历史任务控制">
 <Button disabled={!allowed||control.isPending||data.job?.status!=='running'||!!data.job?.requested_control} onClick={()=>control.mutate('pause')}>暂停重分类</Button>
 <Button disabled={!allowed||control.isPending||!['paused','failed'].includes(data.job?.status)||!!data.job?.requested_control} onClick={()=>control.mutate('resume')}>恢复重分类</Button>
 <Button disabled={!allowed||control.isPending||!['running','paused','failed'].includes(data.job?.status)||!!data.job?.requested_control} onClick={()=>control.mutate('cancel')}>取消重分类</Button>
 </div>
 {control.error&&<AppErrorAlert title="任务控制失败" message={control.error.message} />}
 <div className="application-toolbar">
 <Upload accept=".gz,.tgz" maxCount={1} showUploadList={false} beforeUpload={value=>{setFile(value);return false}} disabled={!allowed||busy}><Button icon={<UploadOutlined />}>选择离线包</Button></Upload>
 {file && <span className="application-identifier">{file.name}</span>}
 <Button type="primary" disabled={!allowed||!file||busy} onClick={()=>update.mutate('import')}>校验并导入</Button>
 <Select aria-label="回滚版本" placeholder="选择保留版本" value={version} onChange={setVersion} options={data.library.versions.filter(v=>v!==data.library.version).map(v=>({value:v,label:v}))} disabled={!allowed||busy} />
 <Button disabled={!allowed||!version||busy} onClick={()=>update.mutate('rollback')}>回滚版本</Button>
 <Button disabled={!allowed||!data.library.version||busy} onClick={()=>update.mutate('reclassify')}>重分类最近 7 天</Button>
 </div>
 {update.isSuccess&&<Alert type="success" title="操作已完成，重分类任务将在后台执行" />}
 {(update.error||data.error||data.job?.error)&&<AppErrorAlert title="操作或后台处理异常" message={update.error?.message||data.error||data.job?.error} />}
 </section>
}
