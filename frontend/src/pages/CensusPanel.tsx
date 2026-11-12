import { useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Drawer, Input, Select, Typography } from 'antd'
import { DownloadOutlined, UploadOutlined } from '@ant-design/icons'
import { getApiBase, request } from '../shared/api/client'
import { activityStates } from './discoveryHardware'
import { compareCensus, differencesCSV, readComparisonCSV, scopeLabel, type CensusRow, type ColumnMapping, type CSVTable, type Difference } from './censusComparison'

type TypeCount = {device_type:string;identified:number;candidate:number;conflict:number;expired:number}
type Summary = {metric_version:string;scope:{sensor_id:string;campus_id?:string;access_domain?:string;vlan?:string;vrf?:string};window:string;status:string;as_of?:string;available_from?:string;last_success_at?:string;oldest_pending_at?:string;failed_batches:number;last_batch_rows:number;last_batch_ms:number;scope_version?:string;observed_ips:number;observed_ipv4:number;observed_ipv6:number;observed_macs:number;random_macs:number;incomplete_scope:number;active_bindings:number;identified_terminals:number;terminal_candidates:number;terminal_conflicts:number;terminal_expired:number;manually_verified:number;types:TypeCount[]}
type Page = {items:CensusRow[];next_cursor:string;has_more:boolean}
type Manifest = {record:'manifest';summary:Summary}
type Item = {record:'item';item:CensusRow}
type End = {record:'end';counts:Record<string,number>;complete:boolean}
type StreamError = {record:'error';code:string;message:string}
type StreamRecord = Manifest|Item|End|StreamError

const terminalNames:Record<string,string>={printer:'打印机',camera:'摄像机',recorder:'录像设备',access_control:'门禁',voip_phone:'VoIP 话机',environment_monitor:'环境监测设备',ups:'UPS',pdu:'PDU'}
const terminalStates:Record<string,string>={identified:'已识别',candidate:'待核实',conflict:'类型冲突',expired:'证据过期'}
const kindNames:Record<string,string>={ip:'IP 标识',mac:'MAC 标识',binding:'当前有效绑定',terminal:'哑终端身份'}
const resultNames:Record<Difference['result'],string>={shared:'双方共有',local_only:'仅镜像侧',external_only:'仅对方系统',type_difference:'类型差异',address_rebind:'地址换绑',scope_review:'作用域待核实',input_review:'导入记录待核实'}
const formatTime=(value?:string)=>value?new Date(value).toLocaleString('zh-CN',{hour12:false}):''
const queryString=(window:string,scope:Record<string,string>)=>new URLSearchParams({window,...Object.fromEntries(Object.entries(scope).filter(([,value])=>value))}).toString()

async function readCensusSnapshot(query:string):Promise<{summary:Summary;rows:CensusRow[]}> {
  const response=await fetch(`${getApiBase()}/discovery/census/compare-stream?${query}`,{credentials:'include',headers:{accept:'application/x-ndjson'}})
  if(!response.ok||!response.body)throw new Error(`比较数据读取失败（HTTP ${response.status}）`)
  const reader=response.body.getReader(),decoder=new TextDecoder()
  let buffer='',manifest:Summary|undefined,end:End|undefined
  const rows:CensusRow[]=[],counts:Record<string,number>={ip:0,ipv4:0,ipv6:0,mac:0,random_mac:0,binding:0,terminal:0,identified_terminal:0,candidate_terminal:0,conflict_terminal:0,expired_terminal:0}
  const accept=(line:string)=>{
    if(!line.trim())return
    const record=JSON.parse(line) as StreamRecord
    if(record.record==='error')throw new Error(`${record.message}（${record.code}）`)
    if(record.record==='manifest'){if(manifest)throw new Error('比较数据清单重复');manifest=record.summary;return}
    if(record.record==='end'){end=record;return}
    if(record.record==='item'){
      if(!manifest||end||!Object.hasOwn(counts,record.item.kind))throw new Error('比较数据顺序无效')
      rows.push(record.item);counts[record.item.kind]++
      if(record.item.kind==='ip')counts[record.item.ip_family===4?'ipv4':'ipv6']++
      if(record.item.kind==='mac'&&record.item.random_mac)counts.random_mac++
      if(record.item.kind==='terminal'){
        const key=`${record.item.classification_status}_terminal`
        if(Object.hasOwn(counts,key))counts[key]++
      }
      if(rows.length>2_000_000)throw new Error('比较数据超过浏览器处理上限')
    }
  }
  try {
    while(true){
      const {value,done}=await reader.read()
      if(done)break
      buffer+=decoder.decode(value,{stream:true})
      let index=buffer.indexOf('\n')
      while(index>=0){accept(buffer.slice(0,index));buffer=buffer.slice(index+1);index=buffer.indexOf('\n')}
    }
    buffer+=decoder.decode()
    if(buffer.trim())accept(buffer)
    if(!manifest||!end?.complete)throw new Error('比较数据未完整结束，请重新读取')
    const finalCounts=end.counts
    if(Object.keys(counts).some(kind=>counts[kind]!==finalCounts[kind]))throw new Error('比较数据行数与结束清单不一致，请重新读取')
    if(counts.ip!==manifest.observed_ips||counts.ipv4!==manifest.observed_ipv4||counts.ipv6!==manifest.observed_ipv6||counts.mac!==manifest.observed_macs||counts.random_mac!==manifest.random_macs||counts.binding!==manifest.active_bindings||counts.identified_terminal!==manifest.identified_terminals||counts.candidate_terminal!==manifest.terminal_candidates||counts.conflict_terminal!==manifest.terminal_conflicts||counts.expired_terminal!==manifest.terminal_expired)throw new Error('比较数据行数与统计口径不一致，请重试')
    return {summary:manifest,rows}
  } finally {reader.releaseLock()}
}

function downloadCSV(rows:Difference[]){
  const url=URL.createObjectURL(new Blob(['\uFEFF',differencesCSV(rows)],{type:'text/csv;charset=utf-8'}))
  const link=document.createElement('a');link.href=url;link.download='镜像标识比对差异.csv';link.click()
  setTimeout(()=>URL.revokeObjectURL(url),1000)
}

export function CensusPanel(){
  const [window,setWindow]=useState('24h')
  const [detailOpen,setDetailOpen]=useState(false)
  const [scope,setScope]=useState({campus_id:'',access_domain:'',vlan:'',vrf:''})
  const [kind,setKind]=useState<keyof typeof kindNames>('ip')
  const [cursor,setCursor]=useState('')
  const [table,setTable]=useState<CSVTable>()
  const [mapping,setMapping]=useState<ColumnMapping>({ip:-1,mac:-1,scope:-1,type:-1})
  const [differences,setDifferences]=useState<Difference[]>()
  const [working,setWorking]=useState(false)
  const [error,setError]=useState('')
  const fileRef=useRef<HTMLInputElement>(null)
  const query=queryString(window,scope)
  const summary=useQuery({queryKey:['discovery-census-summary',query],queryFn:({signal})=>request<Summary>(`/discovery/census/summary?${query}`,{signal}),retry:false})
  const page=useQuery({queryKey:['discovery-census-page',query,kind,cursor],queryFn:({signal})=>request<Page>(`/discovery/census/identifiers?${query}&kind=${kind}&limit=100${kind==='terminal'?'&terminal_status=identified':''}${cursor?`&cursor=${encodeURIComponent(cursor)}`:''}`,{signal}),enabled:detailOpen&&!!summary.data&&summary.data.status!=='initializing'&&!summary.isError,retry:false})
  const changeScope=(key:keyof typeof scope,value:string)=>{setScope(current=>({...current,[key]:value}));setCursor('');setDifferences(undefined)}
  const changeWindow=(value:string)=>{setWindow(value);setCursor('');setDifferences(undefined)}
  const chooseKind=(value:keyof typeof kindNames)=>{setKind(value);setCursor('');setDetailOpen(true)}
  const importFile=async(file?:File)=>{
    if(!file)return
    setError('');setDifferences(undefined)
    try{
      const parsed=await readComparisonCSV(file);setTable(parsed)
      const find=(aliases:string[])=>parsed.headers.findIndex(name=>aliases.includes(name.toLowerCase()))
      setMapping({ip:find(['ip','ip地址','ip address']),mac:find(['mac','mac地址','mac address']),scope:find(['网络作用域','scope','network scope']),type:find(['设备类型','type','device type'])})
    }catch(e){setTable(undefined);setError(e instanceof Error?e.message:String(e))}
  }
  const compare=async()=>{
    if(!table)return
    setWorking(true);setError('');setDifferences(undefined)
    try{const snapshot=await readCensusSnapshot(query);if(snapshot.summary.status==='initializing')throw new Error('镜像统计尚未生成');if(snapshot.summary.status==='scope_changed')throw new Error('站点网段配置已变化，需受控重建后比对');setDifferences(compareCensus(snapshot.rows,table,mapping))}
    catch(e){setError(e instanceof Error?e.message:String(e))}
    finally{setWorking(false)}
  }
  const data=summary.data
  const cards:[string,number|undefined,string,string][]=[['IP',data?.observed_ips,'ip',data?`IPv4 ${data.observed_ipv4} · IPv6 ${data.observed_ipv6}`:''],['MAC',data?.observed_macs,'mac',data?`本地管理 MAC（含随机）${data.random_macs}`:''],['有效 IP–MAC 绑定',data?.active_bindings,'binding','仅当前有效且无冲突'],['已识别哑终端',data?.identified_terminals,'terminal',data?.metric_version==='passive-census/v2'?'窗口内观测 · 已知硬件类型':'五个重点品类 · 可信身份去重']]
  const priorityTypes=['printer','camera','recorder','access_control','voip_phone']
  const extraTypes=['environment_monitor','ups','pdu'].filter(type=>(data?.types.find(item=>item.device_type===type)?.identified??0)>0)
  const statusLabel=data?.status==='ready'?'窗口完整':data?.status==='initializing'?'统计生成中':data?.status==='delayed'?'处理延迟':data?.status==='scope_changed'?'范围配置变化':'窗口或处理不完整'
  return <section className="census-panel" aria-label="镜像可见标识统计">
    <div className="census-header"><div><Typography.Title level={4}>镜像可见标识</Typography.Title><Typography.Text type="secondary">按镜像范围统计；标识数不是物理设备数。</Typography.Text></div><div className="census-controls"><Select size="small" aria-label="统计时间窗" value={window} onChange={changeWindow} options={[{value:'24h',label:'近 24 小时'},{value:'7d',label:'近 7 天'},{value:'30d',label:'近 30 天'}]}/><Button size="small" onClick={()=>setDetailOpen(true)}>范围、清单与比对</Button></div></div>
    {summary.isError&&<div className="census-note census-error" role="alert">统计投影读取失败：{summary.error.message}</div>}
    <div className="census-cards">{cards.map(([label,value,cardKind,hint])=><button key={cardKind} className={`census-card${detailOpen&&kind===cardKind?' is-active':''}`} title={hint} onClick={()=>chooseKind(cardKind as keyof typeof kindNames)}><span>{label}</span><strong>{data?.status==='initializing'||value===undefined?'':value.toLocaleString('zh-CN')}</strong><small>{hint}</small></button>)}</div>
    {data&&<div className="census-brief-status" aria-live="polite"><span>传感器 {data.scope?.sensor_id}</span><span>截至 {formatTime(data.as_of)}</span><span className={data.status==='ready'?'':'census-brief-warning'}>{statusLabel}</span>{data.available_from&&data.status!=='ready'&&<span>可用起点 {formatTime(data.available_from)}</span>}{data.failed_batches>0&&<span className="census-brief-warning">处理失败次数 {data.failed_batches}</span>}{Object.entries(scope).filter(([,value])=>value).map(([key,value])=><span key={key}>{key==='campus_id'?'校区':key==='access_domain'?'接入域':key.toUpperCase()} {value}</span>)}</div>}
    {data&&<div className="census-type-strip"><strong>重点类型</strong>{[...priorityTypes,...extraTypes].map(type=><span key={type}>{terminalNames[type]} {data.status==='initializing'?'':data.types.find(item=>item.device_type===type)?.identified??0}</span>)}{(data.terminal_candidates>0||data.terminal_conflicts>0)&&<span className="census-type-review">待核实 {data.terminal_candidates} · 冲突 {data.terminal_conflicts}</span>}</div>}
    {detailOpen&&<Drawer className="census-detail-drawer" title="镜像标识详情与本地比对" open onClose={()=>setDetailOpen(false)} size={720}>
      <div className="census-detail-body">
    <Typography.Text type="secondary">{data?.metric_version==='passive-census/v2'?'窗口内观测 IP、MAC 和哑终端；哑终端类型可来自此前的可信型号证据，绑定单独按当前有效性统计。':'窗口内观测 IP、MAC；绑定与哑终端按当前有效证据统计。'}标识数不是物理设备数。</Typography.Text>
    {data&&<div className="census-note">IPv4 {data.observed_ipv4} · IPv6 {data.observed_ipv6} · 随机 MAC {data.random_macs} · 有效绑定仅含当前无冲突的 IP–MAC 关系。</div>}
    <div className="census-scope-filters">{([['campus_id','校区'],['access_domain','接入域'],['vlan','VLAN'],['vrf','VRF']] as const).map(([key,label])=><Input key={key} aria-label={`镜像统计${label}`} placeholder={label} value={scope[key]} onChange={event=>changeScope(key,event.target.value)}/>)}</div>
    {data&&<div className="census-note">范围：传感器 {data.scope?.sensor_id}，校区 {scope.campus_id||'全部'}，接入域 {scope.access_domain||'全部'}，VLAN {scope.vlan||'全部'}，VRF {scope.vrf||'全部'} · 截至 {formatTime(data.as_of)||'统计尚未生成'} · {data.status==='ready'?'投影时间窗完整':data.status==='initializing'?'统计尚未生成':data.status==='delayed'?'处理延迟':data.status==='scope_changed'?'站点网段配置已变化，需受控重建':'窗口或处理不完整'}{data.available_from?` · 可用起点 ${formatTime(data.available_from)}`:''}{data.oldest_pending_at?` · 最早积压 ${formatTime(data.oldest_pending_at)}`:''}{data.failed_batches?` · 处理失败次数 ${data.failed_batches}`:''}{data.incomplete_scope?` · 作用域字段不完整 ${data.incomplete_scope}`:''}</div>}
    <div className="census-types">{Object.keys(terminalNames).filter(type=>data?.metric_version==='passive-census/v2'||!['environment_monitor','ups','pdu'].includes(type)).map(device_type=>{const item=data?.types.find(type=>type.device_type===device_type);return <div className="census-type" key={device_type}><strong>{terminalNames[device_type]}</strong><span>已识别 {data?.status==='initializing'?'':item?.identified}</span><span>待核实 {data?.status==='initializing'?'':item?.candidate}</span><span>冲突 {data?.status==='initializing'?'':item?.conflict}</span></div>})}</div>
    {data&&<div className="census-note">{data.metric_version==='passive-census/v2'?'类型证据已撤销':'证据过期'} {data.terminal_expired} · 人工已核实 {data.manually_verified}（尚无校方真值清单）· 标识统计口径 {data.metric_version}{data.last_batch_rows?` · 最近投影 ${data.last_batch_rows} 行 / ${data.last_batch_ms} 毫秒`:''}</div>}
    <div className="census-list"><div className="census-section-head"><strong>{kindNames[kind]}清单</strong><span>与上方统计使用相同时间窗及网络作用域</span></div><div className="census-kind-switch" role="group" aria-label="标识清单类别">{(['ip','mac','binding','terminal'] as const).map(value=><Button key={value} size="small" type={kind===value?'primary':'default'} aria-pressed={kind===value} onClick={()=>chooseKind(value)}>{kindNames[value]}</Button>)}</div>{page.isError&&<div role="alert">清单读取失败：{page.error.message}</div>}<div className="census-rows">{page.data?.items.map(row=><div className="census-row" key={`${row.scope_key}|${row.kind}|${row.value}`}><span className="census-row-value">{row.kind==='terminal'?row.device_key||row.value:row.value}</span><span>{row.kind==='terminal'?`${terminalNames[row.effective_type??'']??row.effective_type??''} · ${terminalStates[row.classification_status??'']??''}`:row.kind==='mac'&&row.random_mac?'本地管理 MAC（含随机）':''}</span><span>{scopeLabel(row)}</span><span className="census-row-times"><time>{formatTime(row.last_seen)}</time>{row.type_evidence_at&&<small>类型依据 {formatTime(row.type_evidence_at)}</small>}{row.activity_status&&<small>{activityStates[row.activity_status]}</small>}</span></div>)}</div>{page.data?.has_more&&<Button onClick={()=>setCursor(page.data!.next_cursor)}>下一页</Button>}</div>
    <div className="census-compare"><div className="census-section-head"><strong>与其他系统比对</strong><span>CSV 仅在浏览器本地读取；作用域列使用“传感器|校区|接入域|VLAN|VRF”</span></div><input className="census-file-input" ref={fileRef} type="file" accept=".csv,text/csv" aria-label="导入对方 CSV" onChange={event=>void importFile(event.target.files?.[0])}/><Button icon={<UploadOutlined/>} onClick={()=>fileRef.current?.click()}>导入对方 CSV</Button>{table&&<><span>{table.rows.length.toLocaleString('zh-CN')} 行</span><div className="census-column-mapping">{([['ip','IP'],['mac','MAC'],['scope','网络作用域'],['type','设备类型（可选）']] as const).map(([key,label])=><label key={key}>{label}<Select aria-label={`${label}列`} value={mapping[key]} onChange={value=>setMapping(current=>({...current,[key]:value}))} options={[{value:-1,label:'空值'},...table.headers.map((name,index)=>({value:index,label:name}))]}/></label>)}</div><Button type="primary" loading={working} onClick={()=>void compare()}>开始本地比对</Button></>}{error&&<div className="census-error" role="alert">{error}</div>}{differences&&<><div className="census-diff-summary">{Object.entries(resultNames).map(([key,label])=><span key={key}>{label} {differences.filter(row=>row.result===key).length}</span>)}</div><Button icon={<DownloadOutlined/>} onClick={()=>downloadCSV(differences.filter(row=>row.result!=='shared'))}>下载差异 CSV</Button><div className="census-diff-preview">{differences.slice(0,30).map((item,index)=><div className="census-row" key={index}><strong>{resultNames[item.result]}</strong><span>{item.ip||item.mac}</span><span>{item.scope}</span><span>{item.reason}</span></div>)}{differences.length>30&&<span>页面显示前 30 行，下载包含全部差异。</span>}</div></>}</div>
      </div>
    </Drawer>}
  </section>
}
