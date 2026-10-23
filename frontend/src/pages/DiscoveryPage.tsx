import {
  useSession} from '../shared/api/queries'
import {can} from '../shared/auth/permissions'
import { useState } from 'react'
import { useQuery,
  useQueryClient } from '@tanstack/react-query'
import { Button,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Switch,
  Tabs,
  Tag,
  Typography,
  message,
} from 'antd'
import { useUrlState } from '../shared/ui/useUrlState'
import { request } from '../shared/api/client'
import { RouterObservationsPanel } from './RouterObservationsPanel'
import { routerRoleLabels } from './routerLabels'
import type { ColumnsType } from 'antd/es/table'
import { AppCursorPagination, AppErrorAlert, AppFactBar, AppListHeader, AppTable, formatDateTime } from '../shared/ui'

type Source = {id:string;name:string;node:string;site:string;domain:string;address:string;snmp_version:string;username?:string;interval_seconds:number;enabled:boolean;config_version:number}
type Observation = {id:string;ip?:string;mac?:string;name?:string;origin:string;port?:string;vlan?:string;observed_at:string;valid_until:string;explanation:string;device_type?:string;capabilities?:string[];manufacturer?:string;model_name?:string}
const fmtTime = formatDateTime
const selfReportedModel=(o:Observation)=>[o.manufacturer,o.model_name].filter(Boolean).join(' ')
type Device = {id:string;observations:Observation[];association:string}
type ScanProfile = {id:string;node:string;site:string;domain:string;version:number;trial_version:number;enabled:boolean;config:{allow:string[];exclude:string[];addresses:string[];interface?:string;protocols:string[];sensitive:boolean;interval_seconds:number}}
type Task = {id:string;source_id:string;status:string;created_at:string;error?:string;result?:{tables?:{name:string;count:number;complete:boolean;error?:string}[]}}
const statuses:Record<string,string>={pending:'等待采集',running:'采集中',complete:'已完成',partial:'部分完成',failed:'失败',cancelled:'已停止'}
const origins:Record<string,string>={fdb:'交换机 MAC 表',neighbor:'网关邻居表',lldp:'LLDP 邻居',dns_sd:'DNS-SD 服务',ssdp:'SSDP 公告',active:'探测响应'}
export function DiscoveryPage({configuration=false,embedded=false}:{configuration?:boolean;embedded?:boolean}){
 const [tab,setTab]=useUrlState('tab',configuration?'sources':'routers',configuration?['sources','scan','tasks']:['routers','devices']);
 const [devicePage,setDevicePage]=useState(1);const [deviceCursors,setDeviceCursors]=useState<string[]>(['']);
 const session=useSession();const manage=can(session.data,'integrations:write')
 const client=useQueryClient();const [form]=Form.useForm();const [editing,setEditing]=useState<Source|null>();const [detail,setDetail]=useState<Device>();const [saving,setSaving]=useState(false)
 const options={refetchInterval:()=>document.visibilityState==='visible'?15000:false,refetchIntervalInBackground:false}
 const sources=useQuery({queryKey:['discovery','sources'],queryFn:()=>request<{items:Source[]}>('/discovery/sources'),enabled:configuration&&tab==='sources',...options})
 const deviceCursor=deviceCursors[devicePage-1]??'';
 const devices=useQuery({queryKey:['discovery','devices',devicePage,deviceCursor],queryFn:()=>request<{items:Device[];next_cursor?:string;has_more:boolean}>(`/discovery/devices?limit=20${deviceCursor?`&cursor=${encodeURIComponent(deviceCursor)}`:''}`),enabled:!configuration&&tab==='devices',...options})
 const tasks=useQuery({queryKey:['discovery','tasks'],queryFn:()=>request<{items:Task[]}>('/discovery/tasks'),enabled:configuration&&tab==='tasks',...options})
 const [scanForm]=Form.useForm();const [scanOpen,setScanOpen]=useState(false);const[scanEditing,setScanEditing]=useState<ScanProfile>();const [preview,setPreview]=useState<number>();
 const profiles=useQuery({queryKey:['discovery','profiles'],queryFn:()=>request<{items:ScanProfile[]}>('/discovery/scan-profiles'),enabled:configuration&&tab==='scan',...options})
 const scanConfig=(v:Record<string,unknown>)=>({allow:String(v.allow??'').split(/[,\s]+/).filter(Boolean),exclude:String(v.exclude??'').split(/[,\s]+/).filter(Boolean),addresses:String(v.addresses??'').split(/[,\s]+/).filter(Boolean),interface:v.interface??'',protocols:v.protocols??['icmp'],sensitive:v.sensitive??false,interval_seconds:Number(v.interval_seconds??86400)})
 async function previewScan(){try{const v=await scanForm.validateFields();const result=await request<{total:number}>('/discovery/preview',{method:'POST',body:JSON.stringify(scanConfig(v))});setPreview(result.total)}catch(e){void message.error(String(e))}}
 async function saveScan(){try{const v=await scanForm.validateFields();await request('/discovery/scan-profiles',{method:'POST',body:JSON.stringify({id:v.id,node:v.node,site:v.site,domain:v.domain,config:scanConfig(v),version:scanEditing?.version??0})});setScanOpen(false);void refresh()}catch(e){void message.error(String(e))}}
 const summary=useQuery({queryKey:['discovery','summary'],queryFn:()=>request<{window:string;infrastructure:number;active_responses:number;pending_association:number}>('/discovery/summary'),enabled:!configuration,...options})
 const nodes=useQuery({queryKey:['discovery','nodes'],queryFn:()=>request<{items:{node:string;available:boolean}[]}>('/discovery/nodes'),enabled:configuration,...options})
 const refresh=()=>client.invalidateQueries({queryKey:['discovery']})
 async function action(path:string){try{await request(path,{method:'POST',body:'{}'});void refresh()}catch(e){void message.error(String(e))}}
 function edit(s:Source|null){setEditing(s);form.resetFields();form.setFieldsValue(s??{snmp_version:'3',interval_seconds:300,enabled:false})}
 async function save(){const v=await form.validateFields();setSaving(true);try{const{community,auth,privacy,...source}=v;await request('/discovery/sources',{method:'POST',body:JSON.stringify({source:{...source,config_version:editing?.config_version??0},secret:{community,auth,privacy},expected_version:editing?.config_version??0})});setEditing(undefined);void refresh()}catch(e){void message.error(String(e))}finally{setSaving(false)}}
 const cols=[{title:'IP',key:'ip',width:130,render:(_:unknown,d:Device)=><span className="discovery-identifier">{d.observations.find(o=>o.ip)?.ip??''}</span>},{title:'终端名称',key:'name',render:(_:unknown,d:Device)=>{const model=d.observations.map(selfReportedModel).find(Boolean);return <div className="discovery-name"><span>{d.observations.find(o=>o.name)?.name??''}</span>{model&&<Typography.Text type="secondary">自报型号 {model}</Typography.Text>}</div>}},{title:'类型与能力',key:'type',render:(_:unknown,d:Device)=><Space wrap>{[...new Set(d.observations.map(o=>o.device_type).filter(Boolean))].map(t=><Tag key={t}>{routerRoleLabels[t!]??t}线索</Tag>)}{[...new Set(d.observations.flatMap(o=>o.capabilities??[]))].map(c=><Tag key={c}>{{printing:'打印服务',scanning:'扫描服务',casting:'投屏服务',network_video:'网络视频',routing:'路由服务',media_rendering:'媒体播放'}[c]??c}</Tag>)}</Space>},{title:'MAC',key:'mac',render:(_:unknown,d:Device)=><span className="discovery-identifier">{d.observations.find(o=>o.mac)?.mac??''}</span>},{title:'发现依据',key:'source',render:(_:unknown,d:Device)=><Space wrap>{[...new Set(d.observations.map(o=>o.origin))].map(o=><Tag key={o}>{origins[o]??o}</Tag>)}</Space>},{title:'位置线索',key:'location',render:(_:unknown,d:Device)=>[...new Set(d.observations.filter(o=>o.port).map(o=>`${o.port}${o.vlan?' / VLAN '+o.vlan:''}`))].join('、')},{title:'读取／响应时间',key:'time',render:(_:unknown,d:Device)=>fmtTime(d.observations[0]?.observed_at)},{title:'操作',key:'action',fixed:'right' as const,width:100,render:(_:unknown,d:Device)=><Button type="link" onClick={()=>setDetail(d)}>查看证据</Button>}]
 const sourceColumns: ColumnsType<Source> = [
  {title:'名称',key:'name',width:140,render:(_,s)=>s.name||s.address},
  {title:'管理 IP',dataIndex:'address',width:120,render:(_,s)=><span className="discovery-identifier">{s.address}</span>},
  {title:'SNMP',key:'snmp',width:100,render:(_,s)=>s.snmp_version==='3'?'v3 authPriv':'v2c 只读'},
  {title:'站点 / 网络范围',key:'site',width:140,render:(_,s)=>`${s.site} / ${s.domain}`},
  {title:'采集节点',dataIndex:'node',width:100},
  {title:'轮询间隔',key:'interval',width:90,render:(_,s)=>`${s.interval_seconds} 秒`},
  {title:'采集方式',key:'enabled',width:90,render:(_,s)=>s.enabled?'定时采集':'手动采集'},
  {title:'操作',key:'action',width:170,fixed:'right' as const,render:(_,s)=><Space wrap><Button type="link" disabled={!manage} onClick={()=>edit(s)}>编辑</Button><Button type="link" disabled={!manage} onClick={()=>void action(`/discovery/sources/${encodeURIComponent(s.id)}/poll`)}>测试并采集</Button></Space>},
 ]
 const scanColumns: ColumnsType<ScanProfile> = [
  {title:'配置标识',dataIndex:'id',width:130,render:(_,p)=><span className="discovery-identifier">{p.id}</span>},
  {title:'采集节点',dataIndex:'node',width:90},
  {title:'站点 / 网络范围',key:'site',width:130,render:(_,p)=>`${p.site} / ${p.domain}`},
  {title:'探测范围',key:'allow',width:215,onCell:()=>({className:'discovery-range-cell'}),render:(_,p)=>p.config.addresses.length?`${p.config.allow.join('、')||'未设置网段'}；指定地址 ${p.config.addresses.length} 个`:p.config.allow.join('、')},
  {title:'定时间隔',key:'interval',width:90,render:(_,p)=>`${p.config.interval_seconds} 秒`},
  {title:'定时状态',key:'enabled',width:90,render:(_,p)=>p.enabled?'定时已启用':'定时关闭'},
  {title:'操作',key:'action',width:235,fixed:'right' as const,render:(_,p)=>scanActions(p)},
 ]
 const scanActions = (p: ScanProfile) => (
  <Space wrap>
   <Button type="link" disabled={!manage} onClick={()=>{setScanEditing(p);scanForm.setFieldsValue({...p,...p.config,allow:p.config.allow.join(', '),exclude:p.config.exclude.join(', '),addresses:p.config.addresses.join(', ')});setPreview(undefined);setScanOpen(true)}}>编辑</Button>
   <Button type="link" title="手动试扫" disabled={!manage} onClick={()=>void action(`/discovery/scan-profiles/${encodeURIComponent(p.id)}/trial`)}>试扫</Button>
   <Button type="link" disabled={!manage||(!p.enabled&&p.trial_version!==p.version)} onClick={()=>{void request(`/discovery/scan-profiles/${encodeURIComponent(p.id)}/schedule`,{method:'POST',body:JSON.stringify({enabled:!p.enabled,version:p.version})}).then(refresh).catch(e=>message.error(String(e)))}}>{p.enabled?'停用':'启用'}</Button>
  </Space>
 )
 const taskColumns: ColumnsType<Task> = [
  {title:'采集源',dataIndex:'source_id',width:160,render:(_,t)=><span className="discovery-identifier">{t.source_id}</span>},
  {title:'状态',key:'status',width:100,render:(_,t)=>statuses[t.status]??t.status},
  {title:'创建时间',key:'created',width:160,render:(_,t)=>fmtTime(t.created_at)},
  {title:'采集结果',key:'tables',width:260,onCell:()=>({className:'discovery-range-cell'}),render:(_,t)=>t.result?.tables?.length?<div className="discovery-task-tables">{t.result.tables.map(v=><div key={v.name}>{v.name} · {v.count} 条{v.error?`；${v.error}`:''}</div>)}</div>:null},
  {title:'错误',key:'error',width:200,onCell:()=>({className:'discovery-range-cell'}),render:(_,t)=>t.error?<span className="discovery-task-error">{t.error}</span>:null},
  {title:'操作',key:'action',width:90,fixed:'right' as const,render:(_,t)=>['pending','running'].includes(t.status)?<Button type="link" disabled={!manage} onClick={()=>void action(`/discovery/tasks/${encodeURIComponent(t.id)}/stop`)}>停止</Button>:null},
 ]
 const tabItems=[
 {key:'routers',label:'路由识别',children:<RouterObservationsPanel/>},
 {key:'devices',label:'发现记录',children:<>
        <AppListHeader title="发现记录" count={`${devices.data?.items.length ?? 0} 条`} />
        <AppTable rowKey="id" columns={cols} dataSource={devices.data?.items??[]} pagination={false} locale={{emptyText:'暂无发现记录'}} scroll={{x:1150}}/>
        <AppCursorPagination previous={devicePage!==1} next={Boolean(devices.data?.has_more)} label={`第 ${devicePage} 页`} onPrevious={()=>setDevicePage(devicePage-1)} onNext={()=>{const next=devices.data?.next_cursor;if(next){setDeviceCursors([...deviceCursors,next]);setDevicePage(devicePage+1)}}} />
      </>},
 {key:'sources',label:'基础设施接入',children:<>
        <AppListHeader title="基础设施接入" count={`${sources.data?.items.length ?? 0} 条`} actions={<Button disabled={!manage} onClick={()=>edit(null)}>新增接入源</Button>} />
        <AppTable rowKey="id" columns={sourceColumns} dataSource={sources.data?.items??[]} scroll={{x:980}} locale={{emptyText:'暂无接入源'}} />
      </>},
 {key:'scan',label:'主动发现',children:<>
        <AppListHeader title="主动发现" count={`${profiles.data?.items.length ?? 0} 条`} actions={<Button disabled={!manage} onClick={()=>{scanForm.resetFields();setScanEditing(undefined);setPreview(undefined);setScanOpen(true)}}>新增探测配置</Button>} />
        <AppFactBar items={['默认关闭，只探测配置范围内的地址','先配置范围并预览，手动试扫通过后才能开启定时','IPv6 只使用已发现或已填写的地址']}/>
        <AppTable rowKey="id" columns={scanColumns} dataSource={profiles.data?.items??[]} scroll={{x:980}} locale={{emptyText:'暂无探测配置'}} />
      </>},
 {key:'tasks',label:'任务与诊断',children:<>
        <AppListHeader title="任务与诊断" count={`${tasks.data?.items.length ?? 0} 条`} description={nodes.data?.items.map(n=>`${n.node} · ${n.available?'任务服务就绪':'任务服务心跳超时'}`).join(' ／ ')} />
        <AppTable rowKey="id" columns={taskColumns} dataSource={tasks.data?.items??[]} scroll={{x:970}} locale={{emptyText:'暂无采集任务'}} />
      </>}
 ];
 const Shell = embedded ? 'section' : 'main'
 return <Shell className={embedded ? 'page-content discovery-page' : 'page discovery-page'}>
 {((tab==='sources'&&sources.error)||(tab==='devices'&&devices.error)||(tab==='tasks'&&tasks.error)||(tab==='scan'&&profiles.error)||(configuration&&nodes.error)||(!configuration&&summary.error))&&<AppErrorAlert title="读取发现数据失败" message={String((tab==='sources'&&sources.error)||(tab==='devices'&&devices.error)||(tab==='tasks'&&tasks.error)||(tab==='scan'&&profiles.error)||(configuration&&nodes.error)||(!configuration&&summary.error))} />}
 <section className="surface">{summary.data&&<div className="discovery-toolbar"><Typography.Text type="secondary">近 24 小时 · 有效发现记录</Typography.Text><Space wrap><span>基础设施 {summary.data.infrastructure}</span><span>探测响应 {summary.data.active_responses}</span></Space></div>}{configuration?<>{tabItems.find(item=>item.key===tab)?.children}</>:<Tabs activeKey={tab} onChange={setTab} destroyOnHidden items={tabItems.filter(item=>['routers','devices'].includes(item.key))}/>}</section>
 <Modal title="配置主动发现" open={scanOpen} onCancel={()=>setScanOpen(false)} onOk={()=>void saveScan()} okButtonProps={{disabled:preview===undefined}}><Form form={scanForm} layout="vertical" onValuesChange={()=>setPreview(undefined)} initialValues={{protocols:['icmp'],sensitive:false}}>{[{name:'id',label:'配置标识'},{name:'node',label:'采集节点'},{name:'site',label:'站点'},{name:'domain',label:'网络范围'},{name:'allow',label:'允许网段（CIDR，逗号分隔）'}].map(f=><Form.Item key={f.name} name={f.name} label={f.label} rules={[{required:true}]}>{f.name==='node'?<Select showSearch options={(nodes.data?.items ?? []).map(n=>({value:n.node,label:n.node}))}/>:<Input disabled={f.name==='id'&&!!scanEditing}/>}</Form.Item>)}<Form.Item name="exclude" label="排除地址／网段（CIDR）"><Input/></Form.Item><Form.Item name="addresses" label="指定 IPv6 地址"><Input/></Form.Item><Form.Item name="interface" label="本地链路接口"><Input/></Form.Item><Form.Item name="sensitive" label="工控／敏感范围" valuePropName="checked"><Switch/></Form.Item><Form.Item name="interval_seconds" label="定时间隔（秒）" initialValue={86400}><InputNumber min={3600} max={604800}/></Form.Item><Form.Item name="protocols" label="探测协议"><Select mode="multiple" options={['icmp','arp','ndp','ipp','ipps','ssdp','onvif'].map(value=>({value,label:value.toUpperCase()}))}/></Form.Item><Button onClick={()=>void previewScan()}>预览目标数</Button>{preview!==undefined&&<Typography.Paragraph>显式目标 {preview} 个，保存后保持关闭。</Typography.Paragraph>}</Form></Modal>
 <Modal title={editing?'编辑接入源':'新增接入源'} open={editing!==undefined} onCancel={()=>setEditing(undefined)} onOk={()=>void save()} confirmLoading={saving} destroyOnHidden><Form form={form} layout="vertical">
 {([{name:'id',label:'接入源标识'},{name:'name',label:'名称'},{name:'address',label:'管理 IP'},{name:'node',label:'采集节点'},{name:'site',label:'站点'},{name:'domain',label:'二层网络范围'}]).map(f=><Form.Item key={f.name} name={f.name} label={f.label} rules={[{required:true}]}>{f.name==='node'?<Select showSearch options={(nodes.data?.items ?? []).map(n=>({value:n.node,label:n.node+(n.available?'':'（心跳超时）')}))}/>:<Input disabled={f.name==='id'&&!!editing}/>}</Form.Item>)}
 <Form.Item name="snmp_version" label="SNMP 版本"><Select options={[{value:'3',label:'SNMPv3 authPriv（SHA-256 / AES）'},{value:'2c',label:'SNMPv2c 只读'}]}/></Form.Item>
 <Form.Item noStyle shouldUpdate={(a,b)=>a.snmp_version!==b.snmp_version}>{({getFieldValue})=>getFieldValue('snmp_version')==='3'?<><Form.Item name="username" label="用户名" rules={[{required:true}]}><Input/></Form.Item><Form.Item name="auth" label="认证口令"><Input.Password autoComplete="new-password"/></Form.Item><Form.Item name="privacy" label="加密口令"><Input.Password autoComplete="new-password"/></Form.Item></>:<Form.Item name="community" label="只读 Community"><Input.Password autoComplete="new-password"/></Form.Item>}</Form.Item>
 <Typography.Paragraph type="secondary">编辑时凭据留空表示保留原值。身份范围映射仅在确认采集范围一致后填写；留空时保留独立发现记录。</Typography.Paragraph>{[{name:'identity_sensor',label:'身份采集器标识'},{name:'identity_campus',label:'身份校区标识'},{name:'identity_vlan',label:'身份 VLAN 范围'},{name:'identity_vrf',label:'身份 VRF 范围'}].map(f=><Form.Item key={f.name} name={f.name} label={f.label}><Input/></Form.Item>)}<Form.Item name="interval_seconds" label="轮询间隔（秒）"><InputNumber min={60} max={86400}/></Form.Item><Form.Item name="enabled" label="启用定时采集" valuePropName="checked"><Switch/></Form.Item></Form></Modal>
 <Modal title="发现证据" open={!!detail} footer={null} onCancel={()=>setDetail(undefined)}><div className="discovery-source-list">{(detail?.observations ?? []).map(o=><article className="discovery-card" key={o.id}><strong>{origins[o.origin]??o.origin}</strong>{(o.ip||o.mac)&&<div className="discovery-identifier">{[o.ip,o.mac].filter(Boolean).join(' ')}</div>}{o.port&&<div>端口 {o.port}</div>}{o.vlan&&<div>VLAN {o.vlan}</div>}{selfReportedModel(o)&&<div>自报型号 {selfReportedModel(o)}</div>}{fmtTime(o.observed_at)&&<div>读取时间 {fmtTime(o.observed_at)}</div>}<div>{o.explanation}</div><Typography.Text type="secondary">事件 {o.id}</Typography.Text></article>)}</div></Modal></Shell>
}
