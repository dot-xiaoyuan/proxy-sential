import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Card, Empty, Form, Input, Modal, Select, Switch, Tag, message } from 'antd'
import { request } from '../shared/api/client'
import { useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
import { AppErrorAlert, AppLoadingState, AppPageHeader, AppServerPagination, useServerPagination } from '../shared/ui'
import { useUrlState } from '../shared/ui/useUrlState'
import type { components } from '../shared/api/generated'

type Entry=components['schemas']['WhitelistEntry']
type Result=components['schemas']['WhitelistPage']
const types={ip:'IP 地址',account:'认证账号',mac:'MAC 地址',network:'网段 / 地址范围',group:'用户组'}
const stateNames={active:'生效中',disabled:'已停用',expired:'已过期',scheduled:'待生效'}
const state=(e:Entry,now:number):keyof typeof stateNames=>!e.enabled?'disabled':e.expires_at && Date.parse(e.expires_at)<=now?'expired':Date.parse(e.valid_from)>now?'scheduled':'active'
const local=(value?:string)=>value?new Date(Date.parse(value)-new Date(value).getTimezoneOffset()*60000).toISOString().slice(0,16):''
const when=(value?:string)=>value?new Date(value).toLocaleString():''

export function WhitelistPage(){
 const session=useSession(),writable=can(session.data,'policies:manage'),cache=useQueryClient()
 const pagination=useServerPagination('whitelist_')
 const [keyword,setKeyword]=useUrlState('keyword','',undefined,['whitelist_page'])
 const [kind,setKind]=useUrlState('type','',Object.keys(types),['whitelist_page'])
 const [stateFilter,setStateFilter]=useUrlState('state','',Object.keys(stateNames),['whitelist_page'])
 const [open,setOpen]=useState(false),[editing,setEditing]=useState<Entry>(),[form]=Form.useForm<Entry>()
 const query=new URLSearchParams({limit:String(pagination.pageSize),cursor:pagination.cursor,keyword,type:kind,state:stateFilter})
 const entries=useQuery({queryKey:['whitelist',query.toString()],queryFn:()=>request<Result>(`/whitelist?${query}`),refetchInterval:30000})
 const mutation=useMutation({mutationFn:({entry,id,op}:{entry:Partial<Entry>;id?:string;op?:string})=>request<Entry>(`/whitelist${id?`/${encodeURIComponent(id)}`:''}${op?`/${op}`:''}`,{method:'POST',body:JSON.stringify(entry)}),onSuccess:()=>{void cache.invalidateQueries({queryKey:['whitelist']})},onError:(e:Error)=>message.error(e.message)})
 const edit=(e?:Entry)=>{setEditing(e);form.resetFields();form.setFieldsValue(e?{...e,valid_from:local(e.valid_from),expires_at:local(e.expires_at)}:{type:'account',enabled:true});setOpen(true)}
 const save=async()=>{try{const value=await form.validateFields();const entry={...value,revision:editing?.revision??0,valid_from:value.valid_from?new Date(value.valid_from).toISOString():undefined,expires_at:value.expires_at?new Date(value.expires_at).toISOString():undefined};await mutation.mutateAsync({entry,id:editing?.entry_id});setOpen(false);message.success('白名单已保存')}catch{/* Validation and request failures are shown by the form or mutation. */}}
 const now=Date.parse(entries.data?.checked_at || new Date().toISOString())
 return <section className="whitelist-page"><AppPageHeader title="白名单" subtitle="按认证身份与地址维护动作豁免" onRefresh={()=>void entries.refetch()}/>
  <Alert type="info" showIcon title="保留检测证据，命中后禁止策略动作" description="支持 IP、账号、MAC、网段和用户组；同账号任一当前认证会话命中时，该账号的处置停止。已发出的动作不会自动撤回，可通过处置记录人工撤销。"/>
  <Card><div className="whitelist-toolbar"><Input.Search aria-label="搜索白名单" placeholder="匹配值、原因或校区" defaultValue={keyword} onSearch={value=>setKeyword(value.trim())} allowClear/><Select aria-label="白名单类型筛选" placeholder="全部类型" allowClear value={kind||undefined} onChange={value=>setKind(value||'')} options={Object.entries(types).map(([value,label])=>({value,label}))}/><Select aria-label="白名单状态筛选" placeholder="全部状态" allowClear value={stateFilter||undefined} onChange={value=>setStateFilter(value||'')} options={Object.entries(stateNames).map(([value,label])=>({value,label}))}/><Button type="primary" disabled={!writable} onClick={()=>edit()}>新增白名单</Button></div>
   {entries.isError?<AppErrorAlert title="白名单读取失败"/>:entries.isLoading?<AppLoadingState rows={4}/>:entries.data?.items.length?<div className="whitelist-list">{entries.data.items.map(e=><article className="whitelist-card" key={e.entry_id}><div className="whitelist-heading"><div><Tag>{types[e.type]}</Tag><strong className="whitelist-value">{e.value}</strong></div><Tag color={state(e,now)==='active'?'blue':undefined}>{stateNames[state(e,now)]}</Tag></div><p>{e.reason}</p><div className="whitelist-facts"><span>生效时间：{when(e.valid_from)}</span><span>有效期：{e.expires_at?when(e.expires_at):'长期'}</span>{e.campus_id&&<span>校区：{e.campus_id}</span>}{e.access_domain&&<span>接入域：{e.access_domain}</span>}</div><div className="whitelist-footer"><span>版本 {e.revision}{e.updated_by&&` · 操作人：${e.updated_by}`}</span><div className="whitelist-actions"><Button disabled={!writable||mutation.isPending} onClick={()=>edit(e)}>编辑</Button><Button disabled={!writable||mutation.isPending||!e.enabled&&!!e.expires_at&&Date.parse(e.expires_at)<=now} onClick={()=>mutation.mutate({id:e.entry_id,op:e.enabled?'disable':'enable',entry:{revision:e.revision}})}>{e.enabled?'停用':'启用'}</Button></div></div></article>)}</div>:<Empty description="暂无白名单"/>}
   <AppServerPagination page={pagination.page} pageSize={pagination.pageSize} total={entries.data?.page.total??0} onChange={pagination.update}/>
  </Card>
  <Modal forceRender okText="保存白名单" cancelText="取消" title={editing?'编辑白名单':'新增白名单'} open={open} confirmLoading={mutation.isPending&&!mutation.variables?.op} onCancel={()=>setOpen(false)} onOk={()=>void save()}><Form form={form} layout="vertical"><Form.Item name="type" label="白名单类型" rules={[{required:true}]}><Select options={Object.entries(types).map(([value,label])=>({value,label}))}/></Form.Item><Form.Item name="value" label="匹配值" rules={[{required:true,max:256}]}><Input placeholder="完整账号、MAC、用户组标识、IP、CIDR 或起始 IP-结束 IP"/></Form.Item><Form.Item name="reason" label="豁免原因" rules={[{required:true,min:2,max:1000}]}><Input.TextArea rows={2}/></Form.Item><Form.Item name="campus_id" label="限定校区"><Input placeholder="留空表示全部校区"/></Form.Item><Form.Item name="access_domain" label="限定接入域"><Input placeholder="填写时需同时指定校区"/></Form.Item><Form.Item name="valid_from" label="生效时间"><Input type="datetime-local"/></Form.Item><Form.Item name="expires_at" label="失效时间"><Input type="datetime-local"/></Form.Item><p className="whitelist-muted">生效时间留空表示立即生效，失效时间留空表示长期。</p><Form.Item name="enabled" label="启用" valuePropName="checked"><Switch/></Form.Item></Form></Modal>
 </section>
}
