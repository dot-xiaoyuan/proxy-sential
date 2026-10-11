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

export function BlacklistPage(){
 const session=useSession(),writable=can(session.data,'policies:manage'),cache=useQueryClient()
 const pagination=useServerPagination('blacklist_')
 const [keyword,setKeyword]=useUrlState('keyword','',undefined,['blacklist_page'])
 const [kind,setKind]=useUrlState('type','',Object.keys(types),['blacklist_page'])
 const [stateFilter,setStateFilter]=useUrlState('state','',Object.keys(stateNames),['blacklist_page'])
 const [open,setOpen]=useState(false),[editing,setEditing]=useState<Entry>(),[form]=Form.useForm<Entry>()
 const query=new URLSearchParams({limit:String(pagination.pageSize),cursor:pagination.cursor,keyword,type:kind,state:stateFilter})
 const entries=useQuery({queryKey:['blacklist',query.toString()],queryFn:()=>request<Result>(`/blacklist?${query}`),refetchInterval:30000})
 const mutation=useMutation({mutationFn:({entry,id,op}:{entry:Partial<Entry>;id?:string;op?:string})=>request<Entry>(`/blacklist${id?`/${encodeURIComponent(id)}`:''}${op?`/${op}`:''}`,{method:'POST',body:JSON.stringify(entry)}),onSuccess:()=>{void cache.invalidateQueries({queryKey:['blacklist']})},onError:(e:Error)=>message.error(e.message)})
 const edit=(e?:Entry)=>{setEditing(e);form.resetFields();form.setFieldsValue(e?{...e,valid_from:local(e.valid_from),expires_at:local(e.expires_at)}:{type:'account',enabled:true});setOpen(true)}
 const save=async()=>{try{const value=await form.validateFields();const entry={...value,revision:editing?.revision??0,valid_from:value.valid_from?new Date(value.valid_from).toISOString():undefined,expires_at:value.expires_at?new Date(value.expires_at).toISOString():undefined};await mutation.mutateAsync({entry,id:editing?.entry_id});setOpen(false);message.success('黑名单已保存')}catch{/* Validation and request failures are shown by the form or mutation. */}}
 const now=Date.parse(entries.data?.checked_at || new Date().toISOString())
 return <section className="blacklist-page"><AppPageHeader title="黑名单" subtitle="命中即进入准入处置的策略名单" onRefresh={()=>void entries.refetch()}/>
  <Alert type="info" showIcon title="命中后需要策略授权才产生动作" description="黑名单只提供命中事实；只有配置了触发条件为黑名单命中的策略，命中账号才会进入动作流程。白名单优先级更高，命中白名单的账号不会被黑名单处置。"/>
  <Card><div className="whitelist-toolbar"><Input.Search aria-label="搜索黑名单" placeholder="匹配值、原因或校区" defaultValue={keyword} onSearch={value=>setKeyword(value.trim())} allowClear/><Select aria-label="黑名单类型筛选" placeholder="全部类型" allowClear value={kind||undefined} onChange={value=>setKind(value||'')} options={Object.entries(types).map(([value,label])=>({value,label}))}/><Select aria-label="黑名单状态筛选" placeholder="全部状态" allowClear value={stateFilter||undefined} onChange={value=>setStateFilter(value||'')} options={Object.entries(stateNames).map(([value,label])=>({value,label}))}/><Button type="primary" disabled={!writable} onClick={()=>edit()}>新增黑名单</Button></div>
   {entries.isError?<AppErrorAlert title="黑名单读取失败"/>:entries.isLoading?<AppLoadingState rows={4}/>:entries.data?.items.length?<div className="whitelist-list">{entries.data.items.map(e=><article className="whitelist-card" key={e.entry_id}><div className="whitelist-heading"><div><Tag>{types[e.type]}</Tag><strong className="whitelist-value">{e.value}</strong></div><Tag color={state(e,now)==='active'?'red':undefined}>{stateNames[state(e,now)]}</Tag></div><p>{e.reason}</p><div className="whitelist-facts"><span>生效时间：{when(e.valid_from)}</span><span>有效期：{e.expires_at?when(e.expires_at):'长期'}</span>{e.campus_id&&<span>校区：{e.campus_id}</span>}{e.access_domain&&<span>接入域：{e.access_domain}</span>}</div><div className="whitelist-footer"><span>版本 {e.revision}{e.updated_by&&` · 操作人：${e.updated_by}`}</span><div className="whitelist-actions"><Button disabled={!writable||mutation.isPending} onClick={()=>edit(e)}>编辑</Button><Button disabled={!writable||mutation.isPending||!e.enabled&&!!e.expires_at&&Date.parse(e.expires_at)<=now} onClick={()=>mutation.mutate({id:e.entry_id,op:e.enabled?'disable':'enable',entry:{revision:e.revision}})}>{e.enabled?'停用':'启用'}</Button></div></div></article>)}</div>:<Empty description="暂无黑名单"/>}
   <AppServerPagination page={pagination.page} pageSize={pagination.pageSize} total={entries.data?.page.total??0} onChange={pagination.update}/>
  </Card>
  <Modal forceRender okText="保存黑名单" cancelText="取消" title={editing?'编辑黑名单':'新增黑名单'} open={open} confirmLoading={mutation.isPending&&!mutation.variables?.op} onCancel={()=>setOpen(false)} onOk={()=>void save()}><Form form={form} layout="vertical"><Form.Item name="type" label="黑名单类型" rules={[{required:true}]}><Select options={Object.entries(types).map(([value,label])=>({value,label}))}/></Form.Item><Form.Item name="value" label="匹配值" rules={[{required:true,max:256}]}><Input placeholder="完整账号、MAC、用户组标识、IP、CIDR 或起始 IP-结束 IP"/></Form.Item><Form.Item name="reason" label="列入原因" rules={[{required:true,min:2,max:1000}]}><Input.TextArea rows={2}/></Form.Item><Form.Item name="campus_id" label="限定校区"><Input placeholder="留空表示全部校区"/></Form.Item><Form.Item name="access_domain" label="限定接入域"><Input placeholder="填写时需同时指定校区"/></Form.Item><Form.Item name="valid_from" label="生效时间"><Input type="datetime-local"/></Form.Item><Form.Item name="expires_at" label="失效时间"><Input type="datetime-local"/></Form.Item><p className="whitelist-muted">生效时间留空表示立即生效，失效时间留空表示长期。</p><Form.Item name="enabled" label="启用" valuePropName="checked"><Switch/></Form.Item></Form></Modal>
 </section>
}
