import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Form, Input, Select, Space, Switch, Tag, Typography, message } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { request } from '../shared/api/client'
import { useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
import { AppFactBar, AppFormModal, AppListHeader, AppListSection, AppServerPagination, AppTable, AppTableBar, formatDate, formatDateTime, useServerPagination } from '../shared/ui'
import { useUrlState } from '../shared/ui/useUrlState'
import type { components } from '../shared/api/generated'
import { statusColor } from '../shared/ui/status'

type Entry=components['schemas']['WhitelistEntry']
type Result=components['schemas']['WhitelistPage']
const types={ip:'IP 地址',account:'认证账号',mac:'MAC 地址',network:'网段 / 范围',group:'用户组'}
const stateNames={active:'生效中',disabled:'已停用',expired:'已过期',scheduled:'待生效'}
const state=(e:Entry,now:number):keyof typeof stateNames=>!e.enabled?'disabled':e.expires_at && Date.parse(e.expires_at)<=now?'expired':Date.parse(e.valid_from)>now?'scheduled':'active'
const local=(value?:string)=>value?new Date(Date.parse(value)-new Date(value).getTimezoneOffset()*60000).toISOString().slice(0,16):''

export function WhitelistPage(){
 const session=useSession(),writable=can(session.data,'policies:manage'),cache=useQueryClient()
 const pagination=useServerPagination('whitelist_')
 const [keyword,setKeyword]=useUrlState('keyword','',undefined,['whitelist_page'])
 const [kind,setKind]=useUrlState('type','',Object.keys(types),['whitelist_page'])
 const [stateFilter,setStateFilter]=useUrlState('state','',Object.keys(stateNames),['whitelist_page'])
 const [searchInput,setSearchInput]=useState(keyword)
 const [open,setOpen]=useState(false),[editing,setEditing]=useState<Entry>(),[form]=Form.useForm<Entry>()
 const query=new URLSearchParams({limit:String(pagination.pageSize),cursor:pagination.cursor,keyword,type:kind,state:stateFilter})
 const entries=useQuery({queryKey:['whitelist',query.toString()],queryFn:()=>request<Result>(`/whitelist?${query}`),refetchInterval:30000})
 const mutation=useMutation({mutationFn:({entry,id,op}:{entry:Partial<Entry>;id?:string;op?:string})=>request<Entry>(`/whitelist${id?`/${encodeURIComponent(id)}`:''}${op?`/${op}`:''}`,{method:'POST',body:JSON.stringify(entry)}),onSuccess:()=>{void cache.invalidateQueries({queryKey:['whitelist']})},onError:(e:Error)=>message.error(e.message)})
 const edit=(e?:Entry)=>{setEditing(e);form.resetFields();form.setFieldsValue(e?{...e,valid_from:local(e.valid_from),expires_at:local(e.expires_at)}:{type:'account',enabled:true});setOpen(true)}
 const save=async()=>{try{const value=await form.validateFields();const entry={...value,revision:editing?.revision??0,valid_from:value.valid_from?new Date(value.valid_from).toISOString():undefined,expires_at:value.expires_at?new Date(value.expires_at).toISOString():undefined};await mutation.mutateAsync({entry,id:editing?.entry_id});setOpen(false);message.success('白名单已保存')}catch{/* Validation and request failures are shown by the form or mutation. */}}
 useEffect(()=>{const timer=globalThis.setTimeout(()=>{const next=searchInput.trim();if(next!==keyword){setKeyword(next);pagination.reset()}},300);return()=>globalThis.clearTimeout(timer)},[searchInput])
 const now=Date.parse(entries.data?.checked_at || new Date().toISOString())
 const columns: ColumnsType<Entry> = [
  {title:'类型',dataIndex:'type',width:110,render:(value:string)=>types[value as keyof typeof types]??value},
  {title:'匹配值',dataIndex:'value',width:200,render:(value:string)=><Typography.Text className="mono list-cell-nowrap" title={value}>{value}</Typography.Text>},
  {title:'状态',key:'state',width:88,render:(_,row)=><Tag color={statusColor(state(row,now))}>{stateNames[state(row,now)]}</Tag>},
  {title:'生效时间',dataIndex:'valid_from',width:110,render:(value:string)=><span title={formatDateTime(value)}>{formatDate(value)}</span>},
  {title:'有效期',key:'expires',width:110,render:(_,row)=>row.expires_at?<span title={formatDateTime(row.expires_at)}>{formatDate(row.expires_at)}</span>:'长期'},
  {title:'范围',key:'scope',width:170,render:(_,row)=>[row.campus_id,row.access_domain].filter(Boolean).join(' / ')},
  {title:'原因',dataIndex:'reason',width:240,render:(value:string)=><Typography.Text className="list-cell-nowrap" title={value}>{value}</Typography.Text>},

  {title:'操作',width:140,fixed:'right',render:(_,row)=><Space wrap><Button size="small" disabled={!writable||mutation.isPending} onClick={()=>edit(row)}>编辑</Button><Button size="small" disabled={!writable||mutation.isPending||!row.enabled&&!!row.expires_at&&Date.parse(row.expires_at)<=now} onClick={()=>mutation.mutate({id:row.entry_id,op:row.enabled?'disable':'enable',entry:{revision:row.revision}})}>{row.enabled?'停用':'启用'}</Button></Space>},
 ]
 return <main className="page">
  <AppFactBar label="白名单规则" items={['命中后禁止策略动作，检测证据照常保留','同一账号任一当前会话命中即停止处置','已发出动作不自动撤回，可在处置记录中撤销']}/>
  <AppTableBar searchPlaceholder="搜索匹配值、原因或校区" searchValue={searchInput} onSearchChange={setSearchInput} filters={<><Select aria-label="白名单类型筛选" placeholder="全部类型" allowClear value={kind||undefined} onChange={value=>{setKind(value||'');pagination.reset()}} options={Object.entries(types).map(([value,label])=>({value,label}))}/><Select aria-label="白名单状态筛选" placeholder="全部状态" allowClear value={stateFilter||undefined} onChange={value=>{setStateFilter(value||'');pagination.reset()}} options={Object.entries(stateNames).map(([value,label])=>({value,label}))}/></>} extra={<Button type="primary" disabled={!writable} onClick={()=>edit()}>新增白名单</Button>}/>
  <section className="surface">
   <AppListHeader title="白名单" count={`${entries.data?.page.total??0} 条`} />
   <AppListSection isError={entries.isError} errorTitle="白名单读取失败" isLoading={entries.isLoading} loadingRows={4} isEmpty={!entries.data?.items.length} emptyText="暂无白名单">
    <AppTable rowKey="entry_id" columns={columns} dataSource={entries.data?.items ?? []} scroll={{x:1180}}/>
   </AppListSection>
   <AppServerPagination page={pagination.page} pageSize={pagination.pageSize} total={entries.data?.page.total??0} onChange={pagination.update}/>
  </section>
  <AppFormModal okText="保存白名单" cancelText="取消" title={editing?'编辑白名单':'新增白名单'} open={open} confirmLoading={mutation.isPending&&!mutation.variables?.op} onCancel={()=>setOpen(false)} onOk={()=>void save()}><Form form={form} layout="vertical"><Form.Item name="type" label="白名单类型" rules={[{required:true}]}><Select options={Object.entries(types).map(([value,label])=>({value,label}))}/></Form.Item><Form.Item name="value" label="匹配值" rules={[{required:true,max:256}]}><Input placeholder="完整账号、MAC、用户组标识、IP、CIDR 或起始 IP-结束 IP"/></Form.Item><Form.Item name="reason" label="豁免原因" rules={[{required:true,min:2,max:1000}]}><Input.TextArea rows={2}/></Form.Item><Form.Item name="campus_id" label="限定校区"><Input placeholder="留空表示全部校区"/></Form.Item><Form.Item name="access_domain" label="限定接入域"><Input placeholder="填写时需同时指定校区"/></Form.Item><Form.Item name="valid_from" label="生效时间"><Input type="datetime-local"/></Form.Item><Form.Item name="expires_at" label="失效时间"><Input type="datetime-local"/></Form.Item><p className="whitelist-muted">生效时间留空表示立即生效，失效时间留空表示长期。</p><Form.Item name="enabled" label="启用" valuePropName="checked"><Switch/></Form.Item></Form></AppFormModal>
 </main>
}
