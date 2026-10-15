import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App } from 'antd'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { AccountAssessmentDetailsPage, AccountAssessmentsPage } from './AccountAssessmentsPage'

const request=vi.hoisted(()=>vi.fn())
vi.mock('../shared/api/client',async(importOriginal)=>{const actual=await importOriginal<typeof import('../shared/api/client')>();return {...actual,request,api:{...actual.api,session:()=>request('/session'),accountAssessments:(query:Record<string,unknown>)=>request(`/account-assessments?${new URLSearchParams(query as Record<string,string>)}`),accountAssessment:(id:string)=>request(`/accounts/${id}/assessment`),createAccountTagReview:(id:string,payload:unknown)=>request(`/accounts/${id}/tag-reviews`,{method:'POST',body:JSON.stringify(payload)})}}})

const now='2026-10-14T02:00:00Z'
const tags=[
  {account_id:'student-1',tag_type:'proxy',assessment_version:'proxy-v1',state:'current',evidence_level:'confirmed',source_type:'risk_assessment',reason:'当前有效研判存在代理行为依据',endpoint_ids:['endpoint-1'],evidence_ids:['evidence-1'],rule_version:'risk-v1',first_seen:now,last_seen:now,valid_until:now,review_state:'pending'},
  {account_id:'student-1',tag_type:'pc',assessment_version:'pc-v1',state:'current',evidence_level:'likely',source_type:'endpoint_recognition',reason:'近 7 天认证关联终端识别为 PC',endpoint_ids:['endpoint-1'],evidence_ids:['endpoint:endpoint-1'],rule_version:'fingerprint-v1',first_seen:now,last_seen:now,valid_until:now,review_state:'pending'},
] as const

function setup(path='/accounts'){
  request.mockImplementation((url:string)=>{
    if(url==='/session')return Promise.resolve({user:{id:'operator',name:'操作员'},role:'operator',permissions:['identity:read','labels:create']})
    if(url.startsWith('/account-assessments'))return Promise.resolve({items:[{account_id:'student-1',tags,endpoint_count:1,primary_reason:tags[0].reason,review_state:'pending',last_assessed_at:now}],state:'ready',as_of:now,page:{limit:20,total:1}})
    if(url==='/accounts/student-1/assessment')return Promise.resolve({account_id:'student-1',state:'ready',as_of:now,tags,history:[],endpoints:[{endpoint_id:'endpoint-1',primary_mac:'00:11:22:33:44:55',brand:'Dell',device_type:'desktop',last_seen:now,evidence_level:'likely'}],reviews:[]})
    if(url==='/accounts/student-1/tag-reviews')return Promise.resolve({review_id:'review-1',account_id:'student-1',tag_type:'proxy',assessment_version:'proxy-v1',decision:'reject',reason:'现场核对',evidence_ids:['evidence-1'],created_by:'operator',created_at:now})
    return Promise.reject(new Error(url))
  })
  const client=new QueryClient({defaultOptions:{queries:{retry:false},mutations:{retry:false}}})
  return render(<QueryClientProvider client={client}><App><MemoryRouter initialEntries={[path]}><Routes><Route path="/accounts" element={<AccountAssessmentsPage/>}/><Route path="/accounts/:accountId" element={<AccountAssessmentDetailsPage/>}/></Routes></MemoryRouter></App></QueryClientProvider>)
}

afterEach(()=>{cleanup();request.mockReset()})

describe('用户研判',()=>{
  it('同时展示多个当前标签且不把评分包装为百分比',async()=>{
    setup()
    expect(await screen.findAllByText('代理')).not.toHaveLength(0)
    expect(screen.getAllByText('PC').length).toBeGreaterThan(0)
    expect(screen.getAllByText('已确认').length).toBeGreaterThan(0)
    expect(document.body.textContent).not.toMatch(/\d+%/)
  })

  it('复核提交绑定当前评估版本',async()=>{
    setup('/accounts/student-1')
    await screen.findByText('当前标签')
    fireEvent.click(screen.getAllByRole('button',{name:/否决/})[0])
    fireEvent.change(screen.getByLabelText('复核原因'),{target:{value:'现场核对'}})
    fireEvent.click(screen.getByRole('button',{name:'提交复核'}))
    await waitFor(()=>expect(request).toHaveBeenCalledWith('/accounts/student-1/tag-reviews',expect.objectContaining({body:expect.stringContaining('"assessment_version":"proxy-v1"')})))
  })
})
